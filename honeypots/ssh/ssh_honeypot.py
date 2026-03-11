"""Lightweight SSH honeypot wrapper for capturing credential guessing attempts."""

from __future__ import annotations

import socketserver
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from honeypot_ids.log_system.log_config import load_port_config, load_project_config
from honeypot_ids.log_system.logger import get_logger


@dataclass
class SSHAttempt:
    """Represent a captured SSH authentication attempt."""

    source_ip: str
    username: str
    password: str


class SSHBruteForceTracker:
    """Track failed login attempts per source IP."""

    def __init__(self, threshold: int) -> None:
        self.threshold = threshold
        self._attempts: dict[str, int] = defaultdict(int)
        self._lock = Lock()

    def register_attempt(self, attempt: SSHAttempt) -> dict[str, Any]:
        """Increment brute force counters and return detection metadata."""
        with self._lock:
            self._attempts[attempt.source_ip] += 1
            attempt_count = self._attempts[attempt.source_ip]

        return {
            "attempt_count": attempt_count,
            "threshold": self.threshold,
            "suspected_bruteforce": attempt_count >= self.threshold,
        }


class SSHHoneypotHandler(socketserver.StreamRequestHandler):
    """Capture fake SSH login attempts over a simple text-based session."""

    tracker: SSHBruteForceTracker

    def handle(self) -> None:
        source_ip = self.client_address[0]
        logger = get_logger()

        try:
            self.wfile.write(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")
            self.wfile.write(b"login as: ")
            username = self.rfile.readline(256).decode("utf-8", errors="ignore").strip()
            self.wfile.write(b"password: ")
            password = self.rfile.readline(256).decode("utf-8", errors="ignore").strip()

            attempt = SSHAttempt(source_ip=source_ip, username=username, password=password)
            metadata = self.tracker.register_attempt(attempt)

            event_name = "ssh_bruteforce_attempt" if metadata["suspected_bruteforce"] else "ssh_login_attempt"
            logger.log_event(
                source_ip=source_ip,
                service="ssh",
                event=event_name,
                attack_type="ssh_bruteforce" if metadata["suspected_bruteforce"] else "authentication_probe",
                payload={"username": username, "password": password},
                metadata=metadata,
                severity="warning" if metadata["suspected_bruteforce"] else "info",
            )
            self.wfile.write(b"Permission denied, please try again.\r\n")
        except OSError as exc:
            logger.log_event(
                source_ip=source_ip,
                service="ssh",
                event="ssh_session_error",
                attack_type="service_error",
                payload=str(exc),
                metadata={},
                severity="error",
            )


class ReusableThreadingTCPServer(socketserver.ThreadingTCPServer):
    """Threaded TCP server configured for fast local restarts."""

    allow_reuse_address = True


def start_ssh_honeypot() -> None:
    """Start the lightweight SSH honeypot server."""
    config = load_project_config()
    ports = load_port_config().get("ports", {})
    ssh_config = config.get("honeypots", {}).get("ssh", {})
    tracker = SSHBruteForceTracker(threshold=int(ssh_config.get("brute_force_threshold", 5)))

    class _ConfiguredHandler(SSHHoneypotHandler):
        pass

    _ConfiguredHandler.tracker = tracker

    host = ssh_config.get("host", "0.0.0.0")
    port = int(ports.get("ssh", 2222))
    server = ReusableThreadingTCPServer((host, port), _ConfiguredHandler)
    print(f"SSH honeypot listening on {host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    start_ssh_honeypot()
