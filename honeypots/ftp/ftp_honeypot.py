"""FTP honeypot built on top of pyftpdlib for login and command capture."""

from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path
from threading import Lock
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from honeypot_ids.log_system.log_config import PROJECT_ROOT, load_port_config, load_project_config
from honeypot_ids.log_system.logger import get_logger

try:
    from pyftpdlib.authorizers import DummyAuthorizer
    from pyftpdlib.handlers import FTPHandler
    from pyftpdlib.servers import FTPServer
except ImportError:
    DummyAuthorizer = None
    FTPHandler = object
    FTPServer = None


FAILED_LOGIN_COUNTS: dict[str, int] = defaultdict(int)
FAILED_LOGIN_LOCK = Lock()


class LoggingFTPHandler(FTPHandler):
    """FTP handler that emits structured honeypot telemetry."""

    def on_connect(self) -> None:
        get_logger().log_event(
            source_ip=self.remote_ip,
            service="ftp",
            event="ftp_connection_opened",
            attack_type="connection_probe",
            payload="FTP connection established",
            metadata={"remote_port": self.remote_port},
        )

    def on_disconnect(self) -> None:
        get_logger().log_event(
            source_ip=self.remote_ip,
            service="ftp",
            event="ftp_connection_closed",
            attack_type="connection_probe",
            payload="FTP connection closed",
            metadata={},
        )

    def on_login(self, username: str) -> None:
        get_logger().log_event(
            source_ip=self.remote_ip,
            service="ftp",
            event="ftp_login_success",
            attack_type="credential_access",
            payload={"username": username},
            metadata={"home": self.fs.root},
            severity="warning",
        )

    def on_login_failed(self, username: str, password: str) -> None:
        with FAILED_LOGIN_LOCK:
            FAILED_LOGIN_COUNTS[self.remote_ip] += 1
            failed_attempts = FAILED_LOGIN_COUNTS[self.remote_ip]

        get_logger().log_event(
            source_ip=self.remote_ip,
            service="ftp",
            event="ftp_login_failed",
            attack_type="ftp_bruteforce",
            payload={"username": username, "password": password},
            metadata={"failed_attempts": failed_attempts},
            severity="warning",
        )

    def pre_process_command(self, line: str, cmd: str, arg: str | None) -> None:
        get_logger().log_event(
            source_ip=self.remote_ip,
            service="ftp",
            event="ftp_command",
            attack_type="command_activity",
            payload=line,
            metadata={"command": cmd, "argument": arg},
        )
        super().pre_process_command(line, cmd, arg)


def start_ftp_honeypot() -> None:
    """Start the FTP honeypot server backed by pyftpdlib."""
    if DummyAuthorizer is None or FTPServer is None:
        raise RuntimeError("pyftpdlib is required to run the FTP honeypot")

    config = load_project_config()
    ports = load_port_config().get("ports", {})
    ftp_config = config.get("honeypots", {}).get("ftp", {})
    port = int(ports.get("ftp", 2121))
    host = ftp_config.get("host", "0.0.0.0")

    home_dir = Path(PROJECT_ROOT) / "data" / "ftp_decoy"
    home_dir.mkdir(parents=True, exist_ok=True)

    authorizer = DummyAuthorizer()
    authorizer.add_user("anonymous", "guest", str(home_dir), perm="elradfmwMT")

    handler = LoggingFTPHandler
    handler.authorizer = authorizer
    handler.banner = "220 ProFTPD 1.3.5a Server ready"

    server = FTPServer((host, port), handler)
    server.max_cons_per_ip = int(ftp_config.get("max_cons_per_ip", 5))
    print(f"FTP honeypot listening on {host}:{port}")
    server.serve_forever(timeout=0.5, blocking=True)


if __name__ == "__main__":
    start_ftp_honeypot()
