"""HTTP honeypot with vulnerable-looking endpoints and heuristic attack logging."""

from __future__ import annotations

import re
import sys
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from honeypot_ids.logging.log_config import load_port_config, load_project_config
from honeypot_ids.logging.logger import get_logger

try:
    from flask import Flask, jsonify, request
except ImportError:
    Flask = None
    jsonify = None
    request = None


SQLI_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"(union\s+select)",
        r"(or\s+1=1)",
        r"(drop\s+table)",
        r"(--|#|/\*)",
        r"(information_schema)",
    )
]
XSS_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"<script",
        r"javascript:",
        r"onerror=",
        r"onload=",
        r"alert\s*\(",
    )
]
DIRECTORY_SCAN_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\.\./",
        r"etc/passwd",
        r"wp-admin",
        r"\.git",
        r"phpmyadmin",
    )
]


def _client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")


def create_app() -> Any:
    """Create the Flask-based HTTP honeypot application."""
    if Flask is None:
        raise RuntimeError("Flask is required to run the HTTP honeypot")

    app = Flask(__name__)
    logger = get_logger()
    config = load_project_config()
    http_config = config.get("honeypots", {}).get("http", {})
    request_history: dict[str, deque[float]] = defaultdict(deque)
    window_seconds = int(http_config.get("anomaly_window_seconds", 60))
    threshold = int(http_config.get("anomaly_request_threshold", 20))

    @app.before_request
    def detect_request_anomalies() -> None:
        source_ip = _client_ip()
        now = time.time()
        history = request_history[source_ip]
        history.append(now)

        while history and now - history[0] > window_seconds:
            history.popleft()

        if len(history) >= threshold:
            logger.log_event(
                source_ip=source_ip,
                service="http",
                event="request_rate_anomaly",
                attack_type="directory_scanning",
                payload=request.full_path,
                metadata={"request_rate": len(history), "window_seconds": window_seconds},
                severity="warning",
            )

    def inspect_payload(payload: str, route_name: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        if any(pattern.search(payload) for pattern in SQLI_PATTERNS):
            findings.append({"event": f"{route_name}_sql_injection_attempt", "attack_type": "sql_injection"})
        if any(pattern.search(payload) for pattern in XSS_PATTERNS):
            findings.append({"event": f"{route_name}_xss_attempt", "attack_type": "xss"})
        if any(pattern.search(payload) for pattern in DIRECTORY_SCAN_PATTERNS):
            findings.append({"event": f"{route_name}_directory_scan_attempt", "attack_type": "directory_scanning"})
        return findings

    def log_request_event(route_name: str, payload: str, metadata: dict[str, Any] | None = None) -> None:
        findings = inspect_payload(payload, route_name)
        source_ip = _client_ip()

        logger.log_event(
            source_ip=source_ip,
            service="http",
            event=f"{route_name}_request",
            attack_type="web_activity",
            payload=payload,
            metadata=metadata or {},
        )

        for finding in findings:
            logger.log_event(
                source_ip=source_ip,
                service="http",
                event=finding["event"],
                attack_type=finding["attack_type"],
                payload=payload,
                metadata=metadata or {},
                severity="warning",
            )

    @app.route("/login", methods=["GET", "POST"])
    def login() -> Any:
        username = request.values.get("username", "")
        password = request.values.get("password", "")
        payload = f"username={username}&password={password}"
        log_request_event("login", payload, {"method": request.method})
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401

    @app.route("/search", methods=["GET"])
    def search() -> Any:
        query = request.args.get("q", "")
        log_request_event("search", query, {"query_length": len(query)})
        return jsonify({"results": [], "query": query})

    @app.route("/admin", methods=["GET"])
    def admin() -> Any:
        path_value = request.args.get("path", request.full_path)
        log_request_event("admin", path_value, {"endpoint": "/admin"})
        return jsonify({"status": "forbidden"}), 403

    @app.route("/upload", methods=["POST"])
    def upload() -> Any:
        file_storage = request.files.get("file")
        file_name = file_storage.filename if file_storage else "unknown"
        raw_body = request.get_data(as_text=True)
        payload = f"filename={file_name};body={raw_body[:2048]}"
        log_request_event("upload", payload, {"filename": file_name})
        return jsonify({"status": "received", "filename": file_name})

    @app.route("/", methods=["GET"])
    def index() -> Any:
        log_request_event("index", request.full_path, {"endpoint": "/"})
        return jsonify({"service": "research-http-honeypot", "status": "ok"})

    return app


def start_http_honeypot() -> None:
    """Start the Flask web honeypot."""
    app = create_app()
    config = load_project_config()
    ports = load_port_config().get("ports", {})
    http_config = config.get("honeypots", {}).get("http", {})
    host = http_config.get("host", "0.0.0.0")
    port = int(ports.get("http", 8080))
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    start_http_honeypot()
