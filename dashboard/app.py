"""Flask dashboard for recent honeypot activity and IDS outputs."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from honeypot_ids.log_system.log_config import get_dashboard_cache_path, load_port_config, load_project_config
from honeypot_ids.log_system.logger import get_logger

try:
    from flask import Flask, jsonify, render_template
except ImportError:
    Flask = None
    jsonify = None
    render_template = None


def load_prediction_cache() -> dict[str, Any]:
    """Load the most recent IDS prediction from disk."""
    cache_path = get_dashboard_cache_path()
    if not cache_path.exists():
        return {}

    try:
        return json.loads(cache_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def create_app() -> Any:
    """Create the dashboard Flask application."""
    if Flask is None:
        raise RuntimeError("Flask is required to run the dashboard")

    app = Flask(__name__)
    logger = get_logger()
    config = load_project_config()
    limit = int(config.get("dashboard", {}).get("recent_event_limit", 50))

    @app.route("/")
    def index() -> Any:
        events = logger.read_recent_events(limit=limit)
        prediction = load_prediction_cache()
        threats = [event for event in events if event.get("attack_type") not in {"benign", "web_activity", "connection_probe", "file_activity", "command_activity"}]
        return render_template("index.html", events=events, threats=threats, prediction=prediction)

    @app.route("/api/logs")
    def api_logs() -> Any:
        return jsonify(logger.read_recent_events(limit=limit))

    @app.route("/api/threats")
    def api_threats() -> Any:
        events = logger.read_recent_events(limit=limit)
        threats = [event for event in events if event.get("attack_type") not in {"benign", "web_activity", "connection_probe", "file_activity", "command_activity"}]
        return jsonify(threats)

    @app.route("/api/prediction")
    def api_prediction() -> Any:
        return jsonify(load_prediction_cache())

    return app


if __name__ == "__main__":
    app = create_app()
    config = load_project_config()
    ports = load_port_config().get("ports", {})
    host = config.get("dashboard", {}).get("host", "127.0.0.1")
    port = int(ports.get("dashboard", config.get("dashboard", {}).get("port", 8050)))
    app.run(host=host, port=port, debug=False)
