"""Centralized structured logger for honeypot events and IDS outputs."""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from honeypot_ids.log_system.log_config import get_dashboard_cache_path, get_log_file_path


class CentralJSONLogger:
    """Write structured JSON events to a single append-only JSONL log."""

    def __init__(self, log_file: Path | None = None) -> None:
        self.log_file = log_file or get_log_file_path()
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def log_event(
        self,
        *,
        source_ip: str,
        service: str,
        event: str,
        payload: str | dict[str, Any] | list[Any] | None,
        attack_type: str | None = None,
        metadata: dict[str, Any] | None = None,
        severity: str = "info",
    ) -> dict[str, Any]:
        """Persist a single event and return the serialized record."""
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": source_ip,
            "service": service,
            "event": event,
            "attack_type": attack_type or event,
            "payload": payload,
            "severity": severity,
            "metadata": metadata or {},
        }

        with self._lock:
            with self.log_file.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=True) + "\n")

        return record

    def cache_prediction(self, prediction: dict[str, Any]) -> None:
        """Persist the most recent IDS prediction for dashboard consumption."""
        cache_path = get_dashboard_cache_path()
        cache_path.write_text(json.dumps(prediction, indent=2, ensure_ascii=True), encoding="utf-8")

    def read_recent_events(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return the most recent structured events from the central log."""
        if not self.log_file.exists():
            return []

        lines = self.log_file.read_text(encoding="utf-8").splitlines()
        recent_lines = lines[-limit:]
        events: list[dict[str, Any]] = []

        for line in recent_lines:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        return list(reversed(events))


LOGGER = CentralJSONLogger()


def get_logger() -> CentralJSONLogger:
    """Return the shared central logger instance."""
    return LOGGER