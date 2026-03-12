"""Feature extraction utilities for converting structured logs into ML-ready vectors."""

from __future__ import annotations

# This module defines the core feature extraction logic that transforms raw honeypot events into structured feature vectors for model training and inference. It includes functions to parse timestamps, count special characters in payloads, infer labels from attack types, and build contextual rate features based on recent event history. The main function `extract_event_features` combines these utilities to produce a flat dictionary of features for each event, which can be easily exported to CSV or fed into a machine learning model.

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any


FEATURE_COLUMNS = [
    "login_attempt_rate",
    "failed_login_ratio",
    "request_rate",
    "payload_length",
    "special_character_count",
    "file_modification_rate",
]


def parse_timestamp(value: str | None) -> datetime:
    """Parse an ISO timestamp, defaulting to the current UTC time when invalid."""
    if not value:
        return datetime.now(timezone.utc)

    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


def count_special_characters(payload: str) -> int:
    """Count non-alphanumeric characters that often appear in exploit payloads."""
    return sum(1 for character in payload if not character.isalnum() and not character.isspace())


def infer_label(event: dict[str, Any]) -> str:
    """Infer a training label from the event metadata."""
    attack_type = str(event.get("attack_type", "") or "").strip().lower()
    return attack_type if attack_type and attack_type not in {"web_activity", "file_activity", "connection_probe", "command_activity"} else "benign"


def build_rate_context(events: list[dict[str, Any]], window_seconds: int = 60) -> dict[int, dict[str, float]]:
    """Compute simple event rate features per event index using a trailing time window."""
    context: dict[int, dict[str, float]] = defaultdict(dict)

    for index, event in enumerate(events):
        current_time = parse_timestamp(event.get("timestamp"))
        window_start = current_time - timedelta(seconds=window_seconds)
        window_events = [
            candidate
            for candidate in events[: index + 1]
            if parse_timestamp(candidate.get("timestamp")) >= window_start
        ]

        source_ip = event.get("source_ip", "unknown")
        source_events = [candidate for candidate in window_events if candidate.get("source_ip") == source_ip]
        failed_logins = [candidate for candidate in source_events if "failed" in str(candidate.get("event", ""))]
        file_events = [candidate for candidate in source_events if "file" in str(candidate.get("event", ""))]
        request_events = [candidate for candidate in source_events if candidate.get("service") == "http"]

        context[index] = {
            "login_attempt_rate": float(len(source_events)) / max(window_seconds, 1),
            "failed_login_ratio": float(len(failed_logins)) / max(len(source_events), 1),
            "request_rate": float(len(request_events)) / max(window_seconds, 1),
            "file_modification_rate": float(len(file_events)) / max(window_seconds, 1),
        }

    return context


def extract_event_features(event: dict[str, Any], rate_context: dict[str, float] | None = None) -> dict[str, Any]:
    """Transform a log event into a flat feature dictionary suitable for CSV export."""
    payload = event.get("payload", "")
    payload_text = payload if isinstance(payload, str) else str(payload)
    metadata = event.get("metadata", {}) if isinstance(event.get("metadata"), dict) else {}
    rate_context = rate_context or {}

    return {
        "timestamp": event.get("timestamp"),
        "source_ip": event.get("source_ip", "unknown"),
        "service": event.get("service", "unknown"),
        "event": event.get("event", "unknown"),
        "label": infer_label(event),
        "login_attempt_rate": float(metadata.get("attempt_count", rate_context.get("login_attempt_rate", 0.0))),
        "failed_login_ratio": float(metadata.get("failed_attempts", rate_context.get("failed_login_ratio", 0.0))),
        "request_rate": float(metadata.get("request_rate", rate_context.get("request_rate", 0.0))),
        "payload_length": float(len(payload_text)),
        "special_character_count": float(count_special_characters(payload_text)),
        "file_modification_rate": float(metadata.get("recent_change_count", rate_context.get("file_modification_rate", 0.0))),
    }
