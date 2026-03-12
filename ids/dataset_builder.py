"""Dataset construction utilities for converting JSONL logs into CSV training data."""
#dataset_builder.py
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from honeypot_ids.ids.feature_extraction import FEATURE_COLUMNS, build_rate_context, extract_event_features
from honeypot_ids.log_system.log_config import get_log_file_path, load_project_config, resolve_project_path


def load_raw_events(log_path: Path | None = None) -> list[dict[str, Any]]:
    """Load JSONL events from the central raw log file."""
    target_path = log_path or get_log_file_path()
    if not target_path.exists():
        return []

    events: list[dict[str, Any]] = []
    for line in target_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def build_feature_rows(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert raw events into flat feature rows."""
    rate_context = build_rate_context(events)
    return [extract_event_features(event, rate_context.get(index)) for index, event in enumerate(events)]


def write_dataset(rows: list[dict[str, Any]], output_path: Path) -> Path:
    """Write the processed dataset to CSV."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["timestamp", "source_ip", "service", "event", "label", *FEATURE_COLUMNS]

    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    return output_path


def build_dataset(output_path: str | None = None) -> Path:
    """Read raw JSONL logs and generate a CSV dataset for model training."""
    config = load_project_config()
    processed_dir = resolve_project_path(config.get("logging", {}).get("processed_dir", "data/processed"))
    dataset_path = resolve_project_path(output_path) if output_path else processed_dir / "honeypot_dataset.csv"
    events = load_raw_events()
    rows = build_feature_rows(events)
    return write_dataset(rows, dataset_path)


if __name__ == "__main__":
    path = build_dataset()
    print(f"Dataset generated at {path}")
