"""Configuration helpers for the honeypot IDS project."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIG_DIR = PROJECT_ROOT / "config"


def load_yaml_file(file_path: Path) -> dict[str, Any]:
    """Load a YAML file and return an empty dictionary when absent."""
    if not file_path.exists():
        return {}

    with file_path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}

    if not isinstance(data, dict):
        raise ValueError(f"YAML file must contain a mapping: {file_path}")

    return data


def load_project_config() -> dict[str, Any]:
    """Load the main project configuration."""
    return load_yaml_file(CONFIG_DIR / "config.yaml")


def load_port_config() -> dict[str, Any]:
    """Load honeypot and dashboard port assignments."""
    return load_yaml_file(CONFIG_DIR / "ports.yaml")


def resolve_project_path(relative_path: str | Path) -> Path:
    """Resolve a path relative to the repository root."""
    path = Path(relative_path)
    return path if path.is_absolute() else PROJECT_ROOT / path


def ensure_runtime_directories() -> None:
    """Ensure directories required by the logging and dataset pipelines exist."""
    config = load_project_config()
    logging_config = config.get("logging", {})

    for relative_dir in (
        logging_config.get("raw_log_dir", "data/raw_logs"),
        logging_config.get("processed_dir", "data/processed"),
        config.get("honeypots", {}).get("ransomware", {}).get("watch_path", "data/decoy_files"),
    ):
        resolve_project_path(relative_dir).mkdir(parents=True, exist_ok=True)


def get_log_file_path() -> Path:
    """Return the path to the central JSONL log file."""
    config = load_project_config()
    logging_config = config.get("logging", {})
    raw_log_dir = resolve_project_path(logging_config.get("raw_log_dir", "data/raw_logs"))
    raw_log_dir.mkdir(parents=True, exist_ok=True)
    return raw_log_dir / logging_config.get("file_name", "honeypot_events.jsonl")


def get_dashboard_cache_path() -> Path:
    """Return the path to the dashboard prediction cache file."""
    config = load_project_config()
    logging_config = config.get("logging", {})
    raw_log_dir = resolve_project_path(logging_config.get("raw_log_dir", "data/raw_logs"))
    raw_log_dir.mkdir(parents=True, exist_ok=True)
    return raw_log_dir / logging_config.get("dashboard_cache_file", "latest_predictions.json")
