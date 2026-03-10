"""Filesystem monitor for ransomware-like behavior against decoy files."""

from __future__ import annotations

import sys
import time
from collections import Counter, deque
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from honeypot_ids.logging.log_config import ensure_runtime_directories, resolve_project_path, load_project_config
from honeypot_ids.logging.logger import get_logger

try:
    from watchdog.events import FileSystemEvent, FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:
    FileSystemEvent = object
    FileSystemEventHandler = object
    Observer = None


class RansomwareEventHandler(FileSystemEventHandler):
    """Detect suspicious filesystem patterns on decoy files."""

    def __init__(self, suspicious_extensions: list[str], rapid_change_threshold: int) -> None:
        super().__init__()
        self.logger = get_logger()
        self.suspicious_extensions = set(suspicious_extensions)
        self.rapid_change_threshold = rapid_change_threshold
        self.change_window: deque[float] = deque()
        self.file_counter: Counter[str] = Counter()

    def on_any_event(self, event: FileSystemEvent) -> None:
        if getattr(event, "is_directory", False):
            return

        source_path = Path(getattr(event, "src_path", "unknown"))
        now = time.time()
        self.change_window.append(now)
        self.file_counter[str(source_path)] += 1

        while self.change_window and now - self.change_window[0] > 10:
            self.change_window.popleft()

        metadata: dict[str, Any] = {
            "path": str(source_path),
            "event_type": getattr(event, "event_type", "unknown"),
            "recent_change_count": len(self.change_window),
            "distinct_files_touched": len(self.file_counter),
        }

        attack_type = "file_activity"
        event_name = "filesystem_activity"
        severity = "info"

        if len(self.change_window) >= self.rapid_change_threshold:
            attack_type = "ransomware_behavior"
            event_name = "rapid_file_changes_detected"
            severity = "warning"

        if source_path.suffix.lower() in self.suspicious_extensions:
            attack_type = "ransomware_behavior"
            event_name = "suspicious_extension_change"
            severity = "warning"

        if len(self.file_counter) >= self.rapid_change_threshold:
            attack_type = "ransomware_behavior"
            event_name = "mass_file_access_detected"
            severity = "warning"

        self.logger.log_event(
            source_ip="127.0.0.1",
            service="ransomware_monitor",
            event=event_name,
            attack_type=attack_type,
            payload=str(source_path),
            metadata=metadata,
            severity=severity,
        )


def ensure_decoy_files(directory: Path) -> None:
    """Create a small set of decoy files for ransomware experiments."""
    directory.mkdir(parents=True, exist_ok=True)
    sample_files = {
        "finance_report.txt": "Quarterly revenue projections\n",
        "credentials_backup.csv": "username,password\nadmin,changeme\n",
        "legal_archive.doc": "Confidential legal archive\n",
    }

    for file_name, content in sample_files.items():
        target = directory / file_name
        if not target.exists():
            target.write_text(content, encoding="utf-8")


def start_file_monitor() -> None:
    """Start watchdog-based monitoring for ransomware-like activity."""
    if Observer is None:
        raise RuntimeError("watchdog is required to run the ransomware file monitor")

    ensure_runtime_directories()
    config = load_project_config()
    monitor_config = config.get("honeypots", {}).get("ransomware", {})
    watch_dir = resolve_project_path(monitor_config.get("watch_path", "data/decoy_files"))
    ensure_decoy_files(watch_dir)

    event_handler = RansomwareEventHandler(
        suspicious_extensions=list(monitor_config.get("suspicious_extensions", [])),
        rapid_change_threshold=int(monitor_config.get("rapid_change_threshold", 10)),
    )
    observer = Observer()
    observer.schedule(event_handler, str(watch_dir), recursive=True)
    observer.start()
    print(f"Ransomware monitor watching {watch_dir}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    start_file_monitor()