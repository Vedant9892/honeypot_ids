"""Start all configured honeypot services in separate processes."""

# This script serves as the main entry point for launching the various honeypot services defined in the project. It reads the configuration to determine which honeypots are enabled, then starts each one in a separate process using Python's multiprocessing module. The script also handles graceful shutdown on keyboard interrupt, ensuring that all honeypot processes are terminated cleanly. This allows researchers to easily deploy and manage multiple honeypot services simultaneously for data collection and analysis.

from __future__ import annotations

# The script serves as the main entry point for launching the various honeypot services defined in the project. It reads the configuration to determine which honeypots are enabled, then starts each one in a separate process using Python's multiprocessing module. The script also handles graceful shutdown on keyboard interrupt, ensuring that all honeypot processes are terminated cleanly. This allows researchers to easily deploy and manage multiple honeypot services simultaneously for data collection and analysis.

import multiprocessing
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from honeypot_ids.honeypots.ftp.ftp_honeypot import start_ftp_honeypot
from honeypot_ids.honeypots.http.web_honeypot import start_http_honeypot
from honeypot_ids.honeypots.ransomware.file_monitor import start_file_monitor
from honeypot_ids.honeypots.ssh.ssh_honeypot import start_ssh_honeypot
from honeypot_ids.log_system.log_config import ensure_runtime_directories, load_project_config


def main() -> None:
    """Launch enabled honeypot services."""
    ensure_runtime_directories()
    config = load_project_config().get("honeypots", {})
    process_specs = [
        ("ssh", start_ssh_honeypot),
        ("ftp", start_ftp_honeypot),
        ("http", start_http_honeypot),
        ("ransomware", start_file_monitor),
    ]
    processes: list[multiprocessing.Process] = []

    for name, target in process_specs:
        if not config.get(name, {}).get("enabled", True):
            continue
        process = multiprocessing.Process(name=f"{name}_honeypot", target=target)
        process.start()
        processes.append(process)

    try:
        for process in processes:
            process.join()
    except KeyboardInterrupt:
        for process in processes:
            process.terminate()
            process.join(timeout=2)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
