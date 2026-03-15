"""Desktop control center for managing honeypots and viewing live telemetry."""

from __future__ import annotations

import json
import importlib.util
import multiprocessing
import os
from queue import Empty
import sys
import threading
import time
import traceback
from collections import Counter, deque
from dataclasses import dataclass
from pathlib import Path
from tkinter import END, StringVar, Tk, filedialog, messagebox, ttk
from typing import Any, Callable

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from honeypot_ids.attack_simulation.directory_scan_sim import run_simulation as run_directory_scan
from honeypot_ids.attack_simulation.ftp_bruteforce_sim import run_simulation as run_ftp_sim
from honeypot_ids.attack_simulation.sql_injection_sim import run_simulation as run_sqli_sim
from honeypot_ids.attack_simulation.ssh_bruteforce_sim import run_simulation as run_ssh_sim
from honeypot_ids.attack_simulation.xss_sim import run_simulation as run_xss_sim
from honeypot_ids.honeypots.ftp.ftp_honeypot import start_ftp_honeypot
from honeypot_ids.honeypots.http.web_honeypot import start_http_honeypot
from honeypot_ids.honeypots.ransomware.file_monitor import start_file_monitor
from honeypot_ids.honeypots.ssh.ssh_honeypot import start_ssh_honeypot
from honeypot_ids.log_system.log_config import (
    ensure_runtime_directories,
    get_log_file_path,
    load_port_config,
    load_project_config,
    resolve_project_path,
)

BENIGN_ATTACK_TYPES = {
    "benign",
    "web_activity",
    "connection_probe",
    "file_activity",
    "command_activity",
    "authentication_probe",
}


@dataclass
class HoneypotRuntime:
    """Track process metadata for a managed honeypot service."""

    name: str
    target: Callable[[], None]
    process: multiprocessing.Process | None = None
    started_at: float | None = None
    last_exitcode: int | None = None
    last_error: str | None = None

    def is_running(self) -> bool:
        return bool(self.process and self.process.is_alive())


def _run_service_entrypoint(
    service_name: str,
    target: Callable[[], None],
    error_queue: multiprocessing.Queue,
) -> None:
    """Run a service entrypoint and report startup errors to the parent process."""
    try:
        target()
    except Exception as exc:  # pylint: disable=broad-except
        error_queue.put(
            {
                "service": service_name,
                "message": str(exc),
                "traceback": traceback.format_exc(),
            }
        )
        raise


class HoneypotControlGUI:
    """Simple structured GUI for honeypot control and live observability."""

    def __init__(self, root: Tk) -> None:
        self.root = root
        self.root.title("Honeypot IDS Control Center")
        self.root.geometry("1320x860")
        self.root.minsize(1120, 720)

        ensure_runtime_directories()
        self.project_config = load_project_config()
        self.port_config = load_port_config().get("ports", {})
        self.log_file_path = get_log_file_path()
        self.decoy_path = resolve_project_path(
            self.project_config.get("honeypots", {}).get("ransomware", {}).get("watch_path", "data/decoy_files")
        )

        self.runtimes: dict[str, HoneypotRuntime] = {
            "ssh": HoneypotRuntime("ssh", start_ssh_honeypot),
            "ftp": HoneypotRuntime("ftp", start_ftp_honeypot),
            "http": HoneypotRuntime("http", start_http_honeypot),
            "ransomware": HoneypotRuntime("ransomware", start_file_monitor),
        }
        self.service_error_queue: multiprocessing.Queue = multiprocessing.Queue()
        self.dependency_issues = self._detect_dependency_issues()

        self.log_offset = 0
        self.events: deque[dict[str, Any]] = deque(maxlen=5000)
        self.tree_item_to_event: dict[str, dict[str, Any]] = {}

        self.service_filter_var = StringVar(value="all")
        self.severity_filter_var = StringVar(value="all")
        self.search_var = StringVar(value="")
        self.autoscroll_var = StringVar(value="on")

        self.status_badge_vars: dict[str, StringVar] = {}
        self.status_detail_vars: dict[str, StringVar] = {}
        self.status_count_var = StringVar(value="Active: 0 / 4")
        self.recent_count_var = StringVar(value="Events (displayed): 0")
        self.threat_count_var = StringVar(value="Threat events: 0")
        self.log_path_var = StringVar(value=f"Log file: {self.log_file_path}")

        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        self._bootstrap_log_state()
        self._schedule_update()

    def _build_ui(self) -> None:
        style = ttk.Style()
        style.configure("Header.TLabel", font=("Segoe UI", 16, "bold"))
        style.configure("SubHeader.TLabel", font=("Segoe UI", 11, "bold"))

        main = ttk.Frame(self.root, padding=10)
        main.pack(fill="both", expand=True)

        top = ttk.Frame(main)
        top.pack(fill="x")

        ttk.Label(top, text="Honeypot IDS Control Center", style="Header.TLabel").pack(side="left")

        action_bar = ttk.Frame(top)
        action_bar.pack(side="right")

        ttk.Button(action_bar, text="Start All", command=self.start_all).pack(side="left", padx=3)
        ttk.Button(action_bar, text="Stop All", command=self.stop_all).pack(side="left", padx=3)
        ttk.Button(action_bar, text="Run Demo Simulations", command=self.run_demo_simulations).pack(side="left", padx=3)

        ttk.Separator(main, orient="horizontal").pack(fill="x", pady=8)

        service_panel = ttk.LabelFrame(main, text="Services", padding=8)
        service_panel.pack(fill="x")

        for row, service in enumerate(("ssh", "ftp", "http", "ransomware")):
            display_name = service.upper() if service != "ransomware" else "RANSOMWARE"
            ttk.Label(service_panel, text=display_name, width=14, style="SubHeader.TLabel").grid(row=row, column=0, padx=4, pady=4, sticky="w")

            badge_var = StringVar(value="Stopped")
            detail_var = StringVar(value=self._service_detail(service))
            self.status_badge_vars[service] = badge_var
            self.status_detail_vars[service] = detail_var

            ttk.Label(service_panel, textvariable=badge_var, width=14).grid(row=row, column=1, padx=4, pady=4, sticky="w")
            ttk.Label(service_panel, textvariable=detail_var, width=54).grid(row=row, column=2, padx=4, pady=4, sticky="w")
            ttk.Button(service_panel, text="Start", command=lambda s=service: self.start_service(s)).grid(row=row, column=3, padx=3, pady=4)
            ttk.Button(service_panel, text="Stop", command=lambda s=service: self.stop_service(s)).grid(row=row, column=4, padx=3, pady=4)

        utility_panel = ttk.LabelFrame(main, text="Utility Actions", padding=8)
        utility_panel.pack(fill="x", pady=8)

        ttk.Button(utility_panel, text="SSH Bruteforce Sim", command=lambda: self.run_simulation_thread("ssh", run_ssh_sim)).grid(row=0, column=0, padx=3, pady=3)
        ttk.Button(utility_panel, text="FTP Bruteforce Sim", command=lambda: self.run_simulation_thread("ftp", run_ftp_sim)).grid(row=0, column=1, padx=3, pady=3)
        ttk.Button(utility_panel, text="SQL Injection Sim", command=lambda: self.run_simulation_thread("sqli", run_sqli_sim)).grid(row=0, column=2, padx=3, pady=3)
        ttk.Button(utility_panel, text="XSS Sim", command=lambda: self.run_simulation_thread("xss", run_xss_sim)).grid(row=0, column=3, padx=3, pady=3)
        ttk.Button(utility_panel, text="Directory Scan Sim", command=lambda: self.run_simulation_thread("dirscan", run_directory_scan)).grid(row=0, column=4, padx=3, pady=3)
        ttk.Button(utility_panel, text="Ransomware File Burst", command=self.run_ransomware_simulation).grid(row=0, column=5, padx=3, pady=3)

        ttk.Button(utility_panel, text="Open Log File", command=self.open_log_file).grid(row=1, column=0, padx=3, pady=3)
        ttk.Button(utility_panel, text="Open Decoy Folder", command=self.open_decoy_folder).grid(row=1, column=1, padx=3, pady=3)
        ttk.Button(utility_panel, text="Export Visible Logs", command=self.export_visible_logs).grid(row=1, column=2, padx=3, pady=3)
        ttk.Button(utility_panel, text="Clear Table", command=self.clear_table_selection).grid(row=1, column=3, padx=3, pady=3)

        summary_panel = ttk.Frame(main)
        summary_panel.pack(fill="x", pady=(2, 6))
        ttk.Label(summary_panel, textvariable=self.status_count_var, style="SubHeader.TLabel").pack(side="left", padx=4)
        ttk.Label(summary_panel, textvariable=self.recent_count_var).pack(side="left", padx=18)
        ttk.Label(summary_panel, textvariable=self.threat_count_var).pack(side="left", padx=18)

        log_panel = ttk.LabelFrame(main, text="Live Events", padding=8)
        log_panel.pack(fill="both", expand=True)

        filter_row = ttk.Frame(log_panel)
        filter_row.pack(fill="x", pady=(0, 6))

        ttk.Label(filter_row, text="Service:").pack(side="left", padx=(0, 2))
        service_filter = ttk.Combobox(
            filter_row,
            textvariable=self.service_filter_var,
            values=("all", "ssh", "ftp", "http", "ransomware_monitor"),
            width=18,
            state="readonly",
        )
        service_filter.pack(side="left", padx=4)
        service_filter.bind("<<ComboboxSelected>>", lambda _event: self.refresh_log_table())

        ttk.Label(filter_row, text="Severity:").pack(side="left", padx=(10, 2))
        severity_filter = ttk.Combobox(
            filter_row,
            textvariable=self.severity_filter_var,
            values=("all", "info", "warning", "error"),
            width=12,
            state="readonly",
        )
        severity_filter.pack(side="left", padx=4)
        severity_filter.bind("<<ComboboxSelected>>", lambda _event: self.refresh_log_table())

        ttk.Label(filter_row, text="Search:").pack(side="left", padx=(10, 2))
        search_entry = ttk.Entry(filter_row, textvariable=self.search_var, width=34)
        search_entry.pack(side="left", padx=4)
        search_entry.bind("<KeyRelease>", lambda _event: self.refresh_log_table())

        autoscroll_check = ttk.Checkbutton(
            filter_row,
            text="Auto-scroll",
            variable=self.autoscroll_var,
            onvalue="on",
            offvalue="off",
        )
        autoscroll_check.pack(side="left", padx=(12, 4))

        columns = ("timestamp", "service", "event", "attack_type", "severity", "source_ip")
        self.log_tree = ttk.Treeview(log_panel, columns=columns, show="headings", height=14)
        for column in columns:
            self.log_tree.heading(column, text=column.replace("_", " ").title())

        self.log_tree.column("timestamp", width=205, anchor="w")
        self.log_tree.column("service", width=130, anchor="center")
        self.log_tree.column("event", width=260, anchor="w")
        self.log_tree.column("attack_type", width=170, anchor="w")
        self.log_tree.column("severity", width=95, anchor="center")
        self.log_tree.column("source_ip", width=145, anchor="center")

        tree_scroll = ttk.Scrollbar(log_panel, orient="vertical", command=self.log_tree.yview)
        self.log_tree.configure(yscrollcommand=tree_scroll.set)

        self.log_tree.pack(side="left", fill="both", expand=True)
        tree_scroll.pack(side="left", fill="y")
        self.log_tree.bind("<<TreeviewSelect>>", self._on_event_selected)

        right_panel = ttk.Frame(log_panel)
        right_panel.pack(side="left", fill="both", padx=(8, 0))

        ttk.Label(right_panel, text="Event Details", style="SubHeader.TLabel").pack(anchor="w")
        self.details_text = ttk.Treeview(
            right_panel,
            columns=("field", "value"),
            show="headings",
            height=12,
        )
        self.details_text.heading("field", text="Field")
        self.details_text.heading("value", text="Value")
        self.details_text.column("field", width=120, anchor="w")
        self.details_text.column("value", width=330, anchor="w")
        self.details_text.pack(fill="both", expand=True, pady=(4, 0))

        ttk.Label(right_panel, textvariable=self.log_path_var, wraplength=430).pack(anchor="w", pady=(8, 2))

    def _service_detail(self, service: str) -> str:
        if service in self.dependency_issues:
            missing = ", ".join(self.dependency_issues[service])
            return f"missing dependencies: {missing}"

        port = self.port_config.get(service)
        if service == "ransomware":
            return f"watching: {self.decoy_path}"
        if port:
            return f"listening on port {port}"
        return "configured"

    def _detect_dependency_issues(self) -> dict[str, list[str]]:
        service_dependencies = {
            "http": ["flask"],
            "ftp": ["pyftpdlib"],
            "ransomware": ["watchdog"],
        }
        issues: dict[str, list[str]] = {}
        for service, dependencies in service_dependencies.items():
            missing = [module for module in dependencies if importlib.util.find_spec(module) is None]
            if missing:
                issues[service] = missing
        return issues

    def _bootstrap_log_state(self) -> None:
        self.log_file_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.log_file_path.exists():
            self.log_offset = 0
            return

        try:
            with self.log_file_path.open("r", encoding="utf-8") as handle:
                lines = handle.read().splitlines()
            for line in lines[-250:]:
                raw = line.strip()
                if not raw:
                    continue
                try:
                    event = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                self.events.append(event)
            self.log_offset = self.log_file_path.stat().st_size
            self.refresh_log_table()
        except OSError:
            self.log_offset = 0

    def _schedule_update(self) -> None:
        self._consume_service_errors()
        self._sync_process_states()
        self._poll_new_logs()
        self._update_summary_labels()
        self.root.after(1000, self._schedule_update)

    def _consume_service_errors(self) -> None:
        while True:
            try:
                error = self.service_error_queue.get_nowait()
            except Empty:
                return
            except (EOFError, OSError):
                return

            service = str(error.get("service", ""))
            runtime = self.runtimes.get(service)
            if runtime is None:
                continue

            message = str(error.get("message", "unknown startup error"))
            trace = str(error.get("traceback", "")).strip()
            runtime.last_error = f"{message} | {trace.splitlines()[-1] if trace else ''}".strip(" |")

    def _sync_process_states(self) -> None:
        active_count = 0
        for name, runtime in self.runtimes.items():
            if runtime.is_running():
                active_count += 1
                uptime = int(time.time() - (runtime.started_at or time.time()))
                self.status_badge_vars[name].set(f"Running ({uptime}s)")
                self.status_detail_vars[name].set(self._service_detail(name))
            else:
                if runtime.process is not None and not runtime.process.is_alive():
                    runtime.last_exitcode = runtime.process.exitcode
                    runtime.process = None
                    runtime.started_at = None

                if runtime.last_exitcode not in {None, 0}:
                    self.status_badge_vars[name].set(f"Crashed ({runtime.last_exitcode})")
                    detail = runtime.last_error or self._service_detail(name)
                    self.status_detail_vars[name].set(f"last error: {detail}")
                else:
                    self.status_badge_vars[name].set("Stopped")
                    self.status_detail_vars[name].set(self._service_detail(name))
        self.status_count_var.set(f"Active: {active_count} / {len(self.runtimes)}")

    def _poll_new_logs(self) -> None:
        if not self.log_file_path.exists():
            return

        try:
            file_size = self.log_file_path.stat().st_size
            if file_size < self.log_offset:
                self.log_offset = 0

            with self.log_file_path.open("r", encoding="utf-8") as handle:
                handle.seek(self.log_offset)
                lines = handle.readlines()
                self.log_offset = handle.tell()
        except OSError:
            return

        if not lines:
            return

        for line in lines:
            raw = line.strip()
            if not raw:
                continue
            try:
                event = json.loads(raw)
            except json.JSONDecodeError:
                continue
            self.events.append(event)

        self.refresh_log_table()

    def event_matches_filter(self, event: dict[str, Any]) -> bool:
        service_filter = self.service_filter_var.get().strip().lower()
        severity_filter = self.severity_filter_var.get().strip().lower()
        search_text = self.search_var.get().strip().lower()

        service = str(event.get("service", "")).lower()
        severity = str(event.get("severity", "")).lower()

        if service_filter and service_filter != "all" and service != service_filter:
            return False

        if severity_filter and severity_filter != "all" and severity != severity_filter:
            return False

        if search_text:
            merged = json.dumps(event, ensure_ascii=True).lower()
            if search_text not in merged:
                return False

        return True

    def _update_summary_labels(self) -> None:
        visible = [event for event in self.events if self.event_matches_filter(event)]
        threat_count = sum(1 for event in visible if str(event.get("attack_type", "")).lower() not in BENIGN_ATTACK_TYPES)
        self.recent_count_var.set(f"Events (displayed): {len(visible)}")
        self.threat_count_var.set(f"Threat events: {threat_count}")

    def refresh_log_table(self) -> None:
        self.log_tree.delete(*self.log_tree.get_children())
        self.tree_item_to_event.clear()

        visible = [event for event in self.events if self.event_matches_filter(event)]

        for event in reversed(visible):
            values = (
                str(event.get("timestamp", "")),
                str(event.get("service", "")),
                str(event.get("event", "")),
                str(event.get("attack_type", "")),
                str(event.get("severity", "")),
                str(event.get("source_ip", "")),
            )
            item_id = self.log_tree.insert("", END, values=values)
            self.tree_item_to_event[item_id] = event

        if self.autoscroll_var.get() == "on":
            children = self.log_tree.get_children()
            if children:
                self.log_tree.see(children[-1])

        self._update_summary_labels()

    def _on_event_selected(self, _event: Any) -> None:
        self.details_text.delete(*self.details_text.get_children())
        selection = self.log_tree.selection()
        if not selection:
            return

        event = self.tree_item_to_event.get(selection[0])
        if not event:
            return

        for field in ("timestamp", "service", "event", "attack_type", "severity", "source_ip"):
            self.details_text.insert("", END, values=(field, str(event.get(field, ""))))

        payload = event.get("payload")
        metadata = event.get("metadata", {})
        self.details_text.insert("", END, values=("payload", json.dumps(payload, ensure_ascii=True)))
        self.details_text.insert("", END, values=("metadata", json.dumps(metadata, ensure_ascii=True)))

    def start_service(self, service: str) -> None:
        self.dependency_issues = self._detect_dependency_issues()
        runtime = self.runtimes[service]
        if runtime.is_running():
            return

        if service in self.dependency_issues:
            missing = ", ".join(self.dependency_issues[service])
            messagebox.showerror("Missing Dependency", f"{service} requires: {missing}")
            runtime.last_error = f"missing dependencies: {missing}"
            runtime.last_exitcode = 1
            self._sync_process_states()
            return

        runtime.last_error = None
        runtime.last_exitcode = None
        process = multiprocessing.Process(
            name=f"{service}_honeypot",
            target=_run_service_entrypoint,
            args=(service, runtime.target, self.service_error_queue),
        )
        process.start()
        runtime.process = process
        runtime.started_at = time.time()
        self._sync_process_states()

    def stop_service(self, service: str) -> None:
        runtime = self.runtimes[service]
        process = runtime.process
        if process is None:
            return

        if process.is_alive():
            process.terminate()
            process.join(timeout=2)
            if process.is_alive() and hasattr(process, "kill"):
                process.kill()
                process.join(timeout=1)

        runtime.process = None
        runtime.started_at = None
        runtime.last_exitcode = 0
        self._sync_process_states()

    def start_all(self) -> None:
        for service in self.runtimes:
            self.start_service(service)

    def stop_all(self) -> None:
        for service in self.runtimes:
            self.stop_service(service)

    def run_simulation_thread(self, name: str, callback: Callable[..., None]) -> None:
        def _runner() -> None:
            try:
                callback()
            except Exception as exc:  # pylint: disable=broad-except
                self.root.after(0, lambda: messagebox.showerror("Simulation Error", f"{name}: {exc}"))

        threading.Thread(target=_runner, name=f"sim_{name}", daemon=True).start()

    def run_ransomware_simulation(self) -> None:
        def _ransomware_burst() -> None:
            self.decoy_path.mkdir(parents=True, exist_ok=True)
            for index in range(12):
                sample = self.decoy_path / f"sim_{index}.locked"
                sample.write_text(f"sample-{index}\n", encoding="utf-8")
                time.sleep(0.1)

        self.run_simulation_thread("ransomware", _ransomware_burst)

    def run_demo_simulations(self) -> None:
        self.run_simulation_thread("ssh", run_ssh_sim)
        self.run_simulation_thread("ftp", run_ftp_sim)
        self.run_simulation_thread("sqli", run_sqli_sim)
        self.run_simulation_thread("xss", run_xss_sim)
        self.run_simulation_thread("dirscan", run_directory_scan)

    def open_log_file(self) -> None:
        self.log_file_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.log_file_path.exists():
            self.log_file_path.touch()

        try:
            os.startfile(str(self.log_file_path))  # type: ignore[attr-defined]
        except OSError as exc:
            messagebox.showerror("Open Log File", str(exc))

    def open_decoy_folder(self) -> None:
        self.decoy_path.mkdir(parents=True, exist_ok=True)
        try:
            os.startfile(str(self.decoy_path))  # type: ignore[attr-defined]
        except OSError as exc:
            messagebox.showerror("Open Decoy Folder", str(exc))

    def clear_table_selection(self) -> None:
        self.log_tree.selection_remove(self.log_tree.selection())
        self.details_text.delete(*self.details_text.get_children())

    def export_visible_logs(self) -> None:
        visible = [event for event in self.events if self.event_matches_filter(event)]
        if not visible:
            messagebox.showinfo("Export Logs", "No visible logs to export.")
            return

        destination = filedialog.asksaveasfilename(
            title="Export Visible Logs",
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("All files", "*.*")],
            initialfile="filtered_honeypot_logs.json",
        )
        if not destination:
            return

        try:
            Path(destination).write_text(json.dumps(visible, indent=2, ensure_ascii=True), encoding="utf-8")
            messagebox.showinfo("Export Logs", f"Exported {len(visible)} events to {destination}")
        except OSError as exc:
            messagebox.showerror("Export Logs", str(exc))

    def _on_close(self) -> None:
        if any(runtime.is_running() for runtime in self.runtimes.values()):
            should_close = messagebox.askyesno("Exit", "Stop all honeypots and close the control center?")
            if not should_close:
                return
            self.stop_all()

        self.root.destroy()


def main() -> None:
    multiprocessing.freeze_support()
    root = Tk()
    HoneypotControlGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
