from __future__ import annotations

import threading

from .service import MonitorService


class MonitorRuntime:
    def __init__(self, service: MonitorService | None = None) -> None:
        self.service = service or MonitorService()
        self.config = self.service.config
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._worker_thread: threading.Thread | None = None
        self._running = False
        self._last_error: str | None = None

    def start(self) -> dict[str, object]:
        with self._lock:
            if self._running:
                return self.service.dashboard_snapshot(True, self._last_error)

            self._running = True
            self._last_error = None
            self._stop_event.clear()
            try:
                self.service.start()
                self._collect_locked()
            except Exception:
                self._running = False
                self._stop_event.set()
                self.service.stop()
                raise
            self._worker_thread = threading.Thread(
                target=self._run_loop,
                name="monitor-runtime",
                daemon=True,
            )
            self._worker_thread.start()
            return self.service.dashboard_snapshot(True, self._last_error)

    def stop(self) -> dict[str, object]:
        with self._lock:
            self._running = False
            self._stop_event.set()
            self.service.stop()
            return self.service.dashboard_snapshot(False, self._last_error)

    def analyze_once(self) -> dict[str, object]:
        with self._lock:
            self._collect_locked()
            return self.service.dashboard_snapshot(self._running, self._last_error)

    def set_mode(self, mode: str) -> dict[str, object]:
        with self._lock:
            self.service.switch_mode(mode)
            return self.service.dashboard_snapshot(self._running, self._last_error)

    def set_privacy_mode(self, privacy_mode: str) -> dict[str, object]:
        with self._lock:
            self.service.set_privacy_mode(privacy_mode)
            if self._running:
                self._collect_locked()
            return self.service.dashboard_snapshot(self._running, self._last_error)

    def set_user(self, user_name: str) -> dict[str, object]:
        with self._lock:
            self.service.switch_user(user_name)
            return self.service.dashboard_snapshot(self._running, self._last_error)

    def queue_demo_scenario(self, scenario_name: str) -> dict[str, object]:
        with self._lock:
            self.service.queue_demo_scenario(scenario_name)
            if self.service.mode == "demo":
                self._collect_locked()
            return self.service.dashboard_snapshot(self._running, self._last_error)

    def set_alert_feedback(
        self,
        alert_id: int,
        label: str,
        note: str = "",
    ) -> dict[str, object]:
        with self._lock:
            return self.service.set_alert_feedback(alert_id, label, note)

    def report_payload(self) -> dict[str, object]:
        with self._lock:
            return self.service.report_payload(self._running, self._last_error)

    def report_csv(self) -> str:
        with self._lock:
            return self.service.report_csv(self._running, self._last_error)

    def report_pdf(self) -> bytes:
        with self._lock:
            return self.service.report_pdf(self._running, self._last_error)

    def run_retention(self) -> dict[str, object]:
        with self._lock:
            self.service.run_retention()
            return self.service.dashboard_snapshot(self._running, self._last_error)

    def refresh_honeypots(self) -> dict[str, object]:
        with self._lock:
            self.service.refresh_honeypots()
            return self.service.dashboard_snapshot(self._running, self._last_error)

    def trigger_honeypot_demo(self, file_name: str | None = None) -> dict[str, object]:
        with self._lock:
            self.service.trigger_honeypot_demo(file_name)
            if self._running and self.service.mode == "live":
                self._collect_locked()
            return self.service.dashboard_snapshot(self._running, self._last_error)

    def export_siem(self, webhook_url: str | None = None) -> dict[str, object]:
        with self._lock:
            return self.service.export_siem(webhook_url=webhook_url)

    def ingest_browser_events(self, payload: dict[str, object]) -> dict[str, object]:
        with self._lock:
            result = self.service.ingest_browser_events(payload)
            self._last_error = None
            return result

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return self.service.dashboard_snapshot(self._running, self._last_error)

    def _collect_locked(self) -> None:
        try:
            self.service.collect_once()
            self._last_error = None
        except Exception as error:
            self._last_error = str(error)
            raise

    def _run_loop(self) -> None:
        while not self._stop_event.wait(self.config.analysis_interval_seconds):
            with self._lock:
                if not self._running:
                    return
                try:
                    self.service.collect_once()
                    self._last_error = None
                except Exception as error:
                    self._last_error = str(error)
