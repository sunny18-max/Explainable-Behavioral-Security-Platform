from __future__ import annotations

import ctypes
import os
import threading
import time
from collections import deque
from datetime import datetime, timedelta
from math import hypot
from random import Random

from .config import MonitorConfig
from .models import ActivityWindow, ProcessObservation

try:
    from pynput import keyboard as pynput_keyboard
    from pynput import mouse as pynput_mouse
except ImportError:  # pragma: no cover - optional dependency
    pynput_keyboard = None
    pynput_mouse = None

try:
    import psutil
except ImportError:  # pragma: no cover - optional dependency
    psutil = None


class WindowsActivityCollector:
    def __init__(self, config: MonitorConfig) -> None:
        self.config = config
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._window_thread: threading.Thread | None = None
        self._keyboard_listener = None
        self._mouse_listener = None
        self._started = False
        self._last_snapshot_at = datetime.now()
        self._session_started_at = datetime.now()
        self._key_timestamps: list[float] = []
        self._mouse_segments: list[tuple[float, float]] = []
        self._active_windows: list[str] = []
        self._process_observations: list[ProcessObservation] = []
        self._notes: list[str] = []
        self._last_mouse_position: tuple[int, int] | None = None
        self._last_mouse_time: float | None = None

    def start(self) -> None:
        if self._started:
            return

        self._started = True
        self._stop_event.clear()
        self._last_snapshot_at = datetime.now()
        self._session_started_at = datetime.now()
        self._reset_buffers()
        self._add_note_once("Privacy-safe mode: keystroke timing only, no key content.")

        if os.name == "nt":
            self._add_note_once("Process-aware foreground window sampling enabled.")
            self._window_thread = threading.Thread(
                target=self._window_sampler_loop,
                name="window-sampler",
                daemon=True,
            )
            self._window_thread.start()
        else:
            self._add_note_once("Active window sampling is available only on Windows.")

        if pynput_keyboard is None:
            self._add_note_once("Install pynput to enable keyboard timing collection.")
        else:
            try:
                self._keyboard_listener = pynput_keyboard.Listener(on_press=self._on_key_press)
                self._keyboard_listener.start()
            except Exception as error:  # pragma: no cover - environment-specific
                self._add_note_once(f"Keyboard listener unavailable: {error}")

        if pynput_mouse is None:
            self._add_note_once("Install pynput to enable mouse movement collection.")
        else:
            try:
                self._mouse_listener = pynput_mouse.Listener(on_move=self._on_mouse_move)
                self._mouse_listener.start()
            except Exception as error:  # pragma: no cover - environment-specific
                self._add_note_once(f"Mouse listener unavailable: {error}")

    def stop(self) -> None:
        if not self._started:
            return

        self._stop_event.set()
        if self._keyboard_listener is not None:
            self._keyboard_listener.stop()
            self._keyboard_listener = None
        if self._mouse_listener is not None:
            self._mouse_listener.stop()
            self._mouse_listener = None
        self._reset_buffers()
        self._started = False

    def _reset_buffers(self) -> None:
        with self._lock:
            self._key_timestamps.clear()
            self._mouse_segments.clear()
            self._active_windows.clear()
            self._process_observations.clear()
            self._notes.clear()
            self._last_mouse_position = None
            self._last_mouse_time = None

    def capture_window(self) -> ActivityWindow:
        now = datetime.now()
        with self._lock:
            key_timestamps = list(self._key_timestamps)
            mouse_segments = list(self._mouse_segments)
            active_windows = list(self._active_windows)
            process_observations = list(self._process_observations)
            notes = list(self._notes)
            self._key_timestamps.clear()
            self._mouse_segments.clear()
            self._active_windows.clear()
            self._process_observations.clear()

        window = ActivityWindow(
            started_at=self._last_snapshot_at,
            ended_at=now,
            key_timestamps=key_timestamps,
            mouse_segments=mouse_segments,
            active_apps=active_windows,
            process_observations=process_observations,
            login_at=self._session_started_at,
            session_duration_minutes=max(
                (now - self._session_started_at).total_seconds() / 60.0,
                1.0,
            ),
            source="live",
            collector_notes=notes,
            scenario_name=None,
            expected_anomaly=None,
        )
        self._last_snapshot_at = now
        return window

    def _on_key_press(self, _key: object) -> None:
        timestamp = time.time()
        with self._lock:
            self._key_timestamps.append(timestamp)

    def _on_mouse_move(self, x: int, y: int) -> None:
        now = time.time()
        with self._lock:
            if self._last_mouse_position is not None and self._last_mouse_time is not None:
                delta_time = now - self._last_mouse_time
                if delta_time > 0:
                    distance = hypot(
                        x - self._last_mouse_position[0],
                        y - self._last_mouse_position[1],
                    )
                    self._mouse_segments.append((distance, delta_time))
            self._last_mouse_position = (x, y)
            self._last_mouse_time = now

    def _window_sampler_loop(self) -> None:
        while not self._stop_event.wait(self.config.active_window_poll_seconds):
            label, process_observation = self._get_active_window_snapshot()
            if not label:
                continue
            with self._lock:
                self._active_windows.append(label)
                if process_observation is not None:
                    self._process_observations.append(process_observation)

    def _get_active_window_snapshot(self) -> tuple[str, ProcessObservation | None]:
        try:
            user32 = ctypes.windll.user32
            hwnd = user32.GetForegroundWindow()
            if not hwnd:
                return "", None
            length = user32.GetWindowTextLengthW(hwnd)
            if length == 0:
                return "", None
            buffer = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buffer, length + 1)
            title = buffer.value.strip()
            process_observation = self._build_process_observation(user32, hwnd, title)
            process_name = process_observation.process_name if process_observation else ""
            if process_name and title:
                return f"{process_name} :: {title}", process_observation
            return process_name or title, process_observation
        except Exception as error:  # pragma: no cover - platform-specific
            self._add_note_once(f"Foreground window sampling unavailable: {error}")
            return "", None

    def _build_process_observation(
        self,
        user32: ctypes.LibraryLoader,
        hwnd: int,
        title: str,
    ) -> ProcessObservation | None:
        try:
            process_id = ctypes.c_ulong()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(process_id))
            if process_id.value == 0:
                return None

            pid = int(process_id.value)
            exe_path = self._get_process_path(pid)
            process_name = os.path.basename(exe_path) if exe_path else ""
            parent_name: str | None = None
            parent_pid: int | None = None
            ancestry: list[str] = []

            if psutil is not None:
                try:
                    process = psutil.Process(pid)
                    process_name = process.name() or process_name
                    exe_path = process.exe() or exe_path
                    current = process.parent()
                    depth = 0
                    while current is not None and depth < 3:
                        parent_label = current.name()
                        if depth == 0:
                            parent_name = parent_label
                            parent_pid = current.pid
                        ancestry.append(parent_label)
                        current = current.parent()
                        depth += 1
                except Exception:
                    pass

            return ProcessObservation(
                observed_at=datetime.now(),
                process_name=process_name or "unknown_process",
                pid=pid,
                parent_name=parent_name,
                parent_pid=parent_pid,
                ancestry=ancestry,
                exe_path=exe_path or None,
                window_title=title or None,
                source="system",
            )
        except Exception:
            return None

    @staticmethod
    def _get_process_path(pid: int) -> str:
        try:
            kernel32 = ctypes.windll.kernel32
            process_handle = kernel32.OpenProcess(0x1000, False, pid)
            if not process_handle:
                return ""
            try:
                buffer_length = ctypes.c_ulong(260)
                buffer = ctypes.create_unicode_buffer(buffer_length.value)
                success = kernel32.QueryFullProcessImageNameW(
                    process_handle,
                    0,
                    buffer,
                    ctypes.byref(buffer_length),
                )
                if not success:
                    return ""
                return buffer.value
            finally:
                kernel32.CloseHandle(process_handle)
        except Exception:
            return ""

    def _add_note_once(self, note: str) -> None:
        with self._lock:
            if note not in self._notes:
                self._notes.append(note)


class DemoActivityCollector:
    scenario_names = (
        "normal",
        "fast_typing",
        "unfamiliar_app",
        "off_hours_login",
        "combined_attack",
        "rapid_switching",
        "session_hijack",
        "identity_mismatch",
        "time_warp",
        "honeypot_access",
    )

    def __init__(self, config: MonitorConfig) -> None:
        self.config = config
        self._random = Random(42)
        self._queued_scenarios: deque[str] = deque()
        self._current_scenario = "normal"
        self._started = False
        self._last_snapshot_at = datetime.now()

    def start(self) -> None:
        self._started = True
        self._last_snapshot_at = datetime.now()

    def stop(self) -> None:
        self._started = False

    def queue_scenario(self, scenario_name: str) -> None:
        if scenario_name in self.scenario_names:
            self._current_scenario = scenario_name
            self._queued_scenarios.append(scenario_name)

    def reference_windows(self, count: int) -> list[ActivityWindow]:
        now = datetime.now()
        return [
            self._build_window("normal", now - timedelta(minutes=count - index))
            for index in range(count)
        ]

    def capture_window(self) -> ActivityWindow:
        if self._queued_scenarios:
            scenario_name = self._queued_scenarios.popleft()
            self._current_scenario = scenario_name
        else:
            scenario_name = self._current_scenario
        now = datetime.now()
        window = self._build_window(scenario_name, now)
        self._last_snapshot_at = now
        return window

    def _build_window(self, scenario_name: str, current_time: datetime) -> ActivityWindow:
        duration_seconds = float(self.config.analysis_interval_seconds)
        start_time = current_time - timedelta(seconds=duration_seconds)
        login_at = current_time.replace(hour=9, minute=15, second=0, microsecond=0)
        session_duration = 45.0
        process_observations: list[ProcessObservation] = []
        honeypot_hits: list[str] = []

        if scenario_name == "fast_typing":
            key_timestamps = self._build_key_timestamps(duration_seconds, 32, 0.02)
            mouse_segments = self._build_mouse_segments(10, 250.0, 0.18)
            active_apps = [
                "code.exe :: Visual Studio Code",
                "msedge.exe :: anomaly detector tuning - Google Search - Microsoft Edge",
                "code.exe :: Visual Studio Code",
            ]
            process_observations = self._demo_process_chain(
                current_time,
                ("code.exe", "explorer.exe"),
                ("msedge.exe", "explorer.exe"),
            )
        elif scenario_name == "unfamiliar_app":
            key_timestamps = self._build_key_timestamps(duration_seconds, 14, 0.05)
            mouse_segments = self._build_mouse_segments(14, 220.0, 0.25)
            active_apps = [
                "code.exe :: Visual Studio Code",
                "brave.exe :: malware triage checklist - Brave Search - Brave",
                "unknown_updater.exe :: Unknown Updater",
                "unknown_updater.exe :: Unknown Updater",
            ]
            process_observations = self._demo_process_chain(
                current_time,
                ("code.exe", "explorer.exe"),
                ("brave.exe", "explorer.exe"),
                ("unknown_updater.exe", "powershell.exe", "explorer.exe"),
            )
        elif scenario_name == "off_hours_login":
            key_timestamps = self._build_key_timestamps(duration_seconds, 12, 0.04)
            mouse_segments = self._build_mouse_segments(12, 200.0, 0.26)
            active_apps = [
                "outlook.exe :: Inbox - Outlook",
                "teams.exe :: Microsoft Teams",
                "outlook.exe :: Inbox - Outlook",
            ]
            login_at = current_time.replace(hour=3, minute=12, second=0, microsecond=0)
            session_duration = 6.0
            process_observations = self._demo_process_chain(
                current_time,
                ("outlook.exe", "explorer.exe"),
                ("teams.exe", "explorer.exe"),
            )
        elif scenario_name == "combined_attack":
            key_timestamps = self._build_key_timestamps(duration_seconds, 38, 0.01)
            mouse_segments = self._build_mouse_segments(18, 520.0, 0.12)
            active_apps = [
                "code.exe :: Visual Studio Code",
                "brave.exe :: credential dumping commands - Google Search - Brave",
                "powershell.exe :: Administrator: Windows PowerShell",
                "credential_dump.exe :: Credential Dump Utility",
            ]
            login_at = current_time.replace(hour=2, minute=47, second=0, microsecond=0)
            session_duration = 4.0
            process_observations = self._demo_process_chain(
                current_time,
                ("code.exe", "explorer.exe"),
                ("brave.exe", "explorer.exe"),
                ("powershell.exe", "explorer.exe"),
                ("credential_dump.exe", "powershell.exe", "explorer.exe"),
            )
        elif scenario_name == "rapid_switching":
            key_timestamps = self._build_key_timestamps(duration_seconds, 18, 0.03)
            mouse_segments = self._build_mouse_segments(22, 280.0, 0.11)
            active_apps = [
                "chrome.exe :: zero trust implementation - Google Search - Google Chrome",
                "code.exe :: Visual Studio Code",
                "explorer.exe :: File Explorer",
                "powershell.exe :: Windows PowerShell",
                "teams.exe :: Microsoft Teams",
                "chrome.exe :: project dashboard - Google Chrome",
            ]
            process_observations = self._demo_process_chain(
                current_time,
                ("chrome.exe", "explorer.exe"),
                ("code.exe", "explorer.exe"),
                ("powershell.exe", "explorer.exe"),
            )
        elif scenario_name == "session_hijack":
            key_timestamps = self._build_key_timestamps(duration_seconds, 27, 0.015)
            mouse_segments = self._build_mouse_segments(20, 460.0, 0.10)
            active_apps = [
                "code.exe :: Visual Studio Code",
                "remote_assist.exe :: Remote Session Console",
                "chrome.exe :: session token replay - Google Search - Google Chrome",
                "remote_assist.exe :: Remote Session Console",
            ]
            login_at = current_time.replace(hour=1, minute=58, second=0, microsecond=0)
            session_duration = 3.0
            process_observations = self._demo_process_chain(
                current_time,
                ("code.exe", "explorer.exe"),
                ("remote_assist.exe", "explorer.exe"),
                ("chrome.exe", "remote_assist.exe", "explorer.exe"),
                ("powershell.exe", "remote_assist.exe", "explorer.exe"),
            )
        elif scenario_name == "identity_mismatch":
            key_timestamps = self._build_key_timestamps(duration_seconds, 34, 0.012)
            mouse_segments = self._build_mouse_segments(24, 510.0, 0.09)
            active_apps = [
                "teams.exe :: Microsoft Teams",
                "powershell.exe :: Administrator: Windows PowerShell",
                "chrome.exe :: dump creds quietly - Google Search - Google Chrome",
                "remote_assist.exe :: Remote Session Console",
                "credential_dump.exe :: Credential Dump Utility",
            ]
            login_at = current_time.replace(hour=4, minute=8, second=0, microsecond=0)
            session_duration = 5.0
            process_observations = self._demo_process_chain(
                current_time,
                ("teams.exe", "explorer.exe"),
                ("powershell.exe", "remote_assist.exe", "explorer.exe"),
                ("chrome.exe", "remote_assist.exe", "explorer.exe"),
                ("credential_dump.exe", "powershell.exe", "remote_assist.exe"),
            )
        elif scenario_name == "time_warp":
            key_timestamps = self._build_key_timestamps(duration_seconds, 40, 0.008)
            mouse_segments = self._build_mouse_segments(28, 540.0, 0.07)
            active_apps = [
                "code.exe :: Visual Studio Code",
                "powershell.exe :: Windows PowerShell",
                "powershell.exe :: Windows PowerShell",
                "chrome.exe :: powershell encodedcommand example - Google Search - Google Chrome",
            ]
            session_duration = 9.0
            process_observations = self._demo_process_chain(
                current_time,
                ("code.exe", "explorer.exe"),
                ("powershell.exe", "explorer.exe"),
                ("chrome.exe", "powershell.exe", "explorer.exe"),
            )
        elif scenario_name == "honeypot_access":
            key_timestamps = self._build_key_timestamps(duration_seconds, 20, 0.018)
            mouse_segments = self._build_mouse_segments(16, 340.0, 0.10)
            active_apps = [
                "explorer.exe :: Executive_Payroll_2026.txt",
                "notepad.exe :: Executive_Payroll_2026.txt - Notepad",
                "powershell.exe :: Windows PowerShell",
            ]
            process_observations = self._demo_process_chain(
                current_time,
                ("explorer.exe",),
                ("notepad.exe", "explorer.exe"),
                ("powershell.exe", "explorer.exe"),
            )
            honeypot_hits = [
                "Honeypot file touched: Executive_Payroll_2026.txt",
                "Honeypot file touched: Privileged_Access_Notes.txt",
            ]
            login_at = current_time.replace(hour=1, minute=41, second=0, microsecond=0)
            session_duration = 2.0
        else:
            key_timestamps = self._build_key_timestamps(duration_seconds, 15, 0.05)
            mouse_segments = self._build_mouse_segments(14, 180.0, 0.24)
            active_apps = [
                "code.exe :: Visual Studio Code",
                "outlook.exe :: Inbox - Outlook",
                "msedge.exe :: team standup notes - Microsoft Edge",
                "code.exe :: Visual Studio Code",
            ]
            process_observations = self._demo_process_chain(
                current_time,
                ("code.exe", "explorer.exe"),
                ("outlook.exe", "explorer.exe"),
                ("msedge.exe", "explorer.exe"),
            )

        return ActivityWindow(
            started_at=start_time,
            ended_at=current_time,
            key_timestamps=key_timestamps,
            mouse_segments=mouse_segments,
            active_apps=active_apps,
            process_observations=process_observations,
            honeypot_hits=honeypot_hits,
            login_at=login_at,
            session_duration_minutes=session_duration,
            source="demo",
            collector_notes=[f"Demo scenario: {scenario_name.replace('_', ' ')}"],
            scenario_name=scenario_name,
            expected_anomaly=scenario_name != "normal",
        )

    def _build_key_timestamps(
        self,
        duration_seconds: float,
        event_count: int,
        jitter: float,
    ) -> list[float]:
        if event_count <= 0:
            return []
        base = time.time() - duration_seconds
        gap = duration_seconds / max(event_count, 1)
        timestamps: list[float] = []
        current = base
        for _ in range(event_count):
            current += gap + self._random.uniform(-jitter, jitter)
            timestamps.append(current)
        return timestamps

    def _build_mouse_segments(
        self,
        count: int,
        average_distance: float,
        average_delta: float,
    ) -> list[tuple[float, float]]:
        segments: list[tuple[float, float]] = []
        for _ in range(count):
            distance = max(average_distance + self._random.uniform(-40.0, 40.0), 10.0)
            delta = max(average_delta + self._random.uniform(-0.04, 0.04), 0.05)
            segments.append((distance, delta))
        return segments

    @staticmethod
    def _demo_process_chain(
        current_time: datetime,
        *chains: tuple[str, ...],
    ) -> list[ProcessObservation]:
        observations: list[ProcessObservation] = []
        for index, chain in enumerate(chains, start=1):
            process_name = chain[0]
            parent_name = chain[1] if len(chain) > 1 else None
            ancestry = list(chain[1:]) if len(chain) > 1 else []
            observations.append(
                ProcessObservation(
                    observed_at=current_time,
                    process_name=process_name,
                    pid=2000 + index,
                    parent_name=parent_name,
                    parent_pid=1000 + index if parent_name else None,
                    ancestry=ancestry,
                    exe_path=f"C:\\Demo\\{process_name}",
                    window_title=process_name,
                    source="demo",
                )
            )
        return observations
