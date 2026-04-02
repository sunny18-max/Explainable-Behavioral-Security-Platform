from __future__ import annotations

import statistics
from collections import Counter
from datetime import datetime

from .models import ActivityWindow, AppObservation, BehaviorFeatures, BrowserEvent


class FeatureExtractor:
    browser_processes = {"chrome.exe", "brave.exe", "msedge.exe", "firefox.exe"}
    browser_suffixes = (
        " - Google Chrome",
        " - Brave",
        " - Microsoft Edge",
        " - Mozilla Firefox",
        " - Chrome",
    )
    search_markers = (
        " - Google Search",
        " - Brave Search",
        " - Bing",
        " - DuckDuckGo",
        " - Yahoo Search",
    )

    def extract(self, window: ActivityWindow) -> BehaviorFeatures:
        key_timestamps = sorted(window.key_timestamps)
        key_intervals = [
            current - previous
            for previous, current in zip(key_timestamps, key_timestamps[1:])
            if current > previous
        ]

        total_mouse_distance = sum(distance for distance, _ in window.mouse_segments)
        total_mouse_time = sum(delta for _, delta in window.mouse_segments)
        mouse_speed = total_mouse_distance / total_mouse_time if total_mouse_time else 0.0

        system_observations = [
            self._parse_app_observation(app)
            for app in window.active_apps
            if app.strip()
        ]
        browser_observations = [
            self._observation_from_browser_event(event)
            for event in window.browser_events
        ]
        app_observations = self._dedupe_observations(
            system_observations + browser_observations
        )
        app_sequence = [
            observation.app_name
            for observation in system_observations + browser_observations
            if observation.app_name
        ]
        apps_seen = app_sequence
        if apps_seen:
            dominant_app = Counter(apps_seen).most_common(1)[0][0]
        else:
            dominant_app = "idle"

        app_switch_count = self._count_switches(apps_seen)
        login_time = window.login_at or datetime.now()
        login_hour = login_time.hour + (login_time.minute / 60.0)
        typing_speed = len(key_timestamps) / window.duration_seconds
        typing_gap_variance = (
            statistics.pvariance(key_intervals) if len(key_intervals) > 1 else 0.0
        )
        activity_intensity = typing_speed + (mouse_speed / 700.0) + app_switch_count * 0.5

        ordered_apps = list(dict.fromkeys(apps_seen))
        return BehaviorFeatures(
            observed_at=window.ended_at,
            typing_speed=typing_speed,
            typing_gap_variance=typing_gap_variance,
            mouse_speed=mouse_speed,
            app_switch_count=app_switch_count,
            unique_app_count=len(set(apps_seen)),
            dominant_app=dominant_app,
            apps_seen=ordered_apps,
            login_hour=login_hour,
            session_duration_minutes=window.session_duration_minutes,
            activity_intensity=activity_intensity,
            keystroke_count=len(key_timestamps),
            mouse_event_count=len(window.mouse_segments),
            app_observations=app_observations,
            process_observations=list(window.process_observations),
            honeypot_hits=list(window.honeypot_hits),
            source=window.source,
        )

    @staticmethod
    def _dedupe_observations(observations: list[AppObservation]) -> list[AppObservation]:
        seen: set[tuple[str, str, str | None, str | None, str | None, str | None]] = set()
        unique: list[AppObservation] = []
        for observation in observations:
            key = (
                observation.app_name,
                observation.window_title,
                observation.tab_title,
                observation.search_query,
                observation.url,
                observation.domain,
            )
            if key in seen:
                continue
            seen.add(key)
            unique.append(observation)
        return unique

    @staticmethod
    def _count_switches(apps_seen: list[str]) -> int:
        if not apps_seen:
            return 0
        switches = 0
        previous = apps_seen[0]
        for current in apps_seen[1:]:
            if current != previous:
                switches += 1
            previous = current
        return switches

    @staticmethod
    def _normalize_app_name(app_name: str) -> str:
        compact = " ".join(app_name.strip().split())
        process_name, separator, _ = compact.partition("::")
        if separator:
            return process_name.strip().lower()
        return compact.lower()

    def _parse_app_observation(self, raw_label: str) -> AppObservation:
        compact = " ".join(raw_label.strip().split())
        app_name = self._normalize_app_name(compact)
        _, separator, trailing_title = compact.partition("::")
        window_title = trailing_title.strip() if separator else compact
        tab_title = None
        search_query = None

        if app_name in self.browser_processes:
            tab_title = self._clean_browser_title(window_title)
            search_query = self._extract_search_query(window_title)

        return AppObservation(
            app_name=app_name,
            window_title=window_title,
            tab_title=tab_title,
            search_query=search_query,
            source="system",
        )

    def _observation_from_browser_event(self, event: BrowserEvent) -> AppObservation:
        return AppObservation(
            app_name=event.browser_name,
            window_title=event.tab_title or event.url or event.domain or event.browser_name,
            tab_title=event.tab_title or None,
            search_query=event.search_query,
            url=event.url or None,
            domain=event.domain or None,
            source=event.source,
        )

    def _clean_browser_title(self, window_title: str) -> str:
        cleaned = window_title
        for suffix in self.browser_suffixes:
            if cleaned.endswith(suffix):
                cleaned = cleaned[: -len(suffix)]
                break
        return cleaned.strip(" -")

    def _extract_search_query(self, window_title: str) -> str | None:
        cleaned = self._clean_browser_title(window_title)
        for marker in self.search_markers:
            if marker in cleaned:
                return cleaned.split(marker, 1)[0].strip() or None
        return None
