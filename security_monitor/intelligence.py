from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from math import sqrt

from .config import MonitorConfig
from .models import ActivityWindow, BehaviorFeatures, BehaviorProfile


@dataclass(slots=True)
class AdvancedBehaviorSignals:
    fingerprint_similarity: float | None = None
    behavior_drift: float | None = None
    time_warp_typing_ratio: float | None = None
    time_warp_mouse_ratio: float | None = None
    context_labels: list[str] = field(default_factory=list)
    intent_matches: list[str] = field(default_factory=list)
    process_alerts: list[str] = field(default_factory=list)
    watchlist_hits: list[str] = field(default_factory=list)
    honeypot_hits: list[str] = field(default_factory=list)
    domain_categories: list[str] = field(default_factory=list)
    replay_summary: str = ""
    timeline: list[dict[str, str]] = field(default_factory=list)


class BehaviorIntelligenceEngine:
    shell_processes = {
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "wscript.exe",
        "cscript.exe",
        "terminal.exe",
    }
    remote_access_processes = {
        "remote_assist.exe",
        "teamviewer.exe",
        "anydesk.exe",
        "mstsc.exe",
    }
    development_processes = {
        "code.exe",
        "devenv.exe",
        "idea64.exe",
        "pycharm64.exe",
    }
    office_processes = {
        "outlook.exe",
        "teams.exe",
        "winword.exe",
        "excel.exe",
        "powerpnt.exe",
    }
    login_markers = ("login", "sign in", "password", "otp", "verification")

    def __init__(self, config: MonitorConfig | None = None) -> None:
        self.config = config or MonitorConfig()

    def analyze(
        self,
        activity_window: ActivityWindow,
        features: BehaviorFeatures,
        profile: BehaviorProfile,
        history: list[BehaviorFeatures],
    ) -> AdvancedBehaviorSignals:
        contexts = self._collect_context_labels(features)
        fingerprint_similarity = self._fingerprint_similarity(features, history)
        behavior_drift = self._behavior_drift(history)
        typing_ratio, mouse_ratio = self._time_warp(features, history)
        intent_matches = self._detect_intent(features, contexts)
        intent_matches.extend(self._detect_sequence_patterns(activity_window, features))
        intent_matches = list(dict.fromkeys(intent_matches))
        process_alerts = self._analyze_process_lineage(features)
        domain_categories = self._collect_domain_categories(features)
        honeypot_hits = list(dict.fromkeys(features.honeypot_hits))
        watchlist_hits = self._collect_watchlist_hits(features, process_alerts, honeypot_hits)
        replay_summary = self._build_replay_summary(
            activity_window,
            features,
            domain_categories,
            watchlist_hits,
            process_alerts,
            honeypot_hits,
        )
        timeline = self._build_timeline(activity_window)

        return AdvancedBehaviorSignals(
            fingerprint_similarity=fingerprint_similarity,
            behavior_drift=behavior_drift,
            time_warp_typing_ratio=typing_ratio,
            time_warp_mouse_ratio=mouse_ratio,
            context_labels=contexts,
            intent_matches=intent_matches,
            process_alerts=process_alerts,
            watchlist_hits=watchlist_hits,
            honeypot_hits=honeypot_hits,
            domain_categories=domain_categories,
            replay_summary=replay_summary,
            timeline=timeline,
        )

    def _collect_context_labels(self, features: BehaviorFeatures) -> list[str]:
        labels: set[str] = set()
        app_names = {app_name.lower() for app_name in features.apps_seen}
        window_titles = [
            (observation.window_title or "").lower()
            for observation in features.app_observations
        ]

        if app_names & self.shell_processes:
            labels.add("admin_shell")
        if app_names & self.remote_access_processes:
            labels.add("remote_access")
        if app_names & self.development_processes:
            labels.add("development")
        if app_names & self.office_processes:
            labels.add("office")
        if app_names & set(self.config.vpn_process_watchlist):
            labels.add("vpn_tool")
        if any(observation.search_query for observation in features.app_observations):
            labels.add("browser_search")
        if any(observation.domain for observation in features.app_observations):
            labels.add("web_activity")
        if any(
            marker in title for marker in self.login_markers for title in window_titles
        ):
            labels.add("login_surface")

        if not labels:
            labels.add("general_desktop")
        return sorted(labels)

    def _fingerprint_similarity(
        self,
        features: BehaviorFeatures,
        history: list[BehaviorFeatures],
    ) -> float | None:
        if len(history) < 4:
            return None

        recent_history = history[-min(len(history), 24) :]
        reference_vector = self._mean_vector(
            [self._fingerprint_vector(sample) for sample in recent_history]
        )
        similarity = self._cosine_similarity(
            self._fingerprint_vector(features),
            reference_vector,
        )
        return round(similarity * 100.0, 1)

    def _behavior_drift(self, history: list[BehaviorFeatures]) -> float | None:
        if len(history) < 10:
            return None

        midpoint = len(history) // 2
        earlier = history[:midpoint]
        recent = history[midpoint:]
        if not earlier or not recent:
            return None

        earlier_vector = self._mean_vector([sample.to_vector() for sample in earlier])
        recent_vector = self._mean_vector([sample.to_vector() for sample in recent])
        drift = 1.0 - self._cosine_similarity(earlier_vector, recent_vector)
        return round(max(drift, 0.0) * 100.0, 1)

    def _time_warp(
        self,
        features: BehaviorFeatures,
        history: list[BehaviorFeatures],
    ) -> tuple[float | None, float | None]:
        if not history:
            return None, None

        reference = history[-min(len(history), 5) :]
        baseline_typing = max(
            sum(sample.typing_speed for sample in reference) / len(reference),
            0.1,
        )
        baseline_mouse = max(
            sum(sample.mouse_speed for sample in reference) / len(reference),
            1.0,
        )
        typing_ratio = features.typing_speed / baseline_typing
        mouse_ratio = features.mouse_speed / baseline_mouse
        return round(typing_ratio, 2), round(mouse_ratio, 2)

    def _fingerprint_vector(self, features: BehaviorFeatures) -> list[float]:
        contexts = set(self._collect_context_labels(features))
        query_count = sum(
            1 for observation in features.app_observations if observation.search_query
        )
        browser_count = sum(
            1 for observation in features.app_observations if observation.domain
        )
        angle_vector = features.to_vector()[5:7]
        return [
            min(features.typing_speed / 8.0, 1.8),
            min(features.typing_gap_variance / 0.08, 1.8),
            min(features.mouse_speed / 2400.0, 1.8),
            min(features.app_switch_count / 7.0, 1.5),
            min(features.unique_app_count / 7.0, 1.5),
            *angle_vector,
            min(features.session_duration_minutes / 60.0, 1.8),
            min(features.activity_intensity / 10.0, 1.8),
            1.35 if "development" in contexts else 0.0,
            1.35 if "office" in contexts else 0.0,
            1.35 if "admin_shell" in contexts else 0.0,
            1.35 if "remote_access" in contexts else 0.0,
            1.35 if "browser_search" in contexts else 0.0,
            min(query_count / 3.0, 1.2),
            min(browser_count / 4.0, 1.2),
        ]

    def _detect_intent(
        self,
        features: BehaviorFeatures,
        context_labels: list[str],
    ) -> list[str]:
        app_names = {app_name.lower() for app_name in features.apps_seen}
        search_queries = [
            (observation.search_query or "").lower()
            for observation in features.app_observations
            if observation.search_query
        ]
        domains = {
            (observation.domain or "").lower()
            for observation in features.app_observations
            if observation.domain
        }
        unknown_apps = [
            app_name
            for app_name in app_names
            if app_name not in self.development_processes
            and app_name not in self.office_processes
            and app_name not in self.shell_processes
            and app_name not in self.remote_access_processes
            and app_name not in {"chrome.exe", "brave.exe", "msedge.exe", "firefox.exe", "idle"}
        ]
        suspicious_query = any(
            keyword in query
            for query in search_queries
            for keyword in ("credential", "mimikatz", "token", "dump", "bypass", "shell")
        )
        third_party_or_vpn_query = any(
            keyword in query
            for query in search_queries
            for keyword in ("vpn", "third-party", "third party", "installer", "apk", "cracked")
        )
        vpn_active = bool(app_names & set(self.config.vpn_process_watchlist))

        matches: list[str] = []
        if suspicious_query and app_names & self.shell_processes:
            matches.append("Browser research followed by shell usage suggests execution intent.")
        if suspicious_query and unknown_apps:
            matches.append("Sensitive browsing plus an unfamiliar executable suggests hands-on intrusion intent.")
        if "remote_access" in context_labels and any(
            "session" in query or "token" in query for query in search_queries
        ):
            matches.append("Remote access activity overlaps with session or token searches.")
        if features.app_switch_count >= 4 and (app_names & self.shell_processes) and unknown_apps:
            matches.append("Rapid tool switching with shell access and a new executable indicates operator-driven activity.")
        if "browser_search" in context_labels and any(
            domain.endswith(search_domain)
            for domain in domains
            for search_domain in ("google.com", "bing.com", "search.brave.com", "duckduckgo.com")
        ) and suspicious_query:
            matches.append("Search-engine activity contains attack-related reconnaissance terms.")
        if third_party_or_vpn_query:
            matches.append("Visible search activity suggests third-party application or VPN acquisition intent.")
        if vpn_active:
            matches.append("VPN or tunneling software is active in the current session window.")
        return matches

    def _analyze_process_lineage(self, features: BehaviorFeatures) -> list[str]:
        alerts: list[str] = []
        browser_processes = {"chrome.exe", "brave.exe", "msedge.exe", "firefox.exe"}
        known_safe = (
            self.development_processes
            | self.office_processes
            | self.remote_access_processes
            | self.shell_processes
            | browser_processes
            | {"explorer.exe", "notepad.exe", "idle"}
        )
        for observation in features.process_observations:
            process_name = observation.process_name.lower()
            parent_name = (observation.parent_name or "").lower()
            ancestry = [item.lower() for item in observation.ancestry]
            if (
                process_name in self.config.suspicious_process_watchlist
                and parent_name in self.config.suspicious_parent_watchlist
            ):
                alerts.append(
                    f"Watchlist executable {process_name} was launched from {parent_name}."
                )
            if (
                process_name not in known_safe
                and any(item in self.config.suspicious_parent_watchlist for item in ancestry)
            ):
                alerts.append(
                    f"Process lineage shows {process_name} descending from shell tooling."
                )
            if (
                process_name in self.shell_processes
                and any(item in self.remote_access_processes for item in ancestry)
            ):
                alerts.append(
                    f"Shell access appeared under remote-access ancestry for {process_name}."
                )
        return list(dict.fromkeys(alerts))

    def _detect_sequence_patterns(
        self,
        activity_window: ActivityWindow,
        features: BehaviorFeatures,
    ) -> list[str]:
        sequence_tokens: list[str] = []
        unknown_seen = False
        for raw_label in activity_window.active_apps:
            lowered = raw_label.lower()
            app_name = lowered.split("::", 1)[0].strip()
            if app_name in {"chrome.exe", "brave.exe", "msedge.exe", "firefox.exe"}:
                if any(term in lowered for term in self.config.suspicious_query_terms) or "search" in lowered:
                    sequence_tokens.append("browser_search")
                else:
                    sequence_tokens.append("browser")
            elif app_name in self.shell_processes:
                sequence_tokens.append("shell")
            elif app_name in self.remote_access_processes:
                sequence_tokens.append("remote_access")
            elif app_name in self.office_processes:
                sequence_tokens.append("office")
            elif app_name.endswith(".exe"):
                sequence_tokens.append("unknown_exe")
                unknown_seen = True

        matches: list[str] = []
        if self._contains_flow(sequence_tokens, "browser_search", "shell", "unknown_exe"):
            matches.append(
                "Sequence analysis found reconnaissance followed by shell access and an unfamiliar executable."
            )
        if self._contains_flow(sequence_tokens, "remote_access", "browser_search", "shell"):
            matches.append(
                "Sequence analysis found remote access, browser research, and shell activity in one flow."
            )
        if self._contains_flow(sequence_tokens, "office", "browser_search", "shell") and unknown_seen:
            matches.append(
                "Routine work transitioned into browser research and shell execution before a new executable appeared."
            )
        if (
            any(observation.search_query for observation in features.app_observations)
            and any(app in self.shell_processes for app in features.apps_seen)
            and unknown_seen
        ):
            matches.append(
                "Search activity, shell access, and an unknown executable appeared within the same session window."
            )
        return matches

    @staticmethod
    def _contains_flow(tokens: list[str], *wanted: str) -> bool:
        if not wanted:
            return False
        position = 0
        for token in tokens:
            if token == wanted[position]:
                position += 1
                if position == len(wanted):
                    return True
        return False

    def _collect_domain_categories(self, features: BehaviorFeatures) -> list[str]:
        categories: set[str] = set()
        for observation in features.app_observations:
            category = self._domain_category(observation.domain or "")
            if category:
                categories.add(category)
        return sorted(categories)

    def _collect_watchlist_hits(
        self,
        features: BehaviorFeatures,
        process_alerts: list[str],
        honeypot_hits: list[str],
    ) -> list[str]:
        hits: list[str] = []
        lower_apps = {app.lower() for app in features.apps_seen}
        for process_name in self.config.suspicious_process_watchlist:
            if process_name in lower_apps:
                hits.append(f"Watchlist process observed: {process_name}")
        for process_name in self.config.vpn_process_watchlist:
            if process_name in lower_apps:
                hits.append(f"VPN or tunneling client observed: {process_name}")

        for observation in features.app_observations:
            query = (observation.search_query or "").lower()
            for term in self.config.suspicious_query_terms:
                if term in query:
                    hits.append(f"Sensitive search term observed: {term}")

        if any(app in self.remote_access_processes for app in lower_apps):
            hits.append("Remote access tooling was active in this window.")
        if any(category == "vpn" for category in self._collect_domain_categories(features)):
            hits.append("VPN-related domain activity was visible in this window.")

        hits.extend(process_alerts)
        hits.extend(honeypot_hits)

        return list(dict.fromkeys(hits))

    def _build_replay_summary(
        self,
        activity_window: ActivityWindow,
        features: BehaviorFeatures,
        domain_categories: list[str],
        watchlist_hits: list[str],
        process_alerts: list[str],
        honeypot_hits: list[str],
    ) -> str:
        visible_queries = [
            observation.search_query
            for observation in features.app_observations
            if observation.search_query
        ]
        domains = {
            observation.domain
            for observation in features.app_observations
            if observation.domain
        }
        shell_count = sum(1 for app in features.apps_seen if app in self.shell_processes)
        process_count = len(features.process_observations)
        summary = (
            f"Window covered {features.unique_app_count} distinct app(s) with "
            f"{features.app_switch_count} switch(es), {len(visible_queries)} visible search query/queries, "
            f"{len(domains)} domain(s), {shell_count} shell-tool activation(s), and "
            f"{process_count} process lineage observation(s)."
        )
        if domain_categories:
            summary += " Domain categories: " + ", ".join(domain_categories) + "."
        if watchlist_hits:
            summary += f" Watchlist matched {len(watchlist_hits)} signal(s)."
        if process_alerts:
            summary += f" Process lineage raised {len(process_alerts)} alert(s)."
        if honeypot_hits:
            summary += f" Honeypot layer raised {len(honeypot_hits)} touch alert(s)."
        if activity_window.scenario_name:
            summary += f" Scenario seed: {activity_window.scenario_name.replace('_', ' ')}."
        return summary

    def _domain_category(self, domain: str) -> str:
        normalized = self._normalize_domain(domain)
        if not normalized:
            return ""
        if self._matches_domain(normalized, self.config.search_domains):
            return "search"
        if self._matches_domain(normalized, self.config.work_domains):
            return "work"
        if self._matches_domain(normalized, self.config.social_domains):
            return "social"
        if self._matches_domain(normalized, self.config.vpn_domains):
            return "vpn"
        if self._matches_domain(normalized, self.config.admin_tool_domains):
            return "admin_reference"
        if "github" in normalized or "docs" in normalized:
            return "technical_reference"
        return "unknown"

    @staticmethod
    def _normalize_domain(domain: str) -> str:
        cleaned = domain.strip().lower()
        if cleaned.startswith("www."):
            cleaned = cleaned[4:]
        return cleaned

    @staticmethod
    def _matches_domain(domain: str, candidates: tuple[str, ...]) -> bool:
        return any(domain == candidate or domain.endswith(f".{candidate}") for candidate in candidates)

    def _build_timeline(self, activity_window: ActivityWindow) -> list[dict[str, str]]:
        timeline: list[dict[str, str]] = []

        timeline.append(
            {
                "time": self._fmt_time(activity_window.started_at),
                "title": "Window opened",
                "detail": f"Monitoring source: {activity_window.source}.",
                "kind": "window",
            }
        )

        active_apps = [label for label in activity_window.active_apps if label.strip()]
        if active_apps:
            step = activity_window.duration_seconds / max(len(active_apps), 1)
            for index, label in enumerate(active_apps[:6]):
                timestamp = activity_window.started_at + timedelta(seconds=step * index)
                timeline.append(
                    {
                        "time": self._fmt_time(timestamp),
                        "title": "Foreground focus",
                        "detail": label,
                        "kind": "app",
                    }
                )

        for event in sorted(activity_window.browser_events, key=lambda item: item.observed_at)[:6]:
            detail = event.tab_title or event.url or event.domain or event.browser_name
            if event.search_query:
                detail = f"{detail} | query: {event.search_query}"
            timeline.append(
                {
                    "time": self._fmt_time(event.observed_at),
                    "title": f"{event.browser_name} active tab",
                    "detail": detail,
                    "kind": "browser",
                }
            )

        for observation in activity_window.process_observations[:5]:
            lineage = " <- ".join(
                [observation.process_name, *[item for item in observation.ancestry if item]]
            )
            timeline.append(
                {
                    "time": self._fmt_time(observation.observed_at),
                    "title": "Process lineage",
                    "detail": lineage,
                    "kind": "process",
                }
            )

        for hit in activity_window.honeypot_hits[:3]:
            timeline.append(
                {
                    "time": self._fmt_time(activity_window.ended_at),
                    "title": "Deception layer",
                    "detail": hit,
                    "kind": "alert",
                }
            )

        if activity_window.collector_notes:
            timeline.append(
                {
                    "time": self._fmt_time(activity_window.ended_at),
                    "title": "Collector notes",
                    "detail": " | ".join(activity_window.collector_notes[:2]),
                    "kind": "note",
                }
            )

        return timeline[:10]

    @staticmethod
    def _mean_vector(vectors: list[list[float]]) -> list[float]:
        if not vectors:
            return []
        dimension = len(vectors[0])
        return [
            sum(vector[index] for vector in vectors) / len(vectors)
            for index in range(dimension)
        ]

    @staticmethod
    def _cosine_similarity(left: list[float], right: list[float]) -> float:
        if not left or not right or len(left) != len(right):
            return 0.0
        dot_product = sum(a * b for a, b in zip(left, right))
        left_norm = sqrt(sum(value * value for value in left))
        right_norm = sqrt(sum(value * value for value in right))
        if left_norm == 0.0 or right_norm == 0.0:
            return 0.0
        similarity = dot_product / (left_norm * right_norm)
        return max(0.0, min(similarity, 1.0))

    @staticmethod
    def _fmt_time(value: datetime) -> str:
        return value.strftime("%H:%M:%S")
