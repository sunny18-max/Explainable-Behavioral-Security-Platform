from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from math import cos, pi, sin
from typing import Any


@dataclass(slots=True)
class ActivityWindow:
    started_at: datetime
    ended_at: datetime
    key_timestamps: list[float] = field(default_factory=list)
    mouse_segments: list[tuple[float, float]] = field(default_factory=list)
    active_apps: list[str] = field(default_factory=list)
    browser_events: list["BrowserEvent"] = field(default_factory=list)
    process_observations: list["ProcessObservation"] = field(default_factory=list)
    honeypot_hits: list[str] = field(default_factory=list)
    login_at: datetime | None = None
    session_duration_minutes: float = 0.0
    source: str = "live"
    collector_notes: list[str] = field(default_factory=list)
    scenario_name: str | None = None
    expected_anomaly: bool | None = None

    @property
    def duration_seconds(self) -> float:
        return max((self.ended_at - self.started_at).total_seconds(), 1.0)


@dataclass(slots=True)
class BrowserEvent:
    observed_at: datetime
    browser_name: str
    tab_title: str
    url: str
    domain: str
    search_query: str | None = None
    source: str = "extension"
    tab_id: int | None = None
    window_id: int | None = None

    def as_record(self) -> dict[str, Any]:
        return {
            "observed_at": self.observed_at.isoformat(),
            "browser_name": self.browser_name,
            "tab_title": self.tab_title,
            "url": self.url,
            "domain": self.domain,
            "search_query": self.search_query,
            "source": self.source,
            "tab_id": self.tab_id,
            "window_id": self.window_id,
        }


@dataclass(slots=True)
class AppObservation:
    app_name: str
    window_title: str
    tab_title: str | None = None
    search_query: str | None = None
    url: str | None = None
    domain: str | None = None
    source: str = "system"

    def as_record(self) -> dict[str, str | None]:
        return {
            "app_name": self.app_name,
            "window_title": self.window_title,
            "tab_title": self.tab_title,
            "search_query": self.search_query,
            "url": self.url,
            "domain": self.domain,
            "source": self.source,
        }


@dataclass(slots=True)
class ProcessObservation:
    observed_at: datetime
    process_name: str
    pid: int | None = None
    parent_name: str | None = None
    parent_pid: int | None = None
    ancestry: list[str] = field(default_factory=list)
    exe_path: str | None = None
    window_title: str | None = None
    source: str = "system"

    def as_record(self) -> dict[str, Any]:
        return {
            "observed_at": self.observed_at.isoformat(),
            "process_name": self.process_name,
            "pid": self.pid,
            "parent_name": self.parent_name,
            "parent_pid": self.parent_pid,
            "ancestry": list(self.ancestry),
            "exe_path": self.exe_path,
            "window_title": self.window_title,
            "source": self.source,
        }


@dataclass(slots=True)
class BehaviorFeatures:
    observed_at: datetime
    typing_speed: float
    typing_gap_variance: float
    mouse_speed: float
    app_switch_count: int
    unique_app_count: int
    dominant_app: str
    apps_seen: list[str]
    login_hour: float
    session_duration_minutes: float
    activity_intensity: float
    keystroke_count: int
    mouse_event_count: int
    app_observations: list[AppObservation] = field(default_factory=list)
    process_observations: list[ProcessObservation] = field(default_factory=list)
    honeypot_hits: list[str] = field(default_factory=list)
    source: str = "live"

    def to_vector(self) -> list[float]:
        angle = (self.login_hour / 24.0) * 2.0 * pi
        return [
            self.typing_speed,
            self.typing_gap_variance,
            self.mouse_speed,
            float(self.app_switch_count),
            float(self.unique_app_count),
            sin(angle),
            cos(angle),
            self.session_duration_minutes,
            self.activity_intensity,
        ]

    def as_record(self) -> dict[str, Any]:
        return {
            "observed_at": self.observed_at.isoformat(),
            "typing_speed": self.typing_speed,
            "typing_gap_variance": self.typing_gap_variance,
            "mouse_speed": self.mouse_speed,
            "app_switch_count": self.app_switch_count,
            "unique_app_count": self.unique_app_count,
            "dominant_app": self.dominant_app,
            "apps_seen": list(self.apps_seen),
            "login_hour": self.login_hour,
            "session_duration_minutes": self.session_duration_minutes,
            "activity_intensity": self.activity_intensity,
            "keystroke_count": self.keystroke_count,
            "mouse_event_count": self.mouse_event_count,
            "app_observations": [
                observation.as_record() for observation in self.app_observations
            ],
            "process_observations": [
                observation.as_record() for observation in self.process_observations
            ],
            "honeypot_hits": list(self.honeypot_hits),
            "source": self.source,
        }


@dataclass(slots=True)
class NumericBaseline:
    mean: float
    median: float
    stdev: float
    lower_bound: float
    upper_bound: float


@dataclass(slots=True)
class BehaviorProfile:
    sample_count: int
    baselines: dict[str, NumericBaseline]
    known_apps: set[str]
    primary_apps: set[str]


@dataclass(slots=True)
class FeatureDeviation:
    feature_name: str
    current_value: float | str
    baseline_value: float | str
    score: float
    severity: str
    reason: str
    confidence: float = 0.0


@dataclass(slots=True)
class DetectionSignal:
    risk_score: float
    is_anomaly: bool
    severity: str
    deviations: list[FeatureDeviation]
    model_used: bool
    model_flagged: bool
    model_score: float
    summary: str = ""
    explanation: str = ""
    reasons: list[str] = field(default_factory=list)
    confidence_score: float = 0.0
    intent_matches: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    risk_factors: list[dict[str, Any]] = field(default_factory=list)
    watchlist_hits: list[str] = field(default_factory=list)
    cluster_key: str = ""
    effective_threshold: float | None = None
    training_mode: bool = False


@dataclass(slots=True)
class AlertRecord:
    id: int
    created_at: datetime
    severity: str
    risk_score: float
    summary: str
    explanation: str
    user_name: str
    feedback_label: str | None = None
    feedback_note: str | None = None
    recommended_actions: list[str] = field(default_factory=list)
    cluster_key: str = ""


@dataclass(slots=True)
class CycleOutcome:
    user_name: str
    mode: str
    features: BehaviorFeatures
    profile: BehaviorProfile
    detection: DetectionSignal
    collector_notes: list[str]
    recent_history: list[BehaviorFeatures]
    recent_alerts: list[AlertRecord]
    fingerprint_similarity: float | None = None
    behavior_drift: float | None = None
    context_labels: list[str] = field(default_factory=list)
    timeline: list[dict[str, str]] = field(default_factory=list)
    replay_summary: str = ""
    risk_factors: list[dict[str, Any]] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    watchlist_hits: list[str] = field(default_factory=list)
    domain_categories: list[str] = field(default_factory=list)
    scenario_name: str | None = None
    expected_anomaly: bool | None = None
    effective_threshold: float | None = None
