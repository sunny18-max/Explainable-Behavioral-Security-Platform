from __future__ import annotations

import csv
from datetime import datetime
from io import StringIO

from .browser_companion import BrowserCompanionParser
from .collectors import DemoActivityCollector, WindowsActivityCollector
from .config import MonitorConfig
from .detection import HybridAnomalyDetector
from .explanations import ExplanationEngine
from .exports import ExportManager
from .feature_engineering import FeatureExtractor
from .honeypot import HoneypotManager
from .intelligence import BehaviorIntelligenceEngine
from .models import AppObservation, BehaviorFeatures, CycleOutcome, DetectionSignal
from .profiling import BehaviorProfiler
from .storage import SQLiteRepository


class MonitorService:
    def __init__(self, config: MonitorConfig | None = None) -> None:
        self.config = config or MonitorConfig()
        self.repository = SQLiteRepository(self.config.database_path)
        self.extractor = FeatureExtractor()
        self.profiler = BehaviorProfiler()
        self.intelligence = BehaviorIntelligenceEngine(self.config)
        self.detector = HybridAnomalyDetector(self.config)
        self.explainer = ExplanationEngine()
        self.exporter = ExportManager(self.config)
        self.browser_parser = BrowserCompanionParser()
        self.live_collector = WindowsActivityCollector(self.config)
        self.demo_collector = DemoActivityCollector(self.config)
        self.honeypots = HoneypotManager(self.config)
        self.mode = "live"
        self.privacy_mode = self.config.default_privacy_mode
        self._active_collector = self.live_collector
        self._started = False
        self.user_id, self.user_name = self.repository.get_or_create_user_record(
            self.config.supported_user
        )
        self.latest_outcome: CycleOutcome | None = None
        self.last_collection_at: datetime | None = None
        self.last_retention_run_at: datetime | None = None
        self.live_session_started_at: datetime | None = None
        self.honeypots.ensure_decoys()

    def start(self) -> None:
        if self._started:
            return
        if self.mode == "live":
            self.live_session_started_at = datetime.now()
        self.latest_outcome = None
        self.last_collection_at = None
        self._active_collector.start()
        self._started = True

    def stop(self) -> None:
        if not self._started:
            return
        self._active_collector.stop()
        self._started = False

    def switch_mode(self, mode: str) -> None:
        if mode not in {"live", "demo"} or mode == self.mode:
            return
        was_running = self._started
        if was_running:
            self._active_collector.stop()

        self.mode = mode
        self._active_collector = (
            self.demo_collector if mode == "demo" else self.live_collector
        )
        self.latest_outcome = None
        self.last_collection_at = None
        self.live_session_started_at = None
        if was_running:
            if self.mode == "live":
                self.live_session_started_at = datetime.now()
            self._active_collector.start()

    def switch_user(self, user_name: str) -> None:
        normalized = user_name.strip() or self.config.supported_user
        was_running = self._started
        if was_running:
            self._active_collector.stop()
        self.user_id, self.user_name = self.repository.get_or_create_user_record(
            normalized
        )
        self.latest_outcome = None
        self.last_collection_at = None
        self.live_session_started_at = None
        if was_running:
            if self.mode == "live":
                self.live_session_started_at = datetime.now()
            self._active_collector.start()

    def list_users(self) -> list[str]:
        users = self.repository.list_users()
        if self.user_name not in users:
            users.append(self.user_name)
        return sorted(set(users))

    def queue_demo_scenario(self, scenario_name: str) -> None:
        self.demo_collector.queue_scenario(scenario_name)

    def set_privacy_mode(self, privacy_mode: str) -> None:
        normalized = privacy_mode.strip().lower()
        if normalized not in {"basic", "browser_aware", "high_detail"}:
            return
        self.privacy_mode = normalized
        self.latest_outcome = None

    def run_retention(self) -> dict[str, object]:
        result = self.repository.apply_retention_policy(
            behavior_retention_days=self.config.raw_behavior_retention_days,
            browser_retention_days=self.config.raw_browser_retention_days,
        )
        self.last_retention_run_at = datetime.now()
        return result

    def refresh_honeypots(self) -> dict[str, object]:
        self.honeypots.ensure_decoys()
        return self.honeypots.summary()

    def trigger_honeypot_demo(self, file_name: str | None = None) -> dict[str, object]:
        self.honeypots.trigger_demo_hit(file_name)
        return self.honeypots.summary()

    def set_alert_feedback(
        self,
        alert_id: int,
        label: str,
        note: str = "",
    ) -> dict[str, object]:
        normalized = label.strip().lower()
        if normalized not in {"true_positive", "false_positive", "needs_review"}:
            return self.dashboard_snapshot(self._started)
        self.repository.set_alert_feedback(alert_id, normalized, note.strip())
        return self.dashboard_snapshot(self._started)

    def export_siem(self, webhook_url: str | None = None) -> dict[str, object]:
        payload = self.report_payload(self._started)
        result = self.exporter.export_siem(payload, webhook_url=webhook_url or None)
        self.repository.record_integration_export(
            self.user_id,
            target_kind="siem",
            target_name="jsonl+webhook" if webhook_url else "jsonl",
            status="ok" if result.get("ok") else "error",
            payload=payload,
            file_path=str(result.get("file_path") or ""),
            webhook_url=webhook_url or None,
            error_message=str(result.get("error")) if result.get("error") else None,
        )
        return {
            **result,
            "snapshot": self.dashboard_snapshot(self._started),
        }

    def report_pdf(self, running: bool, last_error: str | None = None) -> bytes:
        return self.exporter.build_pdf(self.report_payload(running, last_error))

    def ingest_browser_events(self, payload: dict[str, object]) -> dict[str, object]:
        requested_user_name = str(payload.get("user_name") or self.user_name).strip()
        user_name = requested_user_name or self.user_name
        user_id, user_name = self.repository.get_or_create_user_record(user_name)
        raw_events = payload.get("events")

        if isinstance(raw_events, list):
            events = [
                self.browser_parser.from_payload(
                    {
                        **event,
                        "browser_name": event.get("browser_name") or payload.get("browser_name"),
                        "source": event.get("source") or "browser_companion",
                    }
                )
                for event in raw_events
                if isinstance(event, dict)
            ]
        else:
            events = [
                self.browser_parser.from_payload(
                    {
                        **payload,
                        "source": payload.get("source") or "browser_companion",
                    }
                )
            ]

        events = [
            event
            for event in events
            if event.tab_title.strip() or event.url.strip() or event.domain.strip()
        ]

        sanitized_events = [self._sanitize_browser_event(event) for event in events]
        stored_count = self.repository.save_browser_events(user_id, sanitized_events)
        return {
            "ok": True,
            "user_name": user_name,
            "stored_count": stored_count,
            "last_event_at": sanitized_events[-1].observed_at.isoformat() if sanitized_events else None,
        }

    def collect_once(self) -> CycleOutcome:
        if not self._started:
            self.start()

        activity_window = self._active_collector.capture_window()
        if self.mode == "live":
            if self.privacy_mode != "basic":
                activity_window.browser_events = self.repository.load_browser_events_between(
                    self.user_id,
                    activity_window.started_at,
                    activity_window.ended_at,
                )
            if activity_window.browser_events:
                activity_window.collector_notes.append(
                    f"Browser companion events merged: {len(activity_window.browser_events)}"
                )
            activity_window.collector_notes.append(
                f"Privacy mode: {self.privacy_mode.replace('_', ' ')}"
            )
            activity_window.honeypot_hits.extend(
                self.honeypots.check_hits(
                    activity_window.started_at,
                    activity_window.ended_at,
                )
            )
            if activity_window.honeypot_hits:
                activity_window.collector_notes.append(
                    f"Honeypot activity observed: {len(activity_window.honeypot_hits)}"
                )
        features = self.extractor.extract(activity_window)
        features = self._apply_privacy_to_features(features)
        session_scope_start = self._session_scope_start()
        history = self._load_profile_history()
        profile = self.profiler.build(history)
        advanced_signals = self.intelligence.analyze(
            activity_window,
            features,
            profile,
            history,
        )
        feedback_offset = self.repository.load_feedback_adjustment(
            self.user_id,
            self.config.feedback_history_limit,
        )
        detection = self.detector.evaluate(
            features,
            profile,
            history,
            advanced_signals=advanced_signals,
            threshold_offset=feedback_offset,
        )
        detection = self.explainer.enrich(features, profile, detection)
        advanced_signals.timeline.append(
            {
                "time": features.observed_at.strftime("%H:%M:%S"),
                "title": "Detection result",
                "detail": detection.summary,
                "kind": "alert" if detection.is_anomaly else "status",
            }
        )

        baseline_eligible = self._should_update_baseline(detection)
        self.repository.save_behavior_sample(
            self.user_id,
            features,
            detection,
            baseline_eligible=baseline_eligible,
            fingerprint_similarity=advanced_signals.fingerprint_similarity,
            behavior_drift=advanced_signals.behavior_drift,
            timeline=advanced_signals.timeline,
            scenario_name=activity_window.scenario_name,
            expected_anomaly=activity_window.expected_anomaly,
            replay_summary=advanced_signals.replay_summary,
            risk_factors=detection.risk_factors,
            recommended_actions=detection.recommended_actions,
            watchlist_hits=detection.watchlist_hits,
            domain_categories=advanced_signals.domain_categories,
            cluster_key=detection.cluster_key,
        )

        recent_history = self.repository.load_recent_samples(
            self.user_id,
            limit=self.config.chart_history_limit,
            baseline_only=False,
            since=session_scope_start,
        )
        recent_alerts = self.repository.load_recent_alerts(
            self.user_id,
            limit=8,
            since=session_scope_start,
        )
        updated_profile = self.profiler.build(self._load_profile_history())
        self.repository.save_baseline_snapshot(
            self.user_id,
            updated_profile,
            features.observed_at,
            feedback_offset,
        )

        outcome = CycleOutcome(
            user_name=self.user_name,
            mode=self.mode,
            features=features,
            profile=updated_profile,
            detection=detection,
            collector_notes=activity_window.collector_notes,
            recent_history=recent_history,
            recent_alerts=recent_alerts,
            fingerprint_similarity=advanced_signals.fingerprint_similarity,
            behavior_drift=advanced_signals.behavior_drift,
            context_labels=advanced_signals.context_labels,
            timeline=advanced_signals.timeline,
            replay_summary=advanced_signals.replay_summary,
            risk_factors=detection.risk_factors,
            recommended_actions=detection.recommended_actions,
            watchlist_hits=detection.watchlist_hits,
            domain_categories=advanced_signals.domain_categories,
            scenario_name=activity_window.scenario_name,
            expected_anomaly=activity_window.expected_anomaly,
            effective_threshold=detection.effective_threshold,
        )
        self.latest_outcome = outcome
        self.last_collection_at = features.observed_at
        if (
            self.last_retention_run_at is None
            or (features.observed_at - self.last_retention_run_at).total_seconds() >= 1800
        ):
            self.run_retention()
        return outcome

    def _load_profile_history(self) -> list[BehaviorFeatures]:
        history = self.repository.load_recent_samples(
            self.user_id,
            limit=self.config.profile_history_limit,
            baseline_only=True,
        )
        if self.mode == "demo":
            seeded_history = [
                self.extractor.extract(window)
                for window in self.demo_collector.reference_windows(
                    self.config.training_sample_target + 8
                )
            ]
            return seeded_history[-self.config.profile_history_limit :]
        return history[-self.config.profile_history_limit :]

    def _should_update_baseline(self, detection: DetectionSignal) -> bool:
        if detection.training_mode:
            return True
        return not detection.is_anomaly and detection.risk_score < self.config.medium_risk_threshold

    def _session_scope_start(self) -> datetime | None:
        if self.mode != "live":
            return None
        return self.live_session_started_at

    def dashboard_snapshot(self, running: bool, last_error: str | None = None) -> dict[str, object]:
        session_scope_start = self._session_scope_start()
        profile = self.profiler.build(self._load_profile_history())
        metrics = self.repository.load_overview_metrics(self.user_id, since=session_scope_start)
        feedback_summary = self.repository.load_feedback_summary(self.user_id, since=session_scope_start)
        governance = self.repository.load_governance_metrics(self.user_id)
        honeypot_status = self.honeypots.summary()
        history = self.repository.load_recent_telemetry(
            self.user_id,
            self.config.chart_history_limit,
            since=session_scope_start,
        )
        alerts = self.repository.load_recent_alerts(
            self.user_id,
            self.config.alert_history_limit,
            since=session_scope_start,
        )

        return {
            "runtime": {
                "running": running,
                "mode": self.mode,
                "privacy_mode": self.privacy_mode,
                "user_name": self.user_name,
                "analysis_interval_seconds": self.config.analysis_interval_seconds,
                "raw_behavior_retention_days": self.config.raw_behavior_retention_days,
                "raw_browser_retention_days": self.config.raw_browser_retention_days,
                "last_error": last_error,
                "last_retention_run_at": (
                    self.last_retention_run_at.isoformat()
                    if self.last_retention_run_at is not None
                    else None
                ),
                "last_collection_at": (
                    self.last_collection_at.isoformat()
                    if self.last_collection_at is not None
                    else None
                ),
                "live_session_started_at": (
                    self.live_session_started_at.isoformat()
                    if self.live_session_started_at is not None
                    else None
                ),
                "history_scope": "current_live_session" if session_scope_start else "full_user_history",
            },
            "controls": {
                "users": self.list_users(),
                "demo_scenarios": list(self.demo_collector.scenario_names),
                "privacy_modes": ["basic", "browser_aware", "high_detail"],
                "capabilities": {
                    "privacy_controls": True,
                    "retention_controls": True,
                    "honeypot_controls": True,
                    "pdf_export": True,
                    "siem_export": True,
                },
            },
            "stats": {
                **metrics,
                **feedback_summary,
                **governance,
                "profile_samples": profile.sample_count,
                "known_apps": len(profile.known_apps),
                "primary_apps": sorted(profile.primary_apps),
            },
            "analytics": {
                "app_distribution": self.repository.load_app_distribution(self.user_id, since=session_scope_start),
                "severity_distribution": self.repository.load_severity_distribution(self.user_id, since=session_scope_start),
                "query_distribution": self.repository.load_query_distribution(self.user_id, since=session_scope_start),
                "domain_distribution": self.repository.load_domain_distribution(self.user_id, since=session_scope_start),
                "domain_category_distribution": self.repository.load_domain_category_distribution(
                    self.user_id,
                    since=session_scope_start,
                ),
                "recent_browser_activity": self.repository.load_recent_browser_activity(
                    self.user_id,
                    since=session_scope_start,
                ),
                "user_comparison": self.repository.load_user_comparison(),
                "alert_clusters": self.repository.load_alert_clusters(self.user_id, since=session_scope_start),
                "risk_heatmap": self.repository.load_risk_heatmap(self.user_id, since=session_scope_start),
                "baseline_versions": self.repository.load_baseline_versions(self.user_id, since=session_scope_start),
                "demo_evaluation": self.repository.load_demo_evaluation(self.user_id),
                "recent_integrations": self.repository.load_recent_integration_exports(
                    self.user_id,
                    since=session_scope_start,
                ),
                "browser_companion": {
                    "active": self._browser_companion_active(
                        metrics.get("last_browser_event_at")
                    ),
                    "last_event_at": metrics.get("last_browser_event_at"),
                    "event_count": metrics.get("browser_event_count", 0),
                    "distinct_domains": metrics.get("distinct_domains", 0),
                },
                "honeypot": honeypot_status,
            },
            "current": self._serialize_current(profile),
            "history": history,
            "alerts": [
                {
                    "created_at": alert.created_at.isoformat(),
                    "id": alert.id,
                    "severity": alert.severity,
                    "risk_score": alert.risk_score,
                    "summary": alert.summary,
                    "explanation": alert.explanation,
                    "user_name": alert.user_name,
                    "feedback_label": alert.feedback_label,
                    "feedback_note": alert.feedback_note,
                    "recommended_actions": list(alert.recommended_actions),
                    "cluster_key": alert.cluster_key,
                }
                for alert in alerts
            ],
        }

    def report_payload(self, running: bool, last_error: str | None = None) -> dict[str, object]:
        snapshot = self.dashboard_snapshot(running, last_error)
        return {
            "generated_at": datetime.now().isoformat(),
            "user_name": self.user_name,
            "report_type": "behavioral_security_review",
            **snapshot,
        }

    def report_csv(self, running: bool, last_error: str | None = None) -> str:
        payload = self.report_payload(running, last_error)
        buffer = StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["section", "key", "value"])
        for key, value in payload["runtime"].items():
            writer.writerow(["runtime", key, value])
        for key, value in payload["stats"].items():
            writer.writerow(["stats", key, value])
        current = payload.get("current") or {}
        for key, value in current.items():
            if isinstance(value, (list, dict)):
                continue
            writer.writerow(["current", key, value])
        for alert in payload.get("alerts", []):
            writer.writerow(
                [
                    "alert",
                    alert.get("id"),
                    f"{alert.get('severity')} | {alert.get('risk_score')} | {alert.get('summary')}",
                ]
            )
        return buffer.getvalue()

    def _serialize_current(self, profile: object) -> dict[str, object] | None:
        if self.latest_outcome is None:
            return None

        outcome = self.latest_outcome
        detection = outcome.detection
        return {
            "observed_at": outcome.features.observed_at.isoformat(),
            "summary": detection.summary,
            "explanation": detection.explanation,
            "risk_score": detection.risk_score,
            "severity": detection.severity,
            "is_anomaly": detection.is_anomaly,
            "training_mode": detection.training_mode,
            "reasons": list(detection.reasons),
            "dominant_app": outcome.features.dominant_app,
            "apps_seen": list(outcome.features.apps_seen),
            "app_observations": [
                {
                    "app_name": observation.app_name,
                    "window_title": observation.window_title,
                    "tab_title": observation.tab_title,
                    "search_query": observation.search_query,
                    "url": observation.url,
                    "domain": observation.domain,
                    "source": observation.source,
                }
                for observation in outcome.features.app_observations
            ],
            "process_observations": [
                {
                    "observed_at": observation.observed_at.isoformat(),
                    "process_name": observation.process_name,
                    "pid": observation.pid,
                    "parent_name": observation.parent_name,
                    "parent_pid": observation.parent_pid,
                    "ancestry": list(observation.ancestry),
                    "exe_path": observation.exe_path,
                    "window_title": observation.window_title,
                    "source": observation.source,
                }
                for observation in outcome.features.process_observations
            ],
            "search_queries": [
                observation.search_query
                for observation in outcome.features.app_observations
                if observation.search_query
            ],
            "browser_tabs": [
                observation.tab_title
                for observation in outcome.features.app_observations
                if observation.tab_title
            ],
            "urls": [
                observation.url
                for observation in outcome.features.app_observations
                if observation.url
            ],
            "domains": [
                observation.domain
                for observation in outcome.features.app_observations
                if observation.domain
            ],
            "collector_notes": list(outcome.collector_notes),
            "confidence_score": detection.confidence_score,
            "intent_matches": list(detection.intent_matches),
            "recommended_actions": list(detection.recommended_actions),
            "risk_factors": list(detection.risk_factors),
            "watchlist_hits": list(detection.watchlist_hits),
            "honeypot_hits": list(outcome.features.honeypot_hits),
            "fingerprint_similarity": outcome.fingerprint_similarity,
            "behavior_drift": outcome.behavior_drift,
            "context_labels": list(outcome.context_labels),
            "domain_categories": list(outcome.domain_categories),
            "timeline": list(outcome.timeline),
            "replay_summary": outcome.replay_summary,
            "scenario_name": outcome.scenario_name,
            "expected_anomaly": outcome.expected_anomaly,
            "effective_threshold": outcome.effective_threshold,
            "model_used": detection.model_used,
            "model_flagged": detection.model_flagged,
            "model_score": detection.model_score,
            "deviations": [
                {
                    "feature_name": deviation.feature_name,
                    "current_value": deviation.current_value,
                    "baseline_value": deviation.baseline_value,
                    "score": deviation.score,
                    "severity": deviation.severity,
                    "reason": deviation.reason,
                    "confidence": deviation.confidence,
                }
                for deviation in detection.deviations
            ],
            "features": [
                {
                    "name": "typing_speed",
                    "label": "Typing speed",
                    "current": round(outcome.features.typing_speed, 3),
                    "baseline": self._baseline_value(profile, "typing_speed"),
                },
                {
                    "name": "typing_gap_variance",
                    "label": "Typing rhythm variance",
                    "current": round(outcome.features.typing_gap_variance, 5),
                    "baseline": self._baseline_value(profile, "typing_gap_variance"),
                },
                {
                    "name": "mouse_speed",
                    "label": "Mouse speed",
                    "current": round(outcome.features.mouse_speed, 3),
                    "baseline": self._baseline_value(profile, "mouse_speed"),
                },
                {
                    "name": "app_switch_count",
                    "label": "App switch count",
                    "current": outcome.features.app_switch_count,
                    "baseline": self._baseline_value(profile, "app_switch_count"),
                },
                {
                    "name": "unique_app_count",
                    "label": "Unique app count",
                    "current": outcome.features.unique_app_count,
                    "baseline": self._baseline_value(profile, "unique_app_count"),
                },
                {
                    "name": "login_hour",
                    "label": "Login hour",
                    "current": round(outcome.features.login_hour, 2),
                    "baseline": self._baseline_value(profile, "login_hour"),
                },
                {
                    "name": "session_duration_minutes",
                    "label": "Session duration (min)",
                    "current": round(outcome.features.session_duration_minutes, 2),
                    "baseline": self._baseline_value(profile, "session_duration_minutes"),
                },
                {
                    "name": "activity_intensity",
                    "label": "Activity intensity",
                    "current": round(outcome.features.activity_intensity, 3),
                    "baseline": self._baseline_value(profile, "activity_intensity"),
                },
            ],
        }

    @staticmethod
    def _baseline_value(profile: object, field_name: str) -> float | None:
        baseline = getattr(profile, "baselines", {}).get(field_name)
        if baseline is None:
            return None
        return round(baseline.mean, 3)

    def _sanitize_browser_event(self, event: object) -> object:
        if self.privacy_mode == "high_detail":
            return event

        if self.privacy_mode == "browser_aware":
            event.url = ""
            return event

        event.tab_title = "redacted"
        event.url = ""
        event.domain = ""
        event.search_query = None
        return event

    def _apply_privacy_to_features(self, features: BehaviorFeatures) -> BehaviorFeatures:
        if self.privacy_mode == "high_detail":
            return features

        sanitized_observations = []
        for observation in features.app_observations:
            sanitized = {
                "app_name": observation.app_name,
                "window_title": observation.window_title,
                "tab_title": observation.tab_title,
                "search_query": observation.search_query,
                "url": observation.url,
                "domain": observation.domain,
                "source": observation.source,
            }
            if self.privacy_mode == "browser_aware":
                sanitized["url"] = None
            elif observation.app_name in {"chrome.exe", "brave.exe", "msedge.exe", "firefox.exe"}:
                sanitized["tab_title"] = None
                sanitized["search_query"] = None
                sanitized["url"] = None
                sanitized["domain"] = None
            sanitized_observations.append(AppObservation(**sanitized))

        features.app_observations = sanitized_observations
        for observation in features.process_observations:
            if self.privacy_mode != "high_detail":
                observation.exe_path = None
            if self.privacy_mode == "basic":
                observation.window_title = None
        return features

    def _browser_companion_active(self, last_event_at: object) -> bool:
        if not isinstance(last_event_at, str) or not last_event_at:
            return False
        try:
            observed_at = datetime.fromisoformat(last_event_at)
        except ValueError:
            return False
        return (
            datetime.now() - observed_at
        ).total_seconds() <= self.config.browser_companion_stale_seconds
