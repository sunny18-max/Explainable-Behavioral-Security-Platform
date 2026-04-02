from __future__ import annotations

from dataclasses import dataclass

from .config import MonitorConfig
from .intelligence import AdvancedBehaviorSignals
from .models import BehaviorFeatures, BehaviorProfile, DetectionSignal, FeatureDeviation

try:
    from sklearn.ensemble import IsolationForest
except ImportError:  # pragma: no cover - optional dependency
    IsolationForest = None


@dataclass(slots=True)
class NumericFeatureRule:
    weight: float


class HybridAnomalyDetector:
    feature_rules = {
        "typing_speed": NumericFeatureRule(weight=1.2),
        "typing_gap_variance": NumericFeatureRule(weight=0.9),
        "mouse_speed": NumericFeatureRule(weight=0.7),
        "app_switch_count": NumericFeatureRule(weight=0.8),
        "unique_app_count": NumericFeatureRule(weight=0.7),
        "login_hour": NumericFeatureRule(weight=1.3),
        "session_duration_minutes": NumericFeatureRule(weight=0.5),
        "activity_intensity": NumericFeatureRule(weight=1.0),
    }

    def __init__(self, config: MonitorConfig) -> None:
        self.config = config

    def evaluate(
        self,
        features: BehaviorFeatures,
        profile: BehaviorProfile,
        history: list[BehaviorFeatures],
        advanced_signals: AdvancedBehaviorSignals | None = None,
        threshold_offset: float = 0.0,
    ) -> DetectionSignal:
        advanced_signals = advanced_signals or AdvancedBehaviorSignals()
        if profile.sample_count < self.config.training_sample_target:
            remaining = self.config.training_sample_target - profile.sample_count
            return DetectionSignal(
                risk_score=0.0,
                is_anomaly=False,
                severity="training",
                deviations=[],
                model_used=False,
                model_flagged=False,
                model_score=0.0,
                summary=f"Training baseline: {remaining} more sample(s) needed.",
                explanation=(
                    "The system is still learning the user's normal behavior. "
                    "Suspicion scoring begins once the baseline has enough samples."
                ),
                reasons=[
                    f"Baseline building in progress with {profile.sample_count} sample(s)."
                ],
                confidence_score=0.0,
                intent_matches=list(advanced_signals.intent_matches),
                training_mode=True,
            )

        deviations: list[FeatureDeviation] = []
        total_score = 0.0
        for feature_name, rule in self.feature_rules.items():
            baseline = profile.baselines.get(feature_name)
            if baseline is None:
                continue
            current_value = float(getattr(features, feature_name))
            deviation = self._score_numeric(
                feature_name,
                current_value,
                baseline.mean,
                baseline.stdev,
            )
            if deviation is None:
                continue
            deviation.score *= rule.weight
            deviation.confidence = self._confidence_from_score(deviation.score, deviation.severity)
            deviations.append(deviation)
            total_score += deviation.score

        unknown_apps = [
            app_name
            for app_name in features.apps_seen
            if app_name not in profile.known_apps and app_name != "idle"
        ]
        if unknown_apps:
            novelty_score = min(28.0, 15.0 + 5.0 * len(unknown_apps))
            deviations.append(
                FeatureDeviation(
                    feature_name="applications",
                    current_value=", ".join(unknown_apps),
                    baseline_value=", ".join(sorted(profile.known_apps)) or "known baseline",
                    score=novelty_score,
                    severity="high" if len(unknown_apps) > 1 else "medium",
                    reason="Previously unseen application/window observed: " + ", ".join(unknown_apps),
                    confidence=0.72 if len(unknown_apps) == 1 else 0.87,
                )
            )
            total_score += novelty_score

        suspicious_queries = [
            observation.search_query
            for observation in features.app_observations
            if observation.search_query
            and any(
                term in observation.search_query.lower()
                for term in self.config.suspicious_query_terms
            )
        ]
        if suspicious_queries:
            distinct_queries = sorted(set(suspicious_queries))
            query_score = min(24.0, 12.0 + 6.0 * len(distinct_queries))
            deviations.append(
                FeatureDeviation(
                    feature_name="browser_queries",
                    current_value=", ".join(distinct_queries),
                    baseline_value="safe browsing activity",
                    score=query_score,
                    severity="high" if len(distinct_queries) > 1 else "medium",
                    reason=(
                        "Visible browser searches include sensitive or attack-related terms: "
                        + ", ".join(distinct_queries)
                    ),
                    confidence=0.81 if len(distinct_queries) == 1 else 0.9,
                )
            )
            total_score += query_score

        self._apply_context_adjustments(deviations, advanced_signals.context_labels)
        total_score = sum(deviation.score for deviation in deviations)

        if self._should_flag_time_warp(advanced_signals.time_warp_typing_ratio):
            ratio = advanced_signals.time_warp_typing_ratio or 0.0
            score = 12.0 if ratio < 2.8 else 18.0
            deviations.append(
                FeatureDeviation(
                    feature_name="time_warp_typing",
                    current_value=f"{ratio:.2f}x",
                    baseline_value="recent typing rhythm",
                    score=score,
                    severity="medium" if score < 16.0 else "high",
                    reason=(
                        "Typing speed changed too abruptly relative to the recent baseline, "
                        f"spiking by {ratio:.2f}x."
                    ),
                    confidence=min(0.95, 0.55 + ratio / 4.0),
                )
            )
            total_score += score

        if self._should_flag_time_warp(advanced_signals.time_warp_mouse_ratio):
            ratio = advanced_signals.time_warp_mouse_ratio or 0.0
            score = 8.0 if ratio < 2.8 else 14.0
            deviations.append(
                FeatureDeviation(
                    feature_name="time_warp_mouse",
                    current_value=f"{ratio:.2f}x",
                    baseline_value="recent mouse rhythm",
                    score=score,
                    severity="low" if score < 10.0 else "medium",
                    reason=(
                        "Mouse movement speed shifted too quickly compared with the recent "
                        f"interaction pattern, jumping by {ratio:.2f}x."
                    ),
                    confidence=min(0.9, 0.45 + ratio / 4.5),
                )
            )
            total_score += score

        fingerprint_similarity = advanced_signals.fingerprint_similarity
        if fingerprint_similarity is not None and fingerprint_similarity < 78.0:
            score = 12.0 if fingerprint_similarity >= 65.0 else 22.0
            deviations.append(
                FeatureDeviation(
                    feature_name="behavior_fingerprint",
                    current_value=f"{fingerprint_similarity:.1f}%",
                    baseline_value="user identity fingerprint",
                    score=score,
                    severity="medium" if score < 18.0 else "high",
                    reason=(
                        "The current behavior fingerprint is drifting away from the stored "
                        f"user identity profile with only {fingerprint_similarity:.1f}% similarity."
                    ),
                    confidence=0.68 if score < 18.0 else 0.88,
                )
            )
            total_score += score

        if advanced_signals.intent_matches:
            intent_score = min(24.0, 10.0 + 6.0 * len(advanced_signals.intent_matches))
            deviations.append(
                FeatureDeviation(
                    feature_name="intent_detection",
                    current_value=", ".join(advanced_signals.intent_matches),
                    baseline_value="routine user workflow",
                    score=intent_score,
                    severity="high" if len(advanced_signals.intent_matches) > 1 else "medium",
                    reason=advanced_signals.intent_matches[0],
                    confidence=0.8 if len(advanced_signals.intent_matches) == 1 else 0.92,
                )
            )
            total_score += intent_score

        if advanced_signals.process_alerts:
            process_score = min(28.0, 10.0 + 5.0 * len(advanced_signals.process_alerts))
            deviations.append(
                FeatureDeviation(
                    feature_name="process_lineage",
                    current_value=", ".join(advanced_signals.process_alerts[:2]),
                    baseline_value="routine parent-child execution",
                    score=process_score,
                    severity="high" if len(advanced_signals.process_alerts) > 1 else "medium",
                    reason=advanced_signals.process_alerts[0],
                    confidence=0.82 if len(advanced_signals.process_alerts) == 1 else 0.93,
                )
            )
            total_score += process_score

        if advanced_signals.honeypot_hits:
            honeypot_score = min(36.0, 24.0 + 6.0 * len(advanced_signals.honeypot_hits))
            deviations.append(
                FeatureDeviation(
                    feature_name="honeypot_access",
                    current_value=", ".join(advanced_signals.honeypot_hits[:2]),
                    baseline_value="no deception-layer interaction",
                    score=honeypot_score,
                    severity="high",
                    reason=advanced_signals.honeypot_hits[0],
                    confidence=0.97,
                )
            )
            total_score += honeypot_score

        if advanced_signals.watchlist_hits:
            watchlist_score = min(26.0, 10.0 + 4.0 * len(advanced_signals.watchlist_hits))
            deviations.append(
                FeatureDeviation(
                    feature_name="watchlists",
                    current_value=", ".join(advanced_signals.watchlist_hits[:3]),
                    baseline_value="no watchlist matches",
                    score=watchlist_score,
                    severity="high" if len(advanced_signals.watchlist_hits) > 1 else "medium",
                    reason=advanced_signals.watchlist_hits[0],
                    confidence=0.84 if len(advanced_signals.watchlist_hits) == 1 else 0.93,
                )
            )
            total_score += watchlist_score

        model_used, model_flagged, model_score = self._run_isolation_forest(features, history)
        if model_flagged:
            model_bonus = min(20.0, 10.0 + model_score * 15.0)
            deviations.append(
                FeatureDeviation(
                    feature_name="multivariate_pattern",
                    current_value=f"{model_score:.2f}",
                    baseline_value="learned behavior model",
                    score=model_bonus,
                    severity="medium" if model_bonus < 16.0 else "high",
                    reason="The combined behavior pattern does not fit the learned user profile.",
                    confidence=min(0.94, 0.5 + model_score / 2.0),
                )
            )
            total_score += model_bonus

        risk_score = min(100.0, round(total_score, 1))
        effective_threshold = max(35.0, self.config.anomaly_threshold + threshold_offset)
        medium_threshold = max(18.0, self.config.medium_risk_threshold + (threshold_offset / 2.0))
        high_deviation_count = len(
            [deviation for deviation in deviations if deviation.severity == "high"]
        )
        is_anomaly = (
            risk_score >= effective_threshold
            or (model_flagged and risk_score >= medium_threshold)
            or high_deviation_count >= 2
        )
        severity = self._severity_from_score(risk_score, is_anomaly)
        confidence_score = self._overall_confidence(deviations, model_flagged)
        ordered_deviations = sorted(deviations, key=lambda item: item.score, reverse=True)
        risk_factors = self._risk_factor_breakdown(ordered_deviations)
        recommended_actions = self._recommended_actions(
            features,
            ordered_deviations,
            advanced_signals,
            severity,
            risk_score,
        )
        cluster_key = self._cluster_key(ordered_deviations, advanced_signals)

        return DetectionSignal(
            risk_score=risk_score,
            is_anomaly=is_anomaly,
            severity=severity,
            deviations=ordered_deviations,
            model_used=model_used,
            model_flagged=model_flagged,
            model_score=model_score,
            confidence_score=confidence_score,
            intent_matches=list(advanced_signals.intent_matches),
            recommended_actions=recommended_actions,
            risk_factors=risk_factors,
            watchlist_hits=list(advanced_signals.watchlist_hits),
            cluster_key=cluster_key,
            effective_threshold=round(effective_threshold, 1),
        )

    def _score_numeric(
        self,
        feature_name: str,
        current_value: float,
        baseline_mean: float,
        baseline_stdev: float,
    ) -> FeatureDeviation | None:
        tolerance = max(baseline_stdev, abs(baseline_mean) * 0.2, 0.2)
        z_score = abs(current_value - baseline_mean) / tolerance
        if z_score < 1.75:
            return None

        if z_score >= 3.5:
            score = 24.0
            severity = "high"
        elif z_score >= 2.5:
            score = 16.0
            severity = "medium"
        else:
            score = 9.0
            severity = "low"

        return FeatureDeviation(
            feature_name=feature_name,
            current_value=current_value,
            baseline_value=baseline_mean,
            score=score,
            severity=severity,
            reason=self._reason_for_feature(feature_name, current_value, baseline_mean),
            confidence=min(0.94, 0.38 + z_score / 4.0),
        )

    def _run_isolation_forest(
        self,
        features: BehaviorFeatures,
        history: list[BehaviorFeatures],
    ) -> tuple[bool, bool, float]:
        if IsolationForest is None or len(history) < max(self.config.training_sample_target, 20):
            return False, False, 0.0

        model = IsolationForest(
            contamination=0.12,
            n_estimators=120,
            random_state=42,
        )
        history_vectors = [sample.to_vector() for sample in history]
        model.fit(history_vectors)
        prediction = int(model.predict([features.to_vector()])[0])
        score_sample = float(-model.score_samples([features.to_vector()])[0])
        return True, prediction == -1, score_sample

    @staticmethod
    def _reason_for_feature(feature_name: str, current_value: float, baseline_value: float) -> str:
        if feature_name == "typing_speed":
            direction = "faster" if current_value > baseline_value else "slower"
            ratio = current_value / max(baseline_value, 0.1)
            return f"Typing speed is {ratio:.1f}x {direction} than normal."
        if feature_name == "typing_gap_variance":
            return (
                f"Typing rhythm variance is {current_value:.3f} versus the normal "
                f"baseline around {baseline_value:.3f}."
            )
        if feature_name == "mouse_speed":
            direction = "higher" if current_value > baseline_value else "lower"
            return (
                f"Mouse movement speed is {direction} than normal "
                f"({current_value:.1f} vs {baseline_value:.1f})."
            )
        if feature_name == "app_switch_count":
            return (
                f"Application switching count is unusual "
                f"({current_value:.0f} vs baseline {baseline_value:.1f})."
            )
        if feature_name == "unique_app_count":
            return (
                f"Distinct application count is elevated "
                f"({current_value:.0f} vs baseline {baseline_value:.1f})."
            )
        if feature_name == "login_hour":
            return (
                f"Activity time {current_value:.2f}h differs from the usual "
                f"login window near {baseline_value:.2f}h."
            )
        if feature_name == "session_duration_minutes":
            return (
                f"Session duration differs from normal "
                f"({current_value:.1f} min vs {baseline_value:.1f} min)."
            )
        if feature_name == "activity_intensity":
            return (
                f"Overall activity intensity is outside the learned range "
                f"({current_value:.2f} vs {baseline_value:.2f})."
            )
        return f"{feature_name.replace('_', ' ').title()} deviates from the baseline."

    @staticmethod
    def _severity_from_score(risk_score: float, is_anomaly: bool) -> str:
        if not is_anomaly:
            return "normal" if risk_score < 20 else "watch"
        if risk_score >= 80:
            return "critical"
        if risk_score >= 60:
            return "high"
        return "medium"

    @staticmethod
    def _should_flag_time_warp(ratio: float | None) -> bool:
        if ratio is None:
            return False
        return ratio >= 2.2

    @staticmethod
    def _confidence_from_score(score: float, severity: str) -> float:
        base = {
            "low": 0.55,
            "medium": 0.72,
            "high": 0.87,
        }.get(severity, 0.5)
        return min(0.96, base + score / 80.0)

    def _apply_context_adjustments(
        self,
        deviations: list[FeatureDeviation],
        context_labels: list[str],
    ) -> None:
        context_set = set(context_labels)
        for deviation in deviations:
            if deviation.feature_name != "typing_speed":
                continue
            if "development" in context_set and "admin_shell" not in context_set:
                deviation.score = max(6.0, deviation.score * 0.8)
                deviation.reason += " Development tooling context lowers the suspicion slightly."
                deviation.confidence = max(0.45, deviation.confidence - 0.08)
            elif context_set & {"admin_shell", "login_surface", "remote_access"}:
                deviation.score = min(30.0, deviation.score * 1.2)
                deviation.reason += " The active context makes this speed change more suspicious."
                deviation.confidence = min(0.97, deviation.confidence + 0.08)

    @staticmethod
    def _overall_confidence(
        deviations: list[FeatureDeviation],
        model_flagged: bool,
    ) -> float:
        if not deviations and not model_flagged:
            return 12.0
        if not deviations:
            return 61.0

        weighted = sum(deviation.score * deviation.confidence for deviation in deviations)
        total = sum(deviation.score for deviation in deviations) or 1.0
        score = (weighted / total) * 100.0
        if model_flagged:
            score += 6.0
        return round(min(score, 99.0), 1)

    @staticmethod
    def _risk_factor_breakdown(
        deviations: list[FeatureDeviation],
    ) -> list[dict[str, float | str]]:
        total_score = sum(max(deviation.score, 0.0) for deviation in deviations) or 1.0
        return [
            {
                "label": deviation.feature_name.replace("_", " ").title(),
                "score": round(deviation.score, 1),
                "weight_pct": round((deviation.score / total_score) * 100.0, 1),
                "severity": deviation.severity,
            }
            for deviation in deviations[:6]
        ]

    def _recommended_actions(
        self,
        features: BehaviorFeatures,
        deviations: list[FeatureDeviation],
        advanced_signals: AdvancedBehaviorSignals,
        severity: str,
        risk_score: float,
    ) -> list[str]:
        actions: list[str] = []
        app_names = {app.lower() for app in features.apps_seen}
        if severity in {"critical", "high"}:
            actions.append("Validate the user identity and confirm the session is expected.")
        if any(app in {"powershell.exe", "cmd.exe", "pwsh.exe"} for app in app_names):
            actions.append("Inspect recent shell history and review process ancestry for command execution.")
        if advanced_signals.process_alerts:
            actions.append("Review the parent-child process chain and confirm whether shell or remote tools spawned the observed executable.")
        if advanced_signals.watchlist_hits:
            actions.append("Review watchlist hits and isolate the host if the same toolset repeats.")
        if advanced_signals.honeypot_hits:
            actions.append("Treat honeypot file interaction as high-confidence malicious or unauthorized curiosity and investigate immediately.")
        if any("login" in deviation.feature_name for deviation in deviations):
            actions.append("Verify whether the login time matches the user's approved working window.")
        if any("applications" == deviation.feature_name for deviation in deviations):
            actions.append("Check the unfamiliar executable against allowlists before permitting continued execution.")
        if any(observation.search_query for observation in features.app_observations):
            actions.append("Review the visible search queries and browser tabs for reconnaissance or credential-related activity.")
        if risk_score >= 85.0:
            actions.append("Escalate this incident for deeper host triage if the behavior persists across multiple windows.")
        return list(dict.fromkeys(actions))[:5]

    @staticmethod
    def _cluster_key(
        deviations: list[FeatureDeviation],
        advanced_signals: AdvancedBehaviorSignals,
    ) -> str:
        labels = [deviation.feature_name for deviation in deviations[:3]]
        if advanced_signals.watchlist_hits:
            labels.append("watchlist")
        if advanced_signals.intent_matches:
            labels.append("intent")
        if advanced_signals.process_alerts:
            labels.append("process")
        if advanced_signals.honeypot_hits:
            labels.append("honeypot")
        return "|".join(dict.fromkeys(labels)) or "general"
