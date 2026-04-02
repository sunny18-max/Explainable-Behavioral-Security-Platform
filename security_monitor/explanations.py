from __future__ import annotations

from .models import BehaviorFeatures, BehaviorProfile, DetectionSignal


class ExplanationEngine:
    def enrich(
        self,
        features: BehaviorFeatures,
        profile: BehaviorProfile,
        detection: DetectionSignal,
    ) -> DetectionSignal:
        if detection.training_mode:
            return detection

        top_reasons = [deviation.reason for deviation in detection.deviations[:4]]
        if not top_reasons:
            top_reasons = [
                "No strong anomalies were found compared with the learned baseline."
            ]

        if detection.is_anomaly:
            summary = (
                f"Suspicious activity detected with risk score {detection.risk_score:.1f} "
                f"and confidence {detection.confidence_score:.1f}% across "
                f"{len(detection.deviations)} contributing signal(s)."
            )
        else:
            summary = (
                f"Behavior looks normal with risk score {detection.risk_score:.1f} "
                f"and confidence {detection.confidence_score:.1f}%. "
                "No dominant anomaly pattern was confirmed."
            )

        baseline_hint = (
            f"Baseline learned from {profile.sample_count} sample(s). "
            f"Dominant current application: {features.dominant_app}. "
            f"Observed apps in this window: {', '.join(features.apps_seen) or 'idle'}."
        )
        intent_hint = ""
        if detection.intent_matches:
            intent_hint = " Intent signals: " + " | ".join(detection.intent_matches[:3]) + "."
        model_hint = ""
        if detection.model_used:
            verdict = "flagged" if detection.model_flagged else "accepted"
            model_hint = (
                f" Isolation Forest {verdict} this window"
                f" with score {detection.model_score:.2f}."
            )
        action_hint = ""
        if detection.recommended_actions:
            action_hint = " Recommended actions: " + " | ".join(
                detection.recommended_actions[:3]
            ) + "."

        explanation = " ".join(
            [summary, *top_reasons, baseline_hint + intent_hint + model_hint + action_hint]
        ).strip()
        detection.summary = summary
        detection.reasons = top_reasons
        detection.explanation = explanation
        return detection
