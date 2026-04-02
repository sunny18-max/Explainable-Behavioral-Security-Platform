from __future__ import annotations

import statistics
from dataclasses import dataclass

from .models import BehaviorFeatures, BehaviorProfile, NumericBaseline


@dataclass(slots=True)
class Percentiles:
    first_quartile: float
    third_quartile: float


class BehaviorProfiler:
    numeric_fields = (
        "typing_speed",
        "typing_gap_variance",
        "mouse_speed",
        "app_switch_count",
        "unique_app_count",
        "login_hour",
        "session_duration_minutes",
        "activity_intensity",
    )

    def build(self, samples: list[BehaviorFeatures]) -> BehaviorProfile:
        if not samples:
            return BehaviorProfile(
                sample_count=0,
                baselines={},
                known_apps=set(),
                primary_apps=set(),
            )

        baselines = {
            field_name: self._describe([float(getattr(sample, field_name)) for sample in samples])
            for field_name in self.numeric_fields
        }
        known_apps = {
            app_name
            for sample in samples
            for app_name in sample.apps_seen
            if app_name and app_name != "idle"
        }
        primary_apps = {
            sample.dominant_app
            for sample in samples
            if sample.dominant_app and sample.dominant_app != "idle"
        }
        return BehaviorProfile(
            sample_count=len(samples),
            baselines=baselines,
            known_apps=known_apps,
            primary_apps=primary_apps,
        )

    def _describe(self, values: list[float]) -> NumericBaseline:
        if len(values) == 1:
            value = values[0]
            margin = max(abs(value) * 0.25, 0.5)
            return NumericBaseline(
                mean=value,
                median=value,
                stdev=margin,
                lower_bound=max(0.0, value - margin),
                upper_bound=value + margin,
            )

        ordered = sorted(values)
        percentiles = self._quartiles(ordered)
        interquartile_range = max(percentiles.third_quartile - percentiles.first_quartile, 0.0)
        mean = statistics.fmean(ordered)
        median = statistics.median(ordered)
        stdev = max(statistics.pstdev(ordered), abs(mean) * 0.1, 0.15)
        if interquartile_range == 0.0:
            lower_bound = max(0.0, mean - (2.0 * stdev))
            upper_bound = mean + (2.0 * stdev)
        else:
            lower_bound = max(0.0, percentiles.first_quartile - 1.5 * interquartile_range)
            upper_bound = percentiles.third_quartile + 1.5 * interquartile_range

        return NumericBaseline(
            mean=mean,
            median=median,
            stdev=stdev,
            lower_bound=lower_bound,
            upper_bound=upper_bound,
        )

    @staticmethod
    def _quartiles(values: list[float]) -> Percentiles:
        midpoint = len(values) // 2
        if len(values) % 2 == 0:
            lower_half = values[:midpoint]
            upper_half = values[midpoint:]
        else:
            lower_half = values[:midpoint]
            upper_half = values[midpoint + 1 :]

        if not lower_half:
            lower_half = values
        if not upper_half:
            upper_half = values

        return Percentiles(
            first_quartile=statistics.median(lower_half),
            third_quartile=statistics.median(upper_half),
        )
