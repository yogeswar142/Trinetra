"""
tests/test_evaluation.py

Unit tests for evaluation report generator:
1. Precision, Recall, and F1 with 95% bootstrap confidence intervals.
2. Probability calibration: Reliability curve, Expected Calibration Error (ECE), and Brier Score.
3. Incident-level alert clustering, false alert rate (FAR/hour), and Time-to-Detect (TTD).
"""
from __future__ import annotations

import pytest
from trinetra.ml.evaluation import (
    compute_calibration_curve,
    compute_classification_metrics,
    evaluate_incident_operational_metrics,
)


class TestClassificationMetricsAndBootstrapCI:
    def test_perfect_classification(self) -> None:
        y_true = [1] * 50 + [0] * 50
        y_pred = [1] * 50 + [0] * 50

        rep = compute_classification_metrics(y_true, y_pred, n_bootstraps=200, random_seed=42)
        assert rep.sample_count == 100
        assert rep.true_positives == 50
        assert rep.false_positives == 0
        assert rep.precision.point_estimate == 1.0
        assert rep.recall.point_estimate == 1.0
        assert rep.f1.point_estimate == 1.0
        assert rep.precision.ci_lower == 1.0
        assert rep.precision.ci_upper == 1.0

    def test_imperfect_classification_bootstrap_bounds(self) -> None:
        y_true = [1] * 40 + [0] * 60
        # 30 TP, 10 FN, 10 FP, 50 TN
        y_pred = [1] * 30 + [0] * 10 + [1] * 10 + [0] * 50

        rep = compute_classification_metrics(y_true, y_pred, n_bootstraps=500, random_seed=42)
        assert rep.true_positives == 30
        assert rep.false_positives == 10
        assert rep.false_negatives == 10

        # Point estimates
        assert rep.precision.point_estimate == pytest.approx(0.75, abs=0.01)
        assert rep.recall.point_estimate == pytest.approx(0.75, abs=0.01)
        assert rep.f1.point_estimate == pytest.approx(0.75, abs=0.01)

        # Bootstrap CI bounds must contain the point estimate
        assert rep.precision.ci_lower <= rep.precision.point_estimate <= rep.precision.ci_upper
        assert rep.recall.ci_lower <= rep.recall.point_estimate <= rep.recall.ci_upper
        assert rep.f1.ci_lower <= rep.f1.point_estimate <= rep.f1.ci_upper

    def test_group_cluster_bootstrap_ci(self) -> None:
        y_true = [1] * 30 + [0] * 30
        y_pred = [1] * 25 + [0] * 5 + [1] * 5 + [0] * 25
        # 6 clusters of 10 samples each
        groups = ["g1"] * 10 + ["g2"] * 10 + ["g3"] * 10 + ["g4"] * 10 + ["g5"] * 10 + ["g6"] * 10

        rep = compute_classification_metrics(y_true, y_pred, groups=groups, n_bootstraps=300, random_seed=42)
        assert rep.precision.ci_lower <= rep.precision.point_estimate <= rep.precision.ci_upper
        assert rep.recall.ci_lower <= rep.recall.point_estimate <= rep.recall.ci_upper
        assert rep.f1.ci_lower <= rep.f1.point_estimate <= rep.f1.ci_upper


class TestCalibrationCurveAndReliability:
    def test_calibration_curve_with_synthetic_scores(self) -> None:
        y_true = [0, 0, 0, 0, 1, 0, 1, 1, 1, 1]
        y_prob = [0.1, 0.15, 0.2, 0.35, 0.45, 0.6, 0.7, 0.85, 0.9, 0.95]

        cal = compute_calibration_curve(y_true, y_prob, n_bins=5)
        assert cal.brier_score > 0.0
        assert 0.0 <= cal.expected_calibration_error <= 1.0
        assert len(cal.bins) == 5

        # Check that high confidence bins have higher observed positive rate
        low_bin = cal.bins[0]   # [0.0, 0.2]
        high_bin = cal.bins[-1] # [0.8, 1.0]
        assert high_bin.observed_positive_rate > low_bin.observed_positive_rate


class TestIncidentOperationalMetrics:
    def test_incident_clustering_and_far(self) -> None:
        # 10 raw alerts firing across 3 distinct incidents over 2 hours
        alerts = [
            # Incident 1 (Benign False Alarm on host A): 3 alerts at t=10, t=20, t=35
            (10.0, "host_a", False),
            (20.0, "host_a", False),
            (35.0, "host_a", False),
            # Incident 2 (Attack on host B): 4 alerts at t=100, t=110, t=125, t=140
            (100.0, "host_b", True),
            (110.0, "host_b", True),
            (125.0, "host_b", True),
            (140.0, "host_b", True),
            # Incident 3 (Benign False Alarm on host C): 2 alerts at t=300, t=315
            (300.0, "host_c", False),
            (315.0, "host_c", False),
        ]

        attack_start_time = 95.0
        eval_res = evaluate_incident_operational_metrics(
            alert_events=alerts,
            attack_start_ts=attack_start_time,
            duration_hours=2.0,
            incident_window_seconds=60.0,
        )

        assert eval_res.total_alerts == 9
        assert eval_res.deduplicated_incidents == 3
        assert eval_res.false_incidents == 2  # host_a and host_c
        assert eval_res.far_per_hour == pytest.approx(1.0, abs=0.01)  # 2 false incidents / 2.0 hours
        assert eval_res.time_to_detect_seconds == pytest.approx(5.0, abs=0.1)  # 100.0 - 95.0 = 5.0s
