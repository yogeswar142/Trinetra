"""
backend/trinetra/ml/evaluation.py

Evaluation Metrics and Verification Suite for Trinetra ML Detectors:
1. Per-Class Precision, Recall, and F1 with 95% Bootstrap Confidence Intervals (1,000 resamples).
2. Probability Calibration Evaluation:
   - Reliability Curve (fraction of positives vs. mean predicted confidence across bins)
   - Expected Calibration Error (ECE)
   - Brier Score
3. Incident-Level Operational Metrics:
   - Incident-level alert clustering (60s sliding incident window)
   - False Alert Rate per hour (FAR/hour) across benign replay duration
   - Time-to-Detect (TTD) from attack inception
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Optional, Sequence, Tuple
import numpy as np


@dataclass(slots=True)
class MetricCI:
    point_estimate: float
    ci_lower: float
    ci_upper: float


@dataclass(slots=True)
class ClassificationReport:
    sample_count: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: MetricCI
    recall: MetricCI
    f1: MetricCI


@dataclass(slots=True)
class CalibrationBin:
    bin_index: int
    bin_lower: float
    bin_upper: float
    sample_count: int
    mean_confidence: float
    observed_positive_rate: float


@dataclass(slots=True)
class CalibrationReport:
    brier_score: float
    expected_calibration_error: float
    bins: list[CalibrationBin]


@dataclass(slots=True)
class IncidentEvaluation:
    total_alerts: int
    deduplicated_incidents: int
    false_incidents: int
    duration_hours: float
    far_per_hour: float
    time_to_detect_seconds: Optional[float]


def compute_classification_metrics(
    y_true: Sequence[int],
    y_pred: Sequence[int],
    groups: Optional[Sequence[Any]] = None,
    n_bootstraps: int = 1000,
    random_seed: int = 42,
) -> ClassificationReport:
    """
    Computes Precision, Recall, F1 and their 95% bootstrap confidence intervals.
    When groups are provided (e.g. /24 subnet or scenario run), resamples by group/cluster
    to preserve intra-group correlation and prevent optimistic confidence intervals.
    """
    y_t = np.asarray(y_true, dtype=np.int32)
    y_p = np.asarray(y_pred, dtype=np.int32)

    if len(y_t) != len(y_p):
        raise ValueError("Length of y_true and y_pred must match")
    n = len(y_t)
    if n == 0:
        raise ValueError("Cannot evaluate empty predictions")

    tp = int(np.sum((y_t == 1) & (y_p == 1)))
    fp = int(np.sum((y_t == 0) & (y_p == 1)))
    tn = int(np.sum((y_t == 0) & (y_p == 0)))
    fn = int(np.sum((y_t == 1) & (y_p == 0)))

    prec_point = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    rec_point = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1_point = (2 * prec_point * rec_point / (prec_point + rec_point)) if (prec_point + rec_point) > 0 else 0.0

    # Percentile bootstrap (resample by group if provided, else row)
    rng = np.random.default_rng(random_seed)
    boot_prec: list[float] = []
    boot_rec: list[float] = []
    boot_f1: list[float] = []

    if groups is not None:
        if len(groups) != n:
            raise ValueError("Length of groups must match y_true")
        groups_arr = np.asarray(groups)
        unique_groups = np.unique(groups_arr)
        group_to_indices = {g: np.where(groups_arr == g)[0] for g in unique_groups}
        n_g = len(unique_groups)

    for _ in range(n_bootstraps):
        if groups is not None:
            sampled_g = rng.choice(unique_groups, size=n_g, replace=True)
            idx = np.concatenate([group_to_indices[g] for g in sampled_g])
        else:
            idx = rng.integers(0, n, size=n)

        b_yt = y_t[idx]
        b_yp = y_p[idx]

        b_tp = np.sum((b_yt == 1) & (b_yp == 1))
        b_fp = np.sum((b_yt == 0) & (b_yp == 1))
        b_fn = np.sum((b_yt == 1) & (b_yp == 0))

        bp = (b_tp / (b_tp + b_fp)) if (b_tp + b_fp) > 0 else 0.0
        br = (b_tp / (b_tp + b_fn)) if (b_tp + b_fn) > 0 else 0.0
        bf = (2 * bp * br / (bp + br)) if (bp + br) > 0 else 0.0

        boot_prec.append(bp)
        boot_rec.append(br)
        boot_f1.append(bf)

    p_low, p_high = float(np.percentile(boot_prec, 2.5)), float(np.percentile(boot_prec, 97.5))
    r_low, r_high = float(np.percentile(boot_rec, 2.5)), float(np.percentile(boot_rec, 97.5))
    f_low, f_high = float(np.percentile(boot_f1, 2.5)), float(np.percentile(boot_f1, 97.5))

    return ClassificationReport(
        sample_count=n,
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        precision=MetricCI(round(prec_point, 4), round(p_low, 4), round(p_high, 4)),
        recall=MetricCI(round(rec_point, 4), round(r_low, 4), round(r_high, 4)),
        f1=MetricCI(round(f1_point, 4), round(f_low, 4), round(f_high, 4)),
    )


def compute_calibration_curve(
    y_true: Sequence[int],
    y_prob: Sequence[float],
    n_bins: int = 10,
) -> CalibrationReport:
    """
    Computes reliability curve points, Expected Calibration Error (ECE), and Brier Score.
    """
    y_t = np.asarray(y_true, dtype=np.float64)
    y_p = np.asarray(y_prob, dtype=np.float64)

    if len(y_t) != len(y_p):
        raise ValueError("Length of y_true and y_prob must match")
    n = len(y_t)
    if n == 0:
        raise ValueError("Cannot evaluate empty predictions")

    # Brier score
    brier = float(np.mean((y_p - y_t) ** 2))

    bin_edges = np.linspace(0.0, 1.0, n_bins + 1)
    bins_out: list[CalibrationBin] = []
    ece = 0.0

    for i in range(n_bins):
        low, high = bin_edges[i], bin_edges[i + 1]
        if i == n_bins - 1:
            mask = (y_p >= low) & (y_p <= high)
        else:
            mask = (y_p >= low) & (y_p < high)

        count = int(np.sum(mask))
        if count > 0:
            mean_conf = float(np.mean(y_p[mask]))
            pos_rate = float(np.mean(y_t[mask]))
            ece += (count / n) * abs(pos_rate - mean_conf)
        else:
            mean_conf = float((low + high) / 2.0)
            pos_rate = 0.0

        bins_out.append(
            CalibrationBin(
                bin_index=i,
                bin_lower=round(low, 2),
                bin_upper=round(high, 2),
                sample_count=count,
                mean_confidence=round(mean_conf, 4),
                observed_positive_rate=round(pos_rate, 4),
            )
        )

    return CalibrationReport(
        brier_score=round(brier, 4),
        expected_calibration_error=round(ece, 4),
        bins=bins_out,
    )


def cluster_alerts_into_incidents(
    alert_events: Sequence[Tuple[float, str, bool]],  # (ts, entity_id, is_attack)
    incident_window_seconds: float = 60.0,
) -> List[Tuple[float, str, bool, int]]:
    """
    Clusters consecutive alerts for the same entity within incident_window_seconds into a single incident.
    Returns: list of (first_ts, entity_id, is_attack, alert_count)
    """
    sorted_alerts = sorted(alert_events, key=lambda x: x[0])
    incidents: list[Tuple[float, str, bool, int]] = []
    active_incidents: dict[str, list[Any]] = {}  # entity -> [first_ts, last_ts, is_attack, count]

    for ts, entity, is_attack in sorted_alerts:
        if entity in active_incidents:
            first_ts, last_ts, was_attack, count = active_incidents[entity]
            if ts - last_ts <= incident_window_seconds:
                # Merge into existing incident
                active_incidents[entity] = [first_ts, ts, was_attack or is_attack, count + 1]
                continue
            else:
                # Close previous incident
                incidents.append((first_ts, entity, was_attack, count))

        # Start new incident
        active_incidents[entity] = [ts, ts, is_attack, 1]

    for entity, (first_ts, last_ts, was_attack, count) in active_incidents.items():
        incidents.append((first_ts, entity, was_attack, count))

    return incidents


def evaluate_incident_operational_metrics(
    alert_events: Sequence[Tuple[float, str, bool]],
    attack_start_ts: Optional[float],
    duration_hours: float,
    incident_window_seconds: float = 60.0,
) -> IncidentEvaluation:
    """
    Evaluates incident-level deduplication, FAR/hour, and time-to-detect.
    """
    incidents = cluster_alerts_into_incidents(alert_events, incident_window_seconds)
    false_incidents = sum(1 for inc in incidents if not inc[2])
    true_incidents = [inc for inc in incidents if inc[2]]

    far = (false_incidents / duration_hours) if duration_hours > 0 else 0.0

    ttd: Optional[float] = None
    if true_incidents and attack_start_ts is not None:
        first_attack_incident_ts = min(inc[0] for inc in true_incidents)
        ttd = max(0.0, first_attack_incident_ts - attack_start_ts)

    return IncidentEvaluation(
        total_alerts=len(alert_events),
        deduplicated_incidents=len(incidents),
        false_incidents=false_incidents,
        duration_hours=round(duration_hours, 2),
        far_per_hour=round(far, 4),
        time_to_detect_seconds=round(ttd, 3) if ttd is not None else None,
    )
