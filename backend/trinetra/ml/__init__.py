"""
backend/trinetra/ml

Trinetra Machine Learning infrastructure package:
- group_split: Strict spatial / subnet group splitting and anti-leakage guards
- evaluation: Classification metrics, bootstrap CIs, calibration curves, and incident FAR
- artifact_loader: Cryptographically signed model manifest and pre-load integrity verification
"""
from trinetra.ml.artifact_loader import safe_load_artifact
from trinetra.ml.evaluation import (
    compute_calibration_curve,
    compute_classification_metrics,
    evaluate_incident_operational_metrics,
)
from trinetra.ml.group_split import StrictGroupSplitter, validate_no_feature_leakage

__all__ = [
    "StrictGroupSplitter",
    "validate_no_feature_leakage",
    "compute_classification_metrics",
    "compute_calibration_curve",
    "evaluate_incident_operational_metrics",
    "safe_load_artifact",
]
