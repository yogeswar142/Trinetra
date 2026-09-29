"""
backend/trinetra/detectors/exfil.py

Detector for Threat T-f: Data Exfiltration.
Covers: High-volume asymmetric egress, unauthorized bulk file uploads, and slow trickle exfiltration.

Evaluates flow session volume metrics and host-pair statistics, producing standardized
AlertRecords with interpretable EvidenceItems and calibrated confidence scores.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Optional, Tuple
import numpy as np

from trinetra.detectors.base import BaseDetector, IncidentDeduplicator
from trinetra.schemas import (
    AlertRecord,
    Direction,
    Endpoint,
    EvidenceItem,
    MitreAttackRef,
    Severity,
    ThreatClass,
)


@dataclass(slots=True)
class FlowExfilFeatures:
    """Statistical summary of session byte volume and directional asymmetry."""
    flow_id: str
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    egress_bytes: int
    ingress_bytes: int
    duration_seconds: float
    direction: Optional[Direction] = None

    @property
    def r_byte_ratio(self) -> float:
        """Ratio of egress bytes to ingress bytes (R_byte = Bytes_out / (Bytes_in + 1))."""
        return float(self.egress_bytes) / float(self.ingress_bytes + 1)

    @property
    def egress_rate_bps(self) -> float:
        """Egress transfer rate in bits per second."""
        if self.duration_seconds <= 0:
            return float(self.egress_bytes * 8)
        return float(self.egress_bytes * 8) / self.duration_seconds


class ExfiltrationDetector(BaseDetector):
    """
    Detector for Threat T-f (Data Exfiltration).
    Combines rule-based volumetric asymmetry heuristics with an ML classifier.
    """

    FEATURE_NAMES = [
        "r_byte_ratio",
        "egress_bytes",
        "ingress_bytes",
        "duration_seconds",
        "egress_rate_bps",
    ]

    def __init__(
        self,
        model: Optional[Any] = None,
        calibrator: Optional[Any] = None,
        confidence_threshold: float = 0.70,
        model_version: str = "trinetra-exfil-v2b",
        deduplicator: Optional[IncidentDeduplicator] = None,
        # Rule threshold defaults (configurable heuristics)
        r_byte_threshold: float = 3.0,
        min_egress_bytes: int = 50_000,
        trickle_duration_threshold: float = 120.0,
    ) -> None:
        super().__init__(
            detector_id="DETECTOR_T_F_EXFIL",
            threat_class=ThreatClass.DATA_EXFILTRATION,
            model_version=model_version,
            confidence_threshold=confidence_threshold,
            deduplicator=deduplicator,
        )
        self.model = model
        self.calibrator = calibrator
        self.r_byte_threshold = r_byte_threshold
        self.min_egress_bytes = min_egress_bytes
        self.trickle_duration_threshold = trickle_duration_threshold

    def extract_feature_vector(self, feat: FlowExfilFeatures) -> np.ndarray:
        """Extracts standard 5-dimensional feature vector for ML inference."""
        return np.array([
            feat.r_byte_ratio,
            float(feat.egress_bytes),
            float(feat.ingress_bytes),
            feat.duration_seconds,
            feat.egress_rate_bps,
        ], dtype=np.float64).reshape(1, -1)

    def rule_evaluate(self, feat: FlowExfilFeatures) -> tuple[float, list[EvidenceItem]]:
        """
        Rule-based baseline heuristic evaluation.
        Produces interpretable EvidenceItems for each threshold breach.
        """
        evidence: list[EvidenceItem] = []
        score = 0.0

        # Heuristic 1: High-volume asymmetric upload (bulk exfiltration)
        if feat.r_byte_ratio >= self.r_byte_threshold and feat.egress_bytes >= self.min_egress_bytes:
            score = max(score, 0.90)
            evidence.append(
                EvidenceItem(
                    feature="r_byte_ratio",
                    value=round(feat.r_byte_ratio, 2),
                    threshold=self.r_byte_threshold,
                    interpretation=f"Asymmetric egress ratio ({feat.r_byte_ratio:.1f}x) heavily favors outbound transfer",
                    source="rule",
                )
            )
            evidence.append(
                EvidenceItem(
                    feature="egress_bytes",
                    value=feat.egress_bytes,
                    threshold=self.min_egress_bytes,
                    interpretation=f"Total egress volume ({feat.egress_bytes:,} bytes) exceeds standard outbound threshold",
                    source="rule",
                )
            )

        # Heuristic 2: Slow trickle exfiltration (low rate, prolonged duration, asymmetric)
        if (
            feat.r_byte_ratio >= 2.0
            and feat.duration_seconds >= self.trickle_duration_threshold
            and feat.egress_bytes >= 10_000
        ):
            score = max(score, 0.80)
            evidence.append(
                EvidenceItem(
                    feature="duration_seconds",
                    value=round(feat.duration_seconds, 1),
                    threshold=self.trickle_duration_threshold,
                    interpretation=f"Prolonged session duration ({feat.duration_seconds:.1f}s) indicates low-and-slow trickle exfiltration",
                    source="rule",
                )
            )

        return score, evidence

    def predict_proba(self, feat: FlowExfilFeatures) -> float:
        """Returns calibrated continuous probability P(Exfil) in [0, 1]."""
        if self.model is not None:
            vec = self.extract_feature_vector(feat)
            if hasattr(self.model, "predict_proba"):
                raw_prob = float(self.model.predict_proba(vec)[0, 1])
            elif hasattr(self.model, "score_samples"):
                raw_score = float(self.model.score_samples(vec)[0])
                raw_prob = float(1.0 / (1.0 + np.exp(raw_score * 10.0)))
            else:
                raw_prob = float(self.model.predict(vec)[0])

            if self.calibrator is not None:
                raw_prob = float(self.calibrator.predict(np.array([[raw_prob]]))[0])
            return float(np.clip(raw_prob, 0.0, 1.0))

        rule_score, _ = self.rule_evaluate(feat)
        return rule_score

    def evaluate(
        self,
        feat: FlowExfilFeatures,
        current_timestamp: float,
    ) -> Optional[AlertRecord]:
        """
        Evaluates session exfiltration features and returns an AlertRecord if anomalous.
        """
        confidence = self.predict_proba(feat)
        rule_score, evidence = self.rule_evaluate(feat)

        if confidence >= self.confidence_threshold and not evidence:
            evidence.append(
                EvidenceItem(
                    feature="ml_exfil_confidence",
                    value=round(confidence, 3),
                    threshold=self.confidence_threshold,
                    interpretation=f"Trained ML model identified data exfiltration pattern with {confidence*100:.1f}% confidence",
                    source="model",
                )
            )

        effective_conf = max(confidence, rule_score)
        if effective_conf < self.confidence_threshold or not evidence:
            return None

        severity = Severity.CRITICAL if effective_conf >= 0.88 else Severity.HIGH

        mitre = MitreAttackRef(
            tactic="Exfiltration",
            technique_id="T1048.003",
            technique_name="Exfiltration Over Unencrypted/Encrypted Non-C2 Protocol",
        )

        return self.deduplicator.register_detection(
            threat_class=self.threat_class,
            entity_id=f"{feat.src_ip}->{feat.dst_ip}",
            timestamp=current_timestamp,
            confidence=effective_conf,
            evidence=evidence,
            severity=severity,
            source=Endpoint(ip=feat.src_ip, port=0, internal=True),
            destination=Endpoint(ip=feat.dst_ip, port=feat.dst_port, internal=False),
            protocol=feat.protocol,
            flow_id=feat.flow_id,
            mitre_attack=mitre,
            model_version=self.model_version,
        )
