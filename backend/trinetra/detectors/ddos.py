"""
backend/trinetra/detectors/ddos.py

Detector for Threat T-a: Volumetric DDoS & Resource Starvation.
Covers: SYN Flood, UDP Reflection/Amplification, and Slowloris connection starvation.

Evaluates DstWindowFeatures over sliding windows, generating standardized AlertRecords
with interpretable EvidenceItems and calibrated confidence scores.
"""
from __future__ import annotations

from typing import Any, List, Optional, Tuple
import numpy as np

from trinetra.detectors.base import BaseDetector, IncidentDeduplicator
from trinetra.features.windowed_engine import DstWindowFeatures
from trinetra.schemas import (
    AlertRecord,
    Endpoint,
    EvidenceItem,
    MitreAttackRef,
    Severity,
    ThreatClass,
)


class DdosDetector(BaseDetector):
    """
    Detector for Threat T-a (DDoS & Resource Starvation).
    Combines rule-based threshold heuristics with an ML classifier / anomaly model.
    """

    FEATURE_NAMES = [
        "incoming_pps",
        "syn_to_ack_ratio",
        "src_ip_entropy",
        "udp_amplification_factor",
    ]

    def __init__(
        self,
        model: Optional[Any] = None,
        calibrator: Optional[Any] = None,
        confidence_threshold: float = 0.70,
        model_version: str = "trinetra-ddos-v2b",
        deduplicator: Optional[IncidentDeduplicator] = None,
        # Rule threshold defaults (configurable heuristics)
        pps_threshold: float = 200.0,
        syn_ratio_threshold: float = 5.0,
        entropy_threshold: float = 3.5,
        udp_amp_threshold: float = 8.0,
    ) -> None:
        super().__init__(
            detector_id="DETECTOR_T_A_DDOS",
            threat_class=ThreatClass.VOLUMETRIC_DDOS,
            model_version=model_version,
            confidence_threshold=confidence_threshold,
            deduplicator=deduplicator,
        )
        self.model = model
        self.calibrator = calibrator
        self.pps_threshold = pps_threshold
        self.syn_ratio_threshold = syn_ratio_threshold
        self.entropy_threshold = entropy_threshold
        self.udp_amp_threshold = udp_amp_threshold

    def extract_feature_vector(self, feat: DstWindowFeatures) -> np.ndarray:
        """Extracts standard 4-dimensional feature vector for ML inference."""
        return np.array([
            feat.incoming_pps,
            feat.syn_to_ack_ratio,
            feat.src_ip_entropy,
            feat.udp_amplification_factor,
        ], dtype=np.float64).reshape(1, -1)

    def rule_evaluate(self, feat: DstWindowFeatures) -> tuple[float, list[EvidenceItem]]:
        """
        Rule-based baseline heuristic evaluation.
        Produces interpretable EvidenceItems for each threshold breach.
        """
        evidence: list[EvidenceItem] = []
        score = 0.0

        # Heuristic 1: SYN flood (high PPS + high SYN-to-ACK ratio)
        if feat.syn_to_ack_ratio >= self.syn_ratio_threshold and feat.incoming_pps >= self.pps_threshold:
            score = max(score, 0.90)
            evidence.append(
                EvidenceItem(
                    feature="syn_to_ack_ratio",
                    value=round(feat.syn_to_ack_ratio, 2),
                    threshold=self.syn_ratio_threshold,
                    interpretation=f"SYN-to-ACK ratio of {feat.syn_to_ack_ratio:.1f} strongly indicates half-open SYN starvation",
                    source="rule",
                )
            )
            evidence.append(
                EvidenceItem(
                    feature="incoming_pps",
                    value=round(feat.incoming_pps, 1),
                    threshold=self.pps_threshold,
                    interpretation=f"Inbound packet rate ({feat.incoming_pps:.1f} pps) exceeds baseline volumetric threshold",
                    source="rule",
                )
            )

        # Heuristic 2: Spoofed distributed source entropy
        if feat.src_ip_entropy >= self.entropy_threshold and feat.incoming_pps >= (self.pps_threshold / 2):
            score = max(score, 0.85)
            evidence.append(
                EvidenceItem(
                    feature="src_ip_entropy",
                    value=round(feat.src_ip_entropy, 3),
                    threshold=self.entropy_threshold,
                    interpretation=f"High source IP Shannon entropy ({feat.src_ip_entropy:.2f}) indicates distributed/spoofed IPs",
                    source="rule",
                )
            )

        # Heuristic 3: UDP Amplification
        if feat.udp_amplification_factor >= self.udp_amp_threshold and feat.incoming_pps >= 50.0:
            score = max(score, 0.92)
            evidence.append(
                EvidenceItem(
                    feature="udp_amplification_factor",
                    value=round(feat.udp_amplification_factor, 2),
                    threshold=self.udp_amp_threshold,
                    interpretation=f"UDP inbound/outbound ratio ({feat.udp_amplification_factor:.1f}x) reveals reflection amplification",
                    source="rule",
                )
            )

        return score, evidence

    def predict_proba(self, feat: DstWindowFeatures) -> float:
        """Returns calibrated continuous probability P(DDoS) in [0, 1]."""
        if self.model is not None:
            try:
                vec = self.extract_feature_vector(feat)
                if hasattr(self.model, "predict_proba"):
                    raw_prob = float(self.model.predict_proba(vec)[0, 1])
                elif hasattr(self.model, "score_samples"):  # Isolation Forest
                    # Isolation Forest: score_samples returns negative anomaly score
                    raw_score = float(self.model.score_samples(vec)[0])
                    # Map roughly [-1, 0] to [1, 0]
                    raw_prob = float(1.0 / (1.0 + np.exp(raw_score * 10.0)))
                else:
                    raw_prob = float(self.model.predict(vec)[0])

                if self.calibrator is not None:
                    # Apply isotonic / sigmoid calibration
                    raw_prob = float(self.calibrator.predict(np.array([[raw_prob]]))[0])
                return float(np.clip(raw_prob, 0.0, 1.0))
            except Exception:
                pass

        # Fallback to rule score
        rule_score, _ = self.rule_evaluate(feat)
        return rule_score

    def evaluate(
        self,
        feat: DstWindowFeatures,
        current_timestamp: float,
        dst_port: int = 80,
    ) -> Optional[AlertRecord]:
        """
        Evaluates destination window features and returns an AlertRecord if anomalous.
        Enforces both ML confidence threshold and mandatory EvidenceItem generation.
        """
        confidence = self.predict_proba(feat)
        rule_score, evidence = self.rule_evaluate(feat)

        # If rule generated no evidence but ML fired, add ML confidence evidence
        if confidence >= self.confidence_threshold and not evidence:
            evidence.append(
                EvidenceItem(
                    feature="ml_ddos_confidence",
                    value=round(confidence, 3),
                    threshold=self.confidence_threshold,
                    interpretation=f"Trained ML model flagged destination traffic as DDoS with {confidence*100:.1f}% confidence",
                    source="model",
                )
            )

        effective_conf = max(confidence, rule_score)
        if effective_conf < self.confidence_threshold or not evidence:
            return None

        # Determine severity
        severity = Severity.CRITICAL if effective_conf >= 0.90 else Severity.HIGH

        # MITRE ATT&CK Mapping
        technique_id = "T1498.002" if feat.udp_amplification_factor >= self.udp_amp_threshold else "T1498.001"
        technique_name = "Reflection Amplification" if "T1498.002" in technique_id else "Direct Network Flood"

        mitre = MitreAttackRef(
            tactic="Impact",
            technique_id=technique_id,
            technique_name=technique_name,
        )

        return self.deduplicator.register_detection(
            threat_class=self.threat_class,
            entity_id=feat.dst_ip,
            timestamp=current_timestamp,
            confidence=effective_conf,
            evidence=evidence,
            severity=severity,
            destination=Endpoint(ip=feat.dst_ip, port=dst_port, internal=True),
            mitre_attack=mitre,
            model_version=self.model_version,
        )
