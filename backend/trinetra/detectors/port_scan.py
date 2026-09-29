"""
backend/trinetra/detectors/port_scan.py

Detector for Threat T-e: Port Scanning & Reconnaissance.
Covers: Vertical port scans, horizontal subnet sweeps, strobe scans, and slow SYN probes.

Evaluates SrcWindowFeatures over sliding windows, producing standardized AlertRecords
with interpretable EvidenceItems and calibrated confidence scores.
"""
from __future__ import annotations

from typing import Any, List, Optional, Tuple
import numpy as np

from trinetra.detectors.base import BaseDetector, IncidentDeduplicator
from trinetra.features.windowed_engine import SrcWindowFeatures
from trinetra.schemas import (
    AlertRecord,
    Endpoint,
    EvidenceItem,
    MitreAttackRef,
    Severity,
    ThreatClass,
)


class PortScanDetector(BaseDetector):
    """
    Detector for Threat T-e (Port Scanning & Reconnaissance).
    Combines rule-based threshold heuristics with an ML classifier / anomaly model.
    """

    FEATURE_NAMES = [
        "dst_port_count",
        "dst_ip_count",
        "syn_scan_ratio",
        "packet_count",
    ]

    def __init__(
        self,
        model: Optional[Any] = None,
        calibrator: Optional[Any] = None,
        confidence_threshold: float = 0.70,
        model_version: str = "trinetra-portscan-v2b",
        deduplicator: Optional[IncidentDeduplicator] = None,
        # Rule threshold defaults (configurable heuristics)
        dst_port_threshold: int = 15,
        dst_ip_threshold: int = 10,
        syn_ratio_threshold: float = 0.65,
    ) -> None:
        super().__init__(
            detector_id="DETECTOR_T_E_PORTSCAN",
            threat_class=ThreatClass.PORT_SCANNING,
            model_version=model_version,
            confidence_threshold=confidence_threshold,
            deduplicator=deduplicator,
        )
        self.model = model
        self.calibrator = calibrator
        self.dst_port_threshold = dst_port_threshold
        self.dst_ip_threshold = dst_ip_threshold
        self.syn_ratio_threshold = syn_ratio_threshold

    def extract_feature_vector(self, feat: SrcWindowFeatures) -> np.ndarray:
        """Extracts standard 4-dimensional feature vector for ML inference."""
        return np.array([
            float(feat.dst_port_count),
            float(feat.dst_ip_count),
            float(feat.syn_scan_ratio),
            float(feat.packet_count),
        ], dtype=np.float64).reshape(1, -1)

    def rule_evaluate(self, feat: SrcWindowFeatures) -> tuple[float, list[EvidenceItem]]:
        """
        Rule-based baseline heuristic evaluation.
        Produces interpretable EvidenceItems for each threshold breach.
        """
        evidence: list[EvidenceItem] = []
        score = 0.0

        # Heuristic 1: Vertical Port Scan (probes many ports on targets)
        if feat.dst_port_count >= self.dst_port_threshold and feat.syn_scan_ratio >= self.syn_ratio_threshold:
            score = max(score, 0.92)
            evidence.append(
                EvidenceItem(
                    feature="dst_port_count",
                    value=feat.dst_port_count,
                    threshold=self.dst_port_threshold,
                    interpretation=f"Host probed {feat.dst_port_count} distinct ports within window (vertical port scan)",
                    source="rule",
                )
            )
            evidence.append(
                EvidenceItem(
                    feature="syn_scan_ratio",
                    value=round(feat.syn_scan_ratio, 2),
                    threshold=self.syn_ratio_threshold,
                    interpretation=f"SYN-only ratio ({feat.syn_scan_ratio*100:.1f}%) indicates half-open reconnaissance probes",
                    source="rule",
                )
            )

        # Heuristic 2: Horizontal Subnet Sweep (probes same port across many hosts)
        if feat.dst_ip_count >= self.dst_ip_threshold and feat.syn_scan_ratio >= self.syn_ratio_threshold:
            score = max(score, 0.88)
            evidence.append(
                EvidenceItem(
                    feature="dst_ip_count",
                    value=feat.dst_ip_count,
                    threshold=self.dst_ip_threshold,
                    interpretation=f"Host contacted {feat.dst_ip_count} distinct destination IPs within window (horizontal IP sweep)",
                    source="rule",
                )
            )

        # Heuristic 3: Low-and-slow scan probe pattern
        if feat.dst_port_count >= 8 and feat.window_seconds >= 60.0:
            score = max(score, 0.75)
            evidence.append(
                EvidenceItem(
                    feature="dst_port_count",
                    value=feat.dst_port_count,
                    threshold=8,
                    interpretation=f"Probing {feat.dst_port_count} ports over extended {feat.window_seconds:.0f}s window matches slow scan profile",
                    source="rule",
                )
            )

        return score, evidence

    def predict_proba(self, feat: SrcWindowFeatures) -> float:
        """Returns calibrated continuous probability P(PortScan) in [0, 1]."""
        if self.model is not None:
            try:
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
            except Exception:
                pass

        rule_score, _ = self.rule_evaluate(feat)
        return rule_score

    def evaluate(
        self,
        feat: SrcWindowFeatures,
        current_timestamp: float,
        target_ip: Optional[str] = None,
        target_port: int = 0,
    ) -> Optional[AlertRecord]:
        """
        Evaluates source window features and returns an AlertRecord if anomalous.
        """
        confidence = self.predict_proba(feat)
        rule_score, evidence = self.rule_evaluate(feat)

        if confidence >= self.confidence_threshold and not evidence:
            evidence.append(
                EvidenceItem(
                    feature="ml_portscan_confidence",
                    value=round(confidence, 3),
                    threshold=self.confidence_threshold,
                    interpretation=f"Trained ML model identified reconnaissance scan pattern with {confidence*100:.1f}% confidence",
                    source="model",
                )
            )

        effective_conf = max(confidence, rule_score)
        if effective_conf < self.confidence_threshold or not evidence:
            return None

        severity = Severity.HIGH if effective_conf >= 0.85 else Severity.MEDIUM

        mitre = MitreAttackRef(
            tactic="Discovery",
            technique_id="T1046",
            technique_name="Network Service Discovery",
        )

        dst_ep = Endpoint(ip=target_ip, port=target_port, internal=True) if target_ip else None

        return self.deduplicator.register_detection(
            threat_class=self.threat_class,
            entity_id=feat.src_ip,
            timestamp=current_timestamp,
            confidence=effective_conf,
            evidence=evidence,
            severity=severity,
            source=Endpoint(ip=feat.src_ip, port=0, internal=False),
            destination=dst_ep,
            mitre_attack=mitre,
            model_version=self.model_version,
        )
