"""
backend/trinetra/detectors/beacon.py

Detector for Threat T-b: Botnet C2 Beaconing.
Covers: Rigid periodic heartbeats, jittered C2 callbacks (e.g. Cobalt Strike),
        and persistent low-interval C2 channel establishment.

Evaluates PairFeatures (IAT statistics) over bounded streaming state.
Requires a minimum of 20 observed inter-arrival intervals before analysis
to avoid false positives from burst traffic or connection setup.

ARCHITECTURAL INVARIANTS:
1. Zero network sockets, zero transmit capabilities.
2. No payload inspection or decryption.
3. Bounded streaming state via LRU-evicted PairAccumulator in WindowedFeatureEngine.
4. Every alert carries at least one interpretable EvidenceItem.
5. Calibrated confidence via IsotonicRegression fitted on validation split only.
"""
from __future__ import annotations

from typing import Any, List, Optional
import numpy as np

from trinetra.detectors.base import BaseDetector, IncidentDeduplicator
from trinetra.features.windowed_engine import PairFeatures
from trinetra.schemas import (
    AlertRecord,
    Endpoint,
    EvidenceItem,
    MitreAttackRef,
    Severity,
    ThreatClass,
)

# Minimum observed inter-arrival intervals required before beaconing analysis.
# User-approved default (Phase 2c decision): 20 intervals.
# This translates to sample_count >= 21 packets (21 timestamps -> 20 diffs),
# but PairAccumulator.sample_count == len(timestamps), so we check >= MIN_SAMPLES.
MIN_BEACON_SAMPLES: int = 21  # 21 timestamps => 20 IAT intervals


class BeaconDetector(BaseDetector):
    """
    Detector for Threat T-b (Botnet C2 Beaconing).

    Combines rule-based IAT threshold heuristics with an ML classifier.
    Uses PairFeatures (src_ip, dst_ip) computed by WindowedFeatureEngine.

    Rule thresholds are initial heuristics to calibrate on data.
    They are held in configurable constructor parameters, never hard-coded
    in logic, and must be tuned against benign traffic captures before
    deployment in any production environment.

    MITRE ATT&CK: T1071.001 (Application Layer Protocol – Web Protocols)
                  T1071.004 (Application Layer Protocol – DNS)
                  T1102    (Web Service – C2 channel)
    """

    FEATURE_NAMES = [
        "iat_mean",
        "iat_cv",
        "iat_autocorr",
        "iat_std",
        "sample_count",
    ]

    def __init__(
        self,
        model: Optional[Any] = None,
        calibrator: Optional[Any] = None,
        confidence_threshold: float = 0.70,
        model_version: str = "trinetra-beacon-v2c",
        deduplicator: Optional[IncidentDeduplicator] = None,
        # Rule threshold defaults — initial heuristics to calibrate on data
        cv_rigid_threshold: float = 0.20,      # CV < 0.20 → rigid periodic beacon
        cv_jitter_threshold: float = 0.45,     # CV < 0.45 w/ high autocorr → jittered C2
        autocorr_jitter_min: float = 0.70,     # autocorr > 0.70 for jitter classification
        iat_max_seconds: float = 3600.0,       # IAT mean > 1 hour: unlikely to be beaconing
        iat_min_seconds: float = 0.5,          # IAT mean < 0.5s: normal TCP keep-alive noise
        min_samples: int = MIN_BEACON_SAMPLES,
    ) -> None:
        super().__init__(
            detector_id="DETECTOR_T_B_BEACON",
            threat_class=ThreatClass.BOTNET_C2_BEACONING,
            model_version=model_version,
            confidence_threshold=confidence_threshold,
            deduplicator=deduplicator,
        )
        self.model = model
        self.calibrator = calibrator
        self.cv_rigid_threshold = cv_rigid_threshold
        self.cv_jitter_threshold = cv_jitter_threshold
        self.autocorr_jitter_min = autocorr_jitter_min
        self.iat_max_seconds = iat_max_seconds
        self.iat_min_seconds = iat_min_seconds
        self.min_samples = min_samples

    def extract_feature_vector(self, feat: PairFeatures) -> np.ndarray:
        """Extracts standard 5-dimensional feature vector for ML inference."""
        return np.array(
            [
                feat.iat_mean,
                feat.iat_cv,
                feat.iat_autocorr,
                feat.iat_std,
                float(feat.sample_count),
            ],
            dtype=np.float64,
        ).reshape(1, -1)

    def rule_evaluate(self, feat: PairFeatures) -> tuple[float, list[EvidenceItem]]:
        """
        Rule-based IAT heuristic evaluation.
        Returns (confidence_score, [EvidenceItem, ...]).

        All thresholds are initial heuristics to calibrate on data.
        """
        evidence: list[EvidenceItem] = []
        score = 0.0

        # Guard: insufficient samples
        if feat.sample_count < self.min_samples:
            return 0.0, []

        # Guard: IAT mean outside plausible C2 beacon range
        if feat.iat_mean > self.iat_max_seconds or feat.iat_mean < self.iat_min_seconds:
            return 0.0, []

        # Heuristic 1: Rigid periodic beacon (e.g. Metasploit default, Empire, custom RAT)
        # CV < cv_rigid_threshold indicates machine-precision regularity
        if feat.iat_cv < self.cv_rigid_threshold:
            score = max(score, 0.92)
            evidence.append(
                EvidenceItem(
                    feature="iat_cv",
                    value=round(feat.iat_cv, 4),
                    threshold=self.cv_rigid_threshold,
                    interpretation=(
                        f"Inter-arrival time coefficient of variation (CV={feat.iat_cv:.4f}) "
                        f"is below rigid-beacon threshold ({self.cv_rigid_threshold}), "
                        f"indicating machine-precision periodic communication "
                        f"with mean IAT={feat.iat_mean:.2f}s over {feat.sample_count} samples. "
                        f"Initial heuristic — calibrate on benign baseline data."
                    ),
                    source="rule",
                )
            )
            evidence.append(
                EvidenceItem(
                    feature="iat_mean",
                    value=round(feat.iat_mean, 4),
                    threshold=self.iat_min_seconds,
                    interpretation=(
                        f"Mean inter-arrival time {feat.iat_mean:.2f}s is consistent with "
                        f"C2 heartbeat interval (range: {self.iat_min_seconds:.1f}s – "
                        f"{self.iat_max_seconds:.0f}s)."
                    ),
                    source="rule",
                )
            )

        # Heuristic 2: Jittered C2 beacon (e.g. Cobalt Strike, SILENTTRINITY with jitter)
        # Moderate CV but strong autocorrelation — underlying period present despite noise
        elif (
            feat.iat_cv < self.cv_jitter_threshold
            and feat.iat_autocorr > self.autocorr_jitter_min
        ):
            score = max(score, 0.85)
            evidence.append(
                EvidenceItem(
                    feature="iat_autocorr",
                    value=round(feat.iat_autocorr, 4),
                    threshold=self.autocorr_jitter_min,
                    interpretation=(
                        f"IAT normalized autocorrelation peak={feat.iat_autocorr:.4f} "
                        f"exceeds jittered-beacon threshold ({self.autocorr_jitter_min}), "
                        f"revealing underlying periodic structure despite CV={feat.iat_cv:.4f} jitter. "
                        f"Characteristic of Cobalt Strike-style C2 with configurable jitter. "
                        f"Initial heuristic — calibrate on benign baseline data."
                    ),
                    source="rule",
                )
            )
            evidence.append(
                EvidenceItem(
                    feature="iat_cv",
                    value=round(feat.iat_cv, 4),
                    threshold=self.cv_jitter_threshold,
                    interpretation=(
                        f"CV={feat.iat_cv:.4f} below jitter threshold ({self.cv_jitter_threshold}) "
                        f"combined with high autocorrelation indicates jittered beacon pattern."
                    ),
                    source="rule",
                )
            )

        return score, evidence

    def predict_proba(self, feat: PairFeatures) -> float:
        """Returns calibrated continuous probability P(Beaconing) in [0, 1]."""
        if feat.sample_count < self.min_samples:
            return 0.0

        if self.model is not None:
            try:
                vec = self.extract_feature_vector(feat)
                if hasattr(self.model, "predict_proba"):
                    raw_prob = float(self.model.predict_proba(vec)[0, 1])
                elif hasattr(self.model, "score_samples"):  # Isolation Forest fallback
                    raw_score = float(self.model.score_samples(vec)[0])
                    raw_prob = float(1.0 / (1.0 + np.exp(raw_score * 10.0)))
                else:
                    raw_prob = float(self.model.predict(vec)[0])

                if self.calibrator is not None:
                    raw_prob = float(self.calibrator.predict(np.array([[raw_prob]]))[0])
                return float(np.clip(raw_prob, 0.0, 1.0))
            except Exception:
                pass

        # Fallback to rule score
        rule_score, _ = self.rule_evaluate(feat)
        return rule_score

    def evaluate(
        self,
        feat: PairFeatures,
        current_timestamp: float,
        dst_port: int = 443,
    ) -> Optional[AlertRecord]:
        """
        Evaluates PairFeatures for a specific (src_ip, dst_ip) pair.
        Returns an AlertRecord if beaconing is detected; None otherwise.

        Guards against insufficient samples (< min_samples) before any analysis.
        """
        # Minimum sample guard — must have at least 20 observed intervals
        if feat.sample_count < self.min_samples:
            return None

        # Bursty-traffic early-exit guard:
        # Real C2 beacons are periodic. If CV >> 0.80 AND autocorr < 0.30,
        # the traffic is clearly non-periodic (e.g. bursty web, streaming).
        # Skip ML inference entirely in this case to avoid model FPs.
        if feat.iat_cv > 0.80 and feat.iat_autocorr < 0.30:
            return None

        confidence = self.predict_proba(feat)
        rule_score, evidence = self.rule_evaluate(feat)

        # If ML fired but rules produced no evidence, generate ML-confidence evidence
        if confidence >= self.confidence_threshold and not evidence:
            evidence.append(
                EvidenceItem(
                    feature="ml_beacon_confidence",
                    value=round(confidence, 3),
                    threshold=self.confidence_threshold,
                    interpretation=(
                        f"Trained ML model classified ({feat.src_ip} → {feat.dst_ip}) "
                        f"as C2 beaconing with {confidence * 100:.1f}% confidence. "
                        f"Mean IAT={feat.iat_mean:.2f}s, CV={feat.iat_cv:.4f}, "
                        f"autocorr={feat.iat_autocorr:.4f} over {feat.sample_count} samples."
                    ),
                    source="model",
                )
            )

        effective_conf = max(confidence, rule_score)
        if effective_conf < self.confidence_threshold or not evidence:
            return None

        severity = Severity.CRITICAL if effective_conf >= 0.90 else Severity.HIGH

        # Differentiate rigid vs jittered in MITRE sub-technique
        if feat.iat_cv < self.cv_rigid_threshold:
            technique_name = "Application Layer Protocol: Web Protocols (Rigid Beacon)"
        else:
            technique_name = "Application Layer Protocol: Web Protocols (Jittered C2)"

        mitre = MitreAttackRef(
            tactic="Command and Control",
            technique_id="T1071.001",
            technique_name=technique_name,
        )

        # Entity ID convention: host-pair channel, port-specific
        entity_id = f"{feat.src_ip}->{feat.dst_ip}:{dst_port}"

        return self.deduplicator.register_detection(
            threat_class=self.threat_class,
            entity_id=entity_id,
            timestamp=current_timestamp,
            confidence=effective_conf,
            evidence=evidence,
            severity=severity,
            source=Endpoint(ip=feat.src_ip, port=0, internal=True),
            destination=Endpoint(ip=feat.dst_ip, port=dst_port, internal=False),
            protocol="TCP",
            mitre_attack=mitre,
            model_version=self.model_version,
        )
