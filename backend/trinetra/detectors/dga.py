"""
backend/trinetra/detectors/dga.py

Detectors for Threat T-c: DGA Domains and DNS Tunnelling.

Sub-detector 1 — DgaDetector (ThreatClass.DGA_DOMAINS):
    Detects algorithmically-generated domain names using a character tri-gram
    (n=3) language model trained on the Tranco top-1k baseline (our curated sample).
    Features: domain_length, char_entropy, trigram_perplexity, numeric_ratio, vowel_ratio.
    The tri-gram model is built in-memory at detector init and never performs file I/O
    during inference, preserving the air-gap invariant.

Sub-detector 2 — DnsTunnelDetector (ThreatClass.DNS_TUNNELLING):
    Detects DNS tunnelling (data exfiltration/C2 over DNS) using per-client/domain
    aggregated DomainFeatures from WindowedFeatureEngine.
    Features: avg_query_length, max_entropy, txt_record_ratio, query_count.
    Rules: avg_query_length > 35 chars OR txt_record_ratio > 0.5 OR max_entropy > 3.6.
    All thresholds are initial heuristics to calibrate on data.

MITRE ATT&CK:
    DGA:         T1568.002 (Dynamic Resolution: Domain Generation Algorithms)
    DNS Tunnel:  T1071.004 (Application Layer Protocol: DNS)

ARCHITECTURAL INVARIANTS:
1. Zero network sockets, zero transmit capabilities.
2. No payload inspection or decryption.
3. Tri-gram model built entirely from in-memory Tranco baseline; no external calls.
4. Bounded streaming state via LRU-evicted DomainAccumulator in WindowedFeatureEngine.
5. Every alert carries at least one interpretable EvidenceItem.
6. Calibrated confidence via IsotonicRegression fitted on validation split only.

Data provenance:
    Tri-gram LM seed data: data/baselines/tranco_top1k.csv
    (curated 20-row sample — not full Tranco list; labeled as curated sample slice).
    Used only for building a character n-gram probability table for perplexity scoring.
    The DGA simulator generates its own domains from Markov/random algorithms;
    training labels are entirely our own synthetic data (not from DGArchive, which is
    CC BY-NC-SA; our generators are reimplementations from published papers).
"""
from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import numpy as np

from trinetra.detectors.base import BaseDetector, IncidentDeduplicator
from trinetra.features.windowed_engine import DomainFeatures
from trinetra.schemas import (
    AlertRecord,
    Endpoint,
    EvidenceItem,
    MitreAttackRef,
    Severity,
    ThreatClass,
)

# ---------------------------------------------------------------------------
# Tri-gram Language Model (built at module import from Tranco baseline)
# ---------------------------------------------------------------------------

# Repository-root relative path; resolved at import time so that inference
# performs ZERO file I/O (air-gap invariant preserved).
_TRANCO_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent
    / "data" / "baselines" / "tranco_top1k.csv"
)


def _load_tranco_domains(path: Path) -> list[str]:
    """Load domain names from Tranco CSV (rank,domain format). Returns list of lowercase SLDs."""
    domains: list[str] = []
    if not path.exists():
        return domains
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            parts = line.split(",", 1)
            if len(parts) == 2:
                raw_domain = parts[1].strip().lower()
                # Extract SLD (second-level domain) for trigram model
                sld = raw_domain.split(".")[0] if "." in raw_domain else raw_domain
                if sld:
                    domains.append(sld)
    return domains


def _build_trigram_model(domains: list[str], n: int = 3) -> dict[str, dict[str, float]]:
    """
    Build a character n-gram conditional probability model P(c_i | c_{i-n+1}...c_{i-1}).
    Uses Laplace smoothing (add-one) over the ASCII alphabet [a-z0-9-] to handle unseen n-grams.
    'n' is the approved default of 3 (character tri-grams).
    """
    # Vocabulary: lowercase letters, digits, hyphen (valid DNS label characters)
    vocab_chars = [chr(c) for c in range(ord('a'), ord('z') + 1)] + [str(d) for d in range(10)] + ['-']
    vocab_size = len(vocab_chars)

    # Count n-gram transitions: context (n-1 chars) → next char
    transition_counts: dict[str, Counter] = defaultdict(Counter)

    start_pad = "^" * (n - 1)  # Boundary marker (not in vocab, forces smoothing)

    for domain in domains:
        padded = start_pad + domain.lower() + "$"
        for i in range(n - 1, len(padded)):
            context = padded[i - (n - 1): i]
            next_char = padded[i]
            transition_counts[context][next_char] += 1

    # Normalize with Laplace smoothing
    model: dict[str, dict[str, float]] = {}
    for context, counts in transition_counts.items():
        total = sum(counts.values()) + vocab_size  # Laplace denominator
        model[context] = {char: (counts.get(char, 0) + 1) / total for char in vocab_chars}
        # Also assign mass to unseen chars via smoothing
        model[context]["_unk_"] = 1.0 / total

    return model


def _compute_trigram_perplexity(domain: str, model: dict[str, dict[str, float]], n: int = 3) -> float:
    """
    Compute the character tri-gram cross-entropy perplexity of a domain label.
    High perplexity → domain looks random / unlike legitimate TLDs → DGA indicator.
    Formula: PP = exp(H) where H = -1/L * sum(log P(c_i | context_i)).
    Returns a float. Higher values indicate DGA-like names.
    """
    label = domain.lower().split(".")[0]  # Extract SLD only
    if len(label) < n:
        # Too short to score with trigrams; return moderate uncertainty
        return 50.0

    start_pad = "^" * (n - 1)
    padded = start_pad + label

    log_prob_sum = 0.0
    char_count = 0
    min_prob = 1e-9  # Floor to avoid log(0)

    for i in range(n - 1, len(padded)):
        context = padded[i - (n - 1): i]
        next_char = padded[i]
        ctx_probs = model.get(context, {})
        prob = ctx_probs.get(next_char, ctx_probs.get("_unk_", min_prob))
        prob = max(prob, min_prob)
        log_prob_sum += math.log(prob)
        char_count += 1

    if char_count == 0:
        return 100.0

    cross_entropy = -log_prob_sum / char_count  # nats
    perplexity = math.exp(cross_entropy)
    return float(perplexity)


# ---------------------------------------------------------------------------
# Module-level tri-gram model (built once from Tranco baseline)
# ---------------------------------------------------------------------------
_tranco_domains: list[str] = _load_tranco_domains(_TRANCO_PATH)

# Augment with additional common legitimate SLDs to reduce false positives
# (these are well-known domains not covered in the 20-row curated sample)
_SUPPLEMENTARY_LEGIT_SLDS = [
    "mail", "smtp", "pop", "imap", "www", "ftp", "api", "cdn", "static",
    "images", "assets", "media", "login", "auth", "oauth", "connect",
    "blog", "docs", "help", "support", "news", "shop", "store", "app",
    "dev", "staging", "prod", "test", "admin", "panel", "dashboard",
    "analytics", "tracking", "events", "metrics", "monitor", "health",
    "status", "ping", "ntp", "dns", "ldap", "vpn", "proxy", "gateway",
]
_tranco_domains.extend(_SUPPLEMENTARY_LEGIT_SLDS)

_TRIGRAM_MODEL: dict[str, dict[str, float]] = _build_trigram_model(_tranco_domains, n=3)


# ---------------------------------------------------------------------------
# Feature Extraction Helpers
# ---------------------------------------------------------------------------

def _compute_char_entropy(s: str) -> float:
    """Shannon entropy of character distribution in string (bits)."""
    if not s:
        return 0.0
    counts = Counter(s.lower())
    n = len(s)
    entropy = -sum((c / n) * math.log2(c / n) for c in counts.values() if c > 0)
    return float(entropy)


def _compute_numeric_ratio(label: str) -> float:
    """Fraction of characters in label that are digits."""
    if not label:
        return 0.0
    return sum(1 for c in label if c.isdigit()) / len(label)


def _compute_vowel_ratio(label: str) -> float:
    """
    Fraction of alphabetic characters that are vowels.
    Legitimate domains tend to have vowel ratios > 0.25 (readable English).
    DGA names often have very low or very high vowel ratios.
    """
    alpha_chars = [c for c in label.lower() if c.isalpha()]
    if not alpha_chars:
        return 0.0
    vowels = sum(1 for c in alpha_chars if c in "aeiou")
    return vowels / len(alpha_chars)


def extract_dga_features(domain: str) -> np.ndarray:
    """
    Extracts a 5-dimensional feature vector for a single domain query label.
    Returns: [domain_length, char_entropy, trigram_perplexity, numeric_ratio, vowel_ratio]

    Note: 'domain' here is the full query string (e.g. 'abc123xyz.evil.com').
    We extract the SLD (leftmost label) for character-level features.
    """
    # Extract leftmost label (SLD) for character-level features
    label = domain.split(".")[0].lower() if "." in domain else domain.lower()

    domain_length = float(len(label))
    char_entropy = _compute_char_entropy(label)
    trigram_pp = _compute_trigram_perplexity(domain, _TRIGRAM_MODEL, n=3)
    numeric_ratio = _compute_numeric_ratio(label)
    vowel_ratio = _compute_vowel_ratio(label)

    return np.array(
        [domain_length, char_entropy, trigram_pp, numeric_ratio, vowel_ratio],
        dtype=np.float64,
    )


# ---------------------------------------------------------------------------
# DGA Detector
# ---------------------------------------------------------------------------

class DgaDetector(BaseDetector):
    """
    Detector for Threat T-c (DGA Domains).

    Evaluates per-query DNS domain names using:
    1. Character tri-gram perplexity against Tranco-trained LM (high → DGA-like)
    2. Character entropy (high uniform distribution → random generation)
    3. Numeric ratio (many digits → DGA indicator)
    4. Vowel ratio (very low or very high → unnatural name)
    5. Domain label length

    Rule thresholds are initial heuristics to calibrate on data.

    MITRE ATT&CK: T1568.002 (Domain Generation Algorithms)
    """

    FEATURE_NAMES = [
        "domain_length",
        "char_entropy",
        "trigram_perplexity",
        "numeric_ratio",
        "vowel_ratio",
    ]

    def __init__(
        self,
        model: Optional[Any] = None,
        calibrator: Optional[Any] = None,
        confidence_threshold: float = 0.70,
        model_version: str = "trinetra-dga-v2c",
        deduplicator: Optional[IncidentDeduplicator] = None,
        # Rule thresholds — initial heuristics to calibrate on data
        length_threshold: float = 15.0,        # SLD length > 15 chars suspicious
        entropy_threshold: float = 3.5,        # char entropy > 3.5 bits → high randomness
        perplexity_threshold: float = 80.0,    # trigram perplexity > 80 → DGA-like
        numeric_ratio_threshold: float = 0.35, # > 35% digits → likely DGA
    ) -> None:
        super().__init__(
            detector_id="DETECTOR_T_C_DGA",
            threat_class=ThreatClass.DGA_DOMAINS,
            model_version=model_version,
            confidence_threshold=confidence_threshold,
            deduplicator=deduplicator,
        )
        self.model = model
        self.calibrator = calibrator
        self.length_threshold = length_threshold
        self.entropy_threshold = entropy_threshold
        self.perplexity_threshold = perplexity_threshold
        self.numeric_ratio_threshold = numeric_ratio_threshold

    def extract_feature_vector(self, domain: str) -> np.ndarray:
        """Extracts standard 5-dimensional feature vector."""
        return extract_dga_features(domain).reshape(1, -1)

    def rule_evaluate(self, domain: str) -> tuple[float, list[EvidenceItem]]:
        """
        Rule-based DGA heuristics.
        Combines perplexity + entropy + length to produce interpretable EvidenceItems.
        """
        feats = extract_dga_features(domain)
        domain_length, char_entropy, trigram_pp, numeric_ratio, vowel_ratio = feats

        evidence: list[EvidenceItem] = []
        score = 0.0

        label = domain.split(".")[0].lower() if "." in domain else domain.lower()

        # Heuristic 1: High trigram perplexity (character pattern unlike legitimate domains)
        if trigram_pp >= self.perplexity_threshold:
            score = max(score, 0.88)
            evidence.append(
                EvidenceItem(
                    feature="trigram_perplexity",
                    value=round(trigram_pp, 2),
                    threshold=self.perplexity_threshold,
                    interpretation=(
                        f"Domain label '{label}' has trigram perplexity={trigram_pp:.2f} "
                        f"(threshold: {self.perplexity_threshold}). Character n-gram model "
                        f"(n=3, trained on Tranco curated sample) indicates pattern is "
                        f"highly dissimilar from legitimate domain labels. "
                        f"MITRE T1568.002. Initial heuristic — calibrate on benign captures."
                    ),
                    source="rule",
                )
            )

        # Heuristic 2: High character entropy (uniform distribution → random generation)
        if char_entropy >= self.entropy_threshold:
            score = max(score, 0.82)
            evidence.append(
                EvidenceItem(
                    feature="char_entropy",
                    value=round(char_entropy, 3),
                    threshold=self.entropy_threshold,
                    interpretation=(
                        f"Shannon entropy of domain label '{label}'={char_entropy:.3f} bits "
                        f"(threshold: {self.entropy_threshold}). High uniform character "
                        f"distribution is characteristic of algorithmically-generated names. "
                        f"Initial heuristic — calibrate on benign captures."
                    ),
                    source="rule",
                )
            )

        # Heuristic 3: Long SLD with many digits (common in dictionary+number DGAs)
        if domain_length >= self.length_threshold and numeric_ratio >= self.numeric_ratio_threshold:
            score = max(score, 0.80)
            evidence.append(
                EvidenceItem(
                    feature="numeric_ratio",
                    value=round(numeric_ratio, 3),
                    threshold=self.numeric_ratio_threshold,
                    interpretation=(
                        f"Domain label '{label}' is {int(domain_length)} chars with "
                        f"{numeric_ratio * 100:.0f}% digits (threshold: "
                        f"{self.numeric_ratio_threshold * 100:.0f}%). Long high-digit-ratio "
                        f"labels are common in dictionary-number DGA families. "
                        f"Initial heuristic — calibrate on benign captures."
                    ),
                    source="rule",
                )
            )

        return score, evidence

    def predict_proba(self, domain: str) -> float:
        """Returns calibrated P(DGA) in [0, 1]."""
        if self.model is not None:
            try:
                vec = self.extract_feature_vector(domain)
                if hasattr(self.model, "predict_proba"):
                    raw_prob = float(self.model.predict_proba(vec)[0, 1])
                else:
                    raw_prob = float(self.model.predict(vec)[0])

                if self.calibrator is not None:
                    raw_prob = float(self.calibrator.predict(np.array([[raw_prob]]))[0])
                return float(np.clip(raw_prob, 0.0, 1.0))
            except Exception:
                pass

        rule_score, _ = self.rule_evaluate(domain)
        return rule_score

    def evaluate(
        self,
        domain: str,
        client_ip: str,
        current_timestamp: float,
    ) -> Optional[AlertRecord]:
        """
        Evaluates a single DNS query domain for DGA characteristics.
        'domain' is the full query string (e.g. 'abc123xyz.evil.com').
        'client_ip' is the querying host.

        Returns an AlertRecord (first detection) or None (benign / deduplicated).
        """
        # Skip known safe TLDs with short SLDs — simple pre-filter to reduce noise
        label = domain.split(".")[0].lower() if "." in domain else domain.lower()
        if len(label) < 4:
            return None

        # Principled DGA signal guard: at least one indicator must be present before
        # allowing ML to vote. Prevents FPs on benign names like 'google.com'
        # (entropy≈1.9, perplexity≈20) being overridden by ML model uncertainty.
        feats = extract_dga_features(domain)
        char_entropy = feats[1]
        trigram_pp   = feats[2]
        label_len    = feats[0]
        has_dga_signal = (
            char_entropy >= 3.0
            or trigram_pp >= 50.0
            or label_len >= 14.0
            or feats[3] >= 0.25        # high digit ratio
        )
        if not has_dga_signal:
            return None

        confidence = self.predict_proba(domain)
        rule_score, evidence = self.rule_evaluate(domain)

        if confidence >= self.confidence_threshold and not evidence:
            evidence.append(
                EvidenceItem(
                    feature="ml_dga_confidence",
                    value=round(confidence, 3),
                    threshold=self.confidence_threshold,
                    interpretation=(
                        f"ML model classified '{domain}' as DGA with "
                        f"{confidence * 100:.1f}% confidence. "
                        f"Features: len={feats[0]:.0f}, entropy={feats[1]:.3f}, "
                        f"perplexity={feats[2]:.2f}, num_ratio={feats[3]:.3f}."
                    ),
                    source="model",
                )
            )

        effective_conf = max(confidence, rule_score)
        if effective_conf < self.confidence_threshold or not evidence:
            return None

        severity = Severity.HIGH if effective_conf >= 0.90 else Severity.MEDIUM

        mitre = MitreAttackRef(
            tactic="Command and Control",
            technique_id="T1568.002",
            technique_name="Dynamic Resolution: Domain Generation Algorithms",
        )

        # Entity ID: the FQDN itself
        return self.deduplicator.register_detection(
            threat_class=self.threat_class,
            entity_id=domain,
            timestamp=current_timestamp,
            confidence=effective_conf,
            evidence=evidence,
            severity=severity,
            source=Endpoint(ip=client_ip, port=53, internal=True),
            protocol="UDP",
            mitre_attack=mitre,
            model_version=self.model_version,
        )


# ---------------------------------------------------------------------------
# DNS Tunnel Detector
# ---------------------------------------------------------------------------

class DnsTunnelDetector(BaseDetector):
    """
    Detector for Threat T-c (DNS Tunnelling / data exfiltration over DNS).

    Evaluates DomainFeatures from WindowedFeatureEngine for per-client/domain
    aggregated statistics indicating DNS channel abuse.

    Classic indicators: very long query labels (base32/base64 encoded data),
    high TXT record ratio (often used for data retrieval), high per-query entropy.

    All thresholds are initial heuristics to calibrate on data.

    MITRE ATT&CK: T1071.004 (Application Layer Protocol: DNS)
    """

    FEATURE_NAMES = [
        "avg_query_length",
        "max_entropy",
        "txt_record_ratio",
        "query_count",
    ]

    def __init__(
        self,
        model: Optional[Any] = None,
        calibrator: Optional[Any] = None,
        confidence_threshold: float = 0.70,
        model_version: str = "trinetra-dnstunnel-v2c",
        deduplicator: Optional[IncidentDeduplicator] = None,
        # Rule thresholds — initial heuristics to calibrate on data
        query_length_threshold: float = 35.0,  # avg query length > 35 chars → tunnelling
        entropy_threshold: float = 3.6,        # max per-query entropy > 3.6 → encoded data
        txt_ratio_threshold: float = 0.50,     # TXT record ratio > 50% → data retrieval
        min_query_count: int = 5,              # Minimum queries before analysis
    ) -> None:
        super().__init__(
            detector_id="DETECTOR_T_C_DNS_TUNNEL",
            threat_class=ThreatClass.DNS_TUNNELLING,
            model_version=model_version,
            confidence_threshold=confidence_threshold,
            deduplicator=deduplicator,
        )
        self.model = model
        self.calibrator = calibrator
        self.query_length_threshold = query_length_threshold
        self.entropy_threshold = entropy_threshold
        self.txt_ratio_threshold = txt_ratio_threshold
        self.min_query_count = min_query_count

    def extract_feature_vector(self, feat: DomainFeatures) -> np.ndarray:
        """Extracts standard 4-dimensional feature vector."""
        return np.array(
            [
                feat.avg_query_length,
                feat.max_entropy,
                feat.txt_record_ratio,
                float(feat.query_count),
            ],
            dtype=np.float64,
        ).reshape(1, -1)

    def rule_evaluate(self, feat: DomainFeatures) -> tuple[float, list[EvidenceItem]]:
        """
        Rule-based DNS tunnelling heuristics.
        Flags: long queries OR high TXT ratio OR high entropy.
        """
        evidence: list[EvidenceItem] = []
        score = 0.0

        if feat.query_count < self.min_query_count:
            return 0.0, []

        # Heuristic 1: Long query labels (base32/base64-encoded data in subdomains)
        if feat.avg_query_length >= self.query_length_threshold:
            score = max(score, 0.90)
            evidence.append(
                EvidenceItem(
                    feature="avg_query_length",
                    value=round(feat.avg_query_length, 2),
                    threshold=self.query_length_threshold,
                    interpretation=(
                        f"Mean DNS query label length for {feat.client_ip}→{feat.domain} "
                        f"is {feat.avg_query_length:.1f} chars (threshold: "
                        f"{self.query_length_threshold}). Long subdomain labels are the "
                        f"primary indicator of DNS tunnelling (dnscat2, Iodine, dns2tcp). "
                        f"Initial heuristic — calibrate on benign captures."
                    ),
                    source="rule",
                )
            )

        # Heuristic 2: High TXT record ratio (used to retrieve exfiltrated data / C2 commands)
        if feat.txt_record_ratio >= self.txt_ratio_threshold:
            score = max(score, 0.87)
            evidence.append(
                EvidenceItem(
                    feature="txt_record_ratio",
                    value=round(feat.txt_record_ratio, 3),
                    threshold=self.txt_ratio_threshold,
                    interpretation=(
                        f"TXT query ratio={feat.txt_record_ratio * 100:.0f}% for "
                        f"{feat.client_ip}→{feat.domain} (threshold: "
                        f"{self.txt_ratio_threshold * 100:.0f}%). High TXT ratio "
                        f"indicates DNS tunnel C2 response retrieval pattern. "
                        f"Initial heuristic — calibrate on benign captures."
                    ),
                    source="rule",
                )
            )

        # Heuristic 3: High per-query character entropy (encoded/encrypted payload data)
        if feat.max_entropy >= self.entropy_threshold:
            score = max(score, 0.83)
            evidence.append(
                EvidenceItem(
                    feature="max_entropy",
                    value=round(feat.max_entropy, 3),
                    threshold=self.entropy_threshold,
                    interpretation=(
                        f"Maximum per-query Shannon entropy={feat.max_entropy:.3f} bits "
                        f"for {feat.client_ip}→{feat.domain} (threshold: "
                        f"{self.entropy_threshold}). High-entropy subdomains contain "
                        f"base32/base64/hex encoded exfiltrated data. "
                        f"Initial heuristic — calibrate on benign captures."
                    ),
                    source="rule",
                )
            )

        return score, evidence

    def predict_proba(self, feat: DomainFeatures) -> float:
        """Returns calibrated P(DNS tunnel) in [0, 1]."""
        if feat.query_count < self.min_query_count:
            return 0.0

        if self.model is not None:
            try:
                vec = self.extract_feature_vector(feat)
                if hasattr(self.model, "predict_proba"):
                    raw_prob = float(self.model.predict_proba(vec)[0, 1])
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
        feat: DomainFeatures,
        current_timestamp: float,
    ) -> Optional[AlertRecord]:
        """
        Evaluates DomainFeatures for a specific (client_ip, domain) pair.
        Returns an AlertRecord if DNS tunnelling is detected; None otherwise.
        """
        if feat.query_count < self.min_query_count:
            return None

        confidence = self.predict_proba(feat)
        rule_score, evidence = self.rule_evaluate(feat)

        if confidence >= self.confidence_threshold and not evidence:
            evidence.append(
                EvidenceItem(
                    feature="ml_tunnel_confidence",
                    value=round(confidence, 3),
                    threshold=self.confidence_threshold,
                    interpretation=(
                        f"ML model classified {feat.client_ip}→{feat.domain} as "
                        f"DNS tunnel with {confidence * 100:.1f}% confidence. "
                        f"avg_query_len={feat.avg_query_length:.1f}, "
                        f"max_entropy={feat.max_entropy:.3f}, "
                        f"txt_ratio={feat.txt_record_ratio:.3f}, "
                        f"queries={feat.query_count}."
                    ),
                    source="model",
                )
            )

        effective_conf = max(confidence, rule_score)
        if effective_conf < self.confidence_threshold or not evidence:
            return None

        severity = Severity.CRITICAL if effective_conf >= 0.90 else Severity.HIGH

        mitre = MitreAttackRef(
            tactic="Command and Control",
            technique_id="T1071.004",
            technique_name="Application Layer Protocol: DNS",
        )

        # Entity ID convention: client→parent_domain
        entity_id = f"{feat.client_ip}->{feat.domain}"

        return self.deduplicator.register_detection(
            threat_class=self.threat_class,
            entity_id=entity_id,
            timestamp=current_timestamp,
            confidence=effective_conf,
            evidence=evidence,
            severity=severity,
            source=Endpoint(ip=feat.client_ip, port=53, internal=True),
            protocol="UDP",
            mitre_attack=mitre,
            model_version=self.model_version,
        )
