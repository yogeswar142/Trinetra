"""
Vectorized Shannon Entropy Calculations for Trinetra.
Provides high-performance entropy computation for:
- Character distributions (DGA domains, DNS tunneling labels)
- Categorical flow distributions (Source IP entropy, Destination port entropy)
- Raw payload byte distributions (Covert exfiltration detection)
"""
import math
from collections import Counter
from typing import Sequence, Any
import numpy as np


def shannon_entropy_str(s: str) -> float:
    """
    Computes Shannon entropy in bits for an input string:
    H(X) = - sum(p(x) * log2(p(x)))
    """
    if not s:
        return 0.0
    length = len(s)
    counts = Counter(s)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return float(entropy)


def shannon_entropy_bytes(data: bytes) -> float:
    """
    Fast byte-level Shannon entropy over raw payload bytes (0 to 8 bits).
    """
    if not data:
        return 0.0
    length = len(data)
    byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    non_zero = byte_counts[byte_counts > 0]
    p = non_zero / length
    return float(-np.sum(p * np.log2(p)))


# Alias for convenience
shannon_entropy = shannon_entropy_bytes


def categorical_entropy(items: Sequence[Any]) -> float:
    """
    Computes Shannon entropy over categorical tokens (e.g. unique source IPs in a window).
    High entropy approaches log2(N), indicating uniform distribution (spoofed floods).
    Low entropy approaches 0.0, indicating concentrated distribution (single-source floods).
    """
    if not items:
        return 0.0
    length = len(items)
    counts = Counter(items)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return float(entropy)
