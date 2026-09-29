"""
backend/trinetra/ml/group_split.py

Strict Group-Split Cross-Validation Harness & Anti-Leakage Guardrails.
Guarantees:
1. Zero Spatial / Subnet Leakage: Partitions datasets strictly by /24 CIDR prefix, scenario run, or random seed.
2. Disjoint Split Enforcement: Zero IP overlap across Train, Validation, and Test splits.
3. Feature Matrix Purity: Prohibits raw identifiers (IPs, ports, flow IDs, scenario seeds, timestamps)
   from entering the feature space, preventing trivial overfitting to network topology.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Iterable, List, Sequence, Set, Tuple
import numpy as np


ALLOWED_AGGREGATE_SUFFIXES = (
    "_entropy",
    "_count",
    "_ratio",
    "_rate",
    "_fraction",
    "_pps",
    "_factor",
    "_unique",
    "_distinct",
)

FORBIDDEN_IDENTIFIER_PATTERNS = [
    r"^(src|dst|client|server|victim|attacker)?_?ip(_addr)?$",
    r"^(src|dst|client|server)?_?port(_num)?$",
    r"^flow_id$",
    r"^scenario(_id|_run)?$",
    r"^.*seed.*$",
    r"^timestamp$",
    r"^.*mac(_addr)?$",
]


def validate_no_feature_leakage(feature_names: Sequence[str]) -> None:
    """
    Asserts that NO raw topological identifiers or metadata leakage fields
    are present in the model feature space.
    Statistical aggregates (e.g. src_ip_entropy, dst_port_count) are permitted,
    while raw endpoints (e.g. src_ip, dst_port, seed) raise ValueError.
    """
    for col in feature_names:
        clean_col = col.strip().lower()

        # If it's a known statistical aggregate, allow it
        if any(clean_col.endswith(suf) for suf in ALLOWED_AGGREGATE_SUFFIXES):
            continue

        for pat in FORBIDDEN_IDENTIFIER_PATTERNS:
            if re.match(pat, clean_col):
                raise ValueError(
                    f"Data Leakage Violation: Feature '{col}' matches forbidden identifier pattern '{pat}'. "
                    f"Models must learn behavioral dynamics, not static topological endpoints."
                )


def extract_subnet_group(ip_str: str) -> str:
    """
    Extracts the /24 IPv4 or /48 IPv6 network prefix for spatial group partitioning.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.version == 4:
            net = ipaddress.ip_network(f"{ip_str}/24", strict=False)
            return str(net)
        else:
            net = ipaddress.ip_network(f"{ip_str}/48", strict=False)
            return str(net)
    except Exception:
        # Fallback for non-IP entity grouping
        return ip_str


def validate_disjoint_splits(
    train_groups: Iterable[Any],
    val_groups: Iterable[Any],
    test_groups: Iterable[Any],
) -> None:
    """
    Asserts that train, validation, and test splits share ZERO common group entities.
    Raises ValueError if overlap occurs.
    """
    s_train = set(train_groups)
    s_val = set(val_groups)
    s_test = set(test_groups)

    train_val = s_train.intersection(s_val)
    if train_val:
        raise ValueError(f"Data Leakage Violation: Train and Validation sets share groups: {train_val}")

    train_test = s_train.intersection(s_test)
    if train_test:
        raise ValueError(f"Data Leakage Violation: Train and Test sets share groups: {train_test}")

    val_test = s_val.intersection(s_test)
    if val_test:
        raise ValueError(f"Data Leakage Violation: Validation and Test sets share groups: {val_test}")


class StrictGroupSplitter:
    """
    Deterministic group-based train/val/test splitter.
    """

    def __init__(
        self,
        train_ratio: float = 0.60,
        val_ratio: float = 0.20,
        test_ratio: float = 0.20,
        random_seed: int = 42,
    ) -> None:
        if abs((train_ratio + val_ratio + test_ratio) - 1.0) > 1e-5:
            raise ValueError("Split ratios must sum to 1.0")
        self.train_ratio = train_ratio
        self.val_ratio = val_ratio
        self.test_ratio = test_ratio
        self.seed = random_seed

    def split(
        self,
        records: Sequence[Any],
        groups: Sequence[Any],
    ) -> Tuple[List[int], List[int], List[int]]:
        """
        Splits index positions into (train_idx, val_idx, test_idx) ensuring
        all records belonging to any given group reside exclusively in one split.
        """
        if len(records) != len(groups):
            raise ValueError("Length of records and groups must match")

        unique_groups = sorted(list(set(groups)))
        if len(unique_groups) < 3:
            raise ValueError(f"At least 3 distinct groups required for train/val/test split (got {len(unique_groups)})")

        rng = np.random.default_rng(self.seed)
        shuffled_groups = list(unique_groups)
        rng.shuffle(shuffled_groups)

        n_groups = len(shuffled_groups)
        n_train = max(1, int(round(n_groups * self.train_ratio)))
        n_val = max(1, int(round(n_groups * self.val_ratio)))

        # Ensure at least 1 group per partition
        if n_train + n_val >= n_groups:
            n_train = n_groups - 2
            n_val = 1

        train_g = set(shuffled_groups[:n_train])
        val_g = set(shuffled_groups[n_train : n_train + n_val])
        test_g = set(shuffled_groups[n_train + n_val :])

        validate_disjoint_splits(train_g, val_g, test_g)

        train_idx = [i for i, g in enumerate(groups) if g in train_g]
        val_idx = [i for i, g in enumerate(groups) if g in val_g]
        test_idx = [i for i, g in enumerate(groups) if g in test_g]

        return train_idx, val_idx, test_idx
