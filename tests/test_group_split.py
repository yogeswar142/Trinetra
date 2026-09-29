"""
tests/test_group_split.py

Unit tests for StrictGroupSplitter and Anti-Leakage Guardrails:
1. Asserts failure when feature matrices contain topological identifiers (IP, port, seed).
2. Asserts failure when train/test splits share identical /24 subnets or host groups.
3. Asserts clean group-based disjoint splitting on subnets and scenario runs.
"""
from __future__ import annotations

import pytest
from trinetra.ml.group_split import (
    StrictGroupSplitter,
    extract_subnet_group,
    validate_disjoint_splits,
    validate_no_feature_leakage,
)


class TestFeatureLeakageGuardrails:
    def test_clean_features_pass_validation(self) -> None:
        clean_features = [
            "syn_to_ack_ratio",
            "incoming_pps",
            "src_ip_entropy",
            "udp_amplification_factor",
            "iat_mean",
            "iat_cv",
            "shannon_entropy",
            "pst_length",
        ]
        # Must not raise
        validate_no_feature_leakage(clean_features)

    def test_ip_address_leakage_raises_error(self) -> None:
        leaky_features = ["syn_to_ack_ratio", "src_ip", "incoming_pps"]
        with pytest.raises(ValueError, match="Data Leakage Violation.*src_ip"):
            validate_no_feature_leakage(leaky_features)

    def test_port_leakage_raises_error(self) -> None:
        leaky_features = ["dst_port", "iat_cv"]
        with pytest.raises(ValueError, match="Data Leakage Violation.*dst_port"):
            validate_no_feature_leakage(leaky_features)

    def test_scenario_seed_leakage_raises_error(self) -> None:
        leaky_features = ["iat_mean", "scenario_seed"]
        with pytest.raises(ValueError, match="Data Leakage Violation.*scenario_seed"):
            validate_no_feature_leakage(leaky_features)


class TestDisjointSplitsValidation:
    def test_disjoint_sets_pass(self) -> None:
        train_g = {"192.168.1.0/24", "192.168.2.0/24"}
        val_g = {"10.0.1.0/24"}
        test_g = {"172.16.0.0/24"}
        # Must not raise
        validate_disjoint_splits(train_g, val_g, test_g)

    def test_train_test_overlap_raises_error(self) -> None:
        train_g = {"192.168.1.0/24", "10.0.0.0/24"}
        val_g = {"172.16.0.0/24"}
        test_g = {"192.168.1.0/24", "10.1.0.0/24"}  # Overlaps on 192.168.1.0/24
        with pytest.raises(ValueError, match="Train and Test sets share groups"):
            validate_disjoint_splits(train_g, val_g, test_g)


class TestStrictGroupSplitter:
    def test_subnet_group_extraction(self) -> None:
        assert extract_subnet_group("192.168.1.45") == "192.168.1.0/24"
        assert extract_subnet_group("10.50.200.1") == "10.50.200.0/24"

    def test_group_split_zero_leakage_on_subnets(self) -> None:
        # 100 flow records across 10 distinct subnets
        records = [f"flow_{i}" for i in range(100)]
        groups = [f"192.168.{i % 10}.0/24" for i in range(100)]

        splitter = StrictGroupSplitter(train_ratio=0.60, val_ratio=0.20, test_ratio=0.20, random_seed=42)
        train_idx, val_idx, test_idx = splitter.split(records, groups)

        assert len(train_idx) > 0
        assert len(val_idx) > 0
        assert len(test_idx) > 0
        assert len(train_idx) + len(val_idx) + len(test_idx) == 100

        train_subnets = {groups[i] for i in train_idx}
        val_subnets = {groups[i] for i in val_idx}
        test_subnets = {groups[i] for i in test_idx}

        # Assert 100% disjoint groups across all splits
        assert len(train_subnets.intersection(val_subnets)) == 0
        assert len(train_subnets.intersection(test_subnets)) == 0
        assert len(val_subnets.intersection(test_subnets)) == 0

    def test_group_split_on_scenario_seeds(self) -> None:
        # Grouping by scenario run seeds
        records = [f"sample_{i}" for i in range(60)]
        seeds = [f"run_seed_{i % 6}" for i in range(60)]

        splitter = StrictGroupSplitter(train_ratio=0.50, val_ratio=0.25, test_ratio=0.25, random_seed=123)
        train_idx, val_idx, test_idx = splitter.split(records, seeds)

        train_seeds = {seeds[i] for i in train_idx}
        test_seeds = {seeds[i] for i in test_idx}
        assert len(train_seeds.intersection(test_seeds)) == 0
