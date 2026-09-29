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

    def test_connected_groups_multi_attribute(self) -> None:
        # Attributes: (subnet, run_id, seed)
        tuples = [
            ("192.168.1.0/24", "run_1", 101),
            ("192.168.1.0/24", "run_2", 102),  # connected to row 0 via subnet
            ("10.0.1.0/24", "run_3", 201),
            ("10.0.1.0/24", "run_4", 202),      # connected to row 2 via subnet
            ("172.16.1.0/24", "run_5", 301),
            ("172.16.1.0/24", "run_6", 302),    # connected to row 4 via subnet
        ]
        comp_ids = StrictGroupSplitter.compute_connected_groups(tuples)
        assert len(set(comp_ids)) == 3
        # Rows 0 and 1 are in same group
        assert comp_ids[0] == comp_ids[1]
        # Rows 2 and 3 are in same group
        assert comp_ids[2] == comp_ids[3]
        # Rows 4 and 5 are in same group
        assert comp_ids[4] == comp_ids[5]

    def test_lab_data_collapse_fails_loudly(self) -> None:
        # Heavily overlapping attributes bridging all samples into 1 component
        collapsed_tuples = [
            ("192.168.1.0/24", "run_1", 100),
            ("192.168.1.0/24", "run_2", 100),  # overlaps on subnet & seed
            ("10.0.0.0/24", "run_2", 200),      # overlaps on run_2 with row 1
            ("10.0.0.0/24", "run_3", 300),      # overlaps on subnet with row 2
        ]
        with pytest.raises(ValueError, match="Group Constraint Collapse"):
            StrictGroupSplitter.compute_connected_groups(collapsed_tuples)


class TestScenarioLeakageProbe:
    def test_probe_detects_leaky_features(self) -> None:
        import numpy as np
        from trinetra.ml.group_split import probe_scenario_leakage

        # Feature matrix where column 0 directly encodes scenario identity
        rng = np.random.default_rng(42)
        scenario_labels = [0] * 30 + [1] * 30 + [2] * 30
        features = np.zeros((90, 3))
        # Leakage: feature 0 perfectly separates scenarios
        features[:, 0] = np.array(scenario_labels) + rng.normal(0, 0.01, size=90)
        features[:, 1] = rng.normal(0, 1, size=90)
        features[:, 2] = rng.normal(0, 1, size=90)

        with pytest.raises(ValueError, match="Scenario Leakage Detected"):
            probe_scenario_leakage(features, scenario_labels, max_allowed_accuracy=0.85)

    def test_probe_passes_on_non_leaky_features(self) -> None:
        import numpy as np
        from trinetra.ml.group_split import probe_scenario_leakage

        # Pure random noise with zero scenario correlation
        rng = np.random.default_rng(42)
        scenario_labels = [0] * 30 + [1] * 30 + [2] * 30
        features = rng.normal(0, 1, size=(90, 5))

        acc = probe_scenario_leakage(features, scenario_labels, max_allowed_accuracy=0.85)
        assert acc < 0.60

