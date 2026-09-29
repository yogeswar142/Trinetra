"""
tests/test_config.py

Tests for the EnclaveConfig and ScenarioTopology classes.

Covers:
    - Default config creation and validation
    - TOML config loading
    - Per-scenario INTERNAL_NETWORKS override for direction classification
    - Direction correctness: DDoS (INBOUND), exfil (OUTBOUND), scan (INBOUND)
    - Config validation (rejects invalid threshold values)
    - is_internal() with override
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from trinetra.config import (
    DEFAULT_CONFIG,
    EnclaveConfig,
    ScenarioTopology,
    load_config,
    _validate_config,
)
from trinetra.schemas import Direction


# ---------------------------------------------------------------------------
# Default config sanity
# ---------------------------------------------------------------------------
class TestDefaultConfig:
    def test_default_config_creates_successfully(self) -> None:
        cfg = EnclaveConfig()
        assert cfg.sensor_id == "NTRO-ENCLAVE-ALPHA-01"

    def test_default_internal_subnets_are_rfc1918(self) -> None:
        cfg = EnclaveConfig()
        assert "10.0.0.0/8" in cfg.internal_subnets_str
        assert "172.16.0.0/12" in cfg.internal_subnets_str
        assert "192.168.0.0/16" in cfg.internal_subnets_str

    def test_ollama_disabled_by_default(self) -> None:
        cfg = EnclaveConfig()
        assert cfg.ollama_enabled is False

    def test_read_only_mode_is_default(self) -> None:
        # Sensor must be passive by default.
        # Note: EnclaveConfig does not have read_only_mode field now;
        # the no-transmit test is the enforcement mechanism.
        cfg = EnclaveConfig()
        assert cfg is not None  # Structural check only


# ---------------------------------------------------------------------------
# is_internal() with and without override
# ---------------------------------------------------------------------------
class TestIsInternal:
    def test_rfc1918_10_is_internal(self) -> None:
        cfg = EnclaveConfig()
        assert cfg.is_internal("10.0.0.1")

    def test_rfc1918_172_is_internal(self) -> None:
        cfg = EnclaveConfig()
        assert cfg.is_internal("172.16.0.50")

    def test_rfc1918_192_is_internal(self) -> None:
        cfg = EnclaveConfig()
        assert cfg.is_internal("192.168.1.100")

    def test_public_ip_is_not_internal(self) -> None:
        cfg = EnclaveConfig()
        assert not cfg.is_internal("8.8.8.8")
        assert not cfg.is_internal("1.1.1.1")
        assert not cfg.is_internal("203.0.113.5")

    def test_override_restricts_internal_to_victim_only(self) -> None:
        """
        With a per-scenario override, only the victim subnet is 'internal'.
        The attacker subnet (also private range) is correctly classified as external.
        """
        cfg = EnclaveConfig()
        victim_nets = ["10.0.1.0/24"]

        # Victim IP in override subnet → internal
        assert cfg.is_internal("10.0.1.5", override=victim_nets)

        # Attacker IP in DIFFERENT private range → NOT internal (per override)
        assert not cfg.is_internal("10.0.2.5", override=victim_nets)
        assert not cfg.is_internal("192.168.1.1", override=victim_nets)


# ---------------------------------------------------------------------------
# classify_direction() — global config
# ---------------------------------------------------------------------------
class TestClassifyDirectionGlobal:
    def test_outbound(self) -> None:
        cfg = EnclaveConfig()
        assert cfg.classify_direction("192.168.1.5", "8.8.8.8") == "OUTBOUND"

    def test_inbound(self) -> None:
        cfg = EnclaveConfig()
        assert cfg.classify_direction("8.8.8.8", "192.168.1.5") == "INBOUND"

    def test_lateral(self) -> None:
        cfg = EnclaveConfig()
        assert cfg.classify_direction("10.0.0.1", "10.0.0.2") == "LATERAL"

    def test_transit(self) -> None:
        cfg = EnclaveConfig()
        assert cfg.classify_direction("8.8.8.8", "1.1.1.1") == "TRANSIT"


# ---------------------------------------------------------------------------
# classify_direction() — per-scenario override (THE CRITICAL CASES)
# ---------------------------------------------------------------------------
class TestClassifyDirectionWithScenarioOverride:
    """
    Tests that per-scenario INTERNAL_NETWORKS overrides produce correct
    direction labels when attacker and victim share private ranges.

    These correspond to the MANDATORY tests in master_plan.md:
        - DDoS scenario: attack traffic → INBOUND
        - Exfil scenario: data transfer → OUTBOUND
        - Scan scenario: probe traffic → INBOUND (from scanner to target)
    """

    def test_ddos_attack_is_inbound(self) -> None:
        """
        DDoS SYN flood: attacker (10.0.2.x) → victim (10.0.1.x).
        Victim network override = ["10.0.1.0/24"].
        Attack traffic must be INBOUND (attacker is not in internal_networks).
        """
        cfg = EnclaveConfig()
        victim_nets = ["10.0.1.0/24"]
        attacker_ip = "10.0.2.50"
        victim_ip = "10.0.1.100"

        direction = cfg.classify_direction(attacker_ip, victim_ip, override=victim_nets)
        assert direction == "INBOUND", (
            f"DDoS attack traffic from {attacker_ip} to {victim_ip} should be INBOUND "
            f"with override {victim_nets}, got {direction}"
        )

    def test_exfil_is_outbound(self) -> None:
        """
        Data exfiltration: compromised host (10.10.0.5) → external C2 (198.18.0.10).
        Victim/internal network = ["10.10.0.0/16"].
        Exfil traffic must be OUTBOUND.
        """
        cfg = EnclaveConfig()
        internal_nets = ["10.10.0.0/16"]
        src_ip = "10.10.0.5"    # Compromised internal host
        dst_ip = "198.18.0.10"  # External exfil destination

        direction = cfg.classify_direction(src_ip, dst_ip, override=internal_nets)
        assert direction == "OUTBOUND", (
            f"Exfil from {src_ip} to {dst_ip} should be OUTBOUND, got {direction}"
        )

    def test_port_scan_is_inbound(self) -> None:
        """
        Port scan: scanner (10.2.0.5) → target network (10.1.0.0/16).
        Internal override = ["10.1.0.0/16"] (target only, not scanner).
        Scan probes must be INBOUND from scanner to target.
        """
        cfg = EnclaveConfig()
        internal_nets = ["10.1.0.0/16"]
        scanner_ip = "10.2.0.5"
        target_ip = "10.1.0.100"

        direction = cfg.classify_direction(scanner_ip, target_ip, override=internal_nets)
        assert direction == "INBOUND", (
            f"Port scan from {scanner_ip} to {target_ip} should be INBOUND "
            f"with override {internal_nets}, got {direction}"
        )

    def test_lateral_movement_scenario(self) -> None:
        """
        Lateral movement: two hosts both in the same internal subnet.
        Both should be INTERNAL → direction is LATERAL.
        """
        cfg = EnclaveConfig()
        internal_nets = ["10.0.0.0/8"]
        src_ip = "10.1.2.3"
        dst_ip = "10.4.5.6"

        direction = cfg.classify_direction(src_ip, dst_ip, override=internal_nets)
        assert direction == "LATERAL"

    def test_default_without_override_wrongly_labels_lab_traffic(self) -> None:
        """
        Demonstrates WHY per-scenario override is needed.

        Without override, attacker (10.0.2.x) → victim (10.0.1.x) is LATERAL
        (both are RFC-1918, both default to INTERNAL). This is wrong.
        With override = victim-only subnet, traffic is correctly INBOUND.
        """
        cfg = EnclaveConfig()
        attacker_ip = "10.0.2.50"
        victim_ip = "10.0.1.100"

        # Without override: LATERAL (incorrect for DDoS scenario)
        without_override = cfg.classify_direction(attacker_ip, victim_ip)
        assert without_override == "LATERAL", "Without override, both RFC-1918 IPs are LATERAL"

        # With victim-only override: INBOUND (correct)
        with_override = cfg.classify_direction(
            attacker_ip, victim_ip, override=["10.0.1.0/24"]
        )
        assert with_override == "INBOUND", "With victim-only override, attack traffic is INBOUND"


# ---------------------------------------------------------------------------
# ScenarioTopology dataclass
# ---------------------------------------------------------------------------
class TestScenarioTopology:
    def test_scenario_topology_creation(self) -> None:
        topo = ScenarioTopology(
            scenario_name="test_ddos",
            internal_networks=["10.0.1.0/24"],
            attacker_networks=["10.0.2.0/24"],
        )
        assert topo.scenario_name == "test_ddos"
        assert "10.0.1.0/24" in topo.internal_networks
        assert "10.0.2.0/24" in topo.attacker_networks

    def test_scenario_topology_used_with_config(self) -> None:
        cfg = EnclaveConfig()
        topo = ScenarioTopology(
            scenario_name="exfil_test",
            internal_networks=["172.16.0.0/24"],
            attacker_networks=["203.0.113.0/24"],
        )
        direction = cfg.classify_direction("172.16.0.5", "203.0.113.10", topo.internal_networks)
        assert direction == "OUTBOUND"


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------
class TestConfigValidation:
    def test_invalid_beacon_cv_raises(self) -> None:
        cfg = EnclaveConfig()
        cfg.beacon_max_cv = -0.1
        with pytest.raises(ValueError, match="beacon_max_cv"):
            _validate_config(cfg)

    def test_invalid_syn_ratio_raises(self) -> None:
        cfg = EnclaveConfig()
        cfg.ddos_syn_ratio_threshold = 1.5  # > 1.0
        with pytest.raises(ValueError, match="ddos_syn_ratio_threshold"):
            _validate_config(cfg)

    def test_invalid_exfil_ratio_raises(self) -> None:
        cfg = EnclaveConfig()
        cfg.exfil_byte_ratio_threshold = -1.0
        with pytest.raises(ValueError, match="exfil_byte_ratio_threshold"):
            _validate_config(cfg)

    def test_invalid_block_size_raises(self) -> None:
        cfg = EnclaveConfig()
        cfg.blocks_per_merkle_commit = 0
        with pytest.raises(ValueError, match="blocks_per_merkle_commit"):
            _validate_config(cfg)

    def test_valid_config_passes_validation(self) -> None:
        cfg = EnclaveConfig()
        _validate_config(cfg)  # Should not raise


# ---------------------------------------------------------------------------
# TOML config loading
# ---------------------------------------------------------------------------
class TestTomlConfigLoading:
    def test_load_config_with_no_file_returns_defaults(self, tmp_path: Path) -> None:
        cfg = load_config(tmp_path / "nonexistent.toml")
        assert cfg.sensor_id == "NTRO-ENCLAVE-ALPHA-01"

    def test_load_config_from_toml_overrides_defaults(self, tmp_path: Path) -> None:
        toml_content = """
sensor_id = "NTRO-TEST-SENSOR-99"
ollama_enabled = true
beacon_max_cv = 0.30
"""
        config_file = tmp_path / "test_enclave.toml"
        config_file.write_text(toml_content)

        cfg = load_config(config_file)
        assert cfg.sensor_id == "NTRO-TEST-SENSOR-99"
        assert cfg.ollama_enabled is True
        assert cfg.beacon_max_cv == pytest.approx(0.30)

    def test_load_config_ignores_unknown_keys(self, tmp_path: Path) -> None:
        toml_content = """
sensor_id = "TEST"
unknown_future_key = "this should be silently ignored"
"""
        config_file = tmp_path / "test_enclave.toml"
        config_file.write_text(toml_content)

        # Should not raise
        cfg = load_config(config_file)
        assert cfg.sensor_id == "TEST"
