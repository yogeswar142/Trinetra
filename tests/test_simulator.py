"""
tests/test_simulator.py

Tests for the synthetic feed simulator.

MANDATORY DIRECTION TESTS (from master_plan.md):
    1. DDoS scenario: attack traffic → INBOUND
    2. Exfil scenario: data transfer → OUTBOUND
    3. Scan scenario: probe traffic → INBOUND (scanner → target)

Also tests:
    - DNS tunnel scenario: DNS queries are OUTBOUND
    - Beaconing scenario: beacon flows are OUTBOUND
    - assert_direction_correctness() helper works correctly
    - Generated flows have correct protocol fields
    - Per-scenario topology isolation (attacker not in victim network)
"""
from __future__ import annotations

import pytest

from trinetra.config import DEFAULT_CONFIG, EnclaveConfig
from trinetra.schemas import Direction
from trinetra.simulator import (
    ALL_SCENARIOS,
    SCENARIO_BEACON,
    SCENARIO_DDOS_SYN_FLOOD,
    SCENARIO_DNS_TUNNEL,
    SCENARIO_EXFIL,
    SCENARIO_PORT_SCAN,
    SimulatorScenario,
    assert_direction_correctness,
    generate_beacon,
    generate_ddos_syn_flood,
    generate_dns_tunnel,
    generate_exfil,
    generate_port_scan,
)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------
def collect_flows(generator, max_count: int = 50) -> list:
    """Collect up to max_count flows from a generator."""
    flows = []
    for flow in generator:
        flows.append(flow)
        if len(flows) >= max_count:
            break
    return flows


# ---------------------------------------------------------------------------
# DDoS SYN flood — direction must be INBOUND
# ---------------------------------------------------------------------------
class TestDDoSSynFloodScenario:
    def test_ddos_flows_are_inbound(self) -> None:
        """
        MANDATORY TEST: DDoS attack traffic from attacker→victim must be INBOUND.
        Victim network = 10.0.1.0/24; attacker = 10.0.2.0/24.
        Without per-scenario override, both would be LATERAL (both RFC-1918).
        """
        gen = generate_ddos_syn_flood(SCENARIO_DDOS_SYN_FLOOD, DEFAULT_CONFIG)
        flows = collect_flows(gen, max_count=20)

        assert flows, "Generator produced no flows"
        assert_direction_correctness(flows, Direction.INBOUND, "ddos_syn_flood")

    def test_ddos_flows_are_tcp_syn(self) -> None:
        gen = generate_ddos_syn_flood(SCENARIO_DDOS_SYN_FLOOD, DEFAULT_CONFIG)
        flows = collect_flows(gen, max_count=10)

        for flow in flows:
            assert flow.protocol == "TCP"
            assert flow.tcp_flags is not None
            assert flow.tcp_flags["SYN"] is True
            assert flow.tcp_flags["ACK"] is False

    def test_ddos_source_ips_from_attacker_network(self) -> None:
        gen = generate_ddos_syn_flood(SCENARIO_DDOS_SYN_FLOOD, DEFAULT_CONFIG)
        flows = collect_flows(gen, max_count=20)

        for flow in flows:
            # Source must be in attacker network 10.0.2.0/24
            assert flow.src_ip.startswith("10.0.2."), (
                f"DDoS source IP {flow.src_ip} is not in attacker network 10.0.2.0/24"
            )
            # Destination must be in victim network 10.0.1.0/24
            assert flow.dst_ip.startswith("10.0.1."), (
                f"DDoS dest IP {flow.dst_ip} is not in victim network 10.0.1.0/24"
            )


# ---------------------------------------------------------------------------
# DNS tunnel — direction must be OUTBOUND
# ---------------------------------------------------------------------------
class TestDNSTunnelScenario:
    def test_dns_tunnel_flows_are_outbound(self) -> None:
        """
        DNS tunnel: internal compromised host → external C2 DNS server.
        Direction must be OUTBOUND.
        """
        gen = generate_dns_tunnel(SCENARIO_DNS_TUNNEL, DEFAULT_CONFIG)
        flows = collect_flows(gen, max_count=20)

        assert flows, "Generator produced no flows"
        assert_direction_correctness(flows, Direction.OUTBOUND, "dns_tunnel")

    def test_dns_tunnel_query_length_exceeds_threshold(self) -> None:
        """DNS tunnel queries must have query length > 35 chars (per detection spec)."""
        gen = generate_dns_tunnel(SCENARIO_DNS_TUNNEL, DEFAULT_CONFIG)
        flows = collect_flows(gen, max_count=20)

        for flow in flows:
            assert flow.dns_query is not None
            assert len(flow.dns_query) > 35, (
                f"DNS tunnel query {flow.dns_query!r} is too short ({len(flow.dns_query)} chars)"
            )

    def test_dns_tunnel_uses_txt_record_type(self) -> None:
        gen = generate_dns_tunnel(SCENARIO_DNS_TUNNEL, DEFAULT_CONFIG)
        flows = collect_flows(gen, max_count=10)
        for flow in flows:
            assert flow.dns_qtype == "TXT"

    def test_dns_tunnel_protocol_is_dns(self) -> None:
        gen = generate_dns_tunnel(SCENARIO_DNS_TUNNEL, DEFAULT_CONFIG)
        flows = collect_flows(gen, max_count=10)
        for flow in flows:
            assert flow.protocol == "DNS"


# ---------------------------------------------------------------------------
# C2 beaconing — direction must be OUTBOUND
# ---------------------------------------------------------------------------
class TestBeaconingScenario:
    def test_beacon_flows_are_outbound(self) -> None:
        """C2 beacon: internal infected host → external C2. Must be OUTBOUND."""
        gen = generate_beacon(
            SCENARIO_BEACON,
            DEFAULT_CONFIG,
            interval_seconds=5.0,  # Short for test
        )
        flows = collect_flows(gen, max_count=10)

        assert flows, "Generator produced no flows"
        assert_direction_correctness(flows, Direction.OUTBOUND, "c2_beaconing")

    def test_beacon_flows_are_small(self) -> None:
        """Beacon packets must be small (< 200 bytes)."""
        gen = generate_beacon(SCENARIO_BEACON, DEFAULT_CONFIG, interval_seconds=1.0)
        flows = collect_flows(gen, max_count=10)
        for flow in flows:
            assert flow.length < 200, f"Beacon packet too large: {flow.length} bytes"

    def test_beacon_flows_are_tcp(self) -> None:
        gen = generate_beacon(SCENARIO_BEACON, DEFAULT_CONFIG, interval_seconds=1.0)
        flows = collect_flows(gen, max_count=10)
        for flow in flows:
            assert flow.protocol == "TCP"


# ---------------------------------------------------------------------------
# Data exfiltration — direction must be OUTBOUND
# ---------------------------------------------------------------------------
class TestExfilScenario:
    def test_exfil_flows_are_outbound(self) -> None:
        """Exfiltration: internal host sends large chunks to external. Must be OUTBOUND."""
        gen = generate_exfil(SCENARIO_EXFIL, DEFAULT_CONFIG)
        flows = collect_flows(gen, max_count=10)

        assert flows, "Generator produced no flows"
        assert_direction_correctness(flows, Direction.OUTBOUND, "data_exfiltration")

    def test_exfil_flows_are_large(self) -> None:
        """Exfil flows must be large (indicates data transfer, not control)."""
        gen = generate_exfil(SCENARIO_EXFIL, DEFAULT_CONFIG, chunk_bytes=50_000)
        flows = collect_flows(gen, max_count=10)
        for flow in flows:
            assert flow.length > 10_000, f"Exfil flow too small: {flow.length} bytes"


# ---------------------------------------------------------------------------
# Port scan — direction must be INBOUND (scanner→target)
# ---------------------------------------------------------------------------
class TestPortScanScenario:
    def test_port_scan_flows_are_inbound(self) -> None:
        """
        MANDATORY TEST: Port scanner (10.2.0.x) → target (10.1.0.x).
        internal_networks = ["10.1.0.0/16"] (target only).
        Scanner is NOT in internal → scan probes are INBOUND.
        """
        gen = generate_port_scan(SCENARIO_PORT_SCAN, DEFAULT_CONFIG)
        flows = collect_flows(gen, max_count=30)

        assert flows, "Generator produced no flows"
        assert_direction_correctness(flows, Direction.INBOUND, "port_scan")

    def test_port_scan_covers_many_ports(self) -> None:
        gen = generate_port_scan(SCENARIO_PORT_SCAN, DEFAULT_CONFIG)
        flows = collect_flows(gen, max_count=100)
        ports = {f.dst_port for f in flows}
        assert len(ports) > 10, f"Port scan should cover many ports, got {len(ports)}"

    def test_port_scan_flows_are_tcp_syn(self) -> None:
        gen = generate_port_scan(SCENARIO_PORT_SCAN, DEFAULT_CONFIG)
        flows = collect_flows(gen, max_count=20)
        for flow in flows:
            assert flow.protocol == "TCP"
            assert flow.tcp_flags is not None
            assert flow.tcp_flags["SYN"] is True


# ---------------------------------------------------------------------------
# assert_direction_correctness helper
# ---------------------------------------------------------------------------
class TestAssertDirectionCorrectness:
    def test_passes_when_all_flows_have_expected_direction(self) -> None:
        gen = generate_ddos_syn_flood(SCENARIO_DDOS_SYN_FLOOD, DEFAULT_CONFIG)
        flows = collect_flows(gen, max_count=10)
        # Should not raise
        assert_direction_correctness(flows, Direction.INBOUND, "test")

    def test_raises_when_direction_wrong(self) -> None:
        gen = generate_ddos_syn_flood(SCENARIO_DDOS_SYN_FLOOD, DEFAULT_CONFIG)
        flows = collect_flows(gen, max_count=10)

        with pytest.raises(AssertionError, match="wrong direction"):
            assert_direction_correctness(flows, Direction.OUTBOUND, "test")


# ---------------------------------------------------------------------------
# Scenario metadata
# ---------------------------------------------------------------------------
class TestScenarioMetadata:
    def test_all_scenarios_have_names(self) -> None:
        for scenario in ALL_SCENARIOS:
            assert scenario.name, f"Scenario missing name: {scenario}"

    def test_all_scenarios_have_topology(self) -> None:
        for scenario in ALL_SCENARIOS:
            assert scenario.topology, f"Scenario {scenario.name} missing topology"
            assert scenario.topology.internal_networks, (
                f"Scenario {scenario.name} has no internal_networks"
            )
            assert scenario.topology.attacker_networks, (
                f"Scenario {scenario.name} has no attacker_networks"
            )

    def test_attacker_and_victim_are_in_different_subnets(self) -> None:
        """Attacker networks must NOT overlap with victim internal_networks."""
        from ipaddress import ip_network
        for scenario in ALL_SCENARIOS:
            victim_nets = [ip_network(n, strict=False) for n in scenario.topology.internal_networks]
            attacker_nets = [ip_network(n, strict=False) for n in scenario.topology.attacker_networks]
            for v_net in victim_nets:
                for a_net in attacker_nets:
                    assert not v_net.overlaps(a_net), (
                        f"Scenario {scenario.name}: victim {v_net} overlaps attacker {a_net}. "
                        f"Direction labels will be wrong (LATERAL instead of INBOUND/OUTBOUND)."
                    )

    def test_ingest_source_is_simulator(self) -> None:
        gen = generate_ddos_syn_flood(SCENARIO_DDOS_SYN_FLOOD, DEFAULT_CONFIG)
        flows = collect_flows(gen, max_count=5)
        for flow in flows:
            assert flow.ingest_source == "simulator"


# ---------------------------------------------------------------------------
# Encrypted Malware TLS Scenario (T-d)
# ---------------------------------------------------------------------------
class TestEncryptedMalwareTLSScenario:
    def test_malware_tls_flows_are_outbound(self) -> None:
        from trinetra.simulator import SCENARIO_ENCRYPTED_MALWARE_TLS, generate_encrypted_malware_tls
        gen = generate_encrypted_malware_tls(SCENARIO_ENCRYPTED_MALWARE_TLS, DEFAULT_CONFIG)
        flows = collect_flows(gen, max_count=10)
        assert flows
        assert_direction_correctness(flows, Direction.OUTBOUND, "encrypted_malware_tls")

    def test_malware_tls_has_ja3_and_sni(self) -> None:
        from trinetra.simulator import SCENARIO_ENCRYPTED_MALWARE_TLS, generate_encrypted_malware_tls
        gen = generate_encrypted_malware_tls(SCENARIO_ENCRYPTED_MALWARE_TLS, DEFAULT_CONFIG)
        flows = collect_flows(gen, max_count=5)
        for f in flows:
            assert f.tls_ja3 is not None
            assert f.tls_sni is not None
            assert f.tls_cert_self_signed is True


# ---------------------------------------------------------------------------
# Deterministic Emission & Real PCAP Generation
# ---------------------------------------------------------------------------
class TestEmissionAndPcapGeneration:
    def test_emit_scenario_flows_is_deterministic(self) -> None:
        from trinetra.simulator import emit_scenario_flows, SCENARIO_DDOS_SYN_FLOOD
        flows1 = emit_scenario_flows(SCENARIO_DDOS_SYN_FLOOD, max_flows=15)
        flows2 = emit_scenario_flows(SCENARIO_DDOS_SYN_FLOOD, max_flows=15)
        assert len(flows1) == 15
        assert len(flows2) == 15
        for f1, f2 in zip(flows1, flows2):
            assert f1.src_ip == f2.src_ip
            assert f1.dst_ip == f2.dst_ip
            assert f1.src_port == f2.src_port
            assert f1.timestamp == f2.timestamp

    def test_emit_scenario_pcap_creates_valid_pcap(self, tmp_path: Path) -> None:
        import dpkt
        from trinetra.simulator import emit_scenario_pcap, SCENARIO_DDOS_SYN_FLOOD
        pcap_path = tmp_path / "test_ddos.pcap"
        emit_scenario_pcap(SCENARIO_DDOS_SYN_FLOOD, pcap_path, max_packets=20)
        assert pcap_path.exists()
        assert pcap_path.stat().st_size > 0

        # Read back with dpkt.pcap.Reader to verify it's a real valid PCAP
        with open(pcap_path, "rb") as f:
            reader = dpkt.pcap.Reader(f)
            packets = list(reader)
            assert len(packets) == 20
            ts, buf = packets[0]
            eth = dpkt.ethernet.Ethernet(buf)
            assert isinstance(eth.data, dpkt.ip.IP)
            assert isinstance(eth.data.data, dpkt.tcp.TCP)

