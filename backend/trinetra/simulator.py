"""
Trinetra Synthetic Feed Simulator.

Generates synthetic network traffic scenarios for testing and benchmarking.
Each scenario has its own ScenarioTopology config so that direction labels
(INBOUND/OUTBOUND/LATERAL) are correct even when attacker and victim share
private IP ranges.

DESIGN PHILOSOPHY:
    - Detectors are NEVER tested solely on synthetic data.
    - Synthetic data is used for: unit tests, CI smoke tests, and pipeline
      latency benchmarks.
    - Real-PCAP datasets (CTU-13, CIC-IDS, malware-traffic-analysis.net)
      are used for final model training and evaluation.
    - Metrics from synthetic data are reported separately with a clear
      "SYNTHETIC — may not reflect real-world performance" disclaimer.

DIRECTION LABELLING REQUIREMENT:
    Every scenario specifies:
        internal_networks: victim-only subnets
        attacker_networks: source of attack traffic (NOT in internal_networks)

    This ensures:
        DDoS scenario   → attack traffic is INBOUND
        Exfil scenario  → data transfer is OUTBOUND
        Scan scenario   → probe traffic has correct direction per topology
"""
from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Iterator

from trinetra.config import EnclaveConfig, ScenarioTopology
from trinetra.schemas import Direction, FlowEvent


# ---------------------------------------------------------------------------
# Scenario definitions
# ---------------------------------------------------------------------------
@dataclass
class SimulatorScenario:
    """
    A named synthetic traffic scenario with topology and generation parameters.

    Attributes:
        name: Human-readable scenario name.
        topology: Per-scenario network topology (victim vs attacker networks).
        description: What this scenario tests.
        flow_rate_hz: Target flow generation rate in flows/second.
        duration_seconds: Total scenario duration.
    """
    name: str
    topology: ScenarioTopology
    description: str = ""
    flow_rate_hz: float = 1000.0
    duration_seconds: float = 10.0
    rng_seed: int = 42


# ---------------------------------------------------------------------------
# Canonical test scenarios
# ---------------------------------------------------------------------------
SCENARIO_DDOS_SYN_FLOOD = SimulatorScenario(
    name="ddos_syn_flood",
    topology=ScenarioTopology(
        scenario_name="ddos_syn_flood",
        internal_networks=["10.0.1.0/24"],      # Victim subnet
        attacker_networks=["10.0.2.0/24"],      # External (not in internal)
        description=(
            "SYN flood from multiple attacker IPs in 10.0.2.0/24 "
            "targeting victim in 10.0.1.0/24. All attack traffic is INBOUND."
        ),
    ),
    description="High-volume SYN flood DDoS scenario (T-a)",
    flow_rate_hz=5000.0,
    duration_seconds=5.0,
)

SCENARIO_DNS_TUNNEL = SimulatorScenario(
    name="dns_tunnel",
    topology=ScenarioTopology(
        scenario_name="dns_tunnel",
        internal_networks=["192.168.10.0/24"],  # Compromised internal host
        attacker_networks=["198.51.100.0/24"],  # External C2 server
        description=(
            "Compromised host in 192.168.10.0/24 tunnelling data via DNS "
            "to external C2 at 198.51.100.0/24. Traffic is OUTBOUND."
        ),
    ),
    description="DNS tunnelling C2 exfil scenario (T-c)",
    flow_rate_hz=100.0,
    duration_seconds=30.0,
)

SCENARIO_BEACON = SimulatorScenario(
    name="c2_beaconing",
    topology=ScenarioTopology(
        scenario_name="c2_beaconing",
        internal_networks=["172.16.0.0/24"],    # Infected host network
        attacker_networks=["203.0.113.0/24"],   # Public C2 server range
        description=(
            "Infected host in 172.16.0.0/24 beaconing to C2 server in "
            "203.0.113.0/24. Beacon traffic is OUTBOUND."
        ),
    ),
    description="Regular C2 beaconing (T-b)",
    flow_rate_hz=0.1,     # ~1 beacon per 10 seconds
    duration_seconds=120.0,
)

SCENARIO_EXFIL = SimulatorScenario(
    name="data_exfiltration",
    topology=ScenarioTopology(
        scenario_name="data_exfiltration",
        internal_networks=["10.10.0.0/16"],     # Corporate internal network
        attacker_networks=["198.18.0.0/24"],    # External exfil destination
        description=(
            "Compromised host in 10.10.0.0/16 exfiltrating data to "
            "198.18.0.0/24. High egress/ingress byte ratio. OUTBOUND."
        ),
    ),
    description="Data exfiltration scenario (T-f)",
    flow_rate_hz=10.0,
    duration_seconds=60.0,
)

SCENARIO_PORT_SCAN = SimulatorScenario(
    name="port_scan",
    topology=ScenarioTopology(
        scenario_name="port_scan",
        internal_networks=["10.1.0.0/16"],      # Target network
        attacker_networks=["10.2.0.0/24"],      # Scanner (NOT in internal)
        description=(
            "Port scanner in 10.2.0.0/24 scanning targets in 10.1.0.0/16. "
            "Traffic is INBOUND from the scanner's perspective."
        ),
    ),
    description="Port scan / reconnaissance scenario (T-e)",
    flow_rate_hz=2000.0,
    duration_seconds=5.0,
)

ALL_SCENARIOS = [
    SCENARIO_DDOS_SYN_FLOOD,
    SCENARIO_DNS_TUNNEL,
    SCENARIO_BEACON,
    SCENARIO_EXFIL,
    SCENARIO_PORT_SCAN,
]


# ---------------------------------------------------------------------------
# Flow generators per scenario
# ---------------------------------------------------------------------------
def _random_ip(subnet: str, rng: random.Random) -> str:
    """Generate a random IP within a /24 subnet string."""
    base = ".".join(subnet.split(".")[:3])
    return f"{base}.{rng.randint(1, 254)}"


def generate_ddos_syn_flood(
    scenario: SimulatorScenario,
    config: EnclaveConfig,
) -> Iterator[FlowEvent]:
    """
    Generate SYN flood packets.

    Produces high-volume TCP SYN packets from spoofed attacker IPs to a victim IP.
    Expected direction: INBOUND.
    Expected detection signals: high syn_ratio, high pps, high src_entropy.
    """
    rng = random.Random(scenario.rng_seed)
    victim_ip = _random_ip(scenario.topology.internal_networks[0], rng)
    t = time.time()
    end_t = t + scenario.duration_seconds
    interval = 1.0 / scenario.flow_rate_hz

    while t < end_t:
        attacker_ip = _random_ip(scenario.topology.attacker_networks[0], rng)
        direction = config.classify_direction(
            attacker_ip, victim_ip, scenario.topology.internal_networks
        )
        yield FlowEvent(
            timestamp=t,
            src_ip=attacker_ip,
            src_port=rng.randint(1024, 65535),
            dst_ip=victim_ip,
            dst_port=80,
            protocol="TCP",
            length=60,
            tcp_flags={"SYN": True, "ACK": False, "FIN": False, "RST": False},
            tcp_seq=rng.randint(0, 2**32 - 1),
            direction=Direction(direction),
            ingest_source="simulator",
        )
        t += interval + rng.gauss(0, interval * 0.05)  # Small jitter


def generate_dns_tunnel(
    scenario: SimulatorScenario,
    config: EnclaveConfig,
) -> Iterator[FlowEvent]:
    """
    Generate DNS tunnelling queries.

    Produces high-entropy, long-label DNS TXT queries from internal host to external C2.
    Expected direction: OUTBOUND.
    Expected detection signals: high subdomain entropy, query length > 35, TXT record ratio.
    """
    rng = random.Random(scenario.rng_seed)
    src_ip = _random_ip(scenario.topology.internal_networks[0], rng)
    dst_ip = _random_ip(scenario.topology.attacker_networks[0], rng)
    domain = "c2tunnel.example.com"
    t = time.time()
    end_t = t + scenario.duration_seconds
    interval = 1.0 / scenario.flow_rate_hz

    while t < end_t:
        # Generate a high-entropy random subdomain (mimics iodine/dnscat2)
        label_len = rng.randint(36, 63)
        label = "".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=label_len))
        query = f"{label}.{domain}"
        direction = config.classify_direction(src_ip, dst_ip, scenario.topology.internal_networks)
        yield FlowEvent(
            timestamp=t,
            src_ip=src_ip,
            src_port=rng.randint(1024, 65535),
            dst_ip=dst_ip,
            dst_port=53,
            protocol="DNS",
            length=len(query) + 12,  # Approximate DNS packet size
            dns_query=query,
            dns_qtype="TXT",
            dns_is_response=False,
            direction=Direction(direction),
            ingest_source="simulator",
        )
        t += interval + rng.gauss(0, interval * 0.1)


def generate_beacon(
    scenario: SimulatorScenario,
    config: EnclaveConfig,
    interval_seconds: float = 60.0,
    jitter_pct: float = 0.05,
) -> Iterator[FlowEvent]:
    """
    Generate regular C2 beacon flows.

    Produces small TCP flows at a regular interval with low IAT variance.
    Expected direction: OUTBOUND.
    Expected detection signals: low CV (< beacon_max_cv), autocorrelation peak.

    Args:
        interval_seconds: Base beacon interval in seconds.
        jitter_pct: Jitter fraction applied to interval (0.05 = ±5%).
    """
    rng = random.Random(scenario.rng_seed)
    src_ip = _random_ip(scenario.topology.internal_networks[0], rng)
    dst_ip = _random_ip(scenario.topology.attacker_networks[0], rng)
    t = time.time()
    end_t = t + scenario.duration_seconds

    while t < end_t:
        direction = config.classify_direction(src_ip, dst_ip, scenario.topology.internal_networks)
        yield FlowEvent(
            timestamp=t,
            src_ip=src_ip,
            src_port=rng.randint(1024, 65535),
            dst_ip=dst_ip,
            dst_port=443,
            protocol="TCP",
            length=rng.randint(80, 150),   # Small beacon packet
            tcp_flags={"SYN": False, "ACK": True, "FIN": False, "RST": False},
            direction=Direction(direction),
            ingest_source="simulator",
        )
        jitter = rng.gauss(0, interval_seconds * jitter_pct)
        t += interval_seconds + jitter


def generate_exfil(
    scenario: SimulatorScenario,
    config: EnclaveConfig,
    chunk_bytes: int = 50_000,
) -> Iterator[FlowEvent]:
    """
    Generate data exfiltration flows.

    Produces large outbound TCP flows with high egress/ingress byte ratio.
    Expected direction: OUTBOUND.
    Expected detection signals: R_byte > exfil_byte_ratio_threshold, large cumulative bytes.
    """
    rng = random.Random(scenario.rng_seed)
    src_ip = _random_ip(scenario.topology.internal_networks[0], rng)
    dst_ip = _random_ip(scenario.topology.attacker_networks[0], rng)
    t = time.time()
    end_t = t + scenario.duration_seconds
    interval = 1.0 / scenario.flow_rate_hz

    while t < end_t:
        direction = config.classify_direction(src_ip, dst_ip, scenario.topology.internal_networks)
        yield FlowEvent(
            timestamp=t,
            src_ip=src_ip,
            src_port=rng.randint(1024, 65535),
            dst_ip=dst_ip,
            dst_port=rng.choice([443, 8443, 4444]),
            protocol="TCP",
            length=chunk_bytes + rng.randint(-1000, 1000),
            direction=Direction(direction),
            ingest_source="simulator",
        )
        t += interval + rng.gauss(0, interval * 0.2)


def generate_port_scan(
    scenario: SimulatorScenario,
    config: EnclaveConfig,
) -> Iterator[FlowEvent]:
    """
    Generate port scan flows (SYN to many ports on target IPs).

    Expected detection signals: high dst_port_count per src, high SYN ratio, low SYN-ACK rate.
    """
    rng = random.Random(scenario.rng_seed)
    scanner_ip = _random_ip(scenario.topology.attacker_networks[0], rng)
    t = time.time()
    end_t = t + scenario.duration_seconds
    interval = 1.0 / scenario.flow_rate_hz
    port_cycle = list(range(1, 1025))  # Scan first 1024 ports

    for port in port_cycle:
        if t >= end_t:
            break
        target_ip = _random_ip(scenario.topology.internal_networks[0], rng)
        direction = config.classify_direction(
            scanner_ip, target_ip, scenario.topology.internal_networks
        )
        yield FlowEvent(
            timestamp=t,
            src_ip=scanner_ip,
            src_port=rng.randint(40000, 65535),
            dst_ip=target_ip,
            dst_port=port,
            protocol="TCP",
            length=60,
            tcp_flags={"SYN": True, "ACK": False, "FIN": False, "RST": False},
            direction=Direction(direction),
            ingest_source="simulator",
        )
        t += interval


# ---------------------------------------------------------------------------
# Direction correctness assertions (used in tests)
# ---------------------------------------------------------------------------
def assert_direction_correctness(
    flows: list[FlowEvent],
    expected_direction: Direction,
    scenario_name: str,
) -> None:
    """
    Assert that ALL flows in a scenario have the expected direction label.

    This function is used in tests/test_simulator.py to verify that per-scenario
    topology overrides produce correct direction labels for DDoS (INBOUND),
    exfil (OUTBOUND), and scan (INBOUND) scenarios.

    Args:
        flows: List of generated FlowEvent records.
        expected_direction: The Direction enum value all flows should have.
        scenario_name: Used in assertion error messages.

    Raises:
        AssertionError if any flow has an unexpected direction.
    """
    wrong = [f for f in flows if f.direction != expected_direction]
    if wrong:
        raise AssertionError(
            f"Scenario '{scenario_name}': {len(wrong)}/{len(flows)} flows have wrong direction. "
            f"Expected {expected_direction.value}. First offender: "
            f"src={wrong[0].src_ip}, dst={wrong[0].dst_ip}, dir={wrong[0].direction}"
        )
