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

import ipaddress
import random
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

import dpkt

from trinetra.config import DEFAULT_CONFIG, EnclaveConfig, ScenarioTopology
from trinetra.schemas import Direction, FlowEvent, ThreatClass


# ---------------------------------------------------------------------------
# Scenario definitions
# ---------------------------------------------------------------------------
@dataclass
class SimulatorScenario:
    """
    A named synthetic traffic scenario with topology and generation parameters.

    Attributes:
        name: Human-readable scenario name.
        threat_class: Mapped threat category (T-a to T-f).
        topology: Per-scenario network topology (victim vs attacker networks).
        description: What this scenario tests.
        flow_rate_hz: Target flow generation rate in flows/second.
        duration_seconds: Total scenario duration.
        rng_seed: Fixed random seed for deterministic generation.
    """
    name: str
    threat_class: ThreatClass
    topology: ScenarioTopology
    description: str = ""
    flow_rate_hz: float = 1000.0
    duration_seconds: float = 10.0
    rng_seed: int = 42


# ---------------------------------------------------------------------------
# Canonical test scenarios (Covers ALL T-a through T-f)
# ---------------------------------------------------------------------------
SCENARIO_DDOS_SYN_FLOOD = SimulatorScenario(
    name="ddos_syn_flood",
    threat_class=ThreatClass.VOLUMETRIC_DDOS,
    topology=ScenarioTopology(
        scenario_name="ddos_syn_flood",
        internal_networks=["10.0.1.0/24"],      # Victim subnet
        attacker_networks=["10.0.2.0/24"],      # External attacker
        description=(
            "SYN flood from multiple attacker IPs in 10.0.2.0/24 "
            "targeting victim in 10.0.1.0/24. All attack traffic is INBOUND."
        ),
    ),
    description="High-volume SYN flood DDoS scenario (T-a)",
    flow_rate_hz=5000.0,
    duration_seconds=5.0,
    rng_seed=42,
)

SCENARIO_BEACON = SimulatorScenario(
    name="c2_beaconing",
    threat_class=ThreatClass.BOTNET_C2_BEACONING,
    topology=ScenarioTopology(
        scenario_name="c2_beaconing",
        internal_networks=["172.16.0.0/24"],    # Infected internal host
        attacker_networks=["203.0.113.0/24"],   # Public C2 server range
        description=(
            "Infected host in 172.16.0.0/24 beaconing to external C2 in "
            "203.0.113.0/24. Beacon traffic is OUTBOUND."
        ),
    ),
    description="Regular C2 beaconing (T-b)",
    flow_rate_hz=1.0,
    duration_seconds=30.0,
    rng_seed=101,
)

SCENARIO_DNS_TUNNEL = SimulatorScenario(
    name="dns_tunnel",
    threat_class=ThreatClass.DNS_TUNNELLING,
    topology=ScenarioTopology(
        scenario_name="dns_tunnel",
        internal_networks=["192.168.10.0/24"],  # Compromised internal host
        attacker_networks=["198.51.100.0/24"],  # External C2 DNS server
        description=(
            "Compromised host in 192.168.10.0/24 tunnelling data via DNS "
            "to external C2 at 198.51.100.0/24. Traffic is OUTBOUND."
        ),
    ),
    description="DNS tunnelling C2 exfil scenario (T-c)",
    flow_rate_hz=100.0,
    duration_seconds=10.0,
    rng_seed=202,
)

SCENARIO_ENCRYPTED_MALWARE_TLS = SimulatorScenario(
    name="encrypted_malware_tls",
    threat_class=ThreatClass.ENCRYPTED_MALWARE_TLS,
    topology=ScenarioTopology(
        scenario_name="encrypted_malware_tls",
        internal_networks=["192.168.50.0/24"],  # Infected internal endpoint
        attacker_networks=["198.51.100.0/24"],  # C2 / malware drop site
        description=(
            "Infected host establishing TLS connection with known malicious "
            "Cobalt Strike JA3 fingerprint and rigid PST sequence. OUTBOUND."
        ),
    ),
    description="Malware in Encrypted TLS Session (T-d)",
    flow_rate_hz=5.0,
    duration_seconds=10.0,
    rng_seed=303,
)

SCENARIO_PORT_SCAN = SimulatorScenario(
    name="port_scan",
    threat_class=ThreatClass.PORT_SCANNING,
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
    rng_seed=404,
)

SCENARIO_EXFIL = SimulatorScenario(
    name="data_exfiltration",
    threat_class=ThreatClass.DATA_EXFILTRATION,
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
    duration_seconds=10.0,
    rng_seed=505,
)

ALL_SCENARIOS = [
    SCENARIO_DDOS_SYN_FLOOD,
    SCENARIO_BEACON,
    SCENARIO_DNS_TUNNEL,
    SCENARIO_ENCRYPTED_MALWARE_TLS,
    SCENARIO_PORT_SCAN,
    SCENARIO_EXFIL,
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
    base_time: float = 1700000000.0,
) -> Iterator[FlowEvent]:
    """
    Generate SYN flood packets.
    Expected direction: INBOUND.
    """
    rng = random.Random(scenario.rng_seed)
    victim_ip = _random_ip(scenario.topology.internal_networks[0], rng)
    t = base_time
    end_t = t + scenario.duration_seconds
    interval = 1.0 / scenario.flow_rate_hz

    while t < end_t:
        attacker_ip = _random_ip(scenario.topology.attacker_networks[0], rng)
        direction = config.classify_direction(
            attacker_ip, victim_ip, scenario.topology.internal_networks
        )
        yield FlowEvent(
            timestamp=round(t, 6),
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
        t += interval + rng.uniform(0, interval * 0.05)


def generate_beacon(
    scenario: SimulatorScenario,
    config: EnclaveConfig,
    base_time: float = 1700000000.0,
    interval_seconds: float = 5.0,
    jitter_pct: float = 0.05,
) -> Iterator[FlowEvent]:
    """
    Generate regular C2 beacon flows.
    Expected direction: OUTBOUND.
    """
    rng = random.Random(scenario.rng_seed)
    src_ip = _random_ip(scenario.topology.internal_networks[0], rng)
    dst_ip = _random_ip(scenario.topology.attacker_networks[0], rng)
    t = base_time
    end_t = t + scenario.duration_seconds

    while t < end_t:
        direction = config.classify_direction(src_ip, dst_ip, scenario.topology.internal_networks)
        yield FlowEvent(
            timestamp=round(t, 6),
            src_ip=src_ip,
            src_port=rng.randint(1024, 65535),
            dst_ip=dst_ip,
            dst_port=443,
            protocol="TCP",
            length=rng.randint(80, 150),
            tcp_flags={"SYN": False, "ACK": True, "FIN": False, "RST": False},
            direction=Direction(direction),
            ingest_source="simulator",
        )
        jitter = rng.uniform(-interval_seconds * jitter_pct, interval_seconds * jitter_pct)
        t += interval_seconds + jitter


def generate_dns_tunnel(
    scenario: SimulatorScenario,
    config: EnclaveConfig,
    base_time: float = 1700000000.0,
) -> Iterator[FlowEvent]:
    """
    Generate DNS tunnelling queries.
    Expected direction: OUTBOUND.
    """
    rng = random.Random(scenario.rng_seed)
    src_ip = _random_ip(scenario.topology.internal_networks[0], rng)
    dst_ip = _random_ip(scenario.topology.attacker_networks[0], rng)
    domain = "c2tunnel.example.com"
    t = base_time
    end_t = t + scenario.duration_seconds
    interval = 1.0 / scenario.flow_rate_hz

    while t < end_t:
        label_len = rng.randint(36, 63)
        label = "".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=label_len))
        query = f"{label}.{domain}"
        direction = config.classify_direction(src_ip, dst_ip, scenario.topology.internal_networks)
        yield FlowEvent(
            timestamp=round(t, 6),
            src_ip=src_ip,
            src_port=rng.randint(1024, 65535),
            dst_ip=dst_ip,
            dst_port=53,
            protocol="DNS",
            length=len(query) + 12,
            dns_query=query,
            dns_qtype="TXT",
            dns_is_response=False,
            direction=Direction(direction),
            ingest_source="simulator",
        )
        t += interval + rng.uniform(0, interval * 0.1)


def generate_encrypted_malware_tls(
    scenario: SimulatorScenario,
    config: EnclaveConfig,
    base_time: float = 1700000000.0,
) -> Iterator[FlowEvent]:
    """
    Generate TLS sessions with malicious JA3 fingerprint and distinct PST sequence.
    Threat class: T-d (Malware in Encrypted TLS Sessions).
    Expected direction: OUTBOUND.
    """
    rng = random.Random(scenario.rng_seed)
    src_ip = _random_ip(scenario.topology.internal_networks[0], rng)
    dst_ip = _random_ip(scenario.topology.attacker_networks[0], rng)
    # Known Cobalt Strike Malleable C2 JA3 hash from abuse.ch SSLBL
    cobalt_ja3 = "a0e9f5d64349fb13191bc781f81f42e1"
    t = base_time
    end_t = t + scenario.duration_seconds
    interval = 1.0 / scenario.flow_rate_hz

    while t < end_t:
        direction = config.classify_direction(src_ip, dst_ip, scenario.topology.internal_networks)
        yield FlowEvent(
            timestamp=round(t, 6),
            src_ip=src_ip,
            src_port=rng.randint(1024, 65535),
            dst_ip=dst_ip,
            dst_port=443,
            protocol="TLS",
            length=rng.randint(350, 520),
            tls_ja3=cobalt_ja3,
            tls_sni="c2-update-node.net",
            tls_cert_self_signed=True,
            direction=Direction(direction),
            ingest_source="simulator",
        )
        t += interval + rng.uniform(0, interval * 0.1)


def generate_port_scan(
    scenario: SimulatorScenario,
    config: EnclaveConfig,
    base_time: float = 1700000000.0,
) -> Iterator[FlowEvent]:
    """
    Generate port scan flows.
    Expected direction: INBOUND.
    """
    rng = random.Random(scenario.rng_seed)
    scanner_ip = _random_ip(scenario.topology.attacker_networks[0], rng)
    t = base_time
    end_t = t + scenario.duration_seconds
    interval = 1.0 / scenario.flow_rate_hz
    port_cycle = list(range(1, 1025))

    for port in port_cycle:
        if t >= end_t:
            break
        target_ip = _random_ip(scenario.topology.internal_networks[0], rng)
        direction = config.classify_direction(
            scanner_ip, target_ip, scenario.topology.internal_networks
        )
        yield FlowEvent(
            timestamp=round(t, 6),
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


def generate_exfil(
    scenario: SimulatorScenario,
    config: EnclaveConfig,
    base_time: float = 1700000000.0,
    chunk_bytes: int = 50_000,
) -> Iterator[FlowEvent]:
    """
    Generate data exfiltration flows.
    Expected direction: OUTBOUND.
    """
    rng = random.Random(scenario.rng_seed)
    src_ip = _random_ip(scenario.topology.internal_networks[0], rng)
    dst_ip = _random_ip(scenario.topology.attacker_networks[0], rng)
    t = base_time
    end_t = t + scenario.duration_seconds
    interval = 1.0 / scenario.flow_rate_hz

    while t < end_t:
        direction = config.classify_direction(src_ip, dst_ip, scenario.topology.internal_networks)
        yield FlowEvent(
            timestamp=round(t, 6),
            src_ip=src_ip,
            src_port=rng.randint(1024, 65535),
            dst_ip=dst_ip,
            dst_port=rng.choice([443, 8443, 4444]),
            protocol="TCP",
            length=chunk_bytes + rng.randint(-1000, 1000),
            direction=Direction(direction),
            ingest_source="simulator",
        )
        t += interval + rng.uniform(0, interval * 0.2)


def get_scenario_generator(
    scenario: SimulatorScenario,
    config: EnclaveConfig = DEFAULT_CONFIG,
    base_time: float = 1700000000.0,
) -> Iterator[FlowEvent]:
    """Dispatch to the generator corresponding to scenario."""
    if scenario.name == "ddos_syn_flood":
        return generate_ddos_syn_flood(scenario, config, base_time)
    elif scenario.name == "c2_beaconing":
        return generate_beacon(scenario, config, base_time)
    elif scenario.name == "dns_tunnel":
        return generate_dns_tunnel(scenario, config, base_time)
    elif scenario.name == "encrypted_malware_tls":
        return generate_encrypted_malware_tls(scenario, config, base_time)
    elif scenario.name == "port_scan":
        return generate_port_scan(scenario, config, base_time)
    elif scenario.name == "data_exfiltration":
        return generate_exfil(scenario, config, base_time)
    else:
        raise ValueError(f"Unknown scenario: {scenario.name}")


# ---------------------------------------------------------------------------
# Deterministic Output Emission (Flow records & Raw PCAP files)
# ---------------------------------------------------------------------------
def emit_scenario_flows(
    scenario: SimulatorScenario,
    max_flows: int = 100,
    config: EnclaveConfig = DEFAULT_CONFIG,
    base_time: float = 1700000000.0,
) -> list[FlowEvent]:
    """
    Emit normalized internal FlowEvent records deterministically.

    Args:
        scenario: The target SimulatorScenario.
        max_flows: Maximum number of flow events to emit.
        config: EnclaveConfig with subnet definitions.
        base_time: Baseline timestamp.

    Returns:
        List of FlowEvent records.
    """
    gen = get_scenario_generator(scenario, config, base_time)
    flows: list[FlowEvent] = []
    for f in gen:
        flows.append(f)
        if len(flows) >= max_flows:
            break
    return flows


def _ip_to_bytes(ip_str: str) -> bytes:
    """Convert IPv4 string to 4-byte packed binary."""
    return ipaddress.IPv4Address(ip_str).packed


def emit_scenario_pcap(
    scenario: SimulatorScenario,
    output_path: Path,
    max_packets: int = 100,
    config: EnclaveConfig = DEFAULT_CONFIG,
    base_time: float = 1700000000.0,
) -> Path:
    """
    Emit real binary .pcap file with valid Ethernet, IP, and L4 headers.

    Uses dpkt.pcap.Writer with fixed seed parameters to ensure deterministic
    pcap files across runs.

    Args:
        scenario: The target SimulatorScenario.
        output_path: Destination .pcap path.
        max_packets: Number of packets to write.
        config: EnclaveConfig instance.
        base_time: Starting epoch timestamp.

    Returns:
        Path to the generated .pcap file.
    """
    flows = emit_scenario_flows(scenario, max_packets, config, base_time)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "wb") as f:
        writer = dpkt.pcap.Writer(f)
        src_mac = b"\x00\x11\x22\x33\x44\x55"
        dst_mac = b"\x66\x77\x88\x99\xaa\xbb"

        for event in flows:
            # Build L4 layer
            if event.protocol in ("TCP", "TLS"):
                tcp = dpkt.tcp.TCP(
                    sport=event.src_port,
                    dport=event.dst_port,
                    seq=event.tcp_seq if event.tcp_seq is not None else 1000,
                    ack=event.tcp_ack if event.tcp_ack is not None else 0,
                    flags=dpkt.tcp.TH_SYN if (event.tcp_flags and event.tcp_flags.get("SYN")) else dpkt.tcp.TH_ACK,
                    win=64240,
                )
                if event.protocol == "TLS" and event.tls_ja3:
                    # Synthetic TLS handshake payload marker
                    tcp.data = b"\x16\x03\x01\x00\xa0\x01\x00\x00\x9c\x03\x03" + b"\x00" * 32
                elif event.length > 54:
                    tcp.data = b"\x00" * min(event.length - 54, 1400)
                l4_pkt = tcp
                ip_proto = dpkt.ip.IP_PROTO_TCP
            elif event.protocol == "DNS" or event.protocol == "UDP":
                udp = dpkt.udp.UDP(
                    sport=event.src_port,
                    dport=event.dst_port,
                )
                if event.protocol == "DNS" and event.dns_query:
                    # Minimal standard DNS query payload
                    qname_bytes = b"".join(
                        bytes([len(part)]) + part.encode("ascii")
                        for part in event.dns_query.split(".")
                    ) + b"\x00"
                    # Header: ID=0x1234, Flags=0x0100 (standard query), QDCOUNT=1
                    dns_payload = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qname_bytes + b"\x00\x10\x00\x01"
                    udp.data = dns_payload
                else:
                    udp.data = b"\x00" * min(max(event.length - 42, 8), 1400)
                udp.ulen = len(udp)
                l4_pkt = udp
                ip_proto = dpkt.ip.IP_PROTO_UDP
            else:
                # Default IP payload
                l4_pkt = dpkt.tcp.TCP(sport=event.src_port, dport=event.dst_port)
                ip_proto = dpkt.ip.IP_PROTO_TCP

            # Build IPv4 layer
            ip = dpkt.ip.IP(
                src=_ip_to_bytes(event.src_ip),
                dst=_ip_to_bytes(event.dst_ip),
                p=ip_proto,
                ttl=64,
                data=l4_pkt,
            )
            ip.len = len(ip)

            # Build Ethernet layer
            eth = dpkt.ethernet.Ethernet(
                src=src_mac,
                dst=dst_mac,
                type=dpkt.ethernet.ETH_TYPE_IP,
                data=ip,
            )

            writer.writepkt(bytes(eth), ts=event.timestamp)

    return output_path


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
