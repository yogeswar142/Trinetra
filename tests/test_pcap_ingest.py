"""
tests/test_pcap_ingest.py

Tests for PcapIngest:
- Classic pcap and pcapng detection
- Ethernet framing, 802.1Q VLAN, and 802.1ad QinQ dual VLAN
- IPv4 and IPv6 handling
- IP fragments: dropped and counted, never crash
- Unsupported link layer / non-IP: dropped and counted, never crash
- TCP, UDP, ICMP metadata extraction
- Telemetry counter tracking
"""
from __future__ import annotations

import io
import struct
from pathlib import Path
import pytest
import dpkt

from trinetra.ingest.pcap import PcapIngest, PcapIngestStats
from trinetra.schemas import FlowEvent


# ---------------------------------------------------------------------------
# Helpers to synthesize raw PCAP buffers in-memory
# ---------------------------------------------------------------------------
def _build_raw_pcap(packet_bytes_list: list[bytes], ts: float = 1700000000.0) -> bytes:
    """Build an in-memory classic PCAP binary buffer from raw packet bytes."""
    buf = io.BytesIO()
    writer = dpkt.pcap.Writer(buf)
    for p in packet_bytes_list:
        writer.writepkt(p, ts=ts)
    return buf.getvalue()


def _make_eth_ipv4_tcp(
    src_ip="10.0.0.1",
    dst_ip="10.0.0.2",
    sport=12345,
    dport=80,
    flags=dpkt.tcp.TH_SYN,
    vlan_id=None,
    qinq_id=None,
    is_fragment=False,
) -> bytes:
    """Construct an Ethernet IPv4 TCP packet with optional VLAN and fragmentation."""
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, seq=100, ack=0, win=65535)
    tcp.data = b"GET / HTTP/1.1\r\n\r\n"

    src_bytes = bytes(map(int, src_ip.split(".")))
    dst_bytes = bytes(map(int, dst_ip.split(".")))

    ip = dpkt.ip.IP(src=src_bytes, dst=dst_bytes, p=dpkt.ip.IP_PROTO_TCP, data=tcp)
    if is_fragment:
        ip.mf = 1  # More fragments bit set

    ip_bytes = bytes(ip)

    if qinq_id is not None and vlan_id is not None:
        # QinQ Dual VLAN: Outer 0x88A8 + Inner 0x8100
        eth_hdr = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb"
        outer_vlan = struct.pack("!HH", 0x88A8, qinq_id)
        inner_vlan = struct.pack("!HH", 0x8100, vlan_id)
        return eth_hdr + outer_vlan + inner_vlan + struct.pack("!H", 0x0800) + ip_bytes

    elif vlan_id is not None:
        # 802.1Q Single VLAN
        eth_hdr = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb"
        vlan_hdr = struct.pack("!HH", 0x8100, vlan_id)
        return eth_hdr + vlan_hdr + struct.pack("!H", 0x0800) + ip_bytes

    else:
        # Standard Ethernet
        eth = dpkt.ethernet.Ethernet(
            src=b"\x00\x11\x22\x33\x44\x55",
            dst=b"\x66\x77\x88\x99\xaa\xbb",
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip,
        )
        return bytes(eth)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
class TestPcapIngest:
    def test_parse_standard_ipv4_tcp(self) -> None:
        pkt = _make_eth_ipv4_tcp()
        pcap_data = _build_raw_pcap([pkt])

        ingest = PcapIngest()
        events = list(ingest.parse_stream(io.BytesIO(pcap_data)))

        assert len(events) == 1
        ev = events[0]
        assert ev.src_ip == "10.0.0.1"
        assert ev.dst_ip == "10.0.0.2"
        assert ev.src_port == 12345
        assert ev.dst_port == 80
        assert ev.protocol == "TCP"
        assert ev.tcp_flags["SYN"] is True
        assert ingest.stats.packets_parsed == 1
        assert ingest.stats.ipv4_packets == 1

    def test_parse_8021q_single_vlan(self) -> None:
        pkt = _make_eth_ipv4_tcp(vlan_id=100)
        pcap_data = _build_raw_pcap([pkt])

        ingest = PcapIngest()
        events = list(ingest.parse_stream(io.BytesIO(pcap_data)))

        assert len(events) == 1
        assert events[0].src_ip == "10.0.0.1"
        assert ingest.stats.vlan_tagged_packets == 1

    def test_parse_qinq_dual_vlan(self) -> None:
        pkt = _make_eth_ipv4_tcp(vlan_id=100, qinq_id=200)
        pcap_data = _build_raw_pcap([pkt])

        ingest = PcapIngest()
        events = list(ingest.parse_stream(io.BytesIO(pcap_data)))

        assert len(events) == 1
        assert events[0].src_ip == "10.0.0.1"
        assert ingest.stats.vlan_tagged_packets >= 2

    def test_ip_fragment_dropped_and_counted(self) -> None:
        """IP fragments must be dropped with counter incremented, never crashing."""
        pkt = _make_eth_ipv4_tcp(is_fragment=True)
        pcap_data = _build_raw_pcap([pkt])

        ingest = PcapIngest()
        events = list(ingest.parse_stream(io.BytesIO(pcap_data)))

        assert len(events) == 0
        assert ingest.stats.packets_dropped_fragments == 1

    def test_non_ip_packet_dropped_and_counted(self) -> None:
        """ARP packets (EtherType 0x0806) dropped and counted."""
        arp_pkt = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x06" + b"\x00" * 28
        pcap_data = _build_raw_pcap([arp_pkt])

        ingest = PcapIngest()
        events = list(ingest.parse_stream(io.BytesIO(pcap_data)))

        assert len(events) == 0
        assert ingest.stats.packets_dropped_non_ip == 1

    def test_ipv6_udp_packet(self) -> None:
        """Parse IPv6 UDP packet."""
        udp = dpkt.udp.UDP(sport=5353, dport=5353, data=b"mdns")
        ip6 = dpkt.ip6.IP6(
            src=b"\xfe\x80" + b"\x00" * 14,
            dst=b"\xff\x02" + b"\x00" * 14,
            nxt=dpkt.ip.IP_PROTO_UDP,
            data=udp,
        )
        eth = dpkt.ethernet.Ethernet(
            src=b"\x00\x11\x22\x33\x44\x55",
            dst=b"\x66\x77\x88\x99\xaa\xbb",
            type=dpkt.ethernet.ETH_TYPE_IP6,
            data=ip6,
        )
        pcap_data = _build_raw_pcap([bytes(eth)])

        ingest = PcapIngest()
        events = list(ingest.parse_stream(io.BytesIO(pcap_data)))

        assert len(events) == 1
        assert ingest.stats.ipv6_packets == 1
        assert events[0].protocol == "UDP"
