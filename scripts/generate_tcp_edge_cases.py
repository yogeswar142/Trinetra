"""
scripts/generate_tcp_edge_cases.py

Generates 4 crafted deterministic PCAP fixtures for TCP tracking edge cases:
1. tcp_duplicate.pcap: Duplicate sequence number packet retransmission.
2. tcp_out_of_order.pcap: Packets arriving with inverted sequence numbers.
3. tcp_midstream.pcap: Capture starting mid-connection without SYN handshake.
4. tcp_one_sided_loss.pcap: Asymmetric one-sided capture (responder packets only).
"""
from __future__ import annotations

import socket
from pathlib import Path
import dpkt

OUTPUT_DIR = Path("data/fixtures/tcp_edge_cases")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def _write_pcap_packets(filename: str, packets: list[tuple[float, str, int, str, int, int, int, int, bytes]]) -> Path:
    """
    Helper to write raw IP/TCP packets to a pcap file.
    Packets spec: (ts, src_ip, sport, dst_ip, dport, seq, ack, flags, payload)
    """
    path = OUTPUT_DIR / filename
    with open(path, "wb") as f:
        writer = dpkt.pcap.Writer(f)
        src_mac = b"\x00\x11\x22\x33\x44\x55"
        dst_mac = b"\x66\x77\x88\x99\xaa\xbb"

        for ts, s_ip, sp, d_ip, dp, seq, ack, flags, payload in packets:
            tcp = dpkt.tcp.TCP(
                sport=sp,
                dport=dp,
                seq=seq,
                ack=ack,
                flags=flags,
                win=64240,
                data=payload,
            )
            ip = dpkt.ip.IP(
                src=socket.inet_aton(s_ip),
                dst=socket.inet_aton(d_ip),
                p=dpkt.ip.IP_PROTO_TCP,
                ttl=64,
                data=tcp,
            )
            ip.len = len(ip)
            eth = dpkt.ethernet.Ethernet(
                src=src_mac,
                dst=dst_mac,
                type=dpkt.ethernet.ETH_TYPE_IP,
                data=ip,
            )
            writer.writepkt(bytes(eth), ts=ts)
    return path


def generate_duplicate_pcap() -> Path:
    # SYN, SYN-ACK, ACK, Data (seq 1001, len 500), Duplicate Data (seq 1001, len 500)
    packets = [
        (100.0, "192.168.1.10", 49152, "10.0.0.1", 80, 1000, 0, dpkt.tcp.TH_SYN, b""),
        (100.02, "10.0.0.1", 80, "192.168.1.10", 49152, 5000, 1001, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK, b""),
        (100.04, "192.168.1.10", 49152, "10.0.0.1", 80, 1001, 5001, dpkt.tcp.TH_ACK, b""),
        (100.06, "192.168.1.10", 49152, "10.0.0.1", 80, 1001, 5001, dpkt.tcp.TH_ACK, b"A" * 500),
        # Duplicate transmission of seq 1001 with identical payload
        (100.10, "192.168.1.10", 49152, "10.0.0.1", 80, 1001, 5001, dpkt.tcp.TH_ACK, b"A" * 500),
    ]
    return _write_pcap_packets("tcp_duplicate.pcap", packets)


def generate_out_of_order_pcap() -> Path:
    # SYN, SYN-ACK, ACK, Packet 2 (seq 2001, len 500) arrives BEFORE Packet 1 (seq 1001, len 1000)
    packets = [
        (200.0, "192.168.1.20", 49153, "10.0.0.2", 80, 1000, 0, dpkt.tcp.TH_SYN, b""),
        (200.02, "10.0.0.2", 80, "192.168.1.20", 49153, 6000, 1001, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK, b""),
        (200.04, "192.168.1.20", 49153, "10.0.0.2", 80, 1001, 6001, dpkt.tcp.TH_ACK, b""),
        # First data packet: seq 1001, len 1000 -> next expected seq is 2001
        (200.06, "192.168.1.20", 49153, "10.0.0.2", 80, 1001, 6001, dpkt.tcp.TH_ACK, b"B" * 1000),
        # Out-of-order packet: seq 500 arrives when tracker already reached 2001
        (200.08, "192.168.1.20", 49153, "10.0.0.2", 80, 500, 6001, dpkt.tcp.TH_ACK, b"C" * 200),
    ]
    return _write_pcap_packets("tcp_out_of_order.pcap", packets)


def generate_midstream_pcap() -> Path:
    # Capture starts mid-stream: ACK packets with data, no SYN or SYN-ACK seen
    packets = [
        (300.0, "192.168.1.30", 49154, "10.0.0.3", 443, 35000, 80000, dpkt.tcp.TH_ACK, b"M" * 400),
        (300.02, "10.0.0.3", 443, "192.168.1.30", 49154, 80000, 35400, dpkt.tcp.TH_ACK, b"N" * 800),
    ]
    return _write_pcap_packets("tcp_midstream.pcap", packets)


def generate_one_sided_loss_pcap() -> Path:
    # Only reverse packets are observed in capture (e.g., asymmetric routing or one-sided filter)
    packets = [
        (400.0, "10.0.0.4", 80, "192.168.1.40", 49155, 90000, 12000, dpkt.tcp.TH_ACK, b"R" * 250),
        (400.05, "10.0.0.4", 80, "192.168.1.40", 49155, 90250, 12000, dpkt.tcp.TH_ACK, b"R" * 250),
    ]
    return _write_pcap_packets("tcp_one_sided_loss.pcap", packets)


if __name__ == "__main__":
    p1 = generate_duplicate_pcap()
    p2 = generate_out_of_order_pcap()
    p3 = generate_midstream_pcap()
    p4 = generate_one_sided_loss_pcap()
    print(f"Generated 4 TCP edge case PCAPs in {OUTPUT_DIR}:")
    print(f"  {p1.name} ({p1.stat().st_size} bytes)")
    print(f"  {p2.name} ({p2.stat().st_size} bytes)")
    print(f"  {p3.name} ({p3.stat().st_size} bytes)")
    print(f"  {p4.name} ({p4.stat().st_size} bytes)")
