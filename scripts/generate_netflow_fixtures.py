"""
Script to generate standard reference NetFlow v9 binary export fixture
and corresponding PCAP fixture for cross-validation.
"""
from __future__ import annotations

import hashlib
import socket
import struct
from pathlib import Path
import dpkt

FIXTURES_DIR = Path("data/fixtures")
FIXTURES_DIR.mkdir(parents=True, exist_ok=True)

NETFLOW_BIN_PATH = FIXTURES_DIR / "netflow_v9_export.bin"
NETFLOW_PCAP_PATH = FIXTURES_DIR / "netflow_comparison.pcap"

def generate_netflow_v9_fixture() -> bytes:
    # Header: Version 9, 2 FlowSets, sys_uptime=500000ms, unix_secs=1700000000, seq=101, source_id=1
    hdr = struct.pack("!HHIIII", 9, 2, 500000, 1700000000, 101, 1)

    # Template FlowSet: ID=0, Length=32, Template ID=256, 7 fields
    fields = [
        (8, 4),   # IPV4_SRC_ADDR
        (12, 4),  # IPV4_DST_ADDR
        (7, 2),   # L4_SRC_PORT
        (11, 2),  # L4_DST_PORT
        (4, 1),   # PROTOCOL
        (1, 4),   # IN_BYTES
        (6, 1),   # TCP_FLAGS
    ]
    field_bytes = b"".join(struct.pack("!HH", ftype, flen) for ftype, flen in fields)
    tmpl_body = struct.pack("!HH", 256, len(fields)) + field_bytes
    tmpl_flowset = struct.pack("!HH", 0, 4 + len(tmpl_body)) + tmpl_body

    # Data records
    flows_data = [
        # src_ip, dst_ip, sport, dport, proto, bytes, flags
        ("192.168.1.50", "10.0.0.10", 49152, 443, 6, 1420, 0x10),
        ("10.0.0.10", "192.168.1.50", 443, 49152, 6, 6540, 0x18),
        ("192.168.1.50", "8.8.8.8", 53535, 53, 17, 68, 0x00),
        ("8.8.8.8", "192.168.1.50", 53, 53535, 17, 142, 0x00),
    ]

    records = []
    for s_ip, d_ip, sp, dp, proto, b_len, flags in flows_data:
        records.append(
            struct.pack(
                "!4s4sHHBIB",
                socket.inet_aton(s_ip),
                socket.inet_aton(d_ip),
                sp,
                dp,
                proto,
                b_len,
                flags,
            )
        )
    data_body = b"".join(records)
    data_flowset = struct.pack("!HH", 256, 4 + len(data_body)) + data_body

    full_datagram = hdr + tmpl_flowset + data_flowset
    return full_datagram


def generate_matching_pcap() -> None:
    with open(NETFLOW_PCAP_PATH, "wb") as f:
        writer = dpkt.pcap.Writer(f)
        src_mac = b"\x00\x11\x22\x33\x44\x55"
        dst_mac = b"\x66\x77\x88\x99\xaa\xbb"
        base_ts = 1700000000.0

        packets = [
            ("192.168.1.50", "10.0.0.10", 49152, 443, 6, 1420, dpkt.tcp.TH_ACK),
            ("10.0.0.10", "192.168.1.50", 443, 49152, 6, 6540, dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK),
            ("192.168.1.50", "8.8.8.8", 53535, 53, 17, 68, 0),
            ("8.8.8.8", "192.168.1.50", 53, 53535, 17, 142, 0),
        ]

        for i, (s_ip, d_ip, sp, dp, proto, b_len, flags) in enumerate(packets):
            ts = base_ts + i * 0.1
            if proto == 6:
                l4 = dpkt.tcp.TCP(sport=sp, dport=dp, seq=1000 + i * 100, flags=flags)
                payload_len = max(0, b_len - 40)
                l4.data = b"\x00" * payload_len
                ip_p = dpkt.ip.IP_PROTO_TCP
            else:
                l4 = dpkt.udp.UDP(sport=sp, dport=dp)
                payload_len = max(0, b_len - 28)
                l4.data = b"\x00" * payload_len
                l4.ulen = len(l4)
                ip_p = dpkt.ip.IP_PROTO_UDP

            ip = dpkt.ip.IP(
                src=socket.inet_aton(s_ip),
                dst=socket.inet_aton(d_ip),
                p=ip_p,
                ttl=64,
                data=l4,
            )
            ip.len = len(ip)
            eth = dpkt.ethernet.Ethernet(
                src=src_mac,
                dst=dst_mac,
                type=dpkt.ethernet.ETH_TYPE_IP,
                data=ip,
            )
            writer.writepkt(bytes(eth), ts=ts)


if __name__ == "__main__":
    netflow_bytes = generate_netflow_v9_fixture()
    with open(NETFLOW_BIN_PATH, "wb") as f:
        f.write(netflow_bytes)

    h_bin = hashlib.sha256(netflow_bytes).hexdigest()
    print(f"Wrote {NETFLOW_BIN_PATH} ({len(netflow_bytes)} bytes) SHA256: {h_bin}")

    generate_matching_pcap()
    with open(NETFLOW_PCAP_PATH, "rb") as f:
        pcap_bytes = f.read()
    h_pcap = hashlib.sha256(pcap_bytes).hexdigest()
    print(f"Wrote {NETFLOW_PCAP_PATH} ({len(pcap_bytes)} bytes) SHA256: {h_pcap}")
