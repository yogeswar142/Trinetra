"""
scripts/generate_realistic_500k_pcap.py

Generates a realistic multi-flow network capture containing >= 500,000 packets:
- Long-lived multi-packet TCP/TLS flows (file downloads, streaming, TLS sessions)
- Short-lived request/response flows (DNS queries, HTTP handshakes)
- Mixed packet sizes (60B SYNs/ACKs, 300-800B headers, 1420B data MTU)
- Interleaved timestamps across concurrent flows
"""
from __future__ import annotations

import random
import socket
import struct
import time
from pathlib import Path
import dpkt

OUTPUT_PATH = Path("data/fixtures/realistic_mixed_500k.pcap")


def generate_mixed_500k_pcap(target_packets: int = 500_000) -> Path:
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    print(f"Generating realistic mixed capture with {target_packets:,} packets -> {OUTPUT_PATH}...")
    t0 = time.perf_counter()

    rng = random.Random(42)

    # Pre-build common Ethernet headers
    eth_hdr_ip = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"

    # Pre-generate IP byte addresses
    clients = [socket.inet_aton(f"192.168.1.{i}") for i in range(10, 60)]
    servers = [socket.inet_aton(f"10.0.{i}.1") for i in range(1, 20)]
    dns_servers = [socket.inet_aton("8.8.8.8"), socket.inet_aton("1.1.1.1")]

    # Pre-built payload buffers to avoid repeated allocations
    small_payload = b"\x00" * 0       # TCP ACK
    med_payload = b"GET /index.html HTTP/1.1\r\nHost: example.internal\r\nUser-Agent: Mozilla/5.0\r\n\r\n" + b"\x00" * 200
    large_payload = b"\x17\x03\x03" + struct.pack("!H", 1400) + (b"\xaa" * 1395)  # TLS AppData
    dns_query_payload = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"

    # We will simulate concurrent conversations
    # 200 active long-lived TCP/TLS flows
    long_flows = []
    for fid in range(200):
        c_ip = clients[fid % len(clients)]
        s_ip = servers[fid % len(servers)]
        c_port = 40000 + fid
        s_port = 443 if (fid % 2 == 0) else 80
        long_flows.append({
            "client_ip": c_ip,
            "server_ip": s_ip,
            "client_port": c_port,
            "server_port": s_port,
            "seq_fwd": 1000,
            "seq_rev": 5000,
            "is_tls": (s_port == 443),
        })

    packets_written = 0
    sim_time = 1700000000.0

    with open(OUTPUT_PATH, "wb") as f:
        writer = dpkt.pcap.Writer(f)

        # 1. Handshakes for all long-lived flows
        for flow in long_flows:
            # Client SYN
            ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 0, 0x4000, 64, 6, 0, flow["client_ip"], flow["server_ip"])
            tcp_hdr = struct.pack("!HHIIBBHHH", flow["client_port"], flow["server_port"], flow["seq_fwd"], 0, (5 << 4), dpkt.tcp.TH_SYN, 64240, 0, 0)
            writer.writepkt(eth_hdr_ip + ip_hdr + tcp_hdr, ts=sim_time)
            sim_time += 0.0001
            packets_written += 1

            # Server SYN-ACK
            ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 0, 0x4000, 64, 6, 0, flow["server_ip"], flow["client_ip"])
            tcp_hdr = struct.pack("!HHIIBBHHH", flow["server_port"], flow["client_port"], flow["seq_rev"], flow["seq_fwd"] + 1, (5 << 4), dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK, 64240, 0, 0)
            writer.writepkt(eth_hdr_ip + ip_hdr + tcp_hdr, ts=sim_time)
            sim_time += 0.0001
            packets_written += 1

            # Client ACK
            ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 0, 0x4000, 64, 6, 0, flow["client_ip"], flow["server_ip"])
            tcp_hdr = struct.pack("!HHIIBBHHH", flow["client_port"], flow["server_port"], flow["seq_fwd"] + 1, flow["seq_rev"] + 1, (5 << 4), dpkt.tcp.TH_ACK, 64240, 0, 0)
            writer.writepkt(eth_hdr_ip + ip_hdr + tcp_hdr, ts=sim_time)
            sim_time += 0.0001
            packets_written += 1
            flow["seq_fwd"] += 1
            flow["seq_rev"] += 1

        # 2. Main data packet loop
        while packets_written < target_packets:
            roll = rng.random()

            if roll < 0.70:
                # Long-lived TCP/TLS data packet (large server -> client transfer, client ACK)
                flow = rng.choice(long_flows)
                # Server data packet (large MTU)
                ip_len = 40 + len(large_payload)
                ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_len, 0, 0x4000, 64, 6, 0, flow["server_ip"], flow["client_ip"])
                tcp_hdr = struct.pack("!HHIIBBHHH", flow["server_port"], flow["client_port"], flow["seq_rev"], flow["seq_fwd"], (5 << 4), dpkt.tcp.TH_ACK, 64240, 0, 0)
                writer.writepkt(eth_hdr_ip + ip_hdr + tcp_hdr + large_payload, ts=sim_time)
                flow["seq_rev"] += len(large_payload)
                sim_time += 0.00002
                packets_written += 1

                # Client ACK
                if packets_written < target_packets:
                    ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 0, 0x4000, 64, 6, 0, flow["client_ip"], flow["server_ip"])
                    tcp_hdr = struct.pack("!HHIIBBHHH", flow["client_port"], flow["server_port"], flow["seq_fwd"], flow["seq_rev"], (5 << 4), dpkt.tcp.TH_ACK, 64240, 0, 0)
                    writer.writepkt(eth_hdr_ip + ip_hdr + tcp_hdr, ts=sim_time)
                    sim_time += 0.00002
                    packets_written += 1

            elif roll < 0.90:
                # Client request / medium data (HTTP/TLS Client)
                flow = rng.choice(long_flows)
                ip_len = 40 + len(med_payload)
                ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_len, 0, 0x4000, 64, 6, 0, flow["client_ip"], flow["server_ip"])
                tcp_hdr = struct.pack("!HHIIBBHHH", flow["client_port"], flow["server_port"], flow["seq_fwd"], flow["seq_rev"], (5 << 4), dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, 64240, 0, 0)
                writer.writepkt(eth_hdr_ip + ip_hdr + tcp_hdr + med_payload, ts=sim_time)
                flow["seq_fwd"] += len(med_payload)
                sim_time += 0.00003
                packets_written += 1

            else:
                # DNS query / response short flow
                c_ip = rng.choice(clients)
                dns_s = rng.choice(dns_servers)
                c_port = rng.randint(50000, 60000)

                # Query
                udp_len = 8 + len(dns_query_payload)
                ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + udp_len, 0, 0, 64, 17, 0, c_ip, dns_s)
                udp_hdr = struct.pack("!HHHH", c_port, 53, udp_len, 0)
                writer.writepkt(eth_hdr_ip + ip_hdr + udp_hdr + dns_query_payload, ts=sim_time)
                sim_time += 0.00005
                packets_written += 1

                # Response
                if packets_written < target_packets:
                    ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + udp_len, 0, 0, 64, 17, 0, dns_s, c_ip)
                    udp_hdr = struct.pack("!HHHH", 53, c_port, udp_len, 0)
                    writer.writepkt(eth_hdr_ip + ip_hdr + udp_hdr + dns_query_payload, ts=sim_time)
                    sim_time += 0.00005
                    packets_written += 1

    dur = time.perf_counter() - t0
    size_mb = OUTPUT_PATH.stat().st_size / (1024 * 1024)
    print(f"Done! Written {packets_written:,} packets ({size_mb:.2f} MB) in {dur:.2f}s ({packets_written/dur:,.0f} pkts/s generator rate).")
    return OUTPUT_PATH


if __name__ == "__main__":
    generate_mixed_500k_pcap(500_000)
