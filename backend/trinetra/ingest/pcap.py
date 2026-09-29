"""
Trinetra PCAP Ingest Engine.

High-performance, passive receive-only packet ingest based on dpkt.
Supports:
    - Classic libpcap format (.pcap) and modern pcapng format (.pcapng)
    - Standard Ethernet framing (DLT_EN10MB)
    - 802.1Q Single VLAN Tagging (EtherType 0x8100)
    - 802.1ad Provider Bridging / QinQ Dual VLAN Tagging (EtherTypes 0x88A8, 0x9100)
    - IPv4 and IPv6 network layers
    - L4 protocols: TCP (flags, seq, ack), UDP, ICMP, ICMPv6
    - Application layer metadata: DNS queries (UDP 53), TLS ClientHello/ServerHello (TCP 443)

ROBUSTNESS & AIR-GAP GUARANTEES:
    - Zero network transmission (no sockets opened; receive-only stream).
    - IP Fragments: Dropped and counted (stats.packets_dropped_fragments), never crash.
    - Unsupported link types: Dropped and counted (stats.packets_dropped_unsupported_link), never crash.
    - Non-IP frames (ARP, LLDP, STP): Dropped and counted (stats.packets_dropped_non_ip), never crash.
"""
from __future__ import annotations

import io
import socket
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Iterator, Union

import dpkt

from trinetra.features.entropy import shannon_entropy
from trinetra.features.tls_parser import parse_client_hello, parse_server_hello
from trinetra.schemas import FlowEvent, PacketEvent


# ---------------------------------------------------------------------------
# Statistics Dataclass
# ---------------------------------------------------------------------------
@dataclass
class PcapIngestStats:
    """Telemetry counters for packet capture processing."""
    packets_read: int = 0
    packets_parsed: int = 0
    packets_dropped_fragments: int = 0
    packets_dropped_unsupported_link: int = 0
    packets_dropped_non_ip: int = 0
    bytes_read: int = 0
    vlan_tagged_packets: int = 0
    ipv4_packets: int = 0
    ipv6_packets: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    icmp_packets: int = 0


# ---------------------------------------------------------------------------
# Format Detection Constants
# ---------------------------------------------------------------------------
PCAP_MAGIC_MICRO_LE = b"\xd4\xc3\xb2\xa1"
PCAP_MAGIC_MICRO_BE = b"\xa1\xb2\xc3\xd4"
PCAP_MAGIC_NANO_LE = b"\x4d\x3c\xb2\xa1"
PCAP_MAGIC_NANO_BE = b"\xa1\xb2\x3c\x4d"
PCAPNG_SECTION_HEADER_MAGIC = b"\x0a\x0d\x0d\x0a"

ETHERTYPE_IP = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_8021Q = 0x8100
ETHERTYPE_QINQ_88A8 = 0x88A8
ETHERTYPE_QINQ_9100 = 0x9100


# ---------------------------------------------------------------------------
# PCAP Ingest Streamer
# ---------------------------------------------------------------------------
class PcapIngest:
    """
    Passive receive-only packet ingest parser.

    Processes both file-based PCAP streams and in-memory byte buffers.
    """

    def __init__(self) -> None:
        self.stats = PcapIngestStats()

    def parse_file(self, file_path: Union[str, Path]) -> Iterator[FlowEvent]:
        """
        Open a pcap or pcapng file and stream normalized FlowEvent records.

        Args:
            file_path: Path to the .pcap or .pcapng file.

        Yields:
            FlowEvent objects for each valid IPv4/IPv6 packet.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"PCAP file not found: {path}")

        with open(path, "rb") as f:
            yield from self.parse_stream(f)

    def parse_stream(self, stream: BinaryIO) -> Iterator[FlowEvent]:
        """
        Stream FlowEvent records from an open binary file-like object.

        Detects whether the stream is classic PCAP or PCAPNG.
        """
        magic = stream.read(4)
        if len(magic) < 4:
            return

        stream.seek(0)

        # Detect pcapng vs classic pcap
        if magic == PCAPNG_SECTION_HEADER_MAGIC:
            try:
                reader = dpkt.pcapng.Reader(stream)
            except Exception:
                # Fallback to standard reader if pcapng initialization fails
                stream.seek(0)
                reader = dpkt.pcap.Reader(stream)
        else:
            reader = dpkt.pcap.Reader(stream)

        # Inspect datalink type: DLT_EN10MB = 1 (Standard Ethernet)
        datalink = getattr(reader, "datalink", lambda: 1)()
        is_ethernet = (datalink == 1)

        for ts, buf in reader:
            self.stats.packets_read += 1
            self.stats.bytes_read += len(buf)

            if not is_ethernet:
                # Unsupported link layer (e.g. SLL, Raw IP, Loopback)
                # Policy: Drop and count, never crash
                self.stats.packets_dropped_unsupported_link += 1
                continue

            event = self._parse_ethernet_packet(ts, buf)
            if event is not None:
                self.stats.packets_parsed += 1
                yield event

    def _parse_ethernet_packet(self, ts: float, buf: bytes) -> FlowEvent | PacketEvent | None:
        """Parse raw Ethernet frame into normalized FlowEvent."""
        if len(buf) < 14:
            self.stats.packets_dropped_unsupported_link += 1
            return None

        # Parse Ethernet header
        try:
            eth_type = struct.unpack("!H", buf[12:14])[0]
            offset = 14
        except Exception:
            self.stats.packets_dropped_unsupported_link += 1
            return None

        # Handle 802.1ad / 802.1Q VLAN Tagging (Single or QinQ Dual)
        while eth_type in (ETHERTYPE_8021Q, ETHERTYPE_QINQ_88A8, ETHERTYPE_QINQ_9100):
            self.stats.vlan_tagged_packets += 1
            if len(buf) < offset + 4:
                self.stats.packets_dropped_unsupported_link += 1
                return None
            # Next 2 bytes: TCI (Priority + CFI + VLAN ID)
            # Following 2 bytes: Inner EtherType
            eth_type = struct.unpack("!H", buf[offset + 2:offset + 4])[0]
            offset += 4

        # Dispatch based on Network Layer EtherType
        payload_bytes = buf[offset:]

        if eth_type == ETHERTYPE_IP:
            self.stats.ipv4_packets += 1
            return self._parse_ipv4(ts, payload_bytes)
        elif eth_type == ETHERTYPE_IPV6:
            self.stats.ipv6_packets += 1
            return self._parse_ipv6(ts, payload_bytes)
        else:
            # Non-IP traffic (ARP, LLDP, STP, MPLS, etc.)
            self.stats.packets_dropped_non_ip += 1
            return None

    def _parse_ipv4(self, ts: float, data: bytes) -> FlowEvent | None:
        """Parse IPv4 packet."""
        try:
            ip = dpkt.ip.IP(data)
        except Exception:
            self.stats.packets_dropped_non_ip += 1
            return None

        # Check for IP Fragmentation (MF bit set or fragment offset > 0)
        # Policy: Drop and count, never crash!
        if (ip.offset != 0) or (ip.mf != 0):
            self.stats.packets_dropped_fragments += 1
            return None

        src_ip = socket.inet_ntop(socket.AF_INET, ip.src)
        dst_ip = socket.inet_ntop(socket.AF_INET, ip.dst)

        return self._parse_transport(ts, src_ip, dst_ip, ip.p, ip.data, len(data))

    def _parse_ipv6(self, ts: float, data: bytes) -> FlowEvent | None:
        """Parse IPv6 packet."""
        try:
            ip6 = dpkt.ip6.IP6(data)
        except Exception:
            self.stats.packets_dropped_non_ip += 1
            return None

        # Check for IPv6 Fragment extension header (protocol 44)
        if ip6.nxt == dpkt.ip.IP_PROTO_FRAGMENT:
            self.stats.packets_dropped_fragments += 1
            return None

        src_ip = socket.inet_ntop(socket.AF_INET6, ip6.src)
        dst_ip = socket.inet_ntop(socket.AF_INET6, ip6.dst)

        return self._parse_transport(ts, src_ip, dst_ip, ip6.nxt, ip6.data, len(data))

    def _parse_transport(
        self,
        ts: float,
        src_ip: str,
        dst_ip: str,
        proto_num: int,
        transport_data: bytes | dpkt.tcp.TCP | dpkt.udp.UDP | dpkt.icmp.ICMP,
        total_len: int,
    ) -> FlowEvent | None:
        """Parse L4 transport headers (TCP, UDP, ICMP) and extract metadata."""
        if proto_num == dpkt.ip.IP_PROTO_TCP:
            self.stats.tcp_packets += 1
            return self._parse_tcp(ts, src_ip, dst_ip, transport_data, total_len)

        elif proto_num == dpkt.ip.IP_PROTO_UDP:
            self.stats.udp_packets += 1
            return self._parse_udp(ts, src_ip, dst_ip, transport_data, total_len)

        elif proto_num in (dpkt.ip.IP_PROTO_ICMP, 58):  # ICMP or ICMPv6
            self.stats.icmp_packets += 1
            return PacketEvent(
                timestamp=ts,
                src_ip=src_ip,
                src_port=0,
                dst_ip=dst_ip,
                dst_port=0,
                protocol="ICMP",
                length=total_len,
                ingest_source="pcap",
            )
        else:
            # Other IP protocol (e.g. GRE, ESP, IGMP)
            return PacketEvent(
                timestamp=ts,
                src_ip=src_ip,
                src_port=0,
                dst_ip=dst_ip,
                dst_port=0,
                protocol=f"IP_PROTO_{proto_num}",
                length=total_len,
                ingest_source="pcap",
            )

    def _parse_tcp(
        self,
        ts: float,
        src_ip: str,
        dst_ip: str,
        data: bytes | dpkt.tcp.TCP,
        total_len: int,
    ) -> PacketEvent:
        """Parse TCP header, flags, and application-layer TLS handshakes."""
        try:
            tcp = data if isinstance(data, dpkt.tcp.TCP) else dpkt.tcp.TCP(data)
        except Exception:
            return PacketEvent(
                timestamp=ts,
                src_ip=src_ip,
                src_port=0,
                dst_ip=dst_ip,
                dst_port=0,
                protocol="TCP",
                length=total_len,
                ingest_source="pcap",
            )

        tcp_flags = {
            "SYN": bool(tcp.flags & dpkt.tcp.TH_SYN),
            "ACK": bool(tcp.flags & dpkt.tcp.TH_ACK),
            "FIN": bool(tcp.flags & dpkt.tcp.TH_FIN),
            "RST": bool(tcp.flags & dpkt.tcp.TH_RST),
            "PSH": bool(tcp.flags & dpkt.tcp.TH_PUSH),
            "URG": bool(tcp.flags & dpkt.tcp.TH_URG),
            "ECE": bool(tcp.flags & dpkt.tcp.TH_ECE),
            "CWR": bool(tcp.flags & dpkt.tcp.TH_CWR),
        }

        tls_ja3 = None
        tls_ja3s = None
        tls_sni = None
        tls_ja3_string = None
        protocol = "TCP"

        # Check for TLS Handshake payload: Type 22 (Handshake) at byte 0
        payload = bytes(tcp.data)
        if len(payload) >= 6 and payload[0] == 22:
            protocol = "TLS"
            # Handshake Type 1 = ClientHello
            if payload[5] == 1:
                client_hello = parse_client_hello(payload)
                if client_hello:
                    tls_ja3 = client_hello.get("ja3_hash")
                    tls_sni = client_hello.get("server_name")
                    tls_ja3_string = client_hello.get("ja3_string")
            # Handshake Type 2 = ServerHello
            elif payload[5] == 2:
                server_hello = parse_server_hello(payload)
                if server_hello:
                    tls_ja3s = server_hello.get("ja3s_hash")

        return PacketEvent(
            timestamp=ts,
            src_ip=src_ip,
            src_port=tcp.sport,
            dst_ip=dst_ip,
            dst_port=tcp.dport,
            protocol=protocol,
            length=total_len,
            tcp_flags=tcp_flags,
            tcp_seq=tcp.seq,
            tcp_ack=tcp.ack,
            tls_ja3=tls_ja3,
            tls_ja3s=tls_ja3s,
            tls_sni=tls_sni,
            tls_ja3_string=tls_ja3_string,
            payload_entropy=None,
            ingest_source="pcap",
        )

    def _parse_udp(
        self,
        ts: float,
        src_ip: str,
        dst_ip: str,
        data: bytes | dpkt.udp.UDP,
        total_len: int,
    ) -> PacketEvent:
        """Parse UDP header, DNS queries, and QUIC initial metadata."""
        try:
            udp = data if isinstance(data, dpkt.udp.UDP) else dpkt.udp.UDP(data)
        except Exception:
            return PacketEvent(
                timestamp=ts,
                src_ip=src_ip,
                src_port=0,
                dst_ip=dst_ip,
                dst_port=0,
                protocol="UDP",
                length=total_len,
                ingest_source="pcap",
            )

        payload = bytes(udp.data)
        protocol = "UDP"
        dns_query = None
        dns_qtype = None
        dns_is_response = None
        dns_answer_count = None
        quic_version = None
        quic_conn_id_len = None
        quic_packet_type = None

        # Check for DNS (Standard port 53 or mDNS 5353)
        if udp.sport == 53 or udp.dport == 53 or udp.sport == 5353 or udp.dport == 5353:
            try:
                dns = dpkt.dns.DNS(payload)
                protocol = "DNS"
                dns_is_response = bool(dns.qr)
                dns_answer_count = len(dns.an)
                if dns.qd:
                    q = dns.qd[0]
                    dns_query = q.name
                    dns_qtype = str(q.type)
            except Exception:
                pass

        # Check for QUIC (Long-header metadata only, zero key derivation)
        # Long header has highest bit set (0x80)
        elif len(payload) >= 5 and (payload[0] & 0x80) != 0:
            protocol = "QUIC"
            try:
                version = struct.unpack("!I", payload[1:5])[0]
                quic_version = version
                if len(payload) >= 6:
                    dcil = payload[5]
                    quic_conn_id_len = dcil
                # Long header packet type bits: (byte 0 & 0x30) >> 4
                pkt_type_id = (payload[0] & 0x30) >> 4
                packet_types = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}
                quic_packet_type = packet_types.get(pkt_type_id, "Unknown")
            except Exception:
                pass

        return PacketEvent(
            timestamp=ts,
            src_ip=src_ip,
            src_port=udp.sport,
            dst_ip=dst_ip,
            dst_port=udp.dport,
            protocol=protocol,
            length=total_len,
            dns_query=dns_query,
            dns_qtype=dns_qtype,
            dns_is_response=dns_is_response,
            dns_answer_count=dns_answer_count,
            quic_version=quic_version,
            quic_conn_id_len=quic_conn_id_len,
            quic_packet_type=quic_packet_type,
            payload_entropy=None,
            ingest_source="pcap",
        )
