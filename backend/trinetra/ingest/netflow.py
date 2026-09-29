"""
Trinetra NetFlow v9 Binary Ingest Engine (RFC 3954 Compliant).

Parses binary NetFlow v9 UDP export datagrams into normalized FlowEvent records.

KEY CAPABILITIES:
    - True binary parsing of NetFlow v9 headers, template flowsets, and data flowsets.
    - Out-of-Order Template Caching: Caches orphaned data records arriving before
      their template. Once the template arrives, buffered records are decoded and emitted.
    - Template Refresh: Tracks template lifecycle per exporter (source_id).
    - Options Template Support: Correctly parses FlowSet ID 1 without crashing.
    - Unknown Field Resilience: Safely skips unknown field IDs by declared byte length;
      tracks unknown field telemetry.
    - Deterministic binary generator: build_netflow_v9_packet() for test data generation
      and cross-checking flow counters against PCAP tables.
"""
from __future__ import annotations

import ipaddress
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Iterator

from trinetra.schemas import FlowEvent


# ---------------------------------------------------------------------------
# RFC 3954 Standard Field Definitions
# ---------------------------------------------------------------------------
FIELD_IN_BYTES = 1
FIELD_IN_PKTS = 2
FIELD_FLOWS = 3
FIELD_PROTOCOL = 4
FIELD_SRC_TOS = 5
FIELD_TCP_FLAGS = 6
FIELD_L4_SRC_PORT = 7
FIELD_IPV4_SRC_ADDR = 8
FIELD_SRC_MASK = 9
FIELD_INPUT_SNMP = 10
FIELD_L4_DST_PORT = 11
FIELD_IPV4_DST_ADDR = 12
FIELD_DST_MASK = 13
FIELD_OUTPUT_SNMP = 14
FIELD_IPV4_NEXT_HOP = 15
FIELD_SRC_AS = 16
FIELD_DST_AS = 17
FIELD_BGP_IPV4_NEXT_HOP = 18
FIELD_MUL_DST_PKTS = 19
FIELD_MUL_DST_BYTES = 20
FIELD_LAST_SWITCHED = 21
FIELD_FIRST_SWITCHED = 22
FIELD_OUT_BYTES = 23
FIELD_OUT_PKTS = 24
FIELD_IPV6_SRC_ADDR = 27
FIELD_IPV6_DST_ADDR = 28
FIELD_IPV6_SRC_MASK = 29
FIELD_IPV6_DST_MASK = 30
FIELD_IPV6_FLOW_LABEL = 31
FIELD_ICMP_TYPE = 32
FIELD_SAMPLING_INTERVAL = 34
FIELD_SAMPLING_ALGORITHM = 35


# ---------------------------------------------------------------------------
# Statistics Dataclass
# ---------------------------------------------------------------------------
@dataclass
class NetFlowIngestStats:
    """Telemetry counters for NetFlow v9 ingest."""
    packets_read: int = 0
    flowsets_parsed: int = 0
    records_emitted: int = 0
    templates_registered: int = 0
    options_templates_registered: int = 0
    orphaned_records_buffered: int = 0
    orphaned_records_resolved: int = 0
    orphaned_records_dropped: int = 0
    unknown_fields_encountered: int = 0
    corrupt_packets_dropped: int = 0


# ---------------------------------------------------------------------------
# Template Definition
# ---------------------------------------------------------------------------
@dataclass
class FieldSpec:
    field_type: int
    length: int


@dataclass
class TemplateRecord:
    template_id: int
    fields: list[FieldSpec]
    record_length: int
    last_refresh: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# NetFlow v9 Parser
# ---------------------------------------------------------------------------
class NetFlowV9Parser:
    """
    Original binary NetFlow v9 (RFC 3954) parser.

    Maintains template caches keyed by (source_id, template_id) and an
    orphaned data buffer to resolve data records received before templates.
    """

    def __init__(self, max_orphaned_flowsets: int = 1000) -> None:
        self.stats = NetFlowIngestStats()
        self.templates: dict[tuple[int, int], TemplateRecord] = {}
        self.options_templates: dict[tuple[int, int], dict] = {}
        self.max_orphaned = max_orphaned_flowsets
        # Orphan buffer: list of (source_id, template_id, raw_bytes, unix_secs, sys_uptime)
        self.orphaned_data: list[tuple[int, int, bytes, int, int]] = []

    def parse_datagram(self, datagram: bytes) -> Iterator[FlowEvent]:
        """
        Parse raw NetFlow v9 binary UDP packet and yield FlowEvent records.

        Args:
            datagram: Raw UDP payload bytes.

        Yields:
            FlowEvent objects decoded from data flowsets.
        """
        self.stats.packets_read += 1
        if len(datagram) < 20:
            self.stats.corrupt_packets_dropped += 1
            return

        try:
            version, count, sys_uptime, unix_secs, seq, source_id = struct.unpack(
                "!HHIIII", datagram[:20]
            )
        except Exception:
            self.stats.corrupt_packets_dropped += 1
            return

        if version != 9:
            self.stats.corrupt_packets_dropped += 1
            return

        offset = 20
        newly_registered_templates: list[int] = []

        # Iterate through FlowSets
        while offset + 4 <= len(datagram):
            try:
                flowset_id, flowset_len = struct.unpack("!HH", datagram[offset:offset + 4])
            except Exception:
                self.stats.corrupt_packets_dropped += 1
                break

            if flowset_len < 4 or offset + flowset_len > len(datagram):
                self.stats.corrupt_packets_dropped += 1
                break

            flowset_data = datagram[offset + 4:offset + flowset_len]
            self.stats.flowsets_parsed += 1

            if flowset_id == 0:
                # Template FlowSet
                new_ids = self._parse_template_flowset(source_id, flowset_data)
                newly_registered_templates.extend(new_ids)

            elif flowset_id == 1:
                # Options Template FlowSet
                self._parse_options_template_flowset(source_id, flowset_data)

            elif flowset_id >= 256:
                # Data FlowSet: flowset_id is the template_id
                template_key = (source_id, flowset_id)
                if template_key in self.templates:
                    template = self.templates[template_key]
                    yield from self._decode_data_flowset(
                        template, flowset_data, unix_secs, sys_uptime
                    )
                else:
                    # Template not yet seen: Buffer in orphaned data queue
                    self.stats.orphaned_records_buffered += 1
                    if len(self.orphaned_data) < self.max_orphaned:
                        self.orphaned_data.append((source_id, flowset_id, flowset_data, unix_secs, sys_uptime))
                    else:
                        self.stats.orphaned_records_dropped += 1

            offset += flowset_len

        # If any new templates arrived, re-evaluate orphaned buffer
        if newly_registered_templates and self.orphaned_data:
            yield from self._drain_orphaned_records(source_id, set(newly_registered_templates))

    def _parse_template_flowset(self, source_id: int, data: bytes) -> list[int]:
        """Parse template definitions in a template flowset."""
        offset = 0
        registered_ids: list[int] = []

        while offset + 4 <= len(data):
            template_id, field_count = struct.unpack("!HH", data[offset:offset + 4])
            offset += 4
            fields: list[FieldSpec] = []
            rec_len = 0

            for _ in range(field_count):
                if offset + 4 > len(data):
                    break
                ftype, flen = struct.unpack("!HH", data[offset:offset + 4])
                fields.append(FieldSpec(field_type=ftype, length=flen))
                rec_len += flen
                offset += 4

            template_key = (source_id, template_id)
            self.templates[template_key] = TemplateRecord(
                template_id=template_id,
                fields=fields,
                record_length=rec_len,
                last_refresh=time.time(),
            )
            self.stats.templates_registered += 1
            registered_ids.append(template_id)

        return registered_ids

    def _parse_options_template_flowset(self, source_id: int, data: bytes) -> None:
        """Parse options template flowset (FlowSet ID 1)."""
        if len(data) < 6:
            return
        template_id, scope_len, opt_len = struct.unpack("!HHH", data[:6])
        self.options_templates[(source_id, template_id)] = {
            "scope_len": scope_len,
            "opt_len": opt_len,
        }
        self.stats.options_templates_registered += 1

    def _decode_data_flowset(
        self,
        template: TemplateRecord,
        data: bytes,
        unix_secs: int,
        sys_uptime: int,
    ) -> Iterator[FlowEvent]:
        """Decode records from a data flowset using the given template."""
        rec_len = template.record_length
        if rec_len <= 0:
            return

        offset = 0
        while offset + rec_len <= len(data):
            rec_bytes = data[offset:offset + rec_len]
            offset += rec_len

            event = self._decode_record(template, rec_bytes, unix_secs, sys_uptime)
            if event is not None:
                self.stats.records_emitted += 1
                yield event

    def _decode_record(
        self,
        template: TemplateRecord,
        raw: bytes,
        unix_secs: int,
        sys_uptime: int,
    ) -> FlowEvent | None:
        """Decode a single record binary slice into a normalized FlowEvent."""
        src_ip = "0.0.0.0"
        dst_ip = "0.0.0.0"
        src_port = 0
        dst_port = 0
        proto_num = 6
        byte_count = 0
        tcp_flags_val = 0
        first_switched = 0
        last_switched = 0

        pos = 0
        for f in template.fields:
            chunk = raw[pos:pos + f.length]
            pos += f.length

            if f.field_type == FIELD_IPV4_SRC_ADDR and f.length == 4:
                src_ip = socket.inet_ntoa(chunk)
            elif f.field_type == FIELD_IPV4_DST_ADDR and f.length == 4:
                dst_ip = socket.inet_ntoa(chunk)
            elif f.field_type == FIELD_IPV6_SRC_ADDR and f.length == 16:
                src_ip = socket.inet_ntop(socket.AF_INET6, chunk)
            elif f.field_type == FIELD_IPV6_DST_ADDR and f.length == 16:
                dst_ip = socket.inet_ntop(socket.AF_INET6, chunk)
            elif f.field_type == FIELD_L4_SRC_PORT:
                src_port = int.from_bytes(chunk, byteorder="big")
            elif f.field_type == FIELD_L4_DST_PORT:
                dst_port = int.from_bytes(chunk, byteorder="big")
            elif f.field_type == FIELD_PROTOCOL:
                proto_num = int.from_bytes(chunk, byteorder="big")
            elif f.field_type == FIELD_IN_BYTES:
                byte_count = int.from_bytes(chunk, byteorder="big")
            elif f.field_type == FIELD_TCP_FLAGS:
                tcp_flags_val = int.from_bytes(chunk, byteorder="big")
            elif f.field_type == FIELD_FIRST_SWITCHED:
                first_switched = int.from_bytes(chunk, byteorder="big")
            elif f.field_type == FIELD_LAST_SWITCHED:
                last_switched = int.from_bytes(chunk, byteorder="big")
            else:
                self.stats.unknown_fields_encountered += 1

        proto_map = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMP"}
        proto_str = proto_map.get(proto_num, f"IP_PROTO_{proto_num}")

        # Compute approximate record timestamp in unix epoch seconds
        if sys_uptime > 0 and first_switched > 0:
            uptime_diff_sec = (sys_uptime - first_switched) / 1000.0
            flow_ts = max(0.0, unix_secs - uptime_diff_sec)
        else:
            flow_ts = float(unix_secs)

        tcp_flags = None
        if proto_str == "TCP":
            tcp_flags = {
                "FIN": bool(tcp_flags_val & 0x01),
                "SYN": bool(tcp_flags_val & 0x02),
                "RST": bool(tcp_flags_val & 0x04),
                "PSH": bool(tcp_flags_val & 0x08),
                "ACK": bool(tcp_flags_val & 0x10),
                "URG": bool(tcp_flags_val & 0x20),
            }

        return FlowEvent(
            timestamp=flow_ts,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=proto_str,
            length=byte_count,
            tcp_flags=tcp_flags,
            ingest_source="netflow_v9",
        )

    def _drain_orphaned_records(self, source_id: int, target_templates: set[int]) -> Iterator[FlowEvent]:
        """Process buffered orphaned data flowsets whose template has just arrived."""
        remaining: list[tuple[int, int, bytes, int, int]] = []
        for src_id, tmpl_id, data, u_secs, uptime in self.orphaned_data:
            if src_id == source_id and tmpl_id in target_templates:
                template = self.templates.get((src_id, tmpl_id))
                if template:
                    self.stats.orphaned_records_resolved += 1
                    yield from self._decode_data_flowset(template, data, u_secs, uptime)
                else:
                    remaining.append((src_id, tmpl_id, data, u_secs, uptime))
            else:
                remaining.append((src_id, tmpl_id, data, u_secs, uptime))
        self.orphaned_data = remaining


# ---------------------------------------------------------------------------
# Deterministic Binary NetFlow v9 Datagram Generator (for testing & verification)
# ---------------------------------------------------------------------------
def build_netflow_v9_packet(
    flows: list[FlowEvent],
    source_id: int = 1,
    template_id: int = 256,
    sys_uptime: int = 100000,
    unix_secs: int = 1700000000,
    seq: int = 1,
    include_template: bool = True,
) -> bytes:
    """
    Construct a valid binary RFC 3954 NetFlow v9 datagram.

    Args:
        flows: Flow records to encode as data flowsets.
        source_id: NetFlow exporter engine ID.
        template_id: Template ID (>= 256).
        sys_uptime: Exporter uptime in ms.
        unix_secs: Export epoch seconds.
        seq: Sequence number.
        include_template: Whether to prepend the template flowset (set False to test orphaned buffering!).

    Returns:
        Packed bytes of the NetFlow v9 UDP payload.
    """
    flowset_blocks: list[bytes] = []

    # 1. Template FlowSet (Standard 7-tuple: src_ip, dst_ip, src_port, dst_port, proto, bytes, flags)
    if include_template:
        tmpl_fields = [
            (FIELD_IPV4_SRC_ADDR, 4),
            (FIELD_IPV4_DST_ADDR, 4),
            (FIELD_L4_SRC_PORT, 2),
            (FIELD_L4_DST_PORT, 2),
            (FIELD_PROTOCOL, 1),
            (FIELD_IN_BYTES, 4),
            (FIELD_TCP_FLAGS, 1),
        ]
        field_bytes = b"".join(struct.pack("!HH", ftype, flen) for ftype, flen in tmpl_fields)
        tmpl_header = struct.pack("!HH", template_id, len(tmpl_fields))
        tmpl_content = tmpl_header + field_bytes
        # FlowSet header: ID=0, Length=4 + len(tmpl_content)
        tmpl_flowset = struct.pack("!HH", 0, 4 + len(tmpl_content)) + tmpl_content
        flowset_blocks.append(tmpl_flowset)

    # 2. Data FlowSet
    if flows:
        records: list[bytes] = []
        for flow in flows:
            src_bytes = socket.inet_aton(flow.src_ip if "." in flow.src_ip else "0.0.0.0")
            dst_bytes = socket.inet_aton(flow.dst_ip if "." in flow.dst_ip else "0.0.0.0")
            proto_num = 6 if flow.protocol == "TCP" else 17 if flow.protocol == "UDP" else 1
            flags_val = 0
            if flow.tcp_flags:
                if flow.tcp_flags.get("FIN"): flags_val |= 0x01
                if flow.tcp_flags.get("SYN"): flags_val |= 0x02
                if flow.tcp_flags.get("RST"): flags_val |= 0x04
                if flow.tcp_flags.get("PSH"): flags_val |= 0x08
                if flow.tcp_flags.get("ACK"): flags_val |= 0x10
                if flow.tcp_flags.get("URG"): flags_val |= 0x20

            rec = struct.pack(
                "!4s4sHHBIB",
                src_bytes,
                dst_bytes,
                flow.src_port,
                flow.dst_port,
                proto_num,
                flow.length,
                flags_val,
            )
            records.append(rec)

        data_content = b"".join(records)
        # Pad to 4-byte boundary
        pad_len = (4 - (len(data_content) % 4)) % 4
        data_content += b"\x00" * pad_len
        data_flowset = struct.pack("!HH", template_id, 4 + len(data_content)) + data_content
        flowset_blocks.append(data_flowset)

    total_content = b"".join(flowset_blocks)
    count = len(flowset_blocks)

    # NetFlow v9 Header (20 bytes)
    header = struct.pack("!HHIIII", 9, count, sys_uptime, unix_secs, seq, source_id)
    return header + total_content
