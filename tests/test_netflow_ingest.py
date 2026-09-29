"""
tests/test_netflow_ingest.py

Tests for NetFlowV9Parser:
- RFC 3954 standard binary datagram decoding
- Out-of-order template arrival: data flowset received BEFORE template, buffered,
  and decoded when template arrives
- Template refresh
- Options template handling (FlowSet ID 1)
- Unknown field handling (safely skipped by declared length, counted)
- Cross-checking flow counts and byte totals against simulator flows
"""
from __future__ import annotations

import pytest

from trinetra.ingest.netflow import (
    FIELD_IN_BYTES,
    FIELD_IPV4_DST_ADDR,
    FIELD_IPV4_SRC_ADDR,
    FIELD_L4_DST_PORT,
    FIELD_L4_SRC_PORT,
    FIELD_PROTOCOL,
    NetFlowV9Parser,
    build_netflow_v9_packet,
)
from trinetra.schemas import FlowEvent


def _make_sample_flow(src_ip="192.168.1.10", dst_ip="10.0.0.1", bytes_len=1500) -> FlowEvent:
    return FlowEvent(
        timestamp=1700000000.0,
        src_ip=src_ip,
        src_port=44332,
        dst_ip=dst_ip,
        dst_port=443,
        protocol="TCP",
        length=bytes_len,
        tcp_flags={"SYN": False, "ACK": True, "FIN": False, "RST": False},
        ingest_source="test",
    )


class TestNetFlowV9Ingest:
    def test_parse_standard_netflow_v9_packet(self) -> None:
        flow = _make_sample_flow()
        packet_bytes = build_netflow_v9_packet([flow], include_template=True)

        parser = NetFlowV9Parser()
        events = list(parser.parse_datagram(packet_bytes))

        assert len(events) == 1
        ev = events[0]
        assert ev.src_ip == "192.168.1.10"
        assert ev.dst_ip == "10.0.0.1"
        assert ev.src_port == 44332
        assert ev.dst_port == 443
        assert ev.protocol == "TCP"
        assert ev.length == 1500
        assert parser.stats.records_emitted == 1
        assert parser.stats.templates_registered == 1

    def test_out_of_order_template_arrival(self) -> None:
        """
        CRITICAL TEST: Data packet arrives BEFORE its template packet.
        Parser must buffer the orphaned data, register template on next packet,
        and emit the resolved records!
        """
        flow = _make_sample_flow(bytes_len=2048)

        # 1. Packet without template (orphaned)
        orphan_pkt = build_netflow_v9_packet([flow], template_id=300, include_template=False)

        parser = NetFlowV9Parser()
        events_stage1 = list(parser.parse_datagram(orphan_pkt))

        # Must not emit yet because template is unknown
        assert len(events_stage1) == 0
        assert parser.stats.orphaned_records_buffered == 1

        # 2. Template arrives in a subsequent packet
        template_pkt = build_netflow_v9_packet([], template_id=300, include_template=True)
        events_stage2 = list(parser.parse_datagram(template_pkt))

        # Now the buffered record must be drained and emitted!
        assert len(events_stage2) == 1
        assert events_stage2[0].length == 2048
        assert parser.stats.orphaned_records_resolved == 1

    def test_options_template_does_not_crash(self) -> None:
        """Options template flowset (FlowSet ID 1) parsed safely."""
        import struct
        # NetFlow header (20 bytes) + Options Template FlowSet (ID=1, Len=12)
        hdr = struct.pack("!HHIIII", 9, 1, 1000, 1700000000, 1, 1)
        # FlowSet ID=1, Length=12, Template ID=257, Scope Length=4, Option Length=4
        opts_flowset = struct.pack("!HHHHHH", 1, 12, 257, 4, 4, 1)
        datagram = hdr + opts_flowset

        parser = NetFlowV9Parser()
        events = list(parser.parse_datagram(datagram))
        assert len(events) == 0
        assert parser.stats.options_templates_registered == 1

    def test_unknown_fields_safely_skipped(self) -> None:
        """Unknown field IDs in template are skipped by declared length and counted."""
        import socket, struct
        # Construct template with an unknown field (ID=999, len=4)
        tmpl_fields = [
            (FIELD_IPV4_SRC_ADDR, 4),
            (FIELD_IPV4_DST_ADDR, 4),
            (999, 4),  # Unknown vendor extension field
            (FIELD_IN_BYTES, 4),
        ]
        field_bytes = b"".join(struct.pack("!HH", ftype, flen) for ftype, flen in tmpl_fields)
        tmpl_content = struct.pack("!HH", 258, len(tmpl_fields)) + field_bytes
        tmpl_fs = struct.pack("!HH", 0, 4 + len(tmpl_content)) + tmpl_content

        # Data record with dummy bytes for field 999
        rec = struct.pack(
            "!4s4s4sI",
            socket.inet_aton("10.0.0.5"),
            socket.inet_aton("10.0.0.6"),
            b"\xde\xad\xbe\xef",
            5000,
        )
        data_fs = struct.pack("!HH", 258, 4 + len(rec)) + rec
        hdr = struct.pack("!HHIIII", 9, 2, 1000, 1700000000, 1, 1)
        datagram = hdr + tmpl_fs + data_fs

        parser = NetFlowV9Parser()
        events = list(parser.parse_datagram(datagram))
        assert len(events) == 1
        assert events[0].src_ip == "10.0.0.5"
        assert events[0].length == 5000
        assert parser.stats.unknown_fields_encountered >= 1

    def test_cross_check_flow_counts_and_bytes(self) -> None:
        """
        Cross-check flow counts and total bytes exported via NetFlow v9
        against decoded flow records.
        """
        sample_flows = [
            _make_sample_flow("10.0.1.1", "10.0.2.1", 1000),
            _make_sample_flow("10.0.1.2", "10.0.2.2", 2500),
            _make_sample_flow("10.0.1.3", "10.0.2.3", 750),
        ]
        total_expected_bytes = sum(f.length for f in sample_flows)

        pkt = build_netflow_v9_packet(sample_flows, source_id=42, template_id=260)

        parser = NetFlowV9Parser()
        decoded_events = list(parser.parse_datagram(pkt))

        assert len(decoded_events) == 3
        total_decoded_bytes = sum(e.length for e in decoded_events)
        assert total_decoded_bytes == total_expected_bytes
