"""
tests/test_flow_table_tcp.py

Tests for FlowTable and PassiveTcpTracker:
- Bidirectional flow aggregation (A->B and B->A update the same session)
- Per-direction packet & byte counters
- Deterministic timestamp-driven expiry (wall-clock invariant)
- Hard capacity bounds & LRU eviction under SYN flood & wide port scan
- Passive TCP tracking edge cases:
    1. 3-way handshake (SYN -> SYN_SENT, SYN-ACK -> SYN_RCVD, ACK -> ESTABLISHED)
    2. Duplicate packet sequence detection
    3. Out-of-order sequence arrival
    4. Mid-stream capture (first packet without SYN -> MIDSTREAM_ESTABLISHED)
    5. One-sided loss (traffic in only one direction -> HALF_OPEN_OBSERVED)
"""
from __future__ import annotations

import pytest

from trinetra.config import EnclaveConfig, ScenarioTopology
from trinetra.ingest.flow_table import FlowTable
from trinetra.ingest.tcp_tracker import PassiveTcpTracker
from trinetra.schemas import Direction, FlowEvent, TcpState


def _make_event(
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    protocol: str = "TCP",
    length: int = 100,
    ts: float = 1700000000.0,
    flags: dict[str, bool] = None,
    seq: int = 1000,
    ack: int = 0,
) -> FlowEvent:
    return FlowEvent(
        timestamp=ts,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=protocol,
        length=length,
        tcp_flags=flags or {"SYN": True, "ACK": False, "FIN": False, "RST": False},
        tcp_seq=seq,
        tcp_ack=ack,
        ingest_source="test",
    )


class TestBidirectionalFlowTable:
    def test_bidirectional_aggregation_and_counters(self) -> None:
        """Forward and reverse packets must accumulate into the same flow session."""
        cfg = EnclaveConfig()
        table = FlowTable(config=cfg, idle_timeout_seconds=60.0)

        # 1. Forward packet: Client -> Server
        ev_fwd = _make_event("192.168.1.100", 50000, "10.0.0.1", 80, length=200, ts=1.0)
        rec1, exp1 = table.process_event(ev_fwd)

        assert rec1.forward_packets == 1
        assert rec1.forward_bytes == 200
        assert rec1.reverse_packets == 0
        assert rec1.reverse_bytes == 0

        # 2. Reverse packet: Server -> Client
        ev_rev = _make_event(
            "10.0.0.1", 80, "192.168.1.100", 50000, length=1500, ts=1.05,
            flags={"SYN": False, "ACK": True, "FIN": False, "RST": False},
        )
        rec2, exp2 = table.process_event(ev_rev)

        assert rec2.flow_id == rec1.flow_id
        assert rec2.forward_packets == 1
        assert rec2.forward_bytes == 200
        assert rec2.reverse_packets == 1
        assert rec2.reverse_bytes == 1500
        assert rec2.total_packets == 2
        assert rec2.total_bytes == 1700
        assert len(table.flows) == 1

    def test_deterministic_timestamp_driven_expiry(self) -> None:
        """
        Flow expiration must be driven by packet timestamps, NEVER wall-clock time.
        """
        table = FlowTable(idle_timeout_seconds=10.0)

        # Flow A at t = 100.0
        table.process_event(_make_event("10.0.0.1", 1000, "10.0.0.2", 80, ts=100.0))
        assert len(table.flows) == 1

        # Flow B at t = 105.0 (Flow A idle 5s, timeout is 10s -> not expired)
        _, expired = table.process_event(_make_event("10.0.0.3", 2000, "10.0.0.4", 80, ts=105.0))
        assert len(expired) == 0
        assert len(table.flows) == 2

        # Flow C at t = 112.0 (Flow A idle 12s -> expired, Flow B idle 7s -> still active)
        _, expired = table.process_event(_make_event("10.0.0.5", 3000, "10.0.0.6", 80, ts=112.0))
        assert len(expired) == 1
        assert expired[0].initiator_ip == "10.0.0.1"
        assert len(table.flows) == 2

    def test_bounded_memory_under_syn_flood(self) -> None:
        """
        CRITICAL TEST: Under a high-rate spoofed SYN flood, memory must remain
        strictly bounded to max_flows and the pipeline must continue processing.
        """
        table = FlowTable(max_flows=200, idle_timeout_seconds=300.0)

        # Simulate 1,000 distinct spoofed attacker IPs
        for i in range(1, 1001):
            src_ip = f"198.51.{i // 256}.{i % 256}"
            ev = _make_event(src_ip, 10000 + (i % 50000), "10.0.1.10", 80, ts=1000.0 + (i * 0.001))
            table.process_event(ev)
            # Memory constraint invariant
            assert len(table.flows) <= 200

        assert len(table.flows) == 200
        assert table.stats.evicted_flows_capacity == 800
        assert table.stats.total_packets_processed == 1000

    def test_bounded_memory_under_wide_port_scan(self) -> None:
        """
        CRITICAL TEST: Wide vertical port scan hitting 1,000 ports on single victim.
        Memory must stay strictly within max_flows.
        """
        table = FlowTable(max_flows=150, idle_timeout_seconds=300.0)

        for port in range(1, 1001):
            ev = _make_event("10.2.0.5", 40000, "10.1.0.100", port, ts=2000.0 + (port * 0.01))
            table.process_event(ev)
            assert len(table.flows) <= 150

        assert len(table.flows) == 150
        assert table.stats.evicted_flows_capacity == 850


class TestPassiveTcpStateTracker:
    def test_happy_path_three_way_handshake(self) -> None:
        """Test standard 3-way handshake state transitions."""
        tracker = PassiveTcpTracker()

        # 1. Client SYN
        s1 = tracker.process_packet(1.0, is_forward=True, tcp_flags={"SYN": True, "ACK": False}, seq=1000, ack=0, payload_len=0)
        assert s1 == TcpState.SYN_SENT

        # 2. Server SYN-ACK
        s2 = tracker.process_packet(1.02, is_forward=False, tcp_flags={"SYN": True, "ACK": True}, seq=5000, ack=1001, payload_len=0)
        assert s2 == TcpState.SYN_RCVD

        # 3. Client ACK
        s3 = tracker.process_packet(1.04, is_forward=True, tcp_flags={"SYN": False, "ACK": True}, seq=1001, ack=5001, payload_len=0)
        assert s3 == TcpState.ESTABLISHED
        assert tracker.handshake_completed is True
        assert tracker.rtt_ms == pytest.approx(40.0)

    def test_duplicate_packet_detection(self) -> None:
        """Duplicate sequence numbers with identical payload lengths are flagged."""
        tracker = PassiveTcpTracker()
        tracker.state = TcpState.ESTABLISHED

        # Packet 1
        tracker.process_packet(2.0, is_forward=True, tcp_flags={"ACK": True}, seq=2000, ack=5001, payload_len=500)
        assert tracker.fwd_state.duplicate_packets == 0

        # Identical retransmission (same seq, same payload_len)
        tracker.process_packet(2.05, is_forward=True, tcp_flags={"ACK": True}, seq=2000, ack=5001, payload_len=500)
        assert tracker.fwd_state.duplicate_packets == 1

    def test_out_of_order_sequence_detection(self) -> None:
        """Packets arriving with sequence numbers behind next_seq are flagged as out-of-order."""
        tracker = PassiveTcpTracker()
        tracker.state = TcpState.ESTABLISHED

        # Packet with seq=1000, len=1000 -> next_seq = 2000
        tracker.process_packet(3.0, is_forward=True, tcp_flags={"ACK": True}, seq=1000, ack=1, payload_len=1000)

        # Packet arriving with seq=500 (behind next_seq 2000) -> out of order!
        tracker.process_packet(3.01, is_forward=True, tcp_flags={"ACK": True}, seq=500, ack=1, payload_len=500)
        assert tracker.fwd_state.out_of_order_packets == 1

    def test_midstream_capture(self) -> None:
        """First packet seen mid-stream without SYN enters MIDSTREAM_ESTABLISHED."""
        tracker = PassiveTcpTracker()
        state = tracker.process_packet(4.0, is_forward=True, tcp_flags={"SYN": False, "ACK": True}, seq=35000, ack=12000, payload_len=1460)
        assert state == TcpState.MIDSTREAM_ESTABLISHED

    def test_one_sided_loss_half_open(self) -> None:
        """Only reverse direction traffic observed enters HALF_OPEN_OBSERVED."""
        tracker = PassiveTcpTracker()
        state = tracker.process_packet(5.0, is_forward=False, tcp_flags={"SYN": False, "ACK": True}, seq=90000, ack=4000, payload_len=500)
        assert state == TcpState.HALF_OPEN_OBSERVED
