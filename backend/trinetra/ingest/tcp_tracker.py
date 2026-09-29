"""
Trinetra Passive TCP State Tracker.

Statefully tracks TCP connections across a passive optical TAP without transmitting.
Designed specifically for the physical realities of an air-gapped data diode:
1. Mid-Stream Capture: Handles flows whose SYN was missed (starts in MIDSTREAM_ESTABLISHED).
2. Duplicates: Detects repeated sequence numbers with identical payload lengths.
3. Out-of-Order Delivery: Buffers / flags sequence gaps without failing.
4. One-Sided Loss / Asymmetric Routing: Handles traffic where only one direction is visible
   (labeled HALF_OPEN_OBSERVED).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from trinetra.schemas import TcpState


@dataclass(slots=True)
class DirectionTcpState:
    """State tracking for one half of a TCP connection."""
    next_seq: int = 0
    isn: Optional[int] = None
    fin_seen: bool = False
    rst_seen: bool = False
    packets_seen: int = 0
    duplicate_packets: int = 0
    out_of_order_packets: int = 0
    last_seq: int = 0
    last_ack: int = 0
    seen_seqs: set[int] = field(default_factory=set)


@dataclass(slots=True)
class PassiveTcpTracker:
    """
    Passive state tracker for a single bidirectional TCP flow session.
    """
    state: TcpState = TcpState.SYN_SENT
    fwd_state: DirectionTcpState = field(default_factory=DirectionTcpState)
    rev_state: DirectionTcpState = field(default_factory=DirectionTcpState)
    rtt_ms: Optional[float] = None
    syn_ts: Optional[float] = None
    syn_ack_ts: Optional[float] = None
    handshake_completed: bool = False

    def process_packet(
        self,
        ts: float,
        is_forward: bool,
        tcp_flags: dict[str, bool],
        seq: int,
        ack: int,
        payload_len: int,
    ) -> TcpState:
        """
        Update the passive TCP state based on an observed packet.

        Args:
            ts: Packet epoch timestamp.
            is_forward: True if packet is from initiator to responder; False otherwise.
            tcp_flags: Dict of TCP flag booleans (SYN, ACK, FIN, RST, etc.).
            seq: Sequence number.
            ack: Acknowledgment number.
            payload_len: Length of TCP payload.

        Returns:
            The current TcpState after transition.
        """
        curr = self.fwd_state if is_forward else self.rev_state
        peer = self.rev_state if is_forward else self.fwd_state

        curr.packets_seen += 1

        # 1. Duplicate Detection
        # Key on (seq, payload_len). Maintain a small sliding window of 64 recent sequence numbers.
        seq_key = (seq, payload_len)
        if seq_key in curr.seen_seqs:
            curr.duplicate_packets += 1
        else:
            curr.seen_seqs.add(seq_key)
            if len(curr.seen_seqs) > 64:
                # Keep memory strictly bounded
                curr.seen_seqs.pop()

        # 2. Out-of-Order Detection
        if curr.next_seq > 0 and seq < curr.next_seq and not tcp_flags.get("RST"):
            curr.out_of_order_packets += 1
        elif seq > 0:
            curr.next_seq = max(curr.next_seq, seq + max(payload_len, 1))

        curr.last_seq = seq
        curr.last_ack = ack

        syn = tcp_flags.get("SYN", False)
        ack_flag = tcp_flags.get("ACK", False)
        fin = tcp_flags.get("FIN", False)
        rst = tcp_flags.get("RST", False)

        # 3. Connection Teardown
        if rst:
            curr.rst_seen = True
            self.state = TcpState.CLOSED
            return self.state

        if fin:
            curr.fin_seen = True
            if peer.fin_seen:
                self.state = TcpState.CLOSED
            else:
                self.state = TcpState.FIN_WAIT
            return self.state

        # 4. Happy Path State Transitions
        if self.state == TcpState.SYN_SENT:
            if is_forward and syn and not ack_flag:
                # Client SYN
                curr.isn = seq
                self.syn_ts = ts
                self.state = TcpState.SYN_SENT
            elif not is_forward and syn and ack_flag:
                # Server SYN-ACK
                curr.isn = seq
                self.syn_ack_ts = ts
                self.state = TcpState.SYN_RCVD
            elif is_forward and not syn:
                # Packet seen without preceding SYN -> Mid-stream capture!
                self.state = TcpState.MIDSTREAM_ESTABLISHED
            elif not is_forward and not syn:
                # Only reverse direction seen without handshake -> Half-open observed!
                self.state = TcpState.HALF_OPEN_OBSERVED

        elif self.state == TcpState.SYN_RCVD:
            if is_forward and ack_flag and not syn:
                # Client ACK completing 3-way handshake
                self.state = TcpState.ESTABLISHED
                self.handshake_completed = True
                if self.syn_ts is not None and self.syn_ack_ts is not None:
                    self.rtt_ms = max(0.0, (ts - self.syn_ts) * 1000.0)

        elif self.state in (TcpState.ESTABLISHED, TcpState.MIDSTREAM_ESTABLISHED):
            pass

        return self.state
