"""
Trinetra Stateful Flow Table Engine.

Maintains bidirectional flow sessions with deterministic timestamp-driven expiration
and strictly bounded capacity.

CORE ARCHITECTURAL INVARIANTS:
    1. Deterministic Replay: Flow expiration is driven strictly by packet/record
       timestamps (event.timestamp), NEVER by wall-clock time. Replaying the same PCAP
       or NetFlow export produces 100% byte-identical session records.
    2. Bidirectional Key Normalization: Maps A->B and B->A packets to the identical
       flow record, with distinct per-direction counters (forward and reverse).
    3. Topology-Aware Direction Labelling: Evaluates direction (INBOUND, OUTBOUND,
       LATERAL, TRANSIT) via EnclaveConfig and per-scenario ScenarioTopology overrides.
    4. Bounded Memory / Hard Capacity Limits: Enforces max_flows. When capacity is
       reached under flood or scan conditions, evicts the oldest flow (lowest last_time)
       and increments telemetry counters without crashing.
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Optional

from trinetra.config import DEFAULT_CONFIG, EnclaveConfig
from trinetra.ingest.tcp_tracker import PassiveTcpTracker
from trinetra.schemas import Direction, FlowEvent, TcpState


# ---------------------------------------------------------------------------
# Bidirectional Flow Key
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class BidirectionalFlowKey:
    """
    Canonical 5-tuple identifier for bidirectional flow aggregation.
    Guarantees that (src, sport, dst, dport, proto) and (dst, dport, src, sport, proto)
    produce the identical hash and equality.
    """
    ep_a: tuple[str, int]
    ep_b: tuple[str, int]
    protocol: str

    @classmethod
    def from_endpoints(cls, src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str) -> tuple["BidirectionalFlowKey", bool]:
        """
        Create canonical key and indicate if this packet represents the forward direction.

        Returns:
            (BidirectionalFlowKey, is_forward)
        """
        ep1 = (src_ip, src_port)
        ep2 = (dst_ip, dst_port)

        if ep1 <= ep2:
            return cls(ep_a=ep1, ep_b=ep2, protocol=protocol), True
        else:
            return cls(ep_a=ep2, ep_b=ep1, protocol=protocol), False


# ---------------------------------------------------------------------------
# Flow Record
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class FlowRecord:
    """
    Stateful aggregated flow session record.
    """
    flow_id: str
    key: BidirectionalFlowKey
    initiator_ip: str
    initiator_port: int
    responder_ip: str
    responder_port: int
    protocol: str
    direction: Direction
    start_time: float
    last_time: float

    # Per-direction counters
    forward_packets: int = 0
    forward_bytes: int = 0
    reverse_packets: int = 0
    reverse_bytes: int = 0

    # TCP state and flags
    forward_flags: dict[str, bool] = field(default_factory=dict)
    reverse_flags: dict[str, bool] = field(default_factory=dict)
    tcp_tracker: Optional[PassiveTcpTracker] = None

    # Application layer metadata
    dns_query: Optional[str] = None
    dns_qtype: Optional[str] = None
    tls_ja3: Optional[str] = None
    tls_ja3s: Optional[str] = None
    tls_sni: Optional[str] = None
    quic_version: Optional[int] = None
    quic_packet_type: Optional[str] = None

    # Feature extraction vectors
    packet_sizes: list[int] = field(default_factory=list)  # Signed (+len forward, -len reverse)
    packet_timestamps: list[float] = field(default_factory=list)

    @property
    def total_packets(self) -> int:
        return self.forward_packets + self.reverse_packets

    @property
    def total_bytes(self) -> int:
        return self.forward_bytes + self.reverse_bytes

    @property
    def duration_seconds(self) -> float:
        return max(0.0, self.last_time - self.start_time)

    @property
    def tcp_state(self) -> TcpState:
        if self.tcp_tracker:
            return self.tcp_tracker.state
        return TcpState.ESTABLISHED


# ---------------------------------------------------------------------------
# Flow Table Telemetry Counters
# ---------------------------------------------------------------------------
@dataclass
class FlowTableStats:
    total_packets_processed: int = 0
    total_flows_created: int = 0
    active_flows: int = 0
    expired_flows: int = 0
    evicted_flows_capacity: int = 0
    peak_active_flows: int = 0


# ---------------------------------------------------------------------------
# Stateful Flow Table
# ---------------------------------------------------------------------------
class FlowTable:
    """
    Deterministic flow table driven by packet timestamps.
    """

    def __init__(
        self,
        config: EnclaveConfig = DEFAULT_CONFIG,
        topology_override: Optional[list[str]] = None,
        idle_timeout_seconds: Optional[float] = None,
        max_flows: int = 50_000,
    ) -> None:
        self.config = config
        self.topology_override = topology_override
        self.idle_timeout = idle_timeout_seconds or config.flow_idle_timeout_seconds
        self.max_flows = max_flows
        self.stats = FlowTableStats()
        self.flows: OrderedDict[BidirectionalFlowKey, FlowRecord] = OrderedDict()
        self.last_observed_time: float = 0.0
        self._last_expiry_check: float = 0.0

    def process_event(self, event: FlowEvent) -> tuple[FlowRecord, list[FlowRecord]]:
        """
        Ingest a single FlowEvent, update the flow session, and expire idle flows.

        Args:
            event: Packet or flow event from ingest.

        Returns:
            (updated_flow_record, list_of_expired_flows)
        """
        self.stats.total_packets_processed += 1
        current_ts = event.timestamp
        self.last_observed_time = max(self.last_observed_time, current_ts)

        # 1. Deterministic Timestamp-Driven Expiry (1.0s Batching Window)
        # Expire any flows whose idle duration exceeds idle_timeout based strictly on event.timestamp.
        # MAXIMUM EXPIRY STALENESS BOUND:
        # Expiry is evaluated when packet/simulation timestamp advances by >= 1.0s
        # (current_ts - self._last_expiry_check >= 1.0) or when active capacity reaches 95% limit.
        # An idle flow is therefore evicted at most 1.0 second of simulation time after its
        # idle_timeout threshold expires. Because this batching is indexed strictly by event.timestamp
        # (never wall-clock time), repeated replays of identical captures yield 100% bit-identical
        # expiration events and flow table records. At EOF, flush_all() deterministically emits any remaining sessions.
        if (current_ts - self._last_expiry_check >= 1.0) or (len(self.flows) >= self.max_flows * 0.95):
            expired = self._check_expiry(current_ts)
            self._last_expiry_check = current_ts
        else:
            expired = []

        # 2. Get or create flow record
        key, _ = BidirectionalFlowKey.from_endpoints(
            event.src_ip, event.src_port, event.dst_ip, event.dst_port, event.protocol
        )

        if key in self.flows:
            record = self.flows[key]
            # True forward packet = sent by flow initiator
            is_forward = (event.src_ip == record.initiator_ip and event.src_port == record.initiator_port)
            # Move to end of OrderedDict for LRU tracking
            self.flows.move_to_end(key)
        else:
            # First packet of this flow: current sender is the initiator
            is_forward = True
            # Capacity check: Enforce hard max_flows limit
            if len(self.flows) >= self.max_flows:
                # Evict oldest flow (FIFO / LRU front of OrderedDict)
                evicted_key, evicted_record = self.flows.popitem(last=False)
                self.stats.evicted_flows_capacity += 1
                expired.append(evicted_record)

            # Classify direction according to initiator IP
            dir_str = self.config.classify_direction(
                event.src_ip, event.dst_ip, override=self.topology_override
            )
            flow_id = f"{event.src_ip}:{event.src_port}_{event.dst_ip}:{event.dst_port}_{event.protocol}"

            record = FlowRecord(
                flow_id=flow_id,
                key=key,
                initiator_ip=event.src_ip,
                initiator_port=event.src_port,
                responder_ip=event.dst_ip,
                responder_port=event.dst_port,
                protocol=event.protocol,
                direction=Direction(dir_str),
                start_time=current_ts,
                last_time=current_ts,
                tcp_tracker=PassiveTcpTracker() if event.protocol in ("TCP", "TLS") else None,
            )
            self.flows[key] = record
            self.stats.total_flows_created += 1

        # 3. Update Flow Counters
        record.last_time = current_ts

        signed_len = event.length if is_forward else -event.length
        if len(record.packet_sizes) < 64:
            record.packet_sizes.append(signed_len)
            record.packet_timestamps.append(current_ts)

        if is_forward:
            record.forward_packets += 1
            record.forward_bytes += event.length
            if event.tcp_flags:
                record.forward_flags.update(event.tcp_flags)
        else:
            record.reverse_packets += 1
            record.reverse_bytes += event.length
            if event.tcp_flags:
                record.reverse_flags.update(event.tcp_flags)

        # 4. Update TCP State Machine if TCP
        if record.tcp_tracker and event.tcp_flags:
            record.tcp_tracker.process_packet(
                ts=current_ts,
                is_forward=is_forward,
                tcp_flags=event.tcp_flags,
                seq=event.tcp_seq or 0,
                ack=event.tcp_ack or 0,
                payload_len=event.length,
            )

        # 5. Attach Application Layer Metadata if newly observed
        if event.dns_query and not record.dns_query:
            record.dns_query = event.dns_query
            record.dns_qtype = event.dns_qtype
        if event.tls_ja3 and not record.tls_ja3:
            record.tls_ja3 = event.tls_ja3
            record.tls_sni = event.tls_sni
        if event.tls_ja3s and not record.tls_ja3s:
            record.tls_ja3s = event.tls_ja3s
        if event.quic_version and not record.quic_version:
            record.quic_version = event.quic_version
            record.quic_packet_type = event.quic_packet_type

        # Update stats
        self.stats.active_flows = len(self.flows)
        self.stats.peak_active_flows = max(self.stats.peak_active_flows, self.stats.active_flows)

        return record, expired

    def _check_expiry(self, current_ts: float) -> list[FlowRecord]:
        """Evict flows that have been idle longer than idle_timeout."""
        expired: list[FlowRecord] = []
        keys_to_remove: list[BidirectionalFlowKey] = []

        for key, record in self.flows.items():
            if current_ts - record.last_time > self.idle_timeout:
                keys_to_remove.append(key)
                expired.append(record)

        for k in keys_to_remove:
            del self.flows[k]
            self.stats.expired_flows += 1

        return expired

    def flush_all(self) -> list[FlowRecord]:
        """Flush and return all remaining flows in the table (end-of-stream)."""
        all_remaining = list(self.flows.values())
        self.flows.clear()
        self.stats.active_flows = 0
        return all_remaining
