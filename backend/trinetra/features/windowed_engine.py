"""
backend/trinetra/features/windowed_engine.py

Deterministic, Timestamp-Driven Windowed Statistical Feature Engine.
Processes streaming FlowEvent or FlowRecord events and maintains strictly bounded,
LRU-evicted state keyed across 5 operational dimensions:
1. (dst, window): Volumetric DDoS & resource starvation (syn_to_ack_ratio, incoming_pps, src_ip_entropy, udp_amplification)
2. (src, window): Port scanning & horizontal reconnaissance (dst_port_count, dst_ip_count, syn_scan_ratio)
3. (src, dst, pair): Command & Control beaconing IAT tracking (iat_mean, iat_cv, iat_autocorr)
4. (client, domain): DGA & DNS tunneling detection (avg_query_len, max_entropy, txt_ratio)
5. (tls_flow): Encrypted TLS malware sessions (ja3, ja3s, pst_sequence)

ARCHITECTURAL INVARIANTS:
1. Driven strictly by packet/record timestamps (event.timestamp), NEVER wall-clock time.
2. Hard maximum capacities on all internal dictionaries with deterministic LRU eviction.
3. Zero network sockets, zero transmit capabilities.
"""
from __future__ import annotations

from collections import OrderedDict, deque
from dataclasses import dataclass, field
import math
from typing import Any, Dict, List, Optional, Set, Tuple

from trinetra.features.entropy import shannon_entropy_str
from trinetra.features.periodicity import analyze_periodicity
from trinetra.schemas import FlowEvent


# ---------------------------------------------------------------------------
# Feature Output Data Classes
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class DstWindowFeatures:
    dst_ip: str
    window_seconds: float
    packet_count: int
    incoming_pps: float
    syn_count: int
    ack_count: int
    syn_to_ack_ratio: float
    src_ip_entropy: float
    udp_bytes_in: int
    udp_bytes_out: int
    udp_amplification_factor: float


@dataclass(slots=True)
class SrcWindowFeatures:
    src_ip: str
    window_seconds: float
    packet_count: int
    dst_port_count: int
    dst_ip_count: int
    syn_count: int
    syn_scan_ratio: float


@dataclass(slots=True)
class PairFeatures:
    src_ip: str
    dst_ip: str
    sample_count: int
    iat_mean: float
    iat_std: float
    iat_cv: float
    iat_autocorr: float
    is_periodic: bool


@dataclass(slots=True)
class DomainFeatures:
    client_ip: str
    domain: str
    query_count: int
    avg_query_length: float
    max_entropy: float
    txt_record_ratio: float


@dataclass(slots=True)
class TlsFlowFeatures:
    flow_id: str
    ja3: Optional[str]
    ja3s: Optional[str]
    sni: Optional[str]
    pst_length: int
    pst_sequence: list[int]


# ---------------------------------------------------------------------------
# Internal Window Accumulators
# ---------------------------------------------------------------------------
class DstAccumulator:
    """Tracks sliding window statistics targeting a specific destination IP."""
    __slots__ = ("window_sec", "events", "syn_count", "ack_count", "src_counts", "udp_in", "udp_out")

    def __init__(self, window_sec: float) -> None:
        self.window_sec = window_sec
        # Queue of (ts, src_ip, is_syn, is_ack, proto, length, is_inbound)
        self.events: deque[tuple[float, str, bool, bool, str, int, bool]] = deque()
        self.syn_count = 0
        self.ack_count = 0
        self.src_counts: dict[str, int] = {}
        self.udp_in = 0
        self.udp_out = 0

    def add_packet(self, ts: float, src_ip: str, is_syn: bool, is_ack: bool, proto: str, length: int, is_inbound: bool) -> None:
        self.events.append((ts, src_ip, is_syn, is_ack, proto, length, is_inbound))
        if is_syn:
            self.syn_count += 1
        if is_ack:
            self.ack_count += 1
        self.src_counts[src_ip] = self.src_counts.get(src_ip, 0) + 1
        if proto == "UDP":
            if is_inbound:
                self.udp_in += length
            else:
                self.udp_out += length
        self._trim(ts)

    def _trim(self, current_ts: float) -> None:
        cutoff = current_ts - self.window_sec
        while self.events and self.events[0][0] < cutoff:
            ts, src_ip, is_syn, is_ack, proto, length, is_inbound = self.events.popleft()
            if is_syn:
                self.syn_count -= 1
            if is_ack:
                self.ack_count -= 1
            self.src_counts[src_ip] -= 1
            if self.src_counts[src_ip] <= 0:
                del self.src_counts[src_ip]
            if proto == "UDP":
                if is_inbound:
                    self.udp_in -= length
                else:
                    self.udp_out -= length

    def compute_features(self, dst_ip: str, current_ts: float) -> DstWindowFeatures:
        self._trim(current_ts)
        n = len(self.events)
        pps = (n / self.window_sec) if self.window_sec > 0 else 0.0
        syn_ack_ratio = (self.syn_count / (self.ack_count + 1.0))

        # Source IP Shannon entropy
        entropy = 0.0
        if n > 0 and self.src_counts:
            for cnt in self.src_counts.values():
                p = cnt / n
                entropy -= p * math.log2(p)

        amp_factor = (self.udp_in / (self.udp_out + 1.0)) if self.udp_in > 0 else 0.0

        return DstWindowFeatures(
            dst_ip=dst_ip,
            window_seconds=self.window_sec,
            packet_count=n,
            incoming_pps=round(pps, 3),
            syn_count=self.syn_count,
            ack_count=self.ack_count,
            syn_to_ack_ratio=round(syn_ack_ratio, 3),
            src_ip_entropy=round(entropy, 3),
            udp_bytes_in=self.udp_in,
            udp_bytes_out=self.udp_out,
            udp_amplification_factor=round(amp_factor, 3),
        )


class SrcAccumulator:
    """Tracks sliding window statistics originating from a source IP."""
    __slots__ = ("window_sec", "events", "dst_ports", "dst_ips", "syn_count")

    def __init__(self, window_sec: float) -> None:
        self.window_sec = window_sec
        # Queue of (ts, dst_ip, dst_port, is_syn)
        self.events: deque[tuple[float, str, int, bool]] = deque()
        self.dst_ports: dict[int, int] = {}
        self.dst_ips: dict[str, int] = {}
        self.syn_count = 0

    def add_packet(self, ts: float, dst_ip: str, dst_port: int, is_syn: bool) -> None:
        self.events.append((ts, dst_ip, dst_port, is_syn))
        self.dst_ports[dst_port] = self.dst_ports.get(dst_port, 0) + 1
        self.dst_ips[dst_ip] = self.dst_ips.get(dst_ip, 0) + 1
        if is_syn:
            self.syn_count += 1
        self._trim(ts)

    def _trim(self, current_ts: float) -> None:
        cutoff = current_ts - self.window_sec
        while self.events and self.events[0][0] < cutoff:
            ts, dst_ip, dst_port, is_syn = self.events.popleft()
            self.dst_ports[dst_port] -= 1
            if self.dst_ports[dst_port] <= 0:
                del self.dst_ports[dst_port]
            self.dst_ips[dst_ip] -= 1
            if self.dst_ips[dst_ip] <= 0:
                del self.dst_ips[dst_ip]
            if is_syn:
                self.syn_count -= 1

    def compute_features(self, src_ip: str, current_ts: float) -> SrcWindowFeatures:
        self._trim(current_ts)
        n = len(self.events)
        syn_ratio = (self.syn_count / n) if n > 0 else 0.0
        return SrcWindowFeatures(
            src_ip=src_ip,
            window_seconds=self.window_sec,
            packet_count=n,
            dst_port_count=len(self.dst_ports),
            dst_ip_count=len(self.dst_ips),
            syn_count=self.syn_count,
            syn_scan_ratio=round(syn_ratio, 3),
        )


class PairAccumulator:
    """Tracks packet timestamp intervals for a specific (src, dst) pair (C2 beaconing)."""
    __slots__ = ("timestamps", "max_samples")

    def __init__(self, max_samples: int = 64) -> None:
        self.max_samples = max_samples
        self.timestamps: deque[float] = deque(maxlen=max_samples)

    def add_timestamp(self, ts: float) -> None:
        self.timestamps.append(ts)

    def compute_features(self, src_ip: str, dst_ip: str) -> PairFeatures:
        ts_list = list(self.timestamps)
        n = len(ts_list)
        if n < 4:
            return PairFeatures(
                src_ip=src_ip,
                dst_ip=dst_ip,
                sample_count=n,
                iat_mean=0.0,
                iat_std=0.0,
                iat_cv=0.0,
                iat_autocorr=0.0,
                is_periodic=False,
            )

        prof = analyze_periodicity(ts_list, min_samples=4)
        if prof is not None:
            return PairFeatures(
                src_ip=src_ip,
                dst_ip=dst_ip,
                sample_count=n,
                iat_mean=round(prof.mean_iat, 4),
                iat_std=round(prof.std_iat, 4),
                iat_cv=round(prof.cv_iat, 4),
                iat_autocorr=round(prof.autocorr_peak, 4),
                is_periodic=prof.is_periodic or prof.is_jittered_periodic,
            )
        else:
            diffs = [ts_list[i] - ts_list[i - 1] for i in range(1, n) if (ts_list[i] - ts_list[i - 1]) > 0.01]
            mean_v = sum(diffs) / len(diffs) if diffs else 0.0
            return PairFeatures(
                src_ip=src_ip,
                dst_ip=dst_ip,
                sample_count=n,
                iat_mean=round(mean_v, 4),
                iat_std=0.0,
                iat_cv=0.0,
                iat_autocorr=0.0,
                is_periodic=False,
            )


class DomainAccumulator:
    """Tracks DNS queries for a (client_ip, domain) pair."""
    __slots__ = ("query_lengths", "entropies", "txt_count", "total_queries")

    def __init__(self, max_queries: int = 50) -> None:
        self.query_lengths: deque[int] = deque(maxlen=max_queries)
        self.entropies: deque[float] = deque(maxlen=max_queries)
        self.txt_count = 0
        self.total_queries = 0

    def add_query(self, query: str, qtype: Optional[str]) -> None:
        self.total_queries += 1
        qlen = len(query)
        self.query_lengths.append(qlen)
        ent = shannon_entropy_str(query)
        self.entropies.append(ent)
        if qtype == "TXT":
            self.txt_count += 1

    def compute_features(self, client_ip: str, domain: str) -> DomainFeatures:
        n = len(self.query_lengths)
        avg_len = (sum(self.query_lengths) / n) if n > 0 else 0.0
        max_ent = max(self.entropies) if self.entropies else 0.0
        txt_ratio = (self.txt_count / self.total_queries) if self.total_queries > 0 else 0.0
        return DomainFeatures(
            client_ip=client_ip,
            domain=domain,
            query_count=self.total_queries,
            avg_query_length=round(avg_len, 2),
            max_entropy=round(max_ent, 3),
            txt_record_ratio=round(txt_ratio, 3),
        )


# ---------------------------------------------------------------------------
# Master Windowed Feature Engine
# ---------------------------------------------------------------------------
class WindowedFeatureEngine:
    """
    Main stateful feature engine managing bounded window accumulators across all 5 dimensions.
    """

    def __init__(
        self,
        dst_window_seconds: float = 10.0,
        src_window_seconds: float = 10.0,
        max_dst_keys: int = 10_000,
        max_src_keys: int = 10_000,
        max_pair_keys: int = 20_000,
        max_domain_keys: int = 10_000,
        max_tls_keys: int = 10_000,
    ) -> None:
        self.dst_window_seconds = dst_window_seconds
        self.src_window_seconds = src_window_seconds

        self.max_dst_keys = max_dst_keys
        self.max_src_keys = max_src_keys
        self.max_pair_keys = max_pair_keys
        self.max_domain_keys = max_domain_keys
        self.max_tls_keys = max_tls_keys

        self.dst_accumulators: OrderedDict[tuple[str, float], DstAccumulator] = OrderedDict()
        self.src_accumulators: OrderedDict[tuple[str, float], SrcAccumulator] = OrderedDict()
        self.pair_accumulators: OrderedDict[tuple[str, str], PairAccumulator] = OrderedDict()
        self.domain_accumulators: OrderedDict[tuple[str, str], DomainAccumulator] = OrderedDict()
        self.tls_accumulators: OrderedDict[str, TlsFlowFeatures] = OrderedDict()

        self.last_observed_timestamp = 0.0

    def process_event(self, event: FlowEvent) -> None:
        """Process a streaming FlowEvent into bounded window accumulators."""
        ts = event.timestamp
        self.last_observed_timestamp = max(self.last_observed_timestamp, ts)

        is_syn = bool(event.tcp_flags and event.tcp_flags.get("SYN"))
        is_ack = bool(event.tcp_flags and event.tcp_flags.get("ACK"))

        # 1. Update (dst, window)
        dst_key = (event.dst_ip, self.dst_window_seconds)
        if dst_key in self.dst_accumulators:
            self.dst_accumulators.move_to_end(dst_key)
            dst_acc = self.dst_accumulators[dst_key]
        else:
            if len(self.dst_accumulators) >= self.max_dst_keys:
                self.dst_accumulators.popitem(last=False)
            dst_acc = DstAccumulator(self.dst_window_seconds)
            self.dst_accumulators[dst_key] = dst_acc

        dst_acc.add_packet(
            ts=ts,
            src_ip=event.src_ip,
            is_syn=is_syn,
            is_ack=is_ack,
            proto=event.protocol,
            length=event.length,
            is_inbound=True,
        )

        # 2. Update (src, window)
        src_key = (event.src_ip, self.src_window_seconds)
        if src_key in self.src_accumulators:
            self.src_accumulators.move_to_end(src_key)
            src_acc = self.src_accumulators[src_key]
        else:
            if len(self.src_accumulators) >= self.max_src_keys:
                self.src_accumulators.popitem(last=False)
            src_acc = SrcAccumulator(self.src_window_seconds)
            self.src_accumulators[src_key] = src_acc

        src_acc.add_packet(ts=ts, dst_ip=event.dst_ip, dst_port=event.dst_port, is_syn=is_syn)

        # 3. Update (src, dst, pair)
        pair_key = (event.src_ip, event.dst_ip)
        if pair_key in self.pair_accumulators:
            self.pair_accumulators.move_to_end(pair_key)
            pair_acc = self.pair_accumulators[pair_key]
        else:
            if len(self.pair_accumulators) >= self.max_pair_keys:
                self.pair_accumulators.popitem(last=False)
            pair_acc = PairAccumulator(max_samples=64)
            self.pair_accumulators[pair_key] = pair_acc

        pair_acc.add_timestamp(ts)

        # 4. Update (client, domain) if DNS
        if event.dns_query:
            dom_key = (event.src_ip, event.dns_query)
            if dom_key in self.domain_accumulators:
                self.domain_accumulators.move_to_end(dom_key)
                dom_acc = self.domain_accumulators[dom_key]
            else:
                if len(self.domain_accumulators) >= self.max_domain_keys:
                    self.domain_accumulators.popitem(last=False)
                dom_acc = DomainAccumulator(max_queries=50)
                self.domain_accumulators[dom_key] = dom_acc
            dom_acc.add_query(event.dns_query, event.dns_qtype)

        # 5. Update (tls_flow) if TLS metadata present
        if event.tls_ja3 or event.tls_ja3s:
            flow_id = f"{event.src_ip}:{event.src_port}_{event.dst_ip}:{event.dst_port}_{event.protocol}"
            if flow_id in self.tls_accumulators:
                self.tls_accumulators.move_to_end(flow_id)
            else:
                if len(self.tls_accumulators) >= self.max_tls_keys:
                    self.tls_accumulators.popitem(last=False)
                pst = [event.length]
                self.tls_accumulators[flow_id] = TlsFlowFeatures(
                    flow_id=flow_id,
                    ja3=event.tls_ja3,
                    ja3s=event.tls_ja3s,
                    sni=event.tls_sni,
                    pst_length=len(pst),
                    pst_sequence=pst,
                )

    def get_dst_features(self, dst_ip: str, window_sec: Optional[float] = None) -> Optional[DstWindowFeatures]:
        w = window_sec or self.dst_window_seconds
        key = (dst_ip, w)
        acc = self.dst_accumulators.get(key)
        return acc.compute_features(dst_ip, self.last_observed_timestamp) if acc else None

    def get_src_features(self, src_ip: str, window_sec: Optional[float] = None) -> Optional[SrcWindowFeatures]:
        w = window_sec or self.src_window_seconds
        key = (src_ip, w)
        acc = self.src_accumulators.get(key)
        return acc.compute_features(src_ip, self.last_observed_timestamp) if acc else None

    def get_pair_features(self, src_ip: str, dst_ip: str) -> Optional[PairFeatures]:
        key = (src_ip, dst_ip)
        acc = self.pair_accumulators.get(key)
        return acc.compute_features(src_ip, dst_ip) if acc else None

    def get_domain_features(self, client_ip: str, domain: str) -> Optional[DomainFeatures]:
        key = (client_ip, domain)
        acc = self.domain_accumulators.get(key)
        return acc.compute_features(client_ip, domain) if acc else None

    def get_tls_features(self, flow_id: str) -> Optional[TlsFlowFeatures]:
        return self.tls_accumulators.get(flow_id)

    def clear(self) -> None:
        """Clear all accumulators."""
        self.dst_accumulators.clear()
        self.src_accumulators.clear()
        self.pair_accumulators.clear()
        self.domain_accumulators.clear()
        self.tls_accumulators.clear()
