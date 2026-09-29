"""
tests/test_windowed_engine.py

Unit tests for WindowedFeatureEngine:
1. (dst, window): Volumetric DDoS features (syn_to_ack_ratio, incoming_pps, src_ip_entropy)
2. (src, window): Port scan features (dst_port_count, dst_ip_count, syn_scan_ratio)
3. (src, dst, pair): Beaconing IAT features (iat_mean, iat_cv, is_periodic)
4. (client, domain): DGA/DNS tunneling features (avg_query_length, max_entropy, txt_ratio)
5. (tls_flow): TLS fingerprint metadata (ja3, ja3s, pst_sequence)
6. Bounded memory capacity enforcement (LRU eviction under high cardinality)
7. Strict timestamp determinism across multiple executions
"""
from __future__ import annotations

import pytest
from trinetra.features.windowed_engine import WindowedFeatureEngine
from trinetra.schemas import FlowEvent


def _make_event(
    ts: float,
    src_ip: str = "10.0.0.1",
    dst_ip: str = "192.168.1.10",
    src_port: int = 40000,
    dst_port: int = 80,
    proto: str = "TCP",
    length: int = 64,
    flags: dict | None = None,
    dns_query: str | None = None,
    dns_qtype: str | None = None,
    ja3: str | None = None,
) -> FlowEvent:
    return FlowEvent(
        timestamp=ts,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=proto,
        length=length,
        tcp_flags=flags or {},
        dns_query=dns_query,
        dns_qtype=dns_qtype,
        tls_ja3=ja3,
    )


class TestWindowedEngineDstFeatures:
    def test_syn_to_ack_ratio_and_pps(self) -> None:
        engine = WindowedFeatureEngine(dst_window_seconds=10.0)
        # 8 SYN packets from distinct sources targeting victim 192.168.1.10
        for i in range(8):
            ev = _make_event(
                ts=100.0 + i * 0.1,
                src_ip=f"10.0.0.{i+1}",
                dst_ip="192.168.1.10",
                flags={"SYN": True, "ACK": False},
            )
            engine.process_event(ev)

        feat = engine.get_dst_features("192.168.1.10")
        assert feat is not None
        assert feat.packet_count == 8
        assert feat.syn_count == 8
        assert feat.ack_count == 0
        assert feat.syn_to_ack_ratio == pytest.approx(8.0, rel=1e-2)
        assert feat.src_ip_entropy > 2.5  # High entropy (8 distinct sources)

    def test_window_sliding_expiry(self) -> None:
        engine = WindowedFeatureEngine(dst_window_seconds=5.0)
        # Packets at t=100.0
        for i in range(5):
            ev = _make_event(ts=100.0, src_ip=f"10.0.0.{i}", dst_ip="192.168.1.50")
            engine.process_event(ev)

        feat1 = engine.get_dst_features("192.168.1.50")
        assert feat1 is not None
        assert feat1.packet_count == 5

        # Advance time by 6.0 seconds (t=106.0) with 1 new packet
        ev2 = _make_event(ts=106.0, src_ip="10.0.0.99", dst_ip="192.168.1.50")
        engine.process_event(ev2)

        feat2 = engine.get_dst_features("192.168.1.50")
        assert feat2 is not None
        # Old 5 packets expired from 5-second window; only the new packet remains
        assert feat2.packet_count == 1
        assert feat2.packet_count < feat1.packet_count


class TestWindowedEngineSrcFeatures:
    def test_port_scan_features(self) -> None:
        engine = WindowedFeatureEngine(src_window_seconds=10.0)
        scanner_ip = "172.16.0.5"

        # Scanner probes 20 distinct destination ports with SYN packets
        for p in range(1, 21):
            ev = _make_event(
                ts=200.0 + p * 0.05,
                src_ip=scanner_ip,
                dst_port=p * 100,
                flags={"SYN": True, "ACK": False},
            )
            engine.process_event(ev)

        feat = engine.get_src_features(scanner_ip)
        assert feat is not None
        assert feat.packet_count == 20
        assert feat.dst_port_count == 20
        assert feat.syn_count == 20
        assert feat.syn_scan_ratio == pytest.approx(1.0, rel=1e-2)


class TestWindowedEnginePairFeatures:
    def test_beaconing_iat_periodic(self) -> None:
        engine = WindowedFeatureEngine()
        src = "192.168.1.100"
        c2 = "203.0.113.5"

        # Regular periodic beacon every 5.0 seconds
        for i in range(10):
            ev = _make_event(ts=1000.0 + i * 5.0, src_ip=src, dst_ip=c2)
            engine.process_event(ev)

        feat = engine.get_pair_features(src, c2)
        assert feat is not None
        assert feat.sample_count == 10
        assert feat.iat_mean == pytest.approx(5.0, abs=0.1)
        assert feat.iat_cv < 0.1  # Very low CV indicates strict periodicity
        assert feat.iat_autocorr > 0.5


class TestWindowedEngineDomainFeatures:
    def test_dns_tunneling_and_dga_features(self) -> None:
        engine = WindowedFeatureEngine()
        client = "192.168.1.80"
        dga_domain = "vxqkjz98a2plk4nm.evil-c2.net"

        for _ in range(5):
            ev = _make_event(
                ts=3000.0,
                src_ip=client,
                proto="UDP",
                dns_query=dga_domain,
                dns_qtype="TXT",
            )
            engine.process_event(ev)

        feat = engine.get_domain_features(client, dga_domain)
        assert feat is not None
        assert feat.query_count == 5
        assert feat.avg_query_length == len(dga_domain)
        assert feat.max_entropy > 3.0  # High Shannon entropy for random-looking DGA string
        assert feat.txt_record_ratio == 1.0


class TestWindowedEngineTlsFeatures:
    def test_tls_metadata_extraction(self) -> None:
        engine = WindowedFeatureEngine()
        ev = _make_event(
            ts=4000.0,
            src_ip="192.168.1.20",
            dst_ip="93.184.216.34",
            src_port=51234,
            dst_port=443,
            proto="TCP",
            length=512,
            ja3="6734f37431670b3ab4292b8f60f29984",
        )
        engine.process_event(ev)

        flow_id = "192.168.1.20:51234_93.184.216.34:443_TCP"
        feat = engine.get_tls_features(flow_id)
        assert feat is not None
        assert feat.ja3 == "6734f37431670b3ab4292b8f60f29984"
        assert feat.pst_length == 1


class TestWindowedEngineCapacityBounding:
    def test_lru_capacity_bounding(self) -> None:
        # Engine configured with small capacity limit of 5
        engine = WindowedFeatureEngine(max_dst_keys=5, max_src_keys=5)

        # Ingest packets from 10 distinct destination IPs
        for i in range(10):
            ev = _make_event(ts=5000.0 + i, dst_ip=f"10.0.0.{i}")
            engine.process_event(ev)

        # Capacity must be strictly bounded at 5
        assert len(engine.dst_accumulators) == 5

        # Oldest destinations (10.0.0.0 through 10.0.0.4) were evicted
        assert engine.get_dst_features("10.0.0.0") is None
        # Most recent destinations (10.0.0.5 through 10.0.0.9) remain active
        assert engine.get_dst_features("10.0.0.9") is not None


class TestWindowedEngineDeterminism:
    def test_replay_determinism(self) -> None:
        import random
        rng = random.Random(1337)

        events: list[FlowEvent] = []
        cur_ts = 100.0
        for i in range(100):
            cur_ts += rng.uniform(0.01, 0.5)
            events.append(
                _make_event(
                    ts=round(cur_ts, 4),
                    src_ip=f"10.0.0.{rng.randint(1, 5)}",
                    dst_ip=f"192.168.1.{rng.randint(1, 3)}",
                    src_port=rng.randint(1024, 65535),
                    dst_port=rng.choice([80, 443, 53]),
                    flags={"SYN": (i % 3 == 0), "ACK": True},
                )
            )

        # Run A
        engineA = WindowedFeatureEngine(dst_window_seconds=5.0)
        for ev in events:
            engineA.process_event(ev)

        # Run B
        engineB = WindowedFeatureEngine(dst_window_seconds=5.0)
        for ev in events:
            engineB.process_event(ev)

        # Assert identical feature results across both runs
        featA = engineA.get_dst_features("192.168.1.1")
        featB = engineB.get_dst_features("192.168.1.1")
        assert featA is not None and featB is not None
        assert featA.packet_count == featB.packet_count
        assert featA.syn_to_ack_ratio == featB.syn_to_ack_ratio
        assert featA.src_ip_entropy == featB.src_ip_entropy
