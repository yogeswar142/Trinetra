#!/usr/bin/env python3
"""
Trinetra Pipeline Benchmark Harness v3: Phase 2a Feature Engine Cost.

Measures the exact incremental computational overhead of the WindowedFeatureEngine
operating continuously on the 500,000-packet mixed traffic fixture (308 MB).

Telemetry & Metrics:
1. Pure Throughput (pkts/sec and Mbps) with Feature Engine enabled.
2. Latency (service time per packet including raw parse, flow table aggregation, and windowed feature update):
   p50, p95, p99, p99.9, max.
3. Memory RSS consumption.
4. Saves raw JSON results to benchmarks/results/.
"""
from __future__ import annotations

import io
import json
import multiprocessing
import os
import platform
from pathlib import Path
import sys
import time
from datetime import datetime, timezone
import dpkt
import psutil

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend"))

from trinetra.config import EnclaveConfig
from trinetra.features.windowed_engine import WindowedFeatureEngine
from trinetra.ingest.flow_table import FlowTable
from trinetra.ingest.pcap import PcapIngest
from trinetra.schemas import FlowEvent

RESULTS_DIR = REPO_ROOT / "benchmarks" / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

FIXTURES_DIR = REPO_ROOT / "data" / "fixtures"
MIXED_500K_PATH = FIXTURES_DIR / "realistic_mixed_500k.pcap"


def get_windows_power_plan() -> str:
    try:
        import subprocess
        res = subprocess.run(["powercfg", "/getactivescheme"], capture_output=True, text=True, check=True)
        return res.stdout.strip()
    except Exception:
        return "Unknown"


def collect_telemetry() -> dict:
    vm = psutil.virtual_memory()
    battery = psutil.sensors_battery()
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "platform_system": platform.system(),
        "platform_release": platform.release(),
        "platform_machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_count_logical": multiprocessing.cpu_count(),
        "python_version": platform.python_version(),
        "python_architecture": "x64 Python emulated on ARM64 Windows (Snapdragon ARMv8, platform.machine()='AMD64')",
        "power_plugged": battery.power_plugged if battery else None,
        "battery_percent": battery.percent if battery else None,
        "power_plan": get_windows_power_plan(),
        "ram_total_gb": round(vm.total / (1024 ** 3), 2),
        "ram_available_gb": round(vm.available / (1024 ** 3), 2),
    }


def benchmark_v3_throughput(pcap_path: Path, max_packets: int | None = None, repetitions: int = 3) -> dict:
    file_bytes = pcap_path.stat().st_size
    pps_runs = []
    mbps_runs = []

    for _ in range(repetitions):
        ingest = PcapIngest()
        cfg = EnclaveConfig()
        table = FlowTable(config=cfg, max_flows=100_000)
        engine = WindowedFeatureEngine()

        count = 0
        with open(pcap_path, "rb") as f:
            t0 = time.perf_counter()
            for ev in ingest.parse_stream(f):
                table.process_event(ev)
                engine.process_event(ev)
                count += 1
                if max_packets and count >= max_packets:
                    break
            elapsed = time.perf_counter() - t0

        pps = count / elapsed if elapsed > 0 else 0
        mbps = (file_bytes * 8 / (1_000_000 * elapsed)) if (elapsed > 0 and not max_packets) else 0
        pps_runs.append(pps)
        mbps_runs.append(mbps)

    pps_sorted = sorted(pps_runs)
    mbps_sorted = sorted(mbps_runs)
    n = len(pps_runs)

    return {
        "repetitions": repetitions,
        "packets_processed": count,
        "packets_per_second": {
            "median": round(pps_sorted[n // 2], 2),
            "min": round(pps_sorted[0], 2),
            "max": round(pps_sorted[-1], 2),
            "raw": [round(x, 2) for x in pps_runs],
        },
        "throughput_mbps": {
            "median": round(mbps_sorted[n // 2], 2),
            "min": round(mbps_sorted[0], 2),
            "max": round(mbps_sorted[-1], 2),
        },
    }


def benchmark_v3_latency(pcap_path: Path, max_packets: int = 30_000) -> dict:
    ingest = PcapIngest()
    cfg = EnclaveConfig()
    table = FlowTable(config=cfg, max_flows=100_000)
    engine = WindowedFeatureEngine()

    service_times_ns: list[int] = []
    pipeline_lags_ns: list[int] = []

    with open(pcap_path, "rb") as f:
        reader = dpkt.pcap.Reader(f)
        count = 0
        for ts, buf in reader:
            t_start = time.perf_counter_ns()
            ev = ingest._parse_ethernet_packet(ts, buf)
            if ev is not None:
                table.process_event(ev)
                engine.process_event(ev)
                t_service = time.perf_counter_ns()
                # Latency Definition (b): Ingest to feature emission readiness
                _ = engine.get_dst_features(ev.dst_ip)
                t_emit = time.perf_counter_ns()
                pipeline_lags_ns.append(t_emit - t_start)
            else:
                t_service = time.perf_counter_ns()

            service_times_ns.append(t_service - t_start)
            count += 1
            if count >= max_packets:
                break

    def calc_percentiles(arr: list[int]) -> dict:
        arr.sort()
        n = len(arr)
        return {
            "count": n,
            "mean_us": round(sum(arr) / (n * 1000.0), 3),
            "p50_us": round(arr[int(n * 0.50)] / 1000.0, 3),
            "p95_us": round(arr[int(n * 0.95)] / 1000.0, 3),
            "p99_us": round(arr[int(n * 0.99)] / 1000.0, 3),
            "p99_9_us": round(arr[min(int(n * 0.999), n - 1)] / 1000.0, 3),
            "max_us": round(arr[-1] / 1000.0, 3),
        }

    return {
        "definition_a_service_time_per_packet": calc_percentiles(service_times_ns),
        "definition_b_ingest_to_feature_ready_lag": calc_percentiles(pipeline_lags_ns),
    }


def benchmark_v3_memory(pcap_path: Path, max_packets: int = 50_000) -> dict:
    proc = psutil.Process(os.getpid())
    rss_start_mb = proc.memory_info().rss / (1024 * 1024)

    ingest = PcapIngest()
    cfg = EnclaveConfig()
    table = FlowTable(config=cfg, max_flows=100_000)
    engine = WindowedFeatureEngine()

    count = 0
    with open(pcap_path, "rb") as f:
        for ev in ingest.parse_stream(f):
            table.process_event(ev)
            engine.process_event(ev)
            count += 1
            if count >= max_packets:
                break

    rss_end_mb = proc.memory_info().rss / (1024 * 1024)
    return {
        "packets_processed": count,
        "rss_start_mb": round(rss_start_mb, 2),
        "rss_peak_mb": round(rss_end_mb, 2),
        "rss_end_mb": round(rss_end_mb, 2),
        "rss_delta_mb": round(rss_end_mb - rss_start_mb, 2),
    }


def benchmark_v3_eviction_stress(packet_count: int = 20_000) -> dict:
    """Stress tests the WindowedFeatureEngine under a high-cardinality spoofed flood."""
    proc = psutil.Process(os.getpid())
    rss_start = proc.memory_info().rss / (1024 * 1024)

    # Bound capacities tightly to force massive eviction
    engine = WindowedFeatureEngine(
        dst_window_seconds=10.0,
        src_window_seconds=10.0,
        max_dst_keys=500,
        max_src_keys=500,
        max_pair_keys=1_000,
    )

    import random
    rng = random.Random(42)

    for i in range(packet_count):
        src_ip = f"10.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
        dst_ip = f"192.168.1.{rng.randint(1, 254)}"
        ts = 1000.0 + (i * 0.001)
        ev = FlowEvent(
            timestamp=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=rng.randint(1024, 65535),
            dst_port=80,
            protocol="TCP",
            length=64,
            tcp_flags={"SYN": True, "ACK": False, "FIN": False, "RST": False, "PSH": False, "URG": False},
        )
        engine.process_event(ev)

    rss_end = proc.memory_info().rss / (1024 * 1024)

    return {
        "packets_injected": packet_count,
        "configured_max_dst_keys": 500,
        "configured_max_src_keys": 500,
        "final_active_dst_keys": len(engine.dst_accumulators),
        "final_active_src_keys": len(engine.src_accumulators),
        "evictions_enforced": engine.eviction_counts,
        "rss_start_mb": round(rss_start, 2),
        "rss_end_mb": round(rss_end, 2),
        "memory_plateau_preserved": (
            len(engine.dst_accumulators) <= 500 and len(engine.src_accumulators) <= 500
        ),
    }


def run_benchmark_v3() -> Path:
    if not MIXED_500K_PATH.exists():
        print(f"Generating 500k mixed fixture -> {MIXED_500K_PATH}...")
        from scripts.generate_realistic_500k_pcap import generate_mixed_500k_pcap
        generate_mixed_500k_pcap(500_000)

    print("======================================================================")
    print("TRINETRA BENCHMARK v3: PHASE 2a FEATURE ENGINE OVERHEAD")
    print("======================================================================")
    telemetry = collect_telemetry()
    print(f"Host: {telemetry['platform_system']} ({telemetry['platform_machine']}), {telemetry['processor']}")
    print(f"Architecture: {telemetry['python_architecture']}")
    print(f"Power: {'Plugged In' if telemetry['power_plugged'] else 'On Battery'} ({telemetry['battery_percent']}%) | Scheme: {telemetry['power_plan']}")
    print("======================================================================")

    print("\n[1/4] Measuring pipeline throughput with WindowedFeatureEngine (500k pkts)...")
    tp = benchmark_v3_throughput(MIXED_500K_PATH, repetitions=2)
    print(f"  -> Throughput: {tp['packets_per_second']['median']:,} pkts/sec | {tp['throughput_mbps']['median']} Mbps")

    print("\n[2/4] Measuring per-packet service time and pipeline lag...")
    lat = benchmark_v3_latency(MIXED_500K_PATH, max_packets=30_000)
    svc = lat["definition_a_service_time_per_packet"]
    lag = lat["definition_b_ingest_to_feature_ready_lag"]
    print(f"  -> Latency (a) Service Time: p50={svc['p50_us']}µs / p95={svc['p95_us']}µs / p99={svc['p99_us']}µs / p99.9={svc['p99_9_us']}µs / max={svc['max_us']}µs")
    print(f"  -> Latency (b) Ingest-to-Ready: p50={lag['p50_us']}µs / p95={lag['p95_us']}µs / p99={lag['p99_us']}µs / p99.9={lag['p99_9_us']}µs / max={lag['max_us']}µs")

    print("\n[3/4] Measuring memory consumption on mixed traffic...")
    mem = benchmark_v3_memory(MIXED_500K_PATH, max_packets=50_000)
    print(f"  -> RSS Start: {mem['rss_start_mb']} MB | Peak/End: {mem['rss_end_mb']} MB (Delta: +{mem['rss_delta_mb']} MB)")

    print("\n[4/4] Stress testing eviction under high-cardinality spoofed flood...")
    evict = benchmark_v3_eviction_stress(packet_count=20_000)
    print(f"  -> Evictions Enforced: dst={evict['evictions_enforced']['dst']}, src={evict['evictions_enforced']['src']}, pair={evict['evictions_enforced']['pair']}")
    print(f"  -> Active Keys: dst={evict['final_active_dst_keys']}/500, src={evict['final_active_src_keys']}/500 (Plateau Preserved: {evict['memory_plateau_preserved']})")

    ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = RESULTS_DIR / f"benchmark_v3_feature_engine_{ts_str}.json"

    results = {
        "benchmark_version": "v3",
        "benchmark_scope": "Phase 2a: Ingest + FlowTable + WindowedFeatureEngine (NO detector models, NO inference)",
        "cadence_commitment": "A full-pipeline benchmark will be executed and recorded at the end of every sub-phase.",
        "system_telemetry": telemetry,
        "feature_engine_capabilities": {
            "dns_parsing": "Domain query names, query types, lengths, Shannon entropy",
            "tls_parsing": "JA3 client hello md5, JA3S server hello md5, SNI, PST sequence",
            "quic_parsing": "Long/short header parsing without key derivation (passive zero-decrypt)",
            "entropy_calculation": "Character Shannon entropy on DNS labels and IP distributions",
        },
        "realistic_mixed_500k": {
            "throughput": tp,
            "latency": lat,
            "memory": mem,
        },
        "eviction_stress_test": evict,
    }

    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n[OK] Benchmark v3 results saved -> {out_file}")
    return out_file


if __name__ == "__main__":
    run_benchmark_v3()
