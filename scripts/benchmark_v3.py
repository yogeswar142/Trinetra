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

RESULTS_DIR = REPO_ROOT / "benchmarks" / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

FIXTURES_DIR = REPO_ROOT / "data" / "fixtures"
MIXED_500K_PATH = FIXTURES_DIR / "realistic_mixed_500k.pcap"


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
        "power_plugged": battery.power_plugged if battery else None,
        "battery_percent": battery.percent if battery else None,
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

    with open(pcap_path, "rb") as f:
        reader = dpkt.pcap.Reader(f)
        count = 0
        for ts, buf in reader:
            t_start = time.perf_counter_ns()
            ev = ingest._parse_ethernet_packet(ts, buf)
            if ev is not None:
                table.process_event(ev)
                engine.process_event(ev)
            t_end = time.perf_counter_ns()
            service_times_ns.append(t_end - t_start)

            count += 1
            if count >= max_packets:
                break

    service_times_ns.sort()
    n = len(service_times_ns)
    return {
        "count": n,
        "mean_us": round(sum(service_times_ns) / (n * 1000.0), 3),
        "p50_us": round(service_times_ns[int(n * 0.50)] / 1000.0, 3),
        "p95_us": round(service_times_ns[int(n * 0.95)] / 1000.0, 3),
        "p99_us": round(service_times_ns[int(n * 0.99)] / 1000.0, 3),
        "p99_9_us": round(service_times_ns[min(int(n * 0.999), n - 1)] / 1000.0, 3),
        "max_us": round(service_times_ns[-1] / 1000.0, 3),
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
        "rss_initial_mb": round(rss_start_mb, 2),
        "rss_peak_mb": round(rss_end_mb, 2),
        "rss_delta_mb": round(rss_end_mb - rss_start_mb, 2),
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
    print(f"Power: {'Plugged In' if telemetry['power_plugged'] else 'On Battery'} ({telemetry['battery_percent']}%)")
    print("======================================================================")

    print("\n[1/3] Measuring pipeline throughput with WindowedFeatureEngine (500k pkts)...")
    tp = benchmark_v3_throughput(MIXED_500K_PATH, repetitions=2)
    print(f"  -> Throughput: {tp['packets_per_second']['median']:,} pkts/sec | {tp['throughput_mbps']['median']} Mbps")

    print("\n[2/3] Measuring per-packet service time latency...")
    lat = benchmark_v3_latency(MIXED_500K_PATH, max_packets=30_000)
    print(f"  -> Latency (service time p50/p95/p99/p99.9/max): {lat['p50_us']}µs / {lat['p95_us']}µs / {lat['p99_us']}µs / {lat['p99_9_us']}µs / {lat['max_us']}µs")

    print("\n[3/3] Measuring memory consumption...")
    mem = benchmark_v3_memory(MIXED_500K_PATH, max_packets=50_000)
    print(f"  -> Memory RSS Delta: +{mem['rss_delta_mb']} MB (Peak RSS: {mem['rss_peak_mb']} MB)")

    ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = RESULTS_DIR / f"benchmark_v3_feature_engine_{ts_str}.json"

    results = {
        "benchmark_version": "v3",
        "benchmark_scope": "Phase 2a: Ingest + FlowTable + WindowedFeatureEngine (NO detector models, NO inference)",
        "cadence_commitment": "A full-pipeline benchmark will be executed and recorded at the end of every sub-phase.",
        "system_telemetry": telemetry,
        "realistic_mixed_500k": {
            "throughput": tp,
            "latency": lat,
            "memory": mem,
        },
    }

    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n[OK] Benchmark v3 results saved -> {out_file}")
    return out_file


if __name__ == "__main__":
    run_benchmark_v3()
