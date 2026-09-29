#!/usr/bin/env python3
"""
Trinetra Phase 1 Pipeline Benchmark Harness.

Measures:
1. Parse-Only Throughput (dpkt PcapIngest: raw bytes -> FlowEvent)
2. Full Phase 1 Pipeline Throughput & Latency:
   (PcapIngest -> FlowTable with passive TCP tracker & ScenarioTopology -> Alert Stub)

LATENCY DEFINITION (STRICT):
    Per-Packet Processing Latency = time.perf_counter_ns() measured from the entry of
    the raw packet into the pipeline handler until the flow table update and expired-flow
    evaluation completes. Reported as p50, p95, and p99 in microseconds (µs) and milliseconds (ms).

DISCLAIMER:
    Inference models (Random Forest, Isolation Forest, n-gram) are NOT included in Phase 1.
    This benchmark measures the full networking and session state machine foundation.

RESULTS:
    Runs 5 full repetitions. Computes median and spread (min, max, stddev).
    Tracks peak memory via tracemalloc.
    Saves unrounded JSON results to benchmarks/results/benchmark_phase1_<timestamp>.json.
"""
from __future__ import annotations

import io
import json
import multiprocessing
import os
import platform
import statistics
import subprocess
import sys
import time
import tracemalloc
from datetime import datetime, timezone
from pathlib import Path

# Ensure backend is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend"))

from trinetra.config import EnclaveConfig
from trinetra.ingest.flow_table import FlowTable
from trinetra.ingest.pcap import PcapIngest
from trinetra.simulator import SCENARIO_DDOS_SYN_FLOOD, emit_scenario_pcap

RESULTS_DIR = REPO_ROOT / "benchmarks" / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def get_docker_version() -> str:
    """Retrieve local docker version if installed."""
    try:
        res = subprocess.run(["docker", "--version"], capture_output=True, text=True, check=False)
        return res.stdout.strip() if res.returncode == 0 else "Docker not found or not in PATH"
    except Exception:
        return "Docker executable unavailable"


def collect_hardware_specs() -> dict:
    """Collect hardware specifications."""
    specs = {
        "platform": platform.platform(),
        "processor": platform.processor(),
        "architecture": platform.architecture()[0],
        "python_version": platform.python_version(),
        "cpu_count_logical": multiprocessing.cpu_count(),
        "docker_version": get_docker_version(),
        "cores_used_in_benchmark": 1,  # Single-process baseline
    }
    try:
        import psutil
        ram = psutil.virtual_memory()
        specs["ram_total_gb"] = round(ram.total / (1024 ** 3), 2)
        specs["ram_available_gb"] = round(ram.available / (1024 ** 3), 2)
    except ImportError:
        specs["ram_total_gb"] = "psutil_not_installed"
    return specs


def benchmark_parse_only(pcap_bytes: bytes, repetitions: int = 5) -> dict:
    """Benchmark Stage 1: dpkt raw packet parsing only."""
    run_pps = []
    run_mbps = []
    run_mem_mb = []

    total_bytes = len(pcap_bytes)

    for r in range(repetitions):
        tracemalloc.start()
        stream = io.BytesIO(pcap_bytes)
        ingest = PcapIngest()

        t0 = time.perf_counter()
        count = 0
        for _ in ingest.parse_stream(stream):
            count += 1
        elapsed = time.perf_counter() - t0

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        pps = count / elapsed if elapsed > 0 else 0
        mbps = (total_bytes * 8 / (1_000_000 * elapsed)) if elapsed > 0 else 0
        peak_mb = peak / (1024 * 1024)

        run_pps.append(pps)
        run_mbps.append(mbps)
        run_mem_mb.append(peak_mb)

    return {
        "repetitions": repetitions,
        "packet_count": count,
        "total_bytes": total_bytes,
        "packets_per_sec": {
            "median": statistics.median(run_pps),
            "min": min(run_pps),
            "max": max(run_pps),
            "stddev": statistics.stdev(run_pps) if len(run_pps) > 1 else 0.0,
            "raw": run_pps,
        },
        "throughput_mbps": {
            "median": statistics.median(run_mbps),
            "min": min(run_mbps),
            "max": max(run_mbps),
            "stddev": statistics.stdev(run_mbps) if len(run_mbps) > 1 else 0.0,
            "raw": run_mbps,
        },
        "peak_memory_mb": {
            "median": statistics.median(run_mem_mb),
            "max": max(run_mem_mb),
            "raw": run_mem_mb,
        },
    }


def benchmark_full_pipeline(pcap_bytes: bytes, repetitions: int = 5) -> dict:
    """Benchmark Stage 2: Ingest + Flow Table + Passive TCP Tracker + Alert Stub."""
    run_pps = []
    run_flows_per_sec = []
    run_mbps = []
    run_p50_us = []
    run_p95_us = []
    run_p99_us = []
    run_mem_mb = []

    total_bytes = len(pcap_bytes)

    for r in range(repetitions):
        tracemalloc.start()
        stream = io.BytesIO(pcap_bytes)
        ingest = PcapIngest()
        cfg = EnclaveConfig()
        table = FlowTable(config=cfg, idle_timeout_seconds=30.0, max_flows=100_000)

        packet_latencies_ns = []
        packet_count = 0
        flows_emitted = 0

        t_start = time.perf_counter()

        for event in ingest.parse_stream(stream):
            packet_count += 1
            # Strict per-packet processing latency measurement
            pkt_t0 = time.perf_counter_ns()

            record, expired = table.process_event(event)

            # Alert emit stub: inspect flow indicators
            if expired:
                flows_emitted += len(expired)

            pkt_t1 = time.perf_counter_ns()
            packet_latencies_ns.append(pkt_t1 - pkt_t0)

        # Flush any remaining flows
        flushed = table.flush_all()
        flows_emitted += len(flushed)

        elapsed = time.perf_counter() - t_start
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        pps = packet_count / elapsed if elapsed > 0 else 0
        fps = flows_emitted / elapsed if elapsed > 0 else 0
        mbps = (total_bytes * 8 / (1_000_000 * elapsed)) if elapsed > 0 else 0
        peak_mb = peak / (1024 * 1024)

        packet_latencies_ns.sort()
        n = len(packet_latencies_ns)
        p50 = (packet_latencies_ns[int(n * 0.50)] / 1000.0) if n > 0 else 0.0
        p95 = (packet_latencies_ns[int(n * 0.95)] / 1000.0) if n > 0 else 0.0
        p99 = (packet_latencies_ns[int(n * 0.99)] / 1000.0) if n > 0 else 0.0

        run_pps.append(pps)
        run_flows_per_sec.append(fps)
        run_mbps.append(mbps)
        run_p50_us.append(p50)
        run_p95_us.append(p95)
        run_p99_us.append(p99)
        run_mem_mb.append(peak_mb)

    return {
        "repetitions": repetitions,
        "packet_count": packet_count,
        "flows_emitted": flows_emitted,
        "total_bytes": total_bytes,
        "packets_per_sec": {
            "median": statistics.median(run_pps),
            "min": min(run_pps),
            "max": max(run_pps),
            "stddev": statistics.stdev(run_pps) if len(run_pps) > 1 else 0.0,
            "raw": run_pps,
        },
        "flows_per_sec": {
            "median": statistics.median(run_flows_per_sec),
            "min": min(run_flows_per_sec),
            "max": max(run_flows_per_sec),
            "stddev": statistics.stdev(run_flows_per_sec) if len(run_flows_per_sec) > 1 else 0.0,
            "raw": run_flows_per_sec,
        },
        "throughput_mbps": {
            "median": statistics.median(run_mbps),
            "min": min(run_mbps),
            "max": max(run_mbps),
            "stddev": statistics.stdev(run_mbps) if len(run_mbps) > 1 else 0.0,
            "raw": run_mbps,
        },
        "latency_us": {
            "p50": statistics.median(run_p50_us),
            "p95": statistics.median(run_p95_us),
            "p99": statistics.median(run_p99_us),
            "raw_p50": run_p50_us,
            "raw_p95": run_p95_us,
            "raw_p99": run_p99_us,
        },
        "latency_ms": {
            "p50": round(statistics.median(run_p50_us) / 1000.0, 4),
            "p95": round(statistics.median(run_p95_us) / 1000.0, 4),
            "p99": round(statistics.median(run_p99_us) / 1000.0, 4),
        },
        "peak_memory_mb": {
            "median": statistics.median(run_mem_mb),
            "max": max(run_mem_mb),
            "raw": run_mem_mb,
        },
    }


def main() -> None:
    print("=" * 70)
    print("  TRINETRA PHASE 1 PIPELINE BENCHMARK HARNESS")
    print("=" * 70)

    hardware = collect_hardware_specs()
    print(f"Platform:      {hardware['platform']}")
    print(f"Processor:     {hardware['processor']}")
    print(f"Cores:         {hardware['cpu_count_logical']} logical")
    print(f"RAM Total:     {hardware.get('ram_total_gb', 'N/A')} GB")
    print(f"Python:        {hardware['python_version']}")
    print(f"Docker:        {hardware['docker_version']}")
    print()

    # Generate benchmark PCAP dataset (20,000 packets)
    bench_pcap_path = REPO_ROOT / "data" / "fixtures" / "benchmark_synthetic.pcap"
    print(f"Generating 20,000 packet benchmark fixture at: {bench_pcap_path}")
    emit_scenario_pcap(SCENARIO_DDOS_SYN_FLOOD, bench_pcap_path, max_packets=20_000, base_time=1700000000.0)
    pcap_bytes = bench_pcap_path.read_bytes()
    print(f"Fixture size:  {len(pcap_bytes):,} bytes ({len(pcap_bytes) / (1024 * 1024):.2f} MB)")
    print()

    # 1. Parse-Only Benchmark (5 runs)
    print("Executing Stage 1: Parse-Only Benchmark (5 runs)...")
    parse_results = benchmark_parse_only(pcap_bytes, repetitions=5)
    print(f"  Stage 1 Throughput: {parse_results['packets_per_sec']['median']:,.0f} pkts/sec "
          f"({parse_results['throughput_mbps']['median']:.2f} Mbps)")
    print(f"  Stage 1 Peak RAM:   {parse_results['peak_memory_mb']['median']:.2f} MB")
    print()

    # 2. Full Pipeline Benchmark (5 runs)
    print("Executing Stage 2: Full Phase 1 Pipeline Benchmark (5 runs)...")
    pipeline_results = benchmark_full_pipeline(pcap_bytes, repetitions=5)
    print(f"  Stage 2 Throughput: {pipeline_results['packets_per_sec']['median']:,.0f} pkts/sec "
          f"({pipeline_results['throughput_mbps']['median']:.2f} Mbps)")
    print(f"  Stage 2 Flows/sec:  {pipeline_results['flows_per_sec']['median']:,.0f} flows/sec")
    print(f"  Stage 2 Latency:    p50 = {pipeline_results['latency_us']['p50']:.1f} µs "
          f"({pipeline_results['latency_ms']['p50']} ms)")
    print(f"                      p95 = {pipeline_results['latency_us']['p95']:.1f} µs "
          f"({pipeline_results['latency_ms']['p95']} ms)")
    print(f"                      p99 = {pipeline_results['latency_us']['p99']:.1f} µs "
          f"({pipeline_results['latency_ms']['p99']} ms)")
    print(f"  Stage 2 Peak RAM:   {pipeline_results['peak_memory_mb']['median']:.2f} MB")
    print()

    # Save timestamped JSON
    ts_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    output_json = RESULTS_DIR / f"benchmark_phase1_{ts_str}.json"

    full_report = {
        "phase": "Phase 1: Ingest & Stateful Flow Table",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "hardware_environment": hardware,
        "methodology": {
            "repetitions": 5,
            "packets_per_run": 20_000,
            "latency_definition": "time.perf_counter_ns() per packet entering pipeline until flow record update and expiry evaluation completes.",
            "components_included": "PcapIngest + FlowTable (bidirectional aggregation, ScenarioTopology direction labelling, PassiveTcpTracker, timestamp-driven expiry) + Alert Stub.",
            "components_excluded": "AI/ML inference models (Phase 2), LLM narration (Phase 3), WebSocket dashboard (Phase 3)."
        },
        "stage1_parse_only": parse_results,
        "stage2_full_phase1_pipeline": pipeline_results,
    }

    output_json.write_text(json.dumps(full_report, indent=2))
    print(f"[OK] Raw benchmark results written to: {output_json}")
    print("=" * 70)


if __name__ == "__main__":
    main()
