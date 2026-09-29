#!/usr/bin/env python3
"""
scripts/benchmark_pipeline.py

Phase 1 Pipeline Benchmark — Placeholder.

This script will measure the FULL pipeline throughput and alert latency
once Phase 1 (ingest layer) is complete:
    - Parse throughput: packets/sec and Mbps (PCAP ingest)
    - NetFlow v9 parse throughput: flows/sec
    - Full pipeline: parse + flow table + feature extraction + inference + alert emit
    - Alert latency: p50 / p95 / p99 (ms) from first packet to alert emit

Phase 0 stub: records hardware specs and emits a placeholder JSON report.
Replace the TODO sections in Phase 1.

Output: timestamped JSON file at data/benchmark_results_<timestamp>.json
"""
from __future__ import annotations

import json
import platform
import time
from datetime import datetime, timezone
from pathlib import Path

OUTPUT_DIR = Path(__file__).resolve().parent.parent / "data"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def collect_hardware_specs() -> dict:
    """Collect basic hardware information for benchmark reproducibility."""
    import os
    import multiprocessing

    specs = {
        "platform": platform.platform(),
        "processor": platform.processor(),
        "architecture": platform.architecture()[0],
        "python_version": platform.python_version(),
        "cpu_count_logical": multiprocessing.cpu_count(),
        "hostname": platform.node(),
    }

    # Try to get RAM info (Linux/macOS)
    try:
        import psutil  # type: ignore
        ram = psutil.virtual_memory()
        specs["ram_total_gb"] = round(ram.total / (1024 ** 3), 2)
        specs["ram_available_gb"] = round(ram.available / (1024 ** 3), 2)
    except ImportError:
        specs["ram_total_gb"] = "UNKNOWN — install psutil"

    return specs


def run_benchmark() -> dict:
    """
    Run the Phase 1 pipeline benchmark.

    TODO (Phase 1): Replace placeholder results with actual measurements.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    hardware = collect_hardware_specs()

    print(f"Trinetra Pipeline Benchmark — Phase 0 stub")
    print(f"Timestamp: {timestamp}")
    print(f"Hardware: {hardware.get('processor', 'Unknown')}")
    print()
    print("NOTE: Phase 0 produces placeholder results only.")
    print("      Phase 1 will replace these with measured values.")
    print()

    # ---- Phase 0 placeholder results ----
    results = {
        "benchmark_version": "0.0.1-phase0",
        "timestamp": timestamp,
        "hardware": hardware,
        "phase": "Phase 0 — placeholder, not measured",
        "disclaimer": (
            "All performance numbers below are PLACEHOLDERS. "
            "Phase 1 will replace every value with measurements from actual code execution "
            "on the hardware described above. Do NOT cite these numbers."
        ),
        "metrics": {
            "pcap_parse_throughput_pps": "NOT_MEASURED",
            "pcap_parse_throughput_mbps": "NOT_MEASURED",
            "netflow_v9_parse_throughput_flows_per_sec": "NOT_MEASURED",
            "full_pipeline_throughput_flows_per_sec": "NOT_MEASURED",
            "full_pipeline_throughput_mbps": "NOT_MEASURED",
            "alert_latency_p50_ms": "NOT_MEASURED",
            "alert_latency_p95_ms": "NOT_MEASURED",
            "alert_latency_p99_ms": "NOT_MEASURED",
        },
    }

    # ---- Save results ----
    safe_ts = timestamp.replace(":", "-").replace("+", "Z")[:19]
    output_path = OUTPUT_DIR / f"benchmark_results_{safe_ts}.json"
    output_path.write_text(json.dumps(results, indent=2))

    print(f"Results written to: {output_path}")
    print()
    print("Summary:")
    print(f"  All metrics: NOT_MEASURED (Phase 0 stub)")
    print()
    print("Run 'make benchmark' after Phase 1 to get real numbers.")

    return results


if __name__ == "__main__":
    run_benchmark()
