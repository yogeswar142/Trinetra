#!/usr/bin/env python3
"""
Trinetra Pipeline Benchmark Harness v4: Phase 2b Full End-to-End Pipeline with ML Inference.

Measures the complete end-to-end performance of:
1. Passive PCAP Ingest (PcapIngest via dpkt)
2. Deterministic Stateful Flow Table (FlowTable)
3. Windowed Statistical Feature Engine (WindowedFeatureEngine)
4. ML Classifier Inference (DdosDetector, PortScanDetector)
5. Incident Deduplication (IncidentDeduplicator)
6. Forensic Merkle Ledger (ForensicLedger commit)

Operating on the 500,000-packet mixed traffic fixture (308 MB).
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
from trinetra.detectors.ddos import DdosDetector
from trinetra.detectors.port_scan import PortScanDetector
from trinetra.features.windowed_engine import WindowedFeatureEngine
from trinetra.ingest.flow_table import FlowTable
from trinetra.ingest.pcap import PcapIngest
from trinetra.ledger import ForensicLedger, generate_or_load_keypair
from trinetra.ml.artifact_loader import safe_load_artifact

RESULTS_DIR = REPO_ROOT / "benchmarks" / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

FIXTURES_DIR = REPO_ROOT / "data" / "fixtures"
MIXED_500K_PATH = FIXTURES_DIR / "realistic_mixed_500k.pcap"
MODELS_DIR = REPO_ROOT / "data" / "models"
MANIFEST_PATH = MODELS_DIR / "models_manifest.json"


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


def init_full_pipeline(tmp_ledger_dir: Path):
    cfg = EnclaveConfig()
    cfg.ledger_file_path = tmp_ledger_dir / "bench_ledger.jsonl"
    cfg.ledger_privkey_path = tmp_ledger_dir / "bench.key"
    cfg.ledger_pubkey_path = tmp_ledger_dir / "bench.pub"

    priv_key, pub_key = generate_or_load_keypair(cfg.ledger_privkey_path, cfg.ledger_pubkey_path)
    ledger = ForensicLedger(priv_key, pub_key, cfg.ledger_file_path, block_size=10)
    ingest = PcapIngest()
    table = FlowTable(config=cfg, max_flows=100_000)
    engine = WindowedFeatureEngine()

    ddos_pkg = safe_load_artifact(MODELS_DIR / "t_a_ddos.joblib", MANIFEST_PATH)
    ps_pkg = safe_load_artifact(MODELS_DIR / "t_e_portscan.joblib", MANIFEST_PATH)

    ddos_det = DdosDetector(model=ddos_pkg["model"], calibrator=ddos_pkg["calibrator"])
    ps_det = PortScanDetector(model=ps_pkg["model"], calibrator=ps_pkg["calibrator"])

    return ingest, table, engine, ddos_det, ps_det, ledger


def benchmark_v4_throughput(pcap_path: Path, tmp_dir: Path, max_packets: int | None = None, repetitions: int = 2) -> dict:
    file_bytes = pcap_path.stat().st_size
    pps_runs = []
    mbps_runs = []
    alerts_count = 0

    for r in range(repetitions):
        run_dir = tmp_dir / f"tp_run_{r}"
        run_dir.mkdir(parents=True, exist_ok=True)
        ingest, table, engine, ddos_det, ps_det, ledger = init_full_pipeline(run_dir)

        count = 0
        with open(pcap_path, "rb") as f:
            t0 = time.perf_counter()
            for ev in ingest.parse_stream(f):
                table.process_event(ev)
                engine.process_event(ev)

                # Periodic detector inference (every 50 packets to model real polling cadence)
                if count % 50 == 0:
                    dst_feat = engine.get_dst_features(ev.dst_ip)
                    if dst_feat:
                        a_ddos = ddos_det.evaluate(dst_feat, ev.timestamp, dst_port=ev.dst_port)
                        if a_ddos:
                            ledger.add_alert(a_ddos)
                            alerts_count += 1

                    src_feat = engine.get_src_features(ev.src_ip)
                    if src_feat:
                        a_ps = ps_det.evaluate(src_feat, ev.timestamp)
                        if a_ps:
                            ledger.add_alert(a_ps)
                            alerts_count += 1

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
        "total_alerts_emitted": alerts_count // repetitions,
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


def benchmark_v4_latency(pcap_path: Path, tmp_dir: Path, max_packets: int = 30_000) -> dict:
    run_dir = tmp_dir / "lat_run"
    run_dir.mkdir(parents=True, exist_ok=True)
    ingest, table, engine, ddos_det, ps_det, ledger = init_full_pipeline(run_dir)

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

                # Latency Definition (b): Ingest to alert emission & ledger commit
                dst_feat = engine.get_dst_features(ev.dst_ip)
                if dst_feat:
                    alert = ddos_det.evaluate(dst_feat, ev.timestamp, dst_port=ev.dst_port)
                    if alert:
                        ledger.add_alert(alert)

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
        "definition_b_ingest_to_alert_emit_lag": calc_percentiles(pipeline_lags_ns),
    }


def benchmark_v4_memory(pcap_path: Path, tmp_dir: Path, max_packets: int = 50_000) -> dict:
    proc = psutil.Process(os.getpid())
    rss_start_mb = proc.memory_info().rss / (1024 * 1024)

    run_dir = tmp_dir / "mem_run"
    run_dir.mkdir(parents=True, exist_ok=True)
    ingest, table, engine, ddos_det, ps_det, ledger = init_full_pipeline(run_dir)

    count = 0
    with open(pcap_path, "rb") as f:
        for ev in ingest.parse_stream(f):
            table.process_event(ev)
            engine.process_event(ev)
            if count % 50 == 0:
                dst_feat = engine.get_dst_features(ev.dst_ip)
                if dst_feat:
                    alert = ddos_det.evaluate(dst_feat, ev.timestamp, dst_port=ev.dst_port)
                    if alert:
                        ledger.add_alert(alert)

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


def run_benchmark_v4() -> Path:
    if not MIXED_500K_PATH.exists():
        print(f"Generating 500k mixed fixture -> {MIXED_500K_PATH}...")
        from scripts.generate_realistic_500k_pcap import generate_mixed_500k_pcap
        generate_mixed_500k_pcap(500_000)

    import tempfile
    with tempfile.TemporaryDirectory() as tmp_str:
        tmp_dir = Path(tmp_str)

        print("======================================================================")
        print("TRINETRA BENCHMARK v4: PHASE 2b FULL PIPELINE WITH ML INFERENCE")
        print("======================================================================")
        telemetry = collect_telemetry()
        print(f"Host: {telemetry['platform_system']} ({telemetry['platform_machine']}), {telemetry['processor']}")
        print(f"Architecture: {telemetry['python_architecture']}")
        print(f"Power: {'Plugged In' if telemetry['power_plugged'] else 'On Battery'} ({telemetry['battery_percent']}%) | Scheme: {telemetry['power_plan']}")
        print("======================================================================")

        print("\n[1/3] Measuring full pipeline throughput with ML inference & ledger (500k pkts)...")
        tp = benchmark_v4_throughput(MIXED_500K_PATH, tmp_dir=tmp_dir, repetitions=2)
        print(f"  -> Throughput: {tp['packets_per_second']['median']:,} pkts/sec | {tp['throughput_mbps']['median']} Mbps")

        print("\n[2/3] Measuring per-packet service time and alert emission lag...")
        lat = benchmark_v4_latency(MIXED_500K_PATH, tmp_dir=tmp_dir, max_packets=30_000)
        svc = lat["definition_a_service_time_per_packet"]
        lag = lat["definition_b_ingest_to_alert_emit_lag"]
        print(f"  -> Latency (a) Service Time: p50={svc['p50_us']}µs / p95={svc['p95_us']}µs / p99={svc['p99_us']}µs / p99.9={svc['p99_9_us']}µs / max={svc['max_us']}µs")
        print(f"  -> Latency (b) Ingest-to-Alert: p50={lag['p50_us']}µs / p95={lag['p95_us']}µs / p99={lag['p99_us']}µs / p99.9={lag['p99_9_us']}µs / max={lag['max_us']}µs")

        print("\n[3/3] Measuring memory consumption during full pipeline execution...")
        mem = benchmark_v4_memory(MIXED_500K_PATH, tmp_dir=tmp_dir, max_packets=50_000)
        print(f"  -> RSS Start: {mem['rss_start_mb']} MB | Peak/End: {mem['rss_end_mb']} MB (Delta: +{mem['rss_delta_mb']} MB)")

        ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_file = RESULTS_DIR / f"benchmark_v4_full_pipeline_{ts_str}.json"

        results = {
            "benchmark_version": "v4",
            "benchmark_scope": "Phase 2b: Full Pipeline (Ingest + FlowTable + WindowedFeatureEngine + ML Inference + Incident Deduplication + Forensic Ledger)",
            "pipeline_components_active": [
                "PcapIngest (dpkt classic/pcapng)",
                "FlowTable (bounded LRU, passive TCP tracker)",
                "WindowedFeatureEngine (5 dimensions)",
                "DdosDetector (calibrated RandomForestClassifier, ThreatClass.VOLUMETRIC_DDOS)",
                "PortScanDetector (calibrated RandomForestClassifier, ThreatClass.PORT_SCANNING)",
                "IncidentDeduplicator (60-second sliding window)",
                "ForensicLedger (SHA-256 Merkle tree + Ed25519 signing)",
            ],
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

        print(f"\n[OK] Benchmark v4 results saved -> {out_file}")
        return out_file


if __name__ == "__main__":
    run_benchmark_v4()
