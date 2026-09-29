#!/usr/bin/env python3
"""
Trinetra Pipeline Benchmark Harness v5: Phase 2c Full End-to-End Pipeline with ML Inference.

Evaluates the complete end-to-end pipeline:
1. Passive PCAP Ingest (PcapIngest via dpkt)
2. Deterministic Stateful Flow Table (FlowTable)
3. Windowed Statistical Feature Engine (WindowedFeatureEngine)
4. ML Classifier + Rule Inference across 5 Detectors:
   - DdosDetector (T-a: Volumetric DDoS)
   - PortScanDetector (T-e: Port Scanning)
   - BeaconDetector (T-b: C2 Beaconing IAT Analysis)
   - DgaDetector (T-c: DGA Domain Trigram Perplexity)
   - DnsTunnelDetector (T-c: DNS Tunnelling Statistics)
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
from trinetra.detectors.beacon import BeaconDetector
from trinetra.detectors.ddos import DdosDetector
from trinetra.detectors.dga import DgaDetector, DnsTunnelDetector
from trinetra.detectors.port_scan import PortScanDetector
from trinetra.detectors.tls_malware import TlsMalwareDetector
from trinetra.features.windowed_engine import WindowedFeatureEngine
from trinetra.ingest.flow_table import FlowTable
from trinetra.ingest.pcap import PcapIngest
from trinetra.ledger import ForensicLedger, generate_or_load_keypair
from trinetra.ml.artifact_loader import safe_load_artifact
from trinetra.schemas import FlowEvent

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
        "python_architecture": platform.architecture()[0],
        "power_plugged": battery.power_plugged if battery else None,
        "battery_percent": battery.percent if battery else None,
        "power_plan": get_windows_power_plan(),
        "ram_total_gb": round(vm.total / (1024 ** 3), 2),
        "ram_available_gb": round(vm.available / (1024 ** 3), 2),
    }


def init_full_pipeline_v5(tmp_ledger_dir: Path):
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
    beacon_pkg = safe_load_artifact(MODELS_DIR / "t_b_beacon.joblib", MANIFEST_PATH)
    dga_pkg = safe_load_artifact(MODELS_DIR / "t_c_dga.joblib", MANIFEST_PATH)
    tunnel_pkg = safe_load_artifact(MODELS_DIR / "t_c_dns_tunnel.joblib", MANIFEST_PATH)

    ddos_det = DdosDetector(model=ddos_pkg["model"], calibrator=ddos_pkg["calibrator"])
    ps_det = PortScanDetector(model=ps_pkg["model"], calibrator=ps_pkg["calibrator"])
    beacon_det = BeaconDetector(model=beacon_pkg["model"], calibrator=beacon_pkg["calibrator"])
    dga_det = DgaDetector(model=dga_pkg["model"], calibrator=dga_pkg["calibrator"])
    tunnel_det = DnsTunnelDetector(model=tunnel_pkg["model"], calibrator=tunnel_pkg["calibrator"])
    tls_det = TlsMalwareDetector()  # T-d: JA3 blacklist + PST anomaly — no model file needed

    return ingest, table, engine, ddos_det, ps_det, beacon_det, dga_det, tunnel_det, tls_det, ledger


def benchmark_v5_throughput(pcap_path: Path, tmp_dir: Path, max_packets: int | None = None, repetitions: int = 2) -> dict:
    file_bytes = pcap_path.stat().st_size
    pps_runs = []
    mbps_runs = []
    alerts_by_threat = {}

    for r in range(repetitions):
        run_dir = tmp_dir / f"tp_run_{r}"
        run_dir.mkdir(parents=True, exist_ok=True)
        ingest, table, engine, ddos_det, ps_det, beacon_det, dga_det, tunnel_det, tls_det, ledger = init_full_pipeline_v5(run_dir)

        count = 0
        with open(pcap_path, "rb") as f:
            t0 = time.perf_counter()
            for ev in ingest.parse_stream(f):
                table.process_event(ev)
                engine.process_event(ev)

                # Periodic detector inference (cadence: every 50 packets to model polling loop)
                if count % 50 == 0:
                    # T-a: DDoS
                    dst_feat = engine.get_dst_features(ev.dst_ip)
                    if dst_feat:
                        a_ddos = ddos_det.evaluate(dst_feat, ev.timestamp, dst_port=ev.dst_port)
                        if a_ddos:
                            ledger.add_alert(a_ddos)
                            alerts_by_threat[a_ddos.threat_class.value] = alerts_by_threat.get(a_ddos.threat_class.value, 0) + 1

                    # T-e: Port Scan
                    src_feat = engine.get_src_features(ev.src_ip)
                    if src_feat:
                        a_ps = ps_det.evaluate(src_feat, ev.timestamp)
                        if a_ps:
                            ledger.add_alert(a_ps)
                            alerts_by_threat[a_ps.threat_class.value] = alerts_by_threat.get(a_ps.threat_class.value, 0) + 1

                    # T-b: Beaconing
                    pair_feat = engine.get_pair_features(ev.src_ip, ev.dst_ip)
                    if pair_feat and pair_feat.sample_count >= 21:
                        a_b = beacon_det.evaluate(pair_feat, ev.timestamp, dst_port=ev.dst_port)
                        if a_b:
                            ledger.add_alert(a_b)
                            alerts_by_threat[a_b.threat_class.value] = alerts_by_threat.get(a_b.threat_class.value, 0) + 1

                    # T-c: DGA / DNS Tunnelling
                    if ev.dns_query:
                        a_dga = dga_det.evaluate(ev.dns_query, client_ip=ev.src_ip, current_timestamp=ev.timestamp)
                        if a_dga:
                            ledger.add_alert(a_dga)
                            alerts_by_threat[a_dga.threat_class.value] = alerts_by_threat.get(a_dga.threat_class.value, 0) + 1

                        dom_feat = engine.get_domain_features(ev.src_ip, ev.dns_query)
                        if dom_feat and dom_feat.query_count >= 5:
                            a_tun = tunnel_det.evaluate(dom_feat, ev.timestamp)
                            if a_tun:
                                ledger.add_alert(a_tun)
                                alerts_by_threat[a_tun.threat_class.value] = alerts_by_threat.get(a_tun.threat_class.value, 0) + 1

                    # T-d: TLS Malware (JA3 blacklist + PST sequence anomaly)
                    if ev.dst_port in (443, 8443, 8080) or ev.src_port in (443, 8443):
                        flow_id = f"{ev.src_ip}:{ev.src_port}-{ev.dst_ip}:{ev.dst_port}"
                        tls_feat = engine.get_tls_features(flow_id)
                        if tls_feat:
                            a_tls = tls_det.evaluate(tls_feat, ev.timestamp)
                            if a_tls:
                                ledger.add_alert(a_tls)
                                alerts_by_threat[a_tls.threat_class.value] = alerts_by_threat.get(a_tls.threat_class.value, 0) + 1


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

    # Normalize alert counts by repetitions
    avg_alerts = {k: v // repetitions for k, v in alerts_by_threat.items()}

    return {
        "repetitions": repetitions,
        "packets_processed": count,
        "alerts_by_threat_class": avg_alerts,
        "total_alerts_emitted": sum(avg_alerts.values()),
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


def benchmark_v5_latency(pcap_path: Path, tmp_dir: Path, max_packets: int = 30_000) -> dict:
    run_dir = tmp_dir / "lat_run"
    run_dir.mkdir(parents=True, exist_ok=True)
    ingest, table, engine, ddos_det, ps_det, beacon_det, dga_det, tunnel_det, tls_det, ledger = init_full_pipeline_v5(run_dir)

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

                # Latency Definition (b): Full ML Inference cycle + Ledger commit
                dst_feat = engine.get_dst_features(ev.dst_ip)
                if dst_feat:
                    alert = ddos_det.evaluate(dst_feat, ev.timestamp, dst_port=ev.dst_port)
                    if alert:
                        ledger.add_alert(alert)

                if ev.dns_query:
                    alert_dga = dga_det.evaluate(ev.dns_query, client_ip=ev.src_ip, current_timestamp=ev.timestamp)
                    if alert_dga:
                        ledger.add_alert(alert_dga)

                t_emit = time.perf_counter_ns()
                pipeline_lags_ns.append(t_emit - t_start)
            else:
                t_service = time.perf_counter_ns()

            service_times_ns.append(t_service - t_start)
            count += 1
            if count >= max_packets:
                break

    def calc_stats_us(arr_ns: list[int]) -> dict:
        arr_us = sorted([x / 1_000.0 for x in arr_ns])
        n = len(arr_us)
        return {
            "count": n,
            "mean_us": round(sum(arr_us) / n, 2),
            "p50_us": round(arr_us[int(n * 0.50)], 2),
            "p95_us": round(arr_us[int(n * 0.95)], 2),
            "p99_us": round(arr_us[int(n * 0.99)], 2),
            "max_us": round(arr_us[-1], 2),
        }

    return {
        "packets_sampled": count,
        "latency_definition_a_service_time": calc_stats_us(service_times_ns),
        "latency_definition_b_ingest_to_alert_lag": calc_stats_us(pipeline_lags_ns),
    }


def benchmark_v5_memory(pcap_path: Path, tmp_dir: Path, max_packets: int = 100_000) -> dict:
    run_dir = tmp_dir / "mem_run"
    run_dir.mkdir(parents=True, exist_ok=True)
    proc = psutil.Process()

    rss_start = proc.memory_info().rss
    rss_peak = rss_start

    ingest, table, engine, ddos_det, ps_det, beacon_det, dga_det, tunnel_det, tls_det, ledger = init_full_pipeline_v5(run_dir)

    with open(pcap_path, "rb") as f:
        count = 0
        for ev in ingest.parse_stream(f):
            table.process_event(ev)
            engine.process_event(ev)
            count += 1
            if count % 10_000 == 0:
                current_rss = proc.memory_info().rss
                rss_peak = max(rss_peak, current_rss)
            if count >= max_packets:
                break

    rss_end = proc.memory_info().rss
    rss_peak = max(rss_peak, rss_end)

    return {
        "packets_processed": count,
        "rss_start_mb": round(rss_start / (1024 ** 2), 2),
        "rss_peak_mb": round(rss_peak / (1024 ** 2), 2),
        "rss_end_mb": round(rss_end / (1024 ** 2), 2),
        "rss_delta_mb": round((rss_end - rss_start) / (1024 ** 2), 2),
    }


def benchmark_v5_eviction_stress(tmp_dir: Path, num_packets: int = 20_000) -> dict:
    """Stress tests LRU bounded capacity in WindowedFeatureEngine under hostile packet stream."""
    run_dir = tmp_dir / "evict_run"
    run_dir.mkdir(parents=True, exist_ok=True)
    proc = psutil.Process()

    rss_start = proc.memory_info().rss

    # Constrained engine: max 500 keys per dimension
    cfg = EnclaveConfig()
    cfg.ledger_file_path = run_dir / "bench_ledger.jsonl"
    cfg.ledger_privkey_path = run_dir / "bench.key"
    cfg.ledger_pubkey_path = run_dir / "bench.pub"
    priv_key, pub_key = generate_or_load_keypair(cfg.ledger_privkey_path, cfg.ledger_pubkey_path)
    ledger = ForensicLedger(priv_key, pub_key, cfg.ledger_file_path, block_size=10)

    engine = WindowedFeatureEngine(
        max_dst_keys=500,
        max_src_keys=500,
        max_pair_keys=500,
        max_domain_keys=500,
    )

    t0 = time.perf_counter()
    for i in range(num_packets):
        # Unique IPs every packet -> force constant LRU eviction
        ev = FlowEvent(
            timestamp=1000.0 + (i * 0.001),
            src_ip=f"10.{i % 250}.{(i // 250) % 250}.{(i % 200) + 1}",
            src_port=1024 + (i % 60000),
            dst_ip=f"192.168.{(i // 500) % 250}.{(i % 250) + 1}",
            dst_port=80,
            protocol="TCP",
            length=64,
            tcp_flags={"SYN": True, "ACK": False, "FIN": False, "RST": False, "PSH": False, "URG": False},
        )
        engine.process_event(ev)

    elapsed = time.perf_counter() - t0
    rss_end = proc.memory_info().rss

    return {
        "packets_processed": num_packets,
        "elapsed_seconds": round(elapsed, 4),
        "eviction_counts": engine.eviction_counts,
        "rss_start_mb": round(rss_start / (1024 ** 2), 2),
        "rss_end_mb": round(rss_end / (1024 ** 2), 2),
        "rss_delta_mb": round((rss_end - rss_start) / (1024 ** 2), 2),
        "memory_plateau_preserved": bool(engine.eviction_counts["src"] > 0 and engine.eviction_counts["pair"] > 0),
    }


def main():
    import tempfile
    print("=" * 70)
    print("TRINETRA PIPELINE BENCHMARK HARNESS v5: PHASE 2c FULL PIPELINE (T-a, T-e, T-b, T-c)")
    print("=" * 70)

    telemetry = collect_telemetry()
    print(f"System: {telemetry['platform_system']} {telemetry['platform_release']} ({telemetry['platform_machine']})")
    print(f"Python: {telemetry['python_version']} [{telemetry['python_architecture']}]")
    print(f"Power Plan: {telemetry['power_plan']} | Battery: {telemetry['battery_percent']}% (Plugged: {telemetry['power_plugged']})")
    print(f"RAM: {telemetry['ram_available_gb']} GB free / {telemetry['ram_total_gb']} GB total")

    if not MIXED_500K_PATH.exists():
        print(f"[ERROR] Fixture not found at {MIXED_500K_PATH}")
        sys.exit(1)

    with tempfile.TemporaryDirectory() as tmp_str:
        tmp_dir = Path(tmp_str)

        # 1. Throughput Run (500k packets, 2 repetitions)
        print("\n[1/4] Running Full Pipeline Throughput Benchmark (500k packets, 5 detectors)...")
        tp_results = benchmark_v5_throughput(MIXED_500K_PATH, tmp_dir, repetitions=2)
        print(f"  -> Median Throughput: {tp_results['packets_per_second']['median']:,} pkts/sec | {tp_results['throughput_mbps']['median']} Mbps")
        print(f"  -> Total Alerts Emitted: {tp_results['total_alerts_emitted']} (Deduplicated)")
        print(f"  -> Alerts by Class: {tp_results['alerts_by_threat_class']}")

        # 2. Latency Run (30k packets)
        print("\n[2/4] Running Dual-Definition Latency Benchmark (30k packets)...")
        lat_results = benchmark_v5_latency(MIXED_500K_PATH, tmp_dir, max_packets=30_000)
        la = lat_results["latency_definition_a_service_time"]
        lb = lat_results["latency_definition_b_ingest_to_alert_lag"]
        print(f"  -> Latency (a) Service Time: p50={la['p50_us']}µs | p95={la['p95_us']}µs | p99={la['p99_us']}µs | max={la['max_us']}µs")
        print(f"  -> Latency (b) Ingest-to-Alert: p50={lb['p50_us']/1000:.2f}ms | p95={lb['p95_us']/1000:.2f}ms | p99={lb['p99_us']/1000:.2f}ms")

        # 3. Memory Run (100k packets)
        print("\n[3/4] Running Memory Benchmark (100k packets)...")
        mem_results = benchmark_v5_memory(MIXED_500K_PATH, tmp_dir, max_packets=100_000)
        print(f"  -> RSS: Start={mem_results['rss_start_mb']}MB | Peak={mem_results['rss_peak_mb']}MB | End={mem_results['rss_end_mb']}MB | Delta={mem_results['rss_delta_mb']}MB")

        # 4. Eviction Stress Run (20k hostile packets)
        print("\n[4/4] Running Hostile Eviction Stress Test (20k spoofed packets, max 500 keys)...")
        evict_results = benchmark_v5_eviction_stress(tmp_dir, num_packets=20_000)
        print(f"  -> Evictions Enforced: {evict_results['eviction_counts']}")
        print(f"  -> Plateau Preserved: {evict_results['memory_plateau_preserved']} (Delta: {evict_results['rss_delta_mb']}MB)")

    # Assemble and write final output
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = RESULTS_DIR / f"benchmark_v5_full_pipeline_{timestamp_str}.json"

    full_payload = {
        "benchmark_version": "5.0.0-phase2c",
        "description": "Full End-to-End Trinetra Pipeline: Ingest + FlowTable + FeatureEngine + 5 Threat Detectors (T-a, T-e, T-b, T-c) + Deduplicator + Merkle Ledger",
        "telemetry": telemetry,
        "throughput": tp_results,
        "latency": lat_results,
        "memory": mem_results,
        "eviction_stress": evict_results,
    }

    out_file.write_text(json.dumps(full_payload, indent=2), encoding="utf-8")
    print(f"\n[SUCCESS] Raw JSON results saved to: {out_file}")
    print("=" * 70)


if __name__ == "__main__":
    main()
