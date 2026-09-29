"""
tests/test_detectors.py

Unit and end-to-end integration tests for Phase 2b Threat Detectors:
1. Threat T-a: Volumetric DDoS & Resource Starvation (SYN flood, UDP amp, benign baseline)
2. Threat T-e: Port Scanning & Reconnaissance (vertical scan, horizontal sweep, benign single probe)
3. Threat T-f: Data Exfiltration (bulk asymmetric upload, slow trickle, benign download)
4. Incident deduplication (60s sliding window)
5. Model loading with signed manifest integrity
6. End-to-end detection pipeline integration with FlowTable and WindowedFeatureEngine
"""
from __future__ import annotations

from pathlib import Path
import pytest

from trinetra.config import EnclaveConfig
from trinetra.detectors.base import IncidentDeduplicator
from trinetra.detectors.ddos import DdosDetector
from trinetra.detectors.exfil import ExfiltrationDetector, FlowExfilFeatures
from trinetra.detectors.port_scan import PortScanDetector
from trinetra.features.windowed_engine import DstWindowFeatures, SrcWindowFeatures, WindowedFeatureEngine
from trinetra.ingest.flow_table import FlowTable
from trinetra.ingest.pcap import PcapIngest
from trinetra.ledger import ForensicLedger
from trinetra.ml.artifact_loader import safe_load_artifact
from trinetra.schemas import AlertRecord, Direction, FlowEvent, Severity, ThreatClass

REPO_ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = REPO_ROOT / "data" / "models"
MANIFEST_PATH = MODELS_DIR / "models_manifest.json"


# ---------------------------------------------------------------------------
# Threat T-a: Volumetric DDoS Tests
# ---------------------------------------------------------------------------
class TestDdosDetector:
    def test_syn_flood_rule_and_ml_detection(self) -> None:
        model_pkg = safe_load_artifact(MODELS_DIR / "t_a_ddos.joblib", MANIFEST_PATH)
        detector = DdosDetector(
            model=model_pkg["model"],
            calibrator=model_pkg["calibrator"],
            confidence_threshold=0.70,
        )

        feat = DstWindowFeatures(
            dst_ip="192.168.1.100",
            window_seconds=10.0,
            packet_count=5000,
            incoming_pps=500.0,
            syn_count=4800,
            ack_count=20,
            syn_to_ack_ratio=240.0,
            src_ip_entropy=4.8,
            udp_bytes_in=0,
            udp_bytes_out=0,
            udp_amplification_factor=0.0,
        )

        alert = detector.evaluate(feat, current_timestamp=1000.0, dst_port=80)
        assert alert is not None
        assert isinstance(alert, AlertRecord)
        assert alert.threat_class == ThreatClass.VOLUMETRIC_DDOS
        assert alert.destination is not None
        assert alert.destination.ip == "192.168.1.100"
        assert alert.confidence >= 0.70
        assert len(alert.evidence) >= 1
        
        # Check evidence features
        ev_features = [e.feature for e in alert.evidence]
        assert "syn_to_ack_ratio" in ev_features
        assert "incoming_pps" in ev_features

    def test_udp_amplification_detection(self) -> None:
        detector = DdosDetector(confidence_threshold=0.70)
        feat = DstWindowFeatures(
            dst_ip="192.168.1.200",
            window_seconds=10.0,
            packet_count=1000,
            incoming_pps=100.0,
            syn_count=0,
            ack_count=0,
            syn_to_ack_ratio=0.0,
            src_ip_entropy=2.5,
            udp_bytes_in=500_000,
            udp_bytes_out=5_000,
            udp_amplification_factor=100.0,
        )

        alert = detector.evaluate(feat, current_timestamp=1005.0, dst_port=53)
        assert alert is not None
        assert alert.threat_class == ThreatClass.VOLUMETRIC_DDOS
        assert any(e.feature == "udp_amplification_factor" for e in alert.evidence)

    def test_benign_traffic_no_ddos_alert(self) -> None:
        model_pkg = safe_load_artifact(MODELS_DIR / "t_a_ddos.joblib", MANIFEST_PATH)
        detector = DdosDetector(
            model=model_pkg["model"],
            calibrator=model_pkg["calibrator"],
            confidence_threshold=0.70,
        )

        feat = DstWindowFeatures(
            dst_ip="192.168.1.50",
            window_seconds=10.0,
            packet_count=100,
            incoming_pps=10.0,
            syn_count=5,
            ack_count=5,
            syn_to_ack_ratio=1.0,
            src_ip_entropy=1.2,
            udp_bytes_in=1000,
            udp_bytes_out=1000,
            udp_amplification_factor=1.0,
        )

        alert = detector.evaluate(feat, current_timestamp=1010.0)
        assert alert is None

    def test_incident_deduplication(self) -> None:
        detector = DdosDetector(confidence_threshold=0.70)
        feat = DstWindowFeatures(
            dst_ip="192.168.1.100",
            window_seconds=10.0,
            packet_count=5000,
            incoming_pps=500.0,
            syn_count=4800,
            ack_count=20,
            syn_to_ack_ratio=240.0,
            src_ip_entropy=4.5,
            udp_bytes_in=0,
            udp_bytes_out=0,
            udp_amplification_factor=0.0,
        )

        # 1st trigger -> Alert emitted
        alert1 = detector.evaluate(feat, current_timestamp=1000.0)
        assert alert1 is not None

        # 2nd trigger 5 seconds later for same destination -> Deduplicated (None returned)
        alert2 = detector.evaluate(feat, current_timestamp=1005.0)
        assert alert2 is None

        # 3rd trigger 70 seconds later -> New incident after window expiry
        alert3 = detector.evaluate(feat, current_timestamp=1075.0)
        assert alert3 is not None


# ---------------------------------------------------------------------------
# Threat T-e: Port Scan Tests
# ---------------------------------------------------------------------------
class TestPortScanDetector:
    def test_vertical_port_scan_detection(self) -> None:
        model_pkg = safe_load_artifact(MODELS_DIR / "t_e_portscan.joblib", MANIFEST_PATH)
        detector = PortScanDetector(
            model=model_pkg["model"],
            calibrator=model_pkg["calibrator"],
            confidence_threshold=0.70,
        )

        feat = SrcWindowFeatures(
            src_ip="10.0.0.55",
            window_seconds=10.0,
            packet_count=60,
            dst_port_count=50,
            dst_ip_count=1,
            syn_count=58,
            syn_scan_ratio=0.96,
        )

        alert = detector.evaluate(feat, current_timestamp=1100.0, target_ip="192.168.1.10")
        assert alert is not None
        assert alert.threat_class == ThreatClass.PORT_SCANNING
        assert alert.source is not None
        assert alert.source.ip == "10.0.0.55"
        assert alert.mitre_attack is not None
        assert alert.mitre_attack.technique_id == "T1046"
        assert any(e.feature == "dst_port_count" for e in alert.evidence)

    def test_horizontal_ip_sweep_detection(self) -> None:
        detector = PortScanDetector(confidence_threshold=0.70)
        feat = SrcWindowFeatures(
            src_ip="10.0.0.60",
            window_seconds=10.0,
            packet_count=80,
            dst_port_count=1,
            dst_ip_count=35,
            syn_count=75,
            syn_scan_ratio=0.93,
        )

        alert = detector.evaluate(feat, current_timestamp=1105.0)
        assert alert is not None
        assert alert.threat_class == ThreatClass.PORT_SCANNING
        assert any(e.feature == "dst_ip_count" for e in alert.evidence)

    def test_benign_single_session_no_portscan_alert(self) -> None:
        model_pkg = safe_load_artifact(MODELS_DIR / "t_e_portscan.joblib", MANIFEST_PATH)
        detector = PortScanDetector(
            model=model_pkg["model"],
            calibrator=model_pkg["calibrator"],
            confidence_threshold=0.70,
        )

        feat = SrcWindowFeatures(
            src_ip="10.0.0.100",
            window_seconds=10.0,
            packet_count=20,
            dst_port_count=2,
            dst_ip_count=1,
            syn_count=2,
            syn_scan_ratio=0.10,
        )

        alert = detector.evaluate(feat, current_timestamp=1110.0)
        assert alert is None


# ---------------------------------------------------------------------------
# Threat T-f: Data Exfiltration Tests
# ---------------------------------------------------------------------------
class TestExfiltrationDetector:
    def test_bulk_exfiltration_detection(self) -> None:
        model_pkg = safe_load_artifact(MODELS_DIR / "t_f_exfil.joblib", MANIFEST_PATH)
        detector = ExfiltrationDetector(
            model=model_pkg["model"],
            calibrator=model_pkg["calibrator"],
            confidence_threshold=0.70,
        )

        feat = FlowExfilFeatures(
            flow_id="192.168.1.50:49210_203.0.113.80:443_TCP",
            src_ip="192.168.1.50",
            dst_ip="203.0.113.80",
            dst_port=443,
            protocol="TCP",
            egress_bytes=1_500_000,
            ingress_bytes=10_000,
            duration_seconds=45.0,
            direction=Direction.OUTBOUND,
        )

        alert = detector.evaluate(feat, current_timestamp=1200.0)
        assert alert is not None
        assert alert.threat_class == ThreatClass.DATA_EXFILTRATION
        assert alert.severity == Severity.CRITICAL
        assert any(e.feature == "r_byte_ratio" for e in alert.evidence)
        assert any(e.feature == "egress_bytes" for e in alert.evidence)

    def test_trickle_exfiltration_detection(self) -> None:
        detector = ExfiltrationDetector(confidence_threshold=0.70)
        feat = FlowExfilFeatures(
            flow_id="192.168.1.50:50100_203.0.113.90:80_TCP",
            src_ip="192.168.1.50",
            dst_ip="203.0.113.90",
            dst_port=80,
            protocol="TCP",
            egress_bytes=25_000,
            ingress_bytes=5_000,
            duration_seconds=180.0,
            direction=Direction.OUTBOUND,
        )

        alert = detector.evaluate(feat, current_timestamp=1250.0)
        assert alert is not None
        assert alert.threat_class == ThreatClass.DATA_EXFILTRATION
        assert any(e.feature == "duration_seconds" for e in alert.evidence)

    def test_benign_download_no_exfil_alert(self) -> None:
        model_pkg = safe_load_artifact(MODELS_DIR / "t_f_exfil.joblib", MANIFEST_PATH)
        detector = ExfiltrationDetector(
            model=model_pkg["model"],
            calibrator=model_pkg["calibrator"],
            confidence_threshold=0.70,
        )

        feat = FlowExfilFeatures(
            flow_id="192.168.1.50:51200_172.217.16.206:443_TCP",
            src_ip="192.168.1.50",
            dst_ip="172.217.16.206",
            dst_port=443,
            protocol="TCP",
            egress_bytes=5_000,
            ingress_bytes=2_000_000,
            duration_seconds=30.0,
            direction=Direction.OUTBOUND,
        )

        alert = detector.evaluate(feat, current_timestamp=1280.0)
        assert alert is None


# ---------------------------------------------------------------------------
# End-to-End Pipeline & Ledger Integration Test
# ---------------------------------------------------------------------------
class TestDetectorPipelineIntegration:
    def test_full_pipeline_ingest_feature_detector_ledger(self, tmp_path: Path) -> None:
        from trinetra.ledger import ForensicLedger, generate_or_load_keypair

        cfg = EnclaveConfig()
        cfg.ledger_file_path = tmp_path / "test_ledger.jsonl"
        cfg.ledger_privkey_path = tmp_path / "test.key"
        cfg.ledger_pubkey_path = tmp_path / "test.pub"

        priv_key, pub_key = generate_or_load_keypair(cfg.ledger_privkey_path, cfg.ledger_pubkey_path)
        ledger = ForensicLedger(priv_key, pub_key, cfg.ledger_file_path, block_size=2)
        table = FlowTable(config=cfg)
        engine = WindowedFeatureEngine()

        ddos_pkg = safe_load_artifact(MODELS_DIR / "t_a_ddos.joblib", MANIFEST_PATH)
        detector = DdosDetector(model=ddos_pkg["model"], calibrator=ddos_pkg["calibrator"])

        # Stream flood packets into pipeline
        target_ip = "192.168.1.100"
        alerts_emitted: list[AlertRecord] = []

        for i in range(500):
            ev = FlowEvent(
                timestamp=1000.0 + (i * 0.005),
                src_ip=f"10.0.{i % 250}.{i % 250 + 1}",
                src_port=10000 + i,
                dst_ip=target_ip,
                dst_port=80,
                protocol="TCP",
                length=64,
                tcp_flags={"SYN": True, "ACK": False, "FIN": False, "RST": False, "PSH": False, "URG": False},
            )
            table.process_event(ev)
            engine.process_event(ev)

            # Check features periodically
            if i % 100 == 99:
                feat = engine.get_dst_features(target_ip)
                if feat is not None:
                    alert = detector.evaluate(feat, current_timestamp=ev.timestamp, dst_port=80)
                    if alert is not None:
                        alerts_emitted.append(alert)
                        ledger.add_alert(alert)

        assert len(alerts_emitted) >= 1
        first_alert = alerts_emitted[0]
        assert first_alert.threat_class == ThreatClass.VOLUMETRIC_DDOS
        assert len(first_alert.evidence) >= 1
        block = ledger.flush()
        assert block is not None
        assert block.block_height >= 0
