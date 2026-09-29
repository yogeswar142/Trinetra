"""
tests/test_schemas.py

Tests for the Pydantic data schemas (AlertRecord, FlowEvent, BlockRecord, etc.).

Covers:
    - AlertRecord with all 5 mandatory fields
    - AlertRecord rejects empty evidence list (Pydantic enforces min_length=1)
    - EvidenceItem validation
    - FlowEvent creation for various protocols
    - BlockRecord validator (64-char hex digest for block_hash)
    - BlockRecord rejects invalid hex hashes
    - Direction enum coverage
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from trinetra.schemas import (
    AlertRecord,
    BlockRecord,
    Direction,
    EvidenceItem,
    FlowEvent,
    LeafHashRecord,
    MitreAttackRef,
    Severity,
    TcpState,
    ThreatClass,
    ThreatIntelRef,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def minimal_evidence() -> list[EvidenceItem]:
    """Return a single valid EvidenceItem for use in AlertRecord tests."""
    return [
        EvidenceItem(
            feature="syn_ratio",
            value=0.95,
            threshold=0.80,
            interpretation="SYN ratio (0.95) exceeds threshold (0.80) — probable SYN flood.",
            source="rule",
        )
    ]


def valid_alert(**kwargs) -> AlertRecord:
    """Create a valid AlertRecord with mandatory fields, overridable via kwargs."""
    defaults = dict(
        threat_class=ThreatClass.VOLUMETRIC_DDOS,
        severity=Severity.HIGH,
        evidence=minimal_evidence(),
    )
    defaults.update(kwargs)
    return AlertRecord(**defaults)


# ---------------------------------------------------------------------------
# AlertRecord — mandatory fields
# ---------------------------------------------------------------------------
class TestAlertRecordMandatoryFields:
    def test_alert_created_with_mandatory_fields(self) -> None:
        alert = valid_alert()
        assert alert.alert_id  # UUID auto-generated
        assert alert.timestamp  # ISO-8601 auto-generated
        assert alert.threat_class == ThreatClass.VOLUMETRIC_DDOS
        assert alert.severity == Severity.HIGH
        assert len(alert.evidence) == 1

    def test_alert_id_is_uuid_format(self) -> None:
        import uuid
        alert = valid_alert()
        # Should not raise
        parsed = uuid.UUID(alert.alert_id)
        assert parsed.version == 4

    def test_timestamp_is_iso8601(self) -> None:
        from datetime import datetime
        alert = valid_alert()
        # Should parse without error
        dt = datetime.fromisoformat(alert.timestamp)
        assert dt is not None

    def test_two_alerts_have_different_ids(self) -> None:
        a1 = valid_alert()
        a2 = valid_alert()
        assert a1.alert_id != a2.alert_id

    def test_missing_threat_class_raises(self) -> None:
        with pytest.raises(ValidationError):
            AlertRecord(
                severity=Severity.HIGH,
                evidence=minimal_evidence(),
            )

    def test_missing_severity_raises(self) -> None:
        with pytest.raises(ValidationError):
            AlertRecord(
                threat_class=ThreatClass.BOTNET_C2_BEACONING,
                evidence=minimal_evidence(),
            )

    def test_missing_evidence_raises(self) -> None:
        with pytest.raises(ValidationError):
            AlertRecord(
                threat_class=ThreatClass.BOTNET_C2_BEACONING,
                severity=Severity.MEDIUM,
            )


# ---------------------------------------------------------------------------
# AlertRecord — evidence enforcement (mandatory, non-empty)
# ---------------------------------------------------------------------------
class TestAlertRecordEvidenceEnforcement:
    def test_empty_evidence_list_raises(self) -> None:
        """AlertRecord.evidence must have at least 1 item (min_length=1 + model_validator)."""
        with pytest.raises(ValidationError):
            AlertRecord(
                threat_class=ThreatClass.PORT_SCANNING,
                severity=Severity.MEDIUM,
                evidence=[],  # Empty — should FAIL
            )

    def test_single_evidence_item_is_sufficient(self) -> None:
        alert = valid_alert(evidence=minimal_evidence())
        assert len(alert.evidence) == 1

    def test_multiple_evidence_items_accepted(self) -> None:
        ev = [
            EvidenceItem(
                feature="cv",
                value=0.05,
                threshold=0.22,
                interpretation="Low CV indicates periodic beaconing.",
                source="rule",
            ),
            EvidenceItem(
                feature="autocorr_peak",
                value=0.82,
                threshold=0.65,
                interpretation="Autocorrelation peak at lag 6 confirms 60s beacon period.",
                source="model",
            ),
        ]
        alert = valid_alert(
            threat_class=ThreatClass.BOTNET_C2_BEACONING,
            evidence=ev,
        )
        assert len(alert.evidence) == 2


# ---------------------------------------------------------------------------
# EvidenceItem validation
# ---------------------------------------------------------------------------
class TestEvidenceItem:
    def test_valid_evidence_item(self) -> None:
        ev = EvidenceItem(
            feature="dns_entropy",
            value=4.2,
            threshold=3.4,
            interpretation="DNS label entropy (4.2) exceeds DGA threshold (3.4).",
        )
        assert ev.feature == "dns_entropy"
        assert ev.source == "rule"  # Default

    def test_empty_feature_name_raises(self) -> None:
        with pytest.raises(ValidationError, match="feature must not be empty"):
            EvidenceItem(
                feature="   ",  # Whitespace only — should FAIL
                value=0.5,
                interpretation="test",
            )

    def test_none_threshold_is_valid(self) -> None:
        ev = EvidenceItem(
            feature="ml_score",
            value=0.93,
            threshold=None,   # ML-only, no explicit threshold
            interpretation="Isolation Forest anomaly score.",
            source="model",
        )
        assert ev.threshold is None

    def test_source_values(self) -> None:
        for source in ("rule", "model", "blacklist", "cert"):
            ev = EvidenceItem(
                feature="test_feature",
                value=1,
                interpretation="test",
                source=source,
            )
            assert ev.source == source


# ---------------------------------------------------------------------------
# AlertRecord — optional fields
# ---------------------------------------------------------------------------
class TestAlertRecordOptionalFields:
    def test_confidence_defaults_to_0_5(self) -> None:
        alert = valid_alert()
        assert alert.confidence == pytest.approx(0.5)

    def test_confidence_bounds_enforced(self) -> None:
        with pytest.raises(ValidationError):
            valid_alert(confidence=1.5)
        with pytest.raises(ValidationError):
            valid_alert(confidence=-0.1)

    def test_mitre_attack_ref_attached(self) -> None:
        alert = valid_alert(
            mitre_attack=MitreAttackRef(
                tactic="Command and Control",
                technique_id="T1071.001",
                technique_name="Application Layer Protocol: Web Protocols",
            )
        )
        assert alert.mitre_attack is not None
        assert alert.mitre_attack.technique_id == "T1071.001"

    def test_direction_enum_values(self) -> None:
        for d in Direction:
            alert = valid_alert(direction=d)
            assert alert.direction == d

    def test_all_threat_classes_accepted(self) -> None:
        for tc in ThreatClass:
            alert = valid_alert(threat_class=tc)
            assert alert.threat_class == tc

    def test_all_severity_levels_accepted(self) -> None:
        for sev in Severity:
            alert = valid_alert(severity=sev)
            assert alert.severity == sev

    def test_ledger_fields_default_to_none(self) -> None:
        alert = valid_alert()
        assert alert.ledger_block_height is None
        assert alert.ledger_leaf_hash is None


# ---------------------------------------------------------------------------
# FlowEvent
# ---------------------------------------------------------------------------
class TestFlowEvent:
    def test_minimal_flow_event(self) -> None:
        flow = FlowEvent(
            timestamp=1000.0,
            src_ip="10.0.0.1",
            src_port=12345,
            dst_ip="8.8.8.8",
            dst_port=53,
            protocol="UDP",
            length=64,
        )
        assert flow.protocol == "UDP"
        assert flow.ingest_source == "pcap"

    def test_tcp_flow_with_flags(self) -> None:
        flow = FlowEvent(
            timestamp=2000.0,
            src_ip="192.168.1.1",
            src_port=55000,
            dst_ip="10.0.0.2",
            dst_port=80,
            protocol="TCP",
            length=60,
            tcp_flags={"SYN": True, "ACK": False, "FIN": False, "RST": False},
            tcp_seq=1234567890,
        )
        assert flow.tcp_flags is not None
        assert flow.tcp_flags["SYN"] is True
        assert flow.tcp_seq == 1234567890

    def test_dns_flow_with_query(self) -> None:
        flow = FlowEvent(
            timestamp=3000.0,
            src_ip="10.0.0.5",
            src_port=12345,
            dst_ip="8.8.8.8",
            dst_port=53,
            protocol="DNS",
            length=80,
            dns_query="evilmalware.dga.ru",
            dns_qtype="A",
            dns_is_response=False,
        )
        assert flow.dns_query == "evilmalware.dga.ru"

    def test_tls_flow_with_ja3(self) -> None:
        flow = FlowEvent(
            timestamp=4000.0,
            src_ip="192.168.1.5",
            src_port=54321,
            dst_ip="203.0.113.10",
            dst_port=443,
            protocol="TLS",
            length=517,
            tls_ja3="abc123def456" * 4 + "1234",  # 52 chars — not a real hash but for field test
            tls_sni="malware.example.com",
        )
        assert flow.tls_sni == "malware.example.com"

    def test_quic_flow_fields(self) -> None:
        """QUIC metadata fields — no decryption, only header metadata."""
        flow = FlowEvent(
            timestamp=5000.0,
            src_ip="10.0.0.1",
            src_port=12345,
            dst_ip="1.2.3.4",
            dst_port=443,
            protocol="QUIC",
            length=1280,
            quic_version=0x00000001,
            quic_conn_id_len=8,
            quic_packet_type="Initial",
        )
        assert flow.quic_packet_type == "Initial"
        assert flow.quic_version == 0x00000001

    def test_payload_entropy_bounds(self) -> None:
        # Valid: 0..8
        FlowEvent(
            timestamp=1.0,
            src_ip="1.2.3.4",
            src_port=1000,
            dst_ip="5.6.7.8",
            dst_port=80,
            protocol="TCP",
            length=100,
            payload_entropy=7.5,
        )
        # Invalid: > 8
        with pytest.raises(ValidationError):
            FlowEvent(
                timestamp=1.0,
                src_ip="1.2.3.4",
                src_port=1000,
                dst_ip="5.6.7.8",
                dst_port=80,
                protocol="TCP",
                length=100,
                payload_entropy=9.0,
            )

    def test_port_bounds_enforced(self) -> None:
        with pytest.raises(ValidationError):
            FlowEvent(
                timestamp=1.0,
                src_ip="1.2.3.4",
                src_port=70000,  # > 65535
                dst_ip="5.6.7.8",
                dst_port=80,
                protocol="TCP",
                length=100,
            )


# ---------------------------------------------------------------------------
# BlockRecord
# ---------------------------------------------------------------------------
class TestBlockRecord:
    VALID_HASH = "a" * 64  # 64 lowercase hex chars

    def test_valid_block_record(self) -> None:
        block = BlockRecord(
            block_height=0,
            prev_block_hash=self.VALID_HASH,
            merkle_root=self.VALID_HASH,
            timestamp="2026-09-29T20:00:00+00:00",
            block_hash=self.VALID_HASH,
            signature="f" * 128,  # Ed25519 signature = 64 bytes = 128 hex chars
        )
        assert block.block_height == 0

    def test_block_hash_must_be_64_char_hex(self) -> None:
        with pytest.raises(ValidationError):
            BlockRecord(
                block_height=0,
                prev_block_hash=self.VALID_HASH,
                merkle_root=self.VALID_HASH,
                timestamp="2026-09-29T20:00:00+00:00",
                block_hash="not_a_valid_sha256",  # Invalid
                signature="f" * 128,
            )

    def test_block_hash_normalized_to_lowercase(self) -> None:
        block = BlockRecord(
            block_height=0,
            prev_block_hash=self.VALID_HASH,
            merkle_root="A" * 64,   # Uppercase — should be normalized
            timestamp="2026-09-29T20:00:00+00:00",
            block_hash=self.VALID_HASH,
            signature="f" * 128,
        )
        assert block.merkle_root == "a" * 64  # Normalized to lowercase

    def test_genesis_block_height(self) -> None:
        block = BlockRecord(
            block_height=0,
            prev_block_hash=self.VALID_HASH,
            merkle_root=self.VALID_HASH,
            timestamp="2026-09-29T20:00:00+00:00",
            block_hash=self.VALID_HASH,
            signature="f" * 128,
        )
        assert block.block_height == 0

    def test_leaf_hash_record(self) -> None:
        lr = LeafHashRecord(
            alert_id="test-alert-001",
            leaf_hash=self.VALID_HASH,
        )
        assert lr.alert_id == "test-alert-001"


# ---------------------------------------------------------------------------
# TcpState enum coverage
# ---------------------------------------------------------------------------
class TestTcpState:
    def test_all_tcp_states_accessible(self) -> None:
        assert TcpState.SYN_SENT
        assert TcpState.SYN_RCVD
        assert TcpState.ESTABLISHED
        assert TcpState.MIDSTREAM_ESTABLISHED
        assert TcpState.HALF_OPEN_OBSERVED
        assert TcpState.CLOSED
