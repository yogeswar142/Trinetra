"""
Trinetra Pydantic Data Contracts.

Implements the NTRO standardized alert format, MITRE ATT&CK mapping,
and the hash-chained forensic ledger block schema.

The five MANDATORY alert fields (as required by PS 26145) are:
    1. alert_id       — unique identifier
    2. timestamp      — ISO-8601 UTC
    3. threat_class   — one of ThreatClass enum
    4. severity       — one of Severity enum
    5. evidence       — List[EvidenceItem] (non-empty; contains interpretable features)

All other fields are strongly typed but optional for forward compatibility.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------
class ThreatClass(str, Enum):
    """Canonical threat class identifiers mapped to PS 26145 threat types."""
    # T-a: Volumetric DDoS
    VOLUMETRIC_DDOS = "VOLUMETRIC_DDOS"
    UDP_AMPLIFICATION = "UDP_AMPLIFICATION"
    SLOWLORIS = "SLOWLORIS"
    # T-b: Botnet C2 Beaconing
    BOTNET_C2_BEACONING = "BOTNET_C2_BEACONING"
    # T-c: DGA / DNS Tunnelling
    DGA_DOMAINS = "DGA_DOMAINS"
    DNS_TUNNELLING = "DNS_TUNNELLING"
    # T-d: Malware in Encrypted Sessions
    ENCRYPTED_MALWARE_TLS = "ENCRYPTED_MALWARE_TLS"
    # T-e: Port Scanning / Reconnaissance
    PORT_SCANNING = "PORT_SCANNING"
    RECONNAISSANCE = "RECONNAISSANCE"
    # T-f: Data Exfiltration
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    # Generic anomaly (catch-all for anomaly detectors without specific class)
    UNKNOWN_ANOMALY = "UNKNOWN_ANOMALY"


class Severity(str, Enum):
    """Alert severity levels, ordered from highest to lowest."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Direction(str, Enum):
    """Traffic direction as classified by passive topology analysis."""
    INBOUND = "INBOUND"     # External → Internal
    OUTBOUND = "OUTBOUND"   # Internal → External
    LATERAL = "LATERAL"     # Internal → Internal
    TRANSIT = "TRANSIT"     # External → External (pass-through)


class TcpState(str, Enum):
    """Passive TCP state machine states (without transmit capability)."""
    SYN_SENT = "SYN_SENT"
    SYN_RCVD = "SYN_RCVD"
    ESTABLISHED = "ESTABLISHED"
    FIN_WAIT = "FIN_WAIT"
    CLOSED = "CLOSED"
    MIDSTREAM_ESTABLISHED = "MIDSTREAM_ESTABLISHED"  # Mid-stream capture, no SYN seen
    HALF_OPEN_OBSERVED = "HALF_OPEN_OBSERVED"        # Only one direction visible


# ---------------------------------------------------------------------------
# Supporting models
# ---------------------------------------------------------------------------
class Endpoint(BaseModel):
    """Network endpoint (IP + port + internal flag)."""
    ip: str = Field(..., description="IPv4 or IPv6 address string")
    port: int = Field(..., ge=0, le=65535, description="Port number")
    internal: bool = Field(False, description="True if IP is in INTERNAL_NETWORKS")


class EvidenceItem(BaseModel):
    """
    A single interpretable piece of evidence for an alert.

    Every detector must produce at least one EvidenceItem. The feature name,
    measured value, and threshold (if applicable) are all recorded so that
    a human analyst (or judge) can reproduce the reasoning.

    NOTE: thresholds listed here are the values active at alert-time; they
    may differ from the config default if the config was overridden.
    """
    feature: str = Field(
        ...,
        description="Machine-readable feature name (e.g. 'beacon_cv', 'dns_entropy')",
    )
    value: Any = Field(..., description="Measured value of the feature")
    threshold: Optional[Any] = Field(
        None,
        description="Threshold applied at alert time (None if no threshold used, e.g. ML-only)",
    )
    interpretation: str = Field(
        ...,
        description="Human-readable explanation of what this feature indicates",
    )
    source: str = Field(
        "rule",
        description="Origin of this evidence item: 'rule', 'model', 'blacklist', 'cert'",
    )

    @field_validator("feature")
    @classmethod
    def feature_must_be_nonempty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("EvidenceItem.feature must not be empty")
        return v


class MitreAttackRef(BaseModel):
    """MITRE ATT&CK tactic + technique reference."""
    tactic: str = Field(..., description="MITRE ATT&CK tactic name (e.g. 'Command and Control')")
    technique_id: str = Field(..., description="MITRE technique ID (e.g. 'T1071.001')")
    technique_name: str = Field(..., description="MITRE technique name")


class ThreatIntelRef(BaseModel):
    """Optional threat intelligence cross-reference."""
    profile_match: Optional[str] = Field(
        None,
        description="Matched JA3/JA3S hash or campaign name from threat intel feed",
    )
    intel_source: Optional[str] = Field(
        None,
        description="Source of the threat intel (e.g. 'abuse.ch SSLBL', 'CTU-13')",
    )
    associated_playbooks: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Alert record (primary output schema — 5 mandatory fields enforced)
# ---------------------------------------------------------------------------
class AlertRecord(BaseModel):
    """
    Standardized Trinetra alert record.

    MANDATORY fields (PS 26145 requirement):
        alert_id, timestamp, threat_class, severity, evidence

    The evidence list MUST be non-empty. Every alert must contain at least
    one interpretable EvidenceItem explaining why the alert was raised.
    """
    # --- 5 MANDATORY FIELDS ---
    alert_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique alert identifier (UUID-4)",
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO-8601 UTC timestamp of alert generation",
    )
    threat_class: ThreatClass = Field(..., description="Classified threat type")
    severity: Severity = Field(..., description="Alert severity level")
    evidence: list[EvidenceItem] = Field(
        ...,
        min_length=1,
        description="Non-empty list of interpretable evidence items (MANDATORY)",
    )

    # --- Strongly typed optional fields ---
    flow_id: Optional[str] = Field(None, description="5-tuple flow identifier")
    direction: Optional[Direction] = Field(None, description="Traffic direction")
    confidence: float = Field(0.5, ge=0.0, le=1.0, description="Model/rule confidence [0, 1]")
    source: Optional[Endpoint] = None
    destination: Optional[Endpoint] = None
    protocol: Optional[str] = Field(None, description="Protocol name: TCP, UDP, DNS, TLS, QUIC")

    # --- Context and enrichment ---
    mitre_attack: Optional[MitreAttackRef] = None
    threat_intel: Optional[ThreatIntelRef] = None
    chain_id: Optional[str] = Field(
        None,
        description="Threat-chain correlation ID (Phase 4)",
    )
    narration: Optional[str] = Field(
        None,
        description="Human-readable narration (template or Ollama output, attached asynchronously)",
    )
    model_version: str = Field(
        "trinetra-v0.0.1-phase0",
        description="Model/detector version string for reproducibility",
    )

    # --- Ledger anchor (filled in after ledger commit) ---
    ledger_block_height: Optional[int] = Field(
        None,
        description="Block height in the forensic ledger where this alert was committed",
    )
    ledger_leaf_hash: Optional[str] = Field(
        None,
        description="SHA-256 hex digest of this alert's canonical JSON (ledger leaf)",
    )

    @model_validator(mode="after")
    def evidence_must_be_nonempty(self) -> "AlertRecord":
        if not self.evidence:
            raise ValueError("AlertRecord.evidence must contain at least one EvidenceItem")
        return self


# ---------------------------------------------------------------------------
# Flow event (normalized representation of a single network packet/flow)
# ---------------------------------------------------------------------------
class FlowEvent(BaseModel):
    """
    Normalized representation of a single network packet or flow record.

    Produced by the ingest layer. All fields are Optional except the
    5-tuple (src_ip, src_port, dst_ip, dst_port, protocol) and timestamp.
    """
    timestamp: float = Field(..., description="Unix epoch seconds (float for sub-ms precision)")
    src_ip: str
    src_port: int = Field(..., ge=0, le=65535)
    dst_ip: str
    dst_port: int = Field(..., ge=0, le=65535)
    protocol: str = Field(..., description="Protocol: TCP, UDP, ICMP, DNS, TLS, QUIC")
    length: int = Field(..., ge=0, description="Packet/flow payload length in bytes")

    # TCP fields
    tcp_flags: Optional[dict[str, bool]] = Field(
        None,
        description="TCP flags: SYN, ACK, FIN, RST, PSH, URG, ECE, CWR",
    )
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None

    # DNS fields
    dns_query: Optional[str] = None
    dns_qtype: Optional[str] = None
    dns_is_response: Optional[bool] = None
    dns_answer_count: Optional[int] = None

    # TLS fields
    tls_ja3: Optional[str] = Field(None, description="JA3 MD5 hash (ClientHello)")
    tls_ja3s: Optional[str] = Field(None, description="JA3S MD5 hash (ServerHello)")
    tls_sni: Optional[str] = Field(None, description="TLS Server Name Indication")
    tls_ja3_string: Optional[str] = Field(None, description="Raw JA3 string (before hashing)")
    tls_cert_self_signed: Optional[bool] = None
    tls_cert_validity_days: Optional[int] = None
    tls_cert_subject_cn: Optional[str] = None

    # QUIC fields (metadata-only — no key derivation, per C2 constraint)
    quic_version: Optional[int] = Field(None, description="QUIC version from long-header")
    quic_conn_id_len: Optional[int] = Field(None, description="Destination connection ID length")
    quic_packet_type: Optional[str] = Field(
        None,
        description="QUIC packet type: Initial, Handshake, 0-RTT, 1-RTT, VersionNegotiation",
    )

    # Payload features
    payload_entropy: Optional[float] = Field(
        None,
        ge=0.0,
        le=8.0,
        description="Shannon entropy of payload bytes [0, 8]",
    )

    # Flow direction (set by flow table after topology classification)
    direction: Optional[Direction] = None

    # Ingest source metadata
    ingest_source: str = Field("pcap", description="Ingest source: 'pcap', 'netflow_v9', 'ipfix'")


# ---------------------------------------------------------------------------
# Forensic ledger block schema
# ---------------------------------------------------------------------------
class LeafHashRecord(BaseModel):
    """One leaf in the Merkle tree: a SHA-256 hash of one canonical alert JSON."""
    alert_id: str
    leaf_hash: str = Field(..., description="SHA-256(canonical_json(alert)) hex digest")


class BlockRecord(BaseModel):
    """
    One block in the hash-chained forensic ledger.

    CONSTRUCTION RULE (critical):
        block_hash = SHA-256(prev_block_hash || merkle_root || timestamp || metadata)
        signature  = Ed25519_sign(private_key, block_hash)

    The signature is NEVER part of the block_hash preimage.
    The block_hash is computed first; the signature is computed over it after.

    'blockchain' terminology is NOT used. This is a hash-chained, signed
    forensic ledger appropriate for a single air-gapped enclave.
    """
    block_height: int = Field(..., ge=0, description="Monotonically increasing block index (0-based)")
    prev_block_hash: str = Field(
        ...,
        description=(
            "SHA-256 hex digest of the previous block's block_hash. "
            "For block 0 (genesis), this is SHA-256(b'TRINETRA_GENESIS')."
        ),
    )
    merkle_root: str = Field(..., description="Merkle root SHA-256 hex digest of leaf hashes")
    timestamp: str = Field(..., description="ISO-8601 UTC timestamp when block was committed")
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary metadata (sensor_id, alert_count, etc.)",
    )

    # Computed fields (set by ledger module after construction)
    block_hash: str = Field(
        ...,
        description=(
            "SHA-256(prev_block_hash || merkle_root || timestamp || metadata_canonical). "
            "Computed BEFORE signature — signature is NOT in this preimage."
        ),
    )
    signature: str = Field(
        ...,
        description="Ed25519 signature over block_hash bytes, hex-encoded. NOT part of block_hash preimage.",
    )
    leaf_hashes: list[LeafHashRecord] = Field(default_factory=list)

    @field_validator("block_hash", "prev_block_hash", "merkle_root")
    @classmethod
    def must_be_64char_hex(cls, v: str) -> str:
        """Validate SHA-256 hex digest is exactly 64 characters."""
        if len(v) != 64 or not all(c in "0123456789abcdef" for c in v.lower()):
            raise ValueError(f"Expected 64-character lowercase hex SHA-256 digest, got: {v!r}")
        return v.lower()
