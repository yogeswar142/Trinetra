"""
Trinetra Hash-Chained, Ed25519-Signed Forensic Ledger.

This module implements a forensic audit trail for all Trinetra alerts.
It is intentionally NOT called a "blockchain" — it is a hash-chained,
signed forensic ledger appropriate for a single air-gapped enclave.

CONSTRUCTION RULE (invariant — tested in tests/test_ledger.py):
    block_hash = SHA-256(prev_block_hash || merkle_root || timestamp || metadata_canonical)
    signature  = Ed25519_sign(private_key, block_hash)
    *** The signature is NEVER included in the block_hash preimage. ***

WHAT IT PROVIDES:
    Cryptographic proof that no alert was deleted, inserted, or modified
    after signing, within the ledger file.

WHAT IT CANNOT PREVENT:
    Tail truncation — if an attacker has access to the ledger file, they can
    delete the last N blocks. Mitigation: periodically output the head block
    hash to an external channel (printer, syslog, second screen). This is
    documented as a limitation and must be disclosed to judges.

KEY STORAGE:
    Ed25519 private key is stored in the enclave's protected key directory
    with filesystem permissions (600). Not HSM-backed in Phase 0.

TRUSTED TIMESTAMPS:
    Local system clock. Not RFC 3161 certified. Noted as a limitation.
"""
from __future__ import annotations

import hashlib
import json
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Sequence

import orjson
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from trinetra.schemas import AlertRecord, BlockRecord, LeafHashRecord

# Genesis constant — SHA-256(b"TRINETRA_GENESIS") used as prev_hash for block 0.
GENESIS_PREV_HASH: str = hashlib.sha256(b"TRINETRA_GENESIS").hexdigest()


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------
def generate_or_load_keypair(
    privkey_path: Path,
    pubkey_path: Path,
) -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """
    Generate a new Ed25519 keypair or load an existing one.

    If privkey_path does not exist, generates a new keypair and saves both
    files with restrictive permissions (600). The public key is saved as
    raw bytes (32 bytes) in PEM format for easy export.

    Args:
        privkey_path: Path to write/read the private key PEM file.
        pubkey_path: Path to write/read the public key PEM file.

    Returns:
        (private_key, public_key) tuple.
    """
    if privkey_path.exists():
        with open(privkey_path, "rb") as f:
            privkey = serialization.load_pem_private_key(f.read(), password=None)
        assert isinstance(privkey, Ed25519PrivateKey), "Key file is not an Ed25519 private key"
        pubkey = privkey.public_key()
    else:
        privkey = ed25519.Ed25519PrivateKey.generate()
        pubkey = privkey.public_key()

        # Write private key (PEM, no encryption — protected by filesystem perms)
        privkey_bytes = privkey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        privkey_path.parent.mkdir(parents=True, exist_ok=True)
        privkey_path.write_bytes(privkey_bytes)
        try:
            privkey_path.chmod(0o600)
        except OSError:
            pass  # chmod may not work on all platforms (e.g. Windows)

        # Write public key (PEM)
        pubkey_bytes = pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pubkey_path.write_bytes(pubkey_bytes)

    return privkey, pubkey  # type: ignore[return-value]


def load_public_key(pubkey_path: Path) -> Ed25519PublicKey:
    """Load an Ed25519 public key from a PEM file (for verification)."""
    with open(pubkey_path, "rb") as f:
        key = serialization.load_pem_public_key(f.read())
    assert isinstance(key, Ed25519PublicKey)
    return key


# ---------------------------------------------------------------------------
# Merkle tree
# ---------------------------------------------------------------------------
def _sha256(data: bytes) -> str:
    """Return hex-encoded SHA-256 digest of data."""
    return hashlib.sha256(data).hexdigest()


def compute_merkle_root(leaf_hashes: Sequence[str]) -> str:
    """
    Compute a Merkle root from a sequence of SHA-256 hex leaf hashes.

    If the leaf count is odd, the last leaf is duplicated (standard Merkle
    tree convention). An empty leaf list returns the SHA-256 of b'' (empty).

    Args:
        leaf_hashes: Ordered sequence of 64-char hex SHA-256 strings.

    Returns:
        64-char hex SHA-256 Merkle root string.
    """
    if not leaf_hashes:
        return _sha256(b"")

    layer = [bytes.fromhex(h) for h in leaf_hashes]

    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])  # Duplicate last leaf if odd count
        next_layer = []
        for i in range(0, len(layer), 2):
            combined = layer[i] + layer[i + 1]
            next_layer.append(hashlib.sha256(combined).digest())
        layer = next_layer

    return layer[0].hex()


# ---------------------------------------------------------------------------
# Block construction
# ---------------------------------------------------------------------------
def _canonical_metadata(metadata: dict) -> bytes:
    """Return canonical, deterministic JSON bytes for metadata."""
    # orjson sorts keys and produces deterministic output
    return orjson.dumps(metadata, option=orjson.OPT_SORT_KEYS)


def compute_block_hash(
    prev_block_hash: str,
    merkle_root: str,
    timestamp: str,
    metadata: dict,
) -> str:
    """
    Compute the block hash.

    block_hash = SHA-256(
        prev_block_hash_bytes  [32 bytes]
        || merkle_root_bytes   [32 bytes]
        || timestamp_utf8
        || 0x00                [separator]
        || canonical_metadata_json
    )

    The signature is computed OVER this hash and is NOT part of the preimage.

    Args:
        prev_block_hash: 64-char hex SHA-256 of previous block (or GENESIS_PREV_HASH).
        merkle_root: 64-char hex SHA-256 Merkle root of leaf hashes.
        timestamp: ISO-8601 UTC string.
        metadata: Arbitrary dict (will be serialized canonically).

    Returns:
        64-char hex SHA-256 string.
    """
    h = hashlib.sha256()
    h.update(bytes.fromhex(prev_block_hash))
    h.update(bytes.fromhex(merkle_root))
    h.update(timestamp.encode("utf-8"))
    h.update(b"\x00")  # Separator to prevent ambiguity between timestamp and metadata
    h.update(_canonical_metadata(metadata))
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Alert leaf hashing
# ---------------------------------------------------------------------------
def alert_leaf_hash(alert: AlertRecord) -> str:
    """
    Compute the Merkle leaf hash of a single alert.

    leaf_hash = SHA-256(canonical_json(alert))

    The canonical JSON is produced by Pydantic's model_dump_json with
    sorted keys to ensure determinism across Python versions.

    Args:
        alert: A committed AlertRecord.

    Returns:
        64-char hex SHA-256 string.
    """
    canonical = alert.model_dump_json(exclude={"ledger_block_height", "ledger_leaf_hash"})
    # Re-serialize with sorted keys for strict determinism
    canonical_sorted = orjson.dumps(
        json.loads(canonical),
        option=orjson.OPT_SORT_KEYS,
    )
    return _sha256(canonical_sorted)


# ---------------------------------------------------------------------------
# Forensic ledger
# ---------------------------------------------------------------------------
class ForensicLedger:
    """
    Hash-chained, Ed25519-signed forensic ledger.

    Writes one JSONL record per block to ledger_file_path. Each block
    contains a Merkle root of the alerts committed in that block, a hash
    chain linking to the previous block, and an Ed25519 signature over the
    block hash (not included in the preimage).

    Usage:
        ledger = ForensicLedger(privkey, pubkey, ledger_path, block_size=10)
        ledger.add_alert(alert)
        # ... add more alerts ...
        committed_block = ledger.flush()   # Forces a block commit
    """

    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        public_key: Ed25519PublicKey,
        ledger_path: Path,
        block_size: int = 10,
    ) -> None:
        self._privkey = private_key
        self._pubkey = public_key
        self._ledger_path = ledger_path
        self._block_size = block_size
        self._pending_alerts: list[AlertRecord] = []
        self._pending_leaf_hashes: list[str] = []
        self._block_height: int = self._recover_block_height()
        self._prev_block_hash: str = self._recover_prev_hash()

    def _recover_block_height(self) -> int:
        """Read the last committed block height from the ledger file, or return 0."""
        if not self._ledger_path.exists():
            return 0
        last_line = b""
        with open(self._ledger_path, "rb") as f:
            for line in f:
                line = line.strip()
                if line:
                    last_line = line
        if not last_line:
            return 0
        try:
            record = json.loads(last_line)
            return record.get("block_height", 0) + 1
        except (json.JSONDecodeError, KeyError):
            return 0

    def _recover_prev_hash(self) -> str:
        """Read the last committed block hash, or return GENESIS_PREV_HASH."""
        if not self._ledger_path.exists():
            return GENESIS_PREV_HASH
        last_line = b""
        with open(self._ledger_path, "rb") as f:
            for line in f:
                line = line.strip()
                if line:
                    last_line = line
        if not last_line:
            return GENESIS_PREV_HASH
        try:
            record = json.loads(last_line)
            return record.get("block_hash", GENESIS_PREV_HASH)
        except (json.JSONDecodeError, KeyError):
            return GENESIS_PREV_HASH

    def add_alert(self, alert: AlertRecord) -> str:
        """
        Add an alert to the pending batch.

        Computes and stores the alert's leaf hash. If the pending batch
        reaches block_size, automatically commits a block.

        Args:
            alert: A completed AlertRecord.

        Returns:
            The leaf hash of this alert (hex SHA-256).
        """
        leaf = alert_leaf_hash(alert)
        self._pending_alerts.append(alert)
        self._pending_leaf_hashes.append(leaf)
        if len(self._pending_alerts) >= self._block_size:
            self.flush()
        return leaf

    def flush(self, sensor_id: str = "TRINETRA") -> Optional[BlockRecord]:
        """
        Commit the current pending batch as a new block.

        Returns None if there are no pending alerts.

        Args:
            sensor_id: Sensor identifier included in block metadata.

        Returns:
            The committed BlockRecord, or None if nothing to commit.
        """
        if not self._pending_leaf_hashes:
            return None

        timestamp = datetime.now(timezone.utc).isoformat()
        merkle_root = compute_merkle_root(self._pending_leaf_hashes)
        metadata = {
            "sensor_id": sensor_id,
            "alert_count": len(self._pending_leaf_hashes),
        }

        # Step 1: Compute block hash (signature is NOT in preimage)
        block_hash = compute_block_hash(
            self._prev_block_hash,
            merkle_root,
            timestamp,
            metadata,
        )

        # Step 2: Sign the block hash with Ed25519 private key
        signature_bytes = self._privkey.sign(bytes.fromhex(block_hash))
        signature_hex = signature_bytes.hex()

        # Step 3: Build the block record
        leaf_records = [
            LeafHashRecord(alert_id=a.alert_id, leaf_hash=h)
            for a, h in zip(self._pending_alerts, self._pending_leaf_hashes)
        ]
        block = BlockRecord(
            block_height=self._block_height,
            prev_block_hash=self._prev_block_hash,
            merkle_root=merkle_root,
            timestamp=timestamp,
            metadata=metadata,
            block_hash=block_hash,
            signature=signature_hex,
            leaf_hashes=leaf_records,
        )

        # Step 4: Append to ledger file
        self._ledger_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._ledger_path, "ab") as f:
            f.write(block.model_dump_json().encode("utf-8"))
            f.write(b"\n")

        # Step 5: Update state
        self._prev_block_hash = block_hash
        self._block_height += 1
        self._pending_alerts.clear()
        self._pending_leaf_hashes.clear()

        return block

    def get_head_hash(self) -> str:
        """
        Return the current head block hash.

        This value should be periodically recorded to an external channel
        (printer, syslog, second screen) to detect tail truncation attacks.

        Returns:
            64-char hex SHA-256 of the last committed block, or
            GENESIS_PREV_HASH if no blocks have been committed yet.
        """
        return self._prev_block_hash


# ---------------------------------------------------------------------------
# Chain verification
# ---------------------------------------------------------------------------
class VerificationResult:
    """Result of a full chain verification pass."""
    def __init__(self) -> None:
        self.blocks_verified: int = 0
        self.errors: list[str] = []
        self.ok: bool = True
        self.verify_time_ms: float = 0.0

    def __repr__(self) -> str:
        return (
            f"VerificationResult(blocks={self.blocks_verified}, ok={self.ok}, "
            f"errors={self.errors}, time_ms={self.verify_time_ms:.2f})"
        )


def verify_chain(ledger_path: Path, public_key: Ed25519PublicKey) -> VerificationResult:
    """
    Verify the integrity of the entire forensic ledger.

    For each block:
        1. Recomputes block_hash from (prev_block_hash, merkle_root, timestamp, metadata).
        2. Verifies that stored block_hash matches.
        3. Verifies that prev_block_hash matches the previous block's block_hash.
        4. Verifies the Ed25519 signature over block_hash.

    NOTE: Leaf hash and Merkle root re-derivation from stored alert JSONs
    is the responsibility of the alert archival system (not this function,
    which only verifies the block-level chain). Full alert audit would also
    recompute leaf hashes from the original alert JSONL archive.

    Args:
        ledger_path: Path to the JSONL ledger file.
        public_key: Ed25519 public key to verify signatures.

    Returns:
        VerificationResult with errors list and verify_time_ms.
    """
    import time

    result = VerificationResult()
    start = time.perf_counter()

    if not ledger_path.exists():
        result.errors.append(f"Ledger file not found: {ledger_path}")
        result.ok = False
        result.verify_time_ms = (time.perf_counter() - start) * 1000
        return result

    prev_hash = GENESIS_PREV_HASH
    expected_height = 0

    with open(ledger_path, "rb") as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                result.errors.append(f"Line {lineno}: JSON parse error: {exc}")
                result.ok = False
                continue

            # Height monotonicity check
            height = record.get("block_height", -1)
            if height != expected_height:
                result.errors.append(
                    f"Block {height}: expected height {expected_height}, got {height}"
                )
                result.ok = False

            # Chain linkage check
            stored_prev = record.get("prev_block_hash", "")
            if stored_prev != prev_hash:
                result.errors.append(
                    f"Block {height}: chain break — prev_hash mismatch. "
                    f"Expected {prev_hash[:16]}…, got {stored_prev[:16]}…"
                )
                result.ok = False

            # Recompute block hash (signature NOT in preimage)
            expected_block_hash = compute_block_hash(
                stored_prev,
                record.get("merkle_root", ""),
                record.get("timestamp", ""),
                record.get("metadata", {}),
            )
            stored_block_hash = record.get("block_hash", "")
            if expected_block_hash != stored_block_hash:
                result.errors.append(
                    f"Block {height}: block_hash mismatch (data tampered?). "
                    f"Expected {expected_block_hash[:16]}…"
                )
                result.ok = False

            # Signature verification
            sig_hex = record.get("signature", "")
            try:
                public_key.verify(
                    bytes.fromhex(sig_hex),
                    bytes.fromhex(stored_block_hash),
                )
            except Exception as exc:
                result.errors.append(f"Block {height}: Ed25519 signature invalid: {exc}")
                result.ok = False

            prev_hash = stored_block_hash
            expected_height = height + 1
            result.blocks_verified += 1

    result.verify_time_ms = (time.perf_counter() - start) * 1000
    return result
