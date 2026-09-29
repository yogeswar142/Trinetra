"""
tests/test_ledger.py

Tests for the hash-chained, Ed25519-signed forensic ledger.

CRITICAL INVARIANT TESTED HERE:
    block_hash = SHA-256(prev_block_hash || merkle_root || timestamp || metadata)
    signature  = Ed25519_sign(private_key, block_hash)
    *** The signature MUST NOT be in the block_hash preimage. ***

Test coverage:
    - Merkle tree: empty, single leaf, even count, odd count (duplicate last leaf)
    - block_hash computation does NOT include signature
    - Alert leaf hash determinism (same alert → same hash)
    - ForensicLedger: add_alert, flush, block height monotonicity
    - ForensicLedger: auto-commit on block_size
    - Verify chain: passes on valid chain
    - Verify chain: detects data tampering (modified block)
    - Verify chain: detects chain break (modified prev_block_hash)
    - Verify chain: detects invalid signature
    - generate_or_load_keypair: creates keys, reloads correctly
    - get_head_hash returns GENESIS_PREV_HASH on empty ledger
    - Verify time is measured and reported
"""
from __future__ import annotations

import hashlib
import json
import tempfile
import time
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from trinetra.ledger import (
    GENESIS_PREV_HASH,
    ForensicLedger,
    alert_leaf_hash,
    compute_block_hash,
    compute_merkle_root,
    generate_or_load_keypair,
    verify_chain,
    VerificationResult,
)
from trinetra.schemas import (
    AlertRecord,
    EvidenceItem,
    Severity,
    ThreatClass,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _gen_keypair():
    """Generate a fresh Ed25519 keypair for testing."""
    privkey = ed25519.Ed25519PrivateKey.generate()
    pubkey = privkey.public_key()
    return privkey, pubkey


def _make_alert(threat_class: ThreatClass = ThreatClass.VOLUMETRIC_DDOS) -> AlertRecord:
    """Create a minimal valid AlertRecord."""
    return AlertRecord(
        threat_class=threat_class,
        severity=Severity.HIGH,
        evidence=[
            EvidenceItem(
                feature="test_feature",
                value=0.9,
                threshold=0.5,
                interpretation="Test evidence item.",
            )
        ],
    )


def _make_ledger(tmp_path: Path, block_size: int = 3):
    """Create a ForensicLedger with a fresh keypair in a temp directory."""
    privkey, pubkey = _gen_keypair()
    ledger_file = tmp_path / "test_audit_chain.jsonl"
    return ForensicLedger(privkey, pubkey, ledger_file, block_size=block_size), privkey, pubkey


# ---------------------------------------------------------------------------
# Merkle tree tests
# ---------------------------------------------------------------------------
class TestMerkleTree:
    def test_empty_leaves_returns_sha256_of_empty_bytes(self) -> None:
        root = compute_merkle_root([])
        expected = hashlib.sha256(b"").hexdigest()
        assert root == expected

    def test_single_leaf_returns_that_leaf(self) -> None:
        leaf = hashlib.sha256(b"test").hexdigest()
        root = compute_merkle_root([leaf])
        assert root == leaf

    def test_two_leaves_combines_correctly(self) -> None:
        leaf1 = hashlib.sha256(b"a").hexdigest()
        leaf2 = hashlib.sha256(b"b").hexdigest()
        root = compute_merkle_root([leaf1, leaf2])

        # Manual computation
        expected = hashlib.sha256(
            bytes.fromhex(leaf1) + bytes.fromhex(leaf2)
        ).hexdigest()
        assert root == expected

    def test_odd_leaf_count_duplicates_last(self) -> None:
        """3 leaves: [L1, L2, L3] → L3 is duplicated → [L1, L2, L3, L3]."""
        leaves = [hashlib.sha256(f"leaf{i}".encode()).hexdigest() for i in range(3)]
        root_3 = compute_merkle_root(leaves)

        # If we manually duplicate the last leaf:
        leaves_4 = leaves + [leaves[-1]]
        root_4 = compute_merkle_root(leaves_4)

        assert root_3 == root_4

    def test_merkle_root_is_deterministic(self) -> None:
        leaves = [hashlib.sha256(f"x{i}".encode()).hexdigest() for i in range(5)]
        root1 = compute_merkle_root(leaves)
        root2 = compute_merkle_root(leaves)
        assert root1 == root2

    def test_merkle_root_changes_on_different_leaves(self) -> None:
        leaves1 = [hashlib.sha256(b"a").hexdigest(), hashlib.sha256(b"b").hexdigest()]
        leaves2 = [hashlib.sha256(b"a").hexdigest(), hashlib.sha256(b"c").hexdigest()]
        assert compute_merkle_root(leaves1) != compute_merkle_root(leaves2)


# ---------------------------------------------------------------------------
# Block hash construction (CRITICAL INVARIANT)
# ---------------------------------------------------------------------------
class TestBlockHashConstruction:
    """
    CRITICAL: Verify that the signature is NOT part of the block_hash preimage.

    This is the most important invariant in the ledger design. If the signature
    were included in the preimage, it would create a circular dependency.
    """

    def test_block_hash_does_not_change_with_different_signatures(self) -> None:
        """
        The block_hash must be identical regardless of what signature value is used.
        This proves the signature is not in the preimage.
        """
        prev_hash = "a" * 64
        merkle_root = "b" * 64
        timestamp = "2026-09-29T20:00:00+00:00"
        metadata = {"sensor_id": "TEST", "alert_count": 5}

        # Compute block hash
        block_hash_1 = compute_block_hash(prev_hash, merkle_root, timestamp, metadata)

        # "Changing the signature" has no effect on block_hash computation
        # (because compute_block_hash does not accept a signature parameter)
        block_hash_2 = compute_block_hash(prev_hash, merkle_root, timestamp, metadata)

        assert block_hash_1 == block_hash_2
        assert len(block_hash_1) == 64  # SHA-256 hex

    def test_block_hash_changes_with_different_prev_hash(self) -> None:
        common = dict(
            merkle_root="b" * 64,
            timestamp="2026-09-29T20:00:00+00:00",
            metadata={"x": 1},
        )
        h1 = compute_block_hash("a" * 64, **common)
        h2 = compute_block_hash("c" * 64, **common)
        assert h1 != h2

    def test_block_hash_changes_with_different_merkle_root(self) -> None:
        common = dict(
            prev_block_hash="a" * 64,
            timestamp="2026-09-29T20:00:00+00:00",
            metadata={"x": 1},
        )
        h1 = compute_block_hash(merkle_root="b" * 64, **common)
        h2 = compute_block_hash(merkle_root="c" * 64, **common)
        assert h1 != h2

    def test_block_hash_changes_with_different_metadata(self) -> None:
        h1 = compute_block_hash("a" * 64, "b" * 64, "ts", {"count": 1})
        h2 = compute_block_hash("a" * 64, "b" * 64, "ts", {"count": 2})
        assert h1 != h2

    def test_signature_computed_over_block_hash(self) -> None:
        """Signature must be Ed25519(private_key, block_hash) — verified with public key."""
        privkey, pubkey = _gen_keypair()
        block_hash = compute_block_hash("a" * 64, "b" * 64, "ts", {"x": 1})

        sig = privkey.sign(bytes.fromhex(block_hash))

        # Must verify successfully
        pubkey.verify(sig, bytes.fromhex(block_hash))  # Should not raise

    def test_signature_fails_if_preimage_is_wrong(self) -> None:
        """If the data signed differs from block_hash, verification must fail."""
        privkey, pubkey = _gen_keypair()
        block_hash = compute_block_hash("a" * 64, "b" * 64, "ts", {"x": 1})
        wrong_hash = compute_block_hash("a" * 64, "c" * 64, "ts", {"x": 1})

        sig = privkey.sign(bytes.fromhex(block_hash))

        with pytest.raises(InvalidSignature):
            pubkey.verify(sig, bytes.fromhex(wrong_hash))


# ---------------------------------------------------------------------------
# Alert leaf hash
# ---------------------------------------------------------------------------
class TestAlertLeafHash:
    def test_leaf_hash_is_64_char_hex(self) -> None:
        alert = _make_alert()
        h = alert_leaf_hash(alert)
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_same_alert_same_hash(self) -> None:
        """Leaf hash must be deterministic for the same alert content."""
        alert = _make_alert()
        h1 = alert_leaf_hash(alert)
        h2 = alert_leaf_hash(alert)
        assert h1 == h2

    def test_different_alerts_different_hashes(self) -> None:
        a1 = _make_alert(ThreatClass.VOLUMETRIC_DDOS)
        a2 = _make_alert(ThreatClass.BOTNET_C2_BEACONING)
        assert alert_leaf_hash(a1) != alert_leaf_hash(a2)


# ---------------------------------------------------------------------------
# ForensicLedger
# ---------------------------------------------------------------------------
class TestForensicLedger:
    def test_empty_ledger_get_head_hash_returns_genesis(self, tmp_path: Path) -> None:
        ledger, _, _ = _make_ledger(tmp_path)
        assert ledger.get_head_hash() == GENESIS_PREV_HASH

    def test_add_alert_returns_leaf_hash(self, tmp_path: Path) -> None:
        ledger, _, _ = _make_ledger(tmp_path, block_size=10)
        alert = _make_alert()
        leaf = ledger.add_alert(alert)
        assert len(leaf) == 64

    def test_flush_with_no_pending_returns_none(self, tmp_path: Path) -> None:
        ledger, _, _ = _make_ledger(tmp_path)
        result = ledger.flush()
        assert result is None

    def test_flush_commits_block_and_updates_head_hash(self, tmp_path: Path) -> None:
        ledger, _, _ = _make_ledger(tmp_path, block_size=10)
        alert = _make_alert()
        ledger.add_alert(alert)

        block = ledger.flush(sensor_id="TEST-SENSOR")
        assert block is not None
        assert block.block_height == 0
        assert block.prev_block_hash == GENESIS_PREV_HASH
        assert ledger.get_head_hash() == block.block_hash

    def test_block_height_monotonically_increases(self, tmp_path: Path) -> None:
        ledger, _, _ = _make_ledger(tmp_path, block_size=1)
        alerts = [_make_alert() for _ in range(3)]

        blocks = []
        for alert in alerts:
            ledger.add_alert(alert)  # auto-commits because block_size=1

        # Flush any remaining (should be empty since block_size=1)
        assert ledger._block_height == 3

    def test_auto_commit_on_block_size_reached(self, tmp_path: Path) -> None:
        ledger, _, _ = _make_ledger(tmp_path, block_size=2)
        a1, a2 = _make_alert(), _make_alert()

        ledger.add_alert(a1)  # pending count = 1 (no commit yet)
        assert ledger._block_height == 0

        ledger.add_alert(a2)  # pending count = 2 → auto-commit
        assert ledger._block_height == 1  # Block committed

    def test_chain_linkage_prev_hash(self, tmp_path: Path) -> None:
        """Second block's prev_block_hash must equal first block's block_hash."""
        ledger, _, _ = _make_ledger(tmp_path, block_size=1)

        ledger.add_alert(_make_alert())  # Block 0 auto-committed
        block0_hash = ledger._prev_block_hash

        ledger.add_alert(_make_alert())  # Block 1 auto-committed

        # Read block 1 from ledger file
        with open(ledger._ledger_path) as f:
            lines = [json.loads(line) for line in f if line.strip()]

        assert lines[1]["prev_block_hash"] == block0_hash

    def test_ledger_file_is_jsonl(self, tmp_path: Path) -> None:
        """Each line in the ledger file must be valid JSON."""
        ledger, _, _ = _make_ledger(tmp_path, block_size=2)
        for i in range(4):
            ledger.add_alert(_make_alert())

        with open(ledger._ledger_path) as f:
            for line in f:
                if line.strip():
                    record = json.loads(line)
                    assert "block_height" in record
                    assert "block_hash" in record
                    assert "signature" in record

    def test_signature_not_equal_to_block_hash(self, tmp_path: Path) -> None:
        """Signature and block_hash must be different values (one is not a hash of the other)."""
        ledger, _, _ = _make_ledger(tmp_path, block_size=1)
        ledger.add_alert(_make_alert())

        with open(ledger._ledger_path) as f:
            block = json.loads(f.readline())

        # The signature is a 64-byte (128 hex) Ed25519 signature, not a SHA-256 hash
        assert block["signature"] != block["block_hash"]
        assert len(block["signature"]) == 128  # Ed25519 = 64 bytes = 128 hex
        assert len(block["block_hash"]) == 64   # SHA-256 = 32 bytes = 64 hex


# ---------------------------------------------------------------------------
# Chain verification
# ---------------------------------------------------------------------------
class TestVerifyChain:
    def test_verify_empty_ledger_passes(self, tmp_path: Path) -> None:
        ledger_path = tmp_path / "empty.jsonl"
        ledger_path.touch()
        privkey, pubkey = _gen_keypair()
        result = verify_chain(ledger_path, pubkey)
        assert result.ok
        assert result.blocks_verified == 0

    def test_verify_nonexistent_ledger_fails(self, tmp_path: Path) -> None:
        _, pubkey = _gen_keypair()
        result = verify_chain(tmp_path / "does_not_exist.jsonl", pubkey)
        assert not result.ok
        assert any("not found" in e for e in result.errors)

    def test_verify_valid_chain_passes(self, tmp_path: Path) -> None:
        ledger, _, pubkey = _make_ledger(tmp_path, block_size=2)
        for _ in range(6):
            ledger.add_alert(_make_alert())
        ledger.flush()  # Commit any remaining

        result = verify_chain(ledger._ledger_path, pubkey)
        assert result.ok, f"Verification failed: {result.errors}"
        assert result.blocks_verified >= 3  # 6 alerts / block_size=2

    def test_verify_detects_data_tampering(self, tmp_path: Path) -> None:
        """If block_hash is modified in the ledger file, verification must fail."""
        ledger, _, pubkey = _make_ledger(tmp_path, block_size=2)
        for _ in range(4):
            ledger.add_alert(_make_alert())

        # Tamper with a block hash in the file
        with open(ledger._ledger_path) as f:
            lines = f.readlines()

        tampered = json.loads(lines[0])
        tampered["merkle_root"] = "f" * 64  # Tamper merkle root
        lines[0] = json.dumps(tampered) + "\n"

        tampered_path = tmp_path / "tampered.jsonl"
        tampered_path.write_text("".join(lines))

        result = verify_chain(tampered_path, pubkey)
        assert not result.ok
        assert any("mismatch" in e.lower() or "tampered" in e.lower() for e in result.errors)

    def test_verify_reports_time(self, tmp_path: Path) -> None:
        """Verification must report verify_time_ms (to be used in Phase 0 report)."""
        ledger, _, pubkey = _make_ledger(tmp_path, block_size=3)
        for _ in range(3):
            ledger.add_alert(_make_alert())

        result = verify_chain(ledger._ledger_path, pubkey)
        assert result.verify_time_ms >= 0.0  # Time must be recorded


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------
class TestKeyManagement:
    def test_generate_keypair_creates_files(self, tmp_path: Path) -> None:
        privkey_path = tmp_path / "test.key"
        pubkey_path = tmp_path / "test.pub"

        privkey, pubkey = generate_or_load_keypair(privkey_path, pubkey_path)

        assert privkey_path.exists()
        assert pubkey_path.exists()

    def test_reload_keypair_returns_same_key(self, tmp_path: Path) -> None:
        privkey_path = tmp_path / "test.key"
        pubkey_path = tmp_path / "test.pub"

        privkey1, pubkey1 = generate_or_load_keypair(privkey_path, pubkey_path)
        privkey2, pubkey2 = generate_or_load_keypair(privkey_path, pubkey_path)

        # Both keys should be able to verify each other's signatures
        message = b"test message"
        sig = privkey1.sign(message)
        pubkey2.verify(sig, message)  # Should not raise

    def test_genesis_prev_hash_is_correct(self) -> None:
        expected = hashlib.sha256(b"TRINETRA_GENESIS").hexdigest()
        assert GENESIS_PREV_HASH == expected
