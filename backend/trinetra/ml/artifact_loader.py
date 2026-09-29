"""
backend/trinetra/ml/artifact_loader.py

Cryptographically Verified Machine Learning Artifact Loader for Trinetra Enclave.

THREAT MODEL & CODE EXECUTION WARNING:
Python serialization formats (pickle, joblib) allow arbitrary code execution during deserialization
(__reduce__ bytecode injection). In an air-gapped, high-security operational enclave (NTRO), loading
unverified model files represents a critical code execution vector.

DEFENSIVE ARCHITECTURE:
1. Every model artifact is registered in a signed manifest (models_manifest.json).
2. The manifest records the relative file path, canonical SHA-256 checksum, threat class, and model version.
3. The manifest is signed using the enclave's Ed25519 private key (same trust anchor as ForensicLedger).
4. Pre-Load Verification (Zero Deserialization until Proven):
   a. Manifest signature is verified using the enclave's Ed25519 public key.
   b. The target artifact's SHA-256 is computed and compared against the signed manifest.
   c. Deserialization (joblib.load) occurs ONLY if both signature and hash verification succeed.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
import joblib
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class ArtifactSecurityError(Exception):
    """Base exception for artifact security and verification violations."""
    pass


class ManifestSignatureError(ArtifactSecurityError):
    """Raised when the artifact manifest signature fails Ed25519 cryptographic verification."""
    pass


class ArtifactChecksumMismatchError(ArtifactSecurityError):
    """Raised when an artifact's computed SHA-256 does not match the signed manifest."""
    pass


def compute_file_sha256(file_path: Path) -> str:
    """Computes the SHA-256 hex digest of a file on disk."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def canonicalize_manifest_body(manifest: dict[str, Any]) -> bytes:
    """
    Produces deterministic canonical JSON bytes of manifest entries excluding the signature.
    """
    body = {k: v for k, v in manifest.items() if k != "signature_hex"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def create_and_sign_manifest(
    artifacts: list[dict[str, Any]],
    private_key: Ed25519PrivateKey,
    version: str = "1.0.0",
) -> dict[str, Any]:
    """
    Creates a manifest for the given artifacts and signs it with the Ed25519 private key.
    """
    manifest_body = {
        "version": version,
        "artifacts": artifacts,
    }
    canonical_bytes = canonicalize_manifest_body(manifest_body)
    sig = private_key.sign(canonical_bytes)
    manifest_body["signature_hex"] = sig.hex()
    return manifest_body


def verify_manifest_signature(
    manifest: dict[str, Any],
    public_key: Ed25519PublicKey,
) -> None:
    """
    Verifies that the manifest's Ed25519 signature is cryptographically valid.
    Raises ManifestSignatureError on invalid or missing signature.
    """
    sig_hex = manifest.get("signature_hex")
    if not sig_hex:
        raise ManifestSignatureError("Manifest is unsigned (missing 'signature_hex')")

    try:
        sig_bytes = bytes.fromhex(sig_hex)
        canonical_bytes = canonicalize_manifest_body(manifest)
        public_key.verify(sig_bytes, canonical_bytes)
    except (InvalidSignature, ValueError) as err:
        raise ManifestSignatureError(f"Cryptographic verification failed: {err}") from err


def safe_load_artifact(
    artifact_path: Path,
    manifest_path: Path,
    public_key: Ed25519PublicKey,
) -> Any:
    """
    Cryptographically verifies the manifest and artifact checksum BEFORE calling joblib.load.

    Args:
        artifact_path: Path to the .joblib / .pkl model file.
        manifest_path: Path to the models_manifest.json file.
        public_key: Ed25519PublicKey of the signing enclave.

    Returns:
        The deserialized model object.

    Raises:
        ManifestSignatureError: If the manifest signature is invalid or tampered with.
        ArtifactChecksumMismatchError: If the artifact bytes do not match the signed SHA-256.
        FileNotFoundError: If artifact or manifest do not exist.
    """
    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")
    if not artifact_path.exists():
        raise FileNotFoundError(f"Artifact not found: {artifact_path}")

    # 1. Parse manifest
    try:
        manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as err:
        raise ArtifactSecurityError(f"Corrupt manifest JSON: {err}") from err

    # 2. Verify Manifest Signature BEFORE inspecting artifacts
    verify_manifest_signature(manifest_data, public_key)

    # 3. Locate artifact entry in manifest
    target_rel_path = artifact_path.name
    entry: Optional[dict[str, Any]] = None
    for item in manifest_data.get("artifacts", []):
        if item.get("filename") == target_rel_path or item.get("path") == str(artifact_path):
            entry = item
            break

    if not entry:
        raise ArtifactSecurityError(f"Artifact '{target_rel_path}' is not registered in the signed manifest")

    expected_sha256 = entry.get("sha256")
    if not expected_sha256:
        raise ArtifactSecurityError("Manifest entry is missing 'sha256' field")

    # 4. Verify Artifact SHA-256 Hash BEFORE deserialization
    actual_sha256 = compute_file_sha256(artifact_path)
    if actual_sha256.lower() != expected_sha256.lower():
        raise ArtifactChecksumMismatchError(
            f"Pre-load integrity check FAILED for '{artifact_path.name}'. "
            f"Expected: {expected_sha256}, Actual: {actual_sha256}. "
            f"ABORTING DESERIALIZATION TO PREVENT CODE EXECUTION."
        )

    # 5. Deserialization is safe to execute
    return joblib.load(artifact_path)
