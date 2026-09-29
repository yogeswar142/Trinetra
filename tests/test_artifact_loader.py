"""
tests/test_artifact_loader.py

Unit and security tests for ML artifact loading:
1. End-to-end happy path: artifact creation, signing, pre-load verification, and load.
2. Tamper test: single-byte corruption in joblib artifact triggers ArtifactChecksumMismatchError BEFORE deserialization.
3. Signature tamper test: modification of manifest JSON triggers ManifestSignatureError.
4. Wrong key test: verification with untrusted public key triggers ManifestSignatureError.
"""
from __future__ import annotations

import json
from pathlib import Path
import joblib
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from trinetra.ml.artifact_loader import (
    ArtifactChecksumMismatchError,
    ManifestSignatureError,
    compute_file_sha256,
    create_and_sign_manifest,
    safe_load_artifact,
    verify_manifest_signature,
)


@pytest.fixture
def keypair() -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub


class TestArtifactLoaderSecurity:
    def test_happy_path_save_sign_and_load(self, tmp_path: Path, keypair) -> None:
        priv_key, pub_key = keypair
        artifact_path = tmp_path / "dummy_detector.joblib"
        manifest_path = tmp_path / "models_manifest.json"

        # Save dummy model payload
        dummy_model = {"model_name": "TestDDoSDetector", "threshold": 0.85, "weights": [0.1, 0.4, 0.5]}
        joblib.dump(dummy_model, artifact_path)

        # Compute hash and sign manifest
        sha256 = compute_file_sha256(artifact_path)
        manifest_data = create_and_sign_manifest(
            artifacts=[{"filename": artifact_path.name, "sha256": sha256, "threat_class": "T_A_DDOS"}],
            private_key=priv_key,
        )
        manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

        # Safely load artifact
        loaded = safe_load_artifact(artifact_path, manifest_path, pub_key)
        assert loaded == dummy_model

    def test_tampered_artifact_bytes_fails_pre_load(self, tmp_path: Path, keypair) -> None:
        priv_key, pub_key = keypair
        artifact_path = tmp_path / "tampered_model.joblib"
        manifest_path = tmp_path / "models_manifest.json"

        dummy_model = {"model_name": "TestBeaconDetector"}
        joblib.dump(dummy_model, artifact_path)

        sha256 = compute_file_sha256(artifact_path)
        manifest_data = create_and_sign_manifest(
            artifacts=[{"filename": artifact_path.name, "sha256": sha256}],
            private_key=priv_key,
        )
        manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

        # TAMPER: Infiltrate 1 byte alteration into the serialized joblib file
        raw_bytes = bytearray(artifact_path.read_bytes())
        raw_bytes[10] ^= 0xFF
        artifact_path.write_bytes(bytes(raw_bytes))

        # Must raise ArtifactChecksumMismatchError BEFORE joblib.load executes
        with pytest.raises(ArtifactChecksumMismatchError, match="Pre-load integrity check FAILED"):
            safe_load_artifact(artifact_path, manifest_path, pub_key)

    def test_tampered_manifest_fails_signature(self, tmp_path: Path, keypair) -> None:
        priv_key, pub_key = keypair
        artifact_path = tmp_path / "model.joblib"
        manifest_path = tmp_path / "models_manifest.json"

        joblib.dump({"key": "val"}, artifact_path)
        sha256 = compute_file_sha256(artifact_path)
        manifest_data = create_and_sign_manifest(
            artifacts=[{"filename": artifact_path.name, "sha256": sha256}],
            private_key=priv_key,
        )

        # TAMPER: Modify manifest body without signing
        manifest_data["artifacts"][0]["sha256"] = "0" * 64
        manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

        with pytest.raises(ManifestSignatureError, match="Cryptographic verification failed"):
            safe_load_artifact(artifact_path, manifest_path, pub_key)

    def test_untrusted_public_key_fails_verification(self, tmp_path: Path, keypair) -> None:
        priv_key, _ = keypair
        attacker_priv = ed25519.Ed25519PrivateKey.generate()
        untrusted_pub = attacker_priv.public_key()

        artifact_path = tmp_path / "model.joblib"
        manifest_path = tmp_path / "models_manifest.json"

        joblib.dump({"key": "val"}, artifact_path)
        manifest_data = create_and_sign_manifest(
            artifacts=[{"filename": artifact_path.name, "sha256": compute_file_sha256(artifact_path)}],
            private_key=priv_key,
        )
        manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

        with pytest.raises(ManifestSignatureError, match="Cryptographic verification failed"):
            safe_load_artifact(artifact_path, manifest_path, untrusted_pub)
