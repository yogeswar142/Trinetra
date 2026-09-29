"""
scripts/train_and_sign_models.py

End-to-End Training, Calibration, Evaluation, and Cryptographic Signing Pipeline
for Phase 2b + Phase 2c Threat Detectors:
1. Threat T-a: Volumetric DDoS & Resource Starvation
2. Threat T-e: Port Scanning & Reconnaissance
3. Threat T-f: Data Exfiltration
4. Threat T-b: Botnet C2 Beaconing (Phase 2c)
5. Threat T-c/DGA: DGA Domain Generation Algorithms (Phase 2c)
6. Threat T-c/DNS: DNS Tunnelling (Phase 2c)

Anti-Leakage Protocols Enforced:
- StrictGroupSplitter with connected components over /24 subnets and run IDs.
- probe_scenario_leakage validation.
- Isotonic regression fitted strictly on validation split (zero test leakage).
- Cluster bootstrap confidence intervals (95% CI).
- Cryptographic Ed25519 signing into data/models/models_manifest.json.
- Model Cards generated in docs/model_cards/.

EVALUATION DATA PROVENANCE (Phase 2c):
- All training data is SYNTHETIC (simulator-generated).
- F1=1.0 on synthetic data is EXPECTED and is labeled "simulator-only, inflated".
- NO DGArchive data used. DGA domain generators are our own reimplementations
  of published algorithmic papers (CC BY-NC-SA DGArchive terms respected).
- CTU-13 Argus binetflow evaluation is a separate optional step (see evaluation docs).
- Independent captures from capture_runbook.md testbed: NOT YET AVAILABLE.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.isotonic import IsotonicRegression

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend"))

from trinetra.config import EnclaveConfig
from trinetra.ledger import generate_or_load_keypair
from trinetra.ml.artifact_loader import compute_file_sha256, create_and_sign_manifest
from trinetra.ml.evaluation import compute_classification_metrics
from trinetra.ml.group_split import StrictGroupSplitter, probe_scenario_leakage
from trinetra.detectors.dga import extract_dga_features

MODELS_DIR = REPO_ROOT / "data" / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)

MODEL_CARDS_DIR = REPO_ROOT / "docs" / "model_cards"
MODEL_CARDS_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Synthetic Dataset Generators for Phase 2b
# ---------------------------------------------------------------------------
def generate_ddos_dataset() -> tuple[np.ndarray, np.ndarray, list[str]]:
    """Generates T-a dataset: [incoming_pps, syn_to_ack_ratio, src_ip_entropy, udp_amplification_factor]."""
    rng = np.random.RandomState(42)
    n_samples = 600

    X = np.zeros((n_samples, 4), dtype=np.float64)
    y = np.zeros(n_samples, dtype=np.int64)
    subnets: list[str] = []

    subnet_pool = [f"192.168.{i}.0/24" for i in range(1, 11)]

    for i in range(n_samples):
        s_net = subnet_pool[i % len(subnet_pool)]
        subnets.append(s_net)
        is_attack = i % 2 == 1
        y[i] = 1 if is_attack else 0

        if is_attack:
            # DDoS: High PPS, High SYN ratio or high UDP amplification, high entropy
            attack_type = rng.choice(["syn_flood", "udp_amp", "slowloris"])
            if attack_type == "syn_flood":
                X[i, 0] = rng.uniform(300.0, 1500.0)  # incoming_pps
                X[i, 1] = rng.uniform(8.0, 50.0)      # syn_to_ack_ratio
                X[i, 2] = rng.uniform(3.8, 5.5)       # src_ip_entropy
                X[i, 3] = rng.uniform(0.1, 1.0)       # udp_amp
            elif attack_type == "udp_amp":
                X[i, 0] = rng.uniform(100.0, 800.0)
                X[i, 1] = rng.uniform(0.1, 1.0)
                X[i, 2] = rng.uniform(2.5, 4.5)
                X[i, 3] = rng.uniform(10.0, 60.0)
            else:  # Slowloris
                X[i, 0] = rng.uniform(20.0, 80.0)
                X[i, 1] = rng.uniform(3.0, 10.0)
                X[i, 2] = rng.uniform(1.0, 2.5)
                X[i, 3] = rng.uniform(0.1, 1.0)
        else:
            # Benign: Low to normal PPS, 1:1 SYN/ACK, low entropy, low UDP amp
            X[i, 0] = rng.uniform(1.0, 80.0)
            X[i, 1] = rng.uniform(0.8, 1.5)
            X[i, 2] = rng.uniform(0.5, 2.8)
            X[i, 3] = rng.uniform(0.2, 1.8)

    return X, y, subnets


def generate_portscan_dataset() -> tuple[np.ndarray, np.ndarray, list[str]]:
    """Generates T-e dataset: [dst_port_count, dst_ip_count, syn_scan_ratio, packet_count]."""
    rng = np.random.RandomState(43)
    n_samples = 600

    X = np.zeros((n_samples, 4), dtype=np.float64)
    y = np.zeros(n_samples, dtype=np.int64)
    subnets: list[str] = []

    subnet_pool = [f"10.0.{i}.0/24" for i in range(1, 11)]

    for i in range(n_samples):
        s_net = subnet_pool[i % len(subnet_pool)]
        subnets.append(s_net)
        is_attack = i % 2 == 1
        y[i] = 1 if is_attack else 0

        if is_attack:
            scan_type = rng.choice(["vertical", "horizontal", "strobe"])
            if scan_type == "vertical":
                X[i, 0] = rng.randint(25, 200)       # dst_port_count
                X[i, 1] = rng.randint(1, 3)          # dst_ip_count
                X[i, 2] = rng.uniform(0.75, 1.0)     # syn_scan_ratio
                X[i, 3] = rng.randint(30, 250)       # packet_count
            elif scan_type == "horizontal":
                X[i, 0] = rng.randint(1, 4)
                X[i, 1] = rng.randint(15, 80)
                X[i, 2] = rng.uniform(0.70, 1.0)
                X[i, 3] = rng.randint(20, 100)
            else:  # Strobe / sneaky
                X[i, 0] = rng.randint(10, 30)
                X[i, 1] = rng.randint(2, 8)
                X[i, 2] = rng.uniform(0.60, 0.90)
                X[i, 3] = rng.randint(15, 45)
        else:
            # Benign: single host contacting 1-3 ports (e.g. 80, 443, 53)
            X[i, 0] = rng.randint(1, 4)
            X[i, 1] = rng.randint(1, 2)
            X[i, 2] = rng.uniform(0.05, 0.30)
            X[i, 3] = rng.randint(5, 50)

    return X, y, subnets


def generate_exfil_dataset() -> tuple[np.ndarray, np.ndarray, list[str]]:
    """Generates T-f dataset: [r_byte_ratio, egress_bytes, ingress_bytes, duration_seconds, egress_rate_bps]."""
    rng = np.random.RandomState(44)
    n_samples = 600

    X = np.zeros((n_samples, 5), dtype=np.float64)
    y = np.zeros(n_samples, dtype=np.int64)
    subnets: list[str] = []

    subnet_pool = [f"172.16.{i}.0/24" for i in range(1, 11)]

    for i in range(n_samples):
        s_net = subnet_pool[i % len(subnet_pool)]
        subnets.append(s_net)
        is_attack = i % 2 == 1
        y[i] = 1 if is_attack else 0

        if is_attack:
            exfil_type = rng.choice(["bulk", "trickle"])
            if exfil_type == "bulk":
                X[i, 0] = rng.uniform(4.0, 30.0)      # r_byte_ratio
                X[i, 1] = rng.uniform(200_000, 5_000_000)  # egress_bytes
                X[i, 2] = rng.uniform(5_000, 50_000)       # ingress_bytes
                X[i, 3] = rng.uniform(10.0, 120.0)         # duration
                X[i, 4] = (X[i, 1] * 8) / X[i, 3]          # bps
            else:  # Trickle
                X[i, 0] = rng.uniform(2.5, 8.0)
                X[i, 1] = rng.uniform(50_000, 300_000)
                X[i, 2] = rng.uniform(5_000, 30_000)
                X[i, 3] = rng.uniform(180.0, 900.0)
                X[i, 4] = (X[i, 1] * 8) / X[i, 3]
        else:
            # Benign: download dominant (r_byte < 0.5) or symmetric
            X[i, 0] = rng.uniform(0.01, 0.40)
            X[i, 1] = rng.uniform(2_000, 50_000)
            X[i, 2] = rng.uniform(50_000, 2_000_000)
            X[i, 3] = rng.uniform(5.0, 60.0)
            X[i, 4] = (X[i, 1] * 8) / X[i, 3]

    return X, y, subnets


# ---------------------------------------------------------------------------
# Synthetic Dataset Generators for Phase 2c
# ---------------------------------------------------------------------------

def generate_beacon_dataset() -> tuple[np.ndarray, np.ndarray, list[str]]:
    """
    Generates T-b dataset: [iat_mean, iat_cv, iat_autocorr, iat_std, sample_count].

    SIMULATOR-ONLY DATA — labeled as inflated. Not independent evaluation data.
    Simulator-generated beacon patterns; ground truth is determined by generation
    parameters, not observed network captures.
    """
    rng = np.random.RandomState(45)
    n_samples = 600

    X = np.zeros((n_samples, 5), dtype=np.float64)
    y = np.zeros(n_samples, dtype=np.int64)
    subnets: list[str] = []

    subnet_pool = [f"10.10.{i}.0/24" for i in range(1, 11)]

    for i in range(n_samples):
        s_net = subnet_pool[i % len(subnet_pool)]
        subnets.append(s_net)
        is_attack = i % 2 == 1
        y[i] = 1 if is_attack else 0

        if is_attack:
            beacon_type = rng.choice(["rigid", "jittered", "slow_jitter"])
            if beacon_type == "rigid":
                # Rigid C2 heartbeat: very low CV, high autocorr
                iat_mean = rng.uniform(10.0, 300.0)   # 10s – 5min period
                iat_cv   = rng.uniform(0.01, 0.18)    # Very low jitter
                autocorr = rng.uniform(0.85, 1.0)
                iat_std  = iat_mean * iat_cv
            elif beacon_type == "jittered":
                # Cobalt Strike-style jitter: moderate CV, strong autocorr
                iat_mean = rng.uniform(30.0, 600.0)
                iat_cv   = rng.uniform(0.18, 0.42)
                autocorr = rng.uniform(0.70, 0.90)
                iat_std  = iat_mean * iat_cv
            else:  # Slow jitter / long period
                iat_mean = rng.uniform(300.0, 3600.0)
                iat_cv   = rng.uniform(0.05, 0.38)
                autocorr = rng.uniform(0.60, 0.88)
                iat_std  = iat_mean * iat_cv

            sample_count = float(rng.randint(25, 64))  # At least 25 (> min_samples=21)

        else:
            # Benign: high CV (bursty), low autocorr, or very high IAT (idle)
            benign_type = rng.choice(["bursty", "idle", "normal_web"])
            if benign_type == "bursty":
                iat_mean = rng.uniform(0.5, 5.0)
                iat_cv   = rng.uniform(0.80, 3.0)
                autocorr = rng.uniform(0.0, 0.35)
                iat_std  = iat_mean * iat_cv
            elif benign_type == "idle":
                iat_mean = rng.uniform(3600.0, 86400.0)  # Hours between reconnections
                iat_cv   = rng.uniform(0.5, 2.0)
                autocorr = rng.uniform(0.0, 0.4)
                iat_std  = iat_mean * iat_cv
            else:  # Normal web traffic (moderate CV, low autocorr)
                iat_mean = rng.uniform(1.0, 60.0)
                iat_cv   = rng.uniform(0.50, 1.50)
                autocorr = rng.uniform(0.0, 0.50)
                iat_std  = iat_mean * iat_cv

            sample_count = float(rng.randint(21, 50))

        X[i, 0] = iat_mean
        X[i, 1] = iat_cv
        X[i, 2] = autocorr
        X[i, 3] = iat_std
        X[i, 4] = sample_count

    return X, y, subnets


def _generate_dga_domain(rng: np.random.RandomState, length: int) -> str:
    """Generates a random DGA-like domain using pure random character selection."""
    charset = "abcdefghijklmnopqrstuvwxyz0123456789"
    label = "".join(rng.choice(list(charset)) for _ in range(length))
    return f"{label}.evil.com"


def _generate_legit_domain(rng: np.random.RandomState) -> str:
    """Generates a benign-looking domain from a vocabulary of real names."""
    legit_slds = [
        "google", "youtube", "facebook", "microsoft", "apple", "netflix",
        "amazon", "wikipedia", "cloudflare", "linkedin", "twitter", "instagram",
        "github", "yahoo", "reddit", "bing", "office", "live", "adobe", "dropbox",
        "mail", "smtp", "api", "cdn", "static", "images", "assets", "media",
        "login", "auth", "blog", "docs", "help", "support", "news", "shop",
    ]
    tlds = [".com", ".org", ".net", ".io", ".co"]
    sld = rng.choice(legit_slds)
    tld = rng.choice(tlds)
    return f"{sld}{tld}"


def generate_dga_dataset() -> tuple[np.ndarray, np.ndarray, list[str]]:
    """
    Generates T-c/DGA dataset: [domain_length, char_entropy, trigram_perplexity, numeric_ratio, vowel_ratio].

    DGA domains: random character strings (our reimplementation of algorithmic generation,
    NOT from DGArchive — CC BY-NC-SA applies).
    Benign domains: drawn from vocabulary of real SLDs (Tranco-inspired).

    SIMULATOR-ONLY DATA — labeled as inflated.
    """
    rng = np.random.RandomState(46)
    n_samples = 600

    X = np.zeros((n_samples, 5), dtype=np.float64)
    y = np.zeros(n_samples, dtype=np.int64)
    subnets: list[str] = []

    subnet_pool = [f"10.20.{i}.0/24" for i in range(1, 11)]

    for i in range(n_samples):
        s_net = subnet_pool[i % len(subnet_pool)]
        subnets.append(s_net)
        is_attack = i % 2 == 1
        y[i] = 1 if is_attack else 0

        if is_attack:
            dga_type = rng.choice(["pure_random", "hex_random", "digit_heavy"])
            if dga_type == "pure_random":
                length = int(rng.randint(12, 25))
                domain = _generate_dga_domain(rng, length)
            elif dga_type == "hex_random":
                # Hex-alphabet DGA (common in banking trojans)
                charset = "abcdef0123456789"
                length = int(rng.randint(10, 20))
                label = "".join(rng.choice(list(charset)) for _ in range(length))
                domain = f"{label}.malware.net"
            else:  # Digit heavy
                length = int(rng.randint(8, 18))
                # Mix 40-60% digits
                alpha = "abcdefghijklmnopqrstuvwxyz"
                digits = "0123456789"
                label = "".join(
                    rng.choice(list(digits)) if rng.random() < 0.50 else rng.choice(list(alpha))
                    for _ in range(length)
                )
                domain = f"{label}.c2.ru"
        else:
            domain = _generate_legit_domain(rng)

        feats = extract_dga_features(domain)
        X[i] = feats

    return X, y, subnets


def generate_dns_tunnel_dataset() -> tuple[np.ndarray, np.ndarray, list[str]]:
    """
    Generates T-c/DNS dataset: [avg_query_length, max_entropy, txt_record_ratio, query_count].

    DNS tunnel traffic: long subdomain labels with encoded data, high TXT ratio.
    Benign DNS: short, low-entropy, mostly A/AAAA record queries.

    SIMULATOR-ONLY DATA — labeled as inflated.
    """
    rng = np.random.RandomState(47)
    n_samples = 600

    X = np.zeros((n_samples, 4), dtype=np.float64)
    y = np.zeros(n_samples, dtype=np.int64)
    subnets: list[str] = []

    subnet_pool = [f"10.30.{i}.0/24" for i in range(1, 11)]

    for i in range(n_samples):
        s_net = subnet_pool[i % len(subnet_pool)]
        subnets.append(s_net)
        is_attack = i % 2 == 1
        y[i] = 1 if is_attack else 0

        if is_attack:
            tunnel_type = rng.choice(["dnscat2", "iodine", "dns2tcp"])
            if tunnel_type == "dnscat2":
                # dnscat2: very long subdomains, mixed TXT + A queries
                avg_len = rng.uniform(38.0, 80.0)
                max_ent = rng.uniform(3.8, 4.5)
                txt_ratio = rng.uniform(0.15, 0.60)
                q_count = float(rng.randint(20, 200))
            elif tunnel_type == "iodine":
                # Iodine: base32 encoded, very long, mostly NULL/CNAME
                avg_len = rng.uniform(45.0, 120.0)
                max_ent = rng.uniform(3.5, 4.3)
                txt_ratio = rng.uniform(0.05, 0.30)
                q_count = float(rng.randint(50, 500))
            else:  # dns2tcp: TXT queries dominate
                avg_len = rng.uniform(30.0, 60.0)
                max_ent = rng.uniform(3.2, 4.2)
                txt_ratio = rng.uniform(0.55, 0.95)
                q_count = float(rng.randint(10, 100))
        else:
            # Benign DNS: short names, low entropy, mostly A records
            avg_len = rng.uniform(5.0, 28.0)
            max_ent = rng.uniform(1.5, 3.2)
            txt_ratio = rng.uniform(0.0, 0.10)
            q_count = float(rng.randint(1, 50))

        X[i, 0] = avg_len
        X[i, 1] = max_ent
        X[i, 2] = txt_ratio
        X[i, 3] = q_count

    return X, y, subnets


# ---------------------------------------------------------------------------
# Training & Calibration Runner
# ---------------------------------------------------------------------------
def train_and_evaluate_threat(
    threat_name: str,
    threat_code: str,
    X: np.ndarray,
    y: np.ndarray,
    subnets: list[str],
    feature_names: list[str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Trains Random Forest, fits Isotonic Calibration on Val split, and evaluates on Test split."""
    splitter = StrictGroupSplitter(train_ratio=0.60, val_ratio=0.20, test_ratio=0.20, random_seed=42)
    train_idx, val_idx, test_idx = splitter.split(X, subnets)

    # Validate against scenario leakage
    leakage_acc = probe_scenario_leakage(X, subnets, max_allowed_accuracy=0.90)

    X_train, y_train = X[train_idx], y[train_idx]
    X_val, y_val = X[val_idx], y[val_idx]
    X_test, y_test = X[test_idx], y[test_idx]
    test_subnets = [subnets[i] for i in test_idx]

    # Train Random Forest Classifier
    clf = RandomForestClassifier(n_estimators=40, max_depth=6, random_state=42)
    clf.fit(X_train, y_train)

    # Fit Isotonic Calibration STRICTLY on Validation Split
    val_probs = clf.predict_proba(X_val)[:, 1]
    calibrator = IsotonicRegression(out_of_bounds="clip")
    calibrator.fit(val_probs, y_val)

    # Predict on Held-Out Test Split
    test_raw_probs = clf.predict_proba(X_test)[:, 1]
    test_cal_probs = calibrator.predict(test_raw_probs)
    test_preds = (test_cal_probs >= 0.50).astype(int)

    from sklearn.metrics import roc_auc_score
    from trinetra.ml.evaluation import compute_calibration_curve

    # Compute comprehensive evaluation metrics with cluster bootstrap CI
    cls_rep = compute_classification_metrics(
        y_true=y_test,
        y_pred=test_preds,
        groups=test_subnets,
        n_bootstraps=200,
    )
    cal_rep = compute_calibration_curve(
        y_true=y_test,
        y_prob=test_cal_probs,
        n_bins=10,
    )
    roc_auc = float(roc_auc_score(y_test, test_cal_probs)) if len(set(y_test)) > 1 else 1.0

    metrics = {
        "accuracy": float(np.mean(test_preds == y_test)),
        "precision": cls_rep.precision.point_estimate,
        "precision_ci": (cls_rep.precision.ci_lower, cls_rep.precision.ci_upper),
        "recall": cls_rep.recall.point_estimate,
        "recall_ci": (cls_rep.recall.ci_lower, cls_rep.recall.ci_upper),
        "f1": cls_rep.f1.point_estimate,
        "f1_ci": (cls_rep.f1.ci_lower, cls_rep.f1.ci_upper),
        "roc_auc": roc_auc,
        "brier_score": cal_rep.brier_score,
        "expected_calibration_error": cal_rep.expected_calibration_error,
    }

    model_package = {
        "threat_class": threat_code,
        "feature_names": feature_names,
        "model": clf,
        "calibrator": calibrator,
        "threshold": 0.70,
        "evaluation_metrics": metrics,
    }

    return model_package, metrics


def generate_model_card(
    threat_code: str,
    threat_title: str,
    feature_names: list[str],
    metrics: dict[str, Any],
    out_path: Path,
    phase: str = "2b",
    data_note: str = "",
) -> None:
    """Generates standardized Markdown Model Card."""
    disclaimer = (
        "\n\n> **⚠ SIMULATOR-ONLY EVALUATION**: Metrics above were measured on "
        "synthetic simulator data. F1=1.0 is EXPECTED and is NOT a performance "
        "claim. Separate evaluation on CTU-13 Argus binetflow or independent "
        "captures is required before any production deployment claim.\n"
        if phase == "2c" else ""
    )
    data_section = f"\n## 5. Data Provenance\n{data_note}\n" if data_note else ""

    content = f"""# Model Card: Trinetra {threat_code} ({threat_title})
**Model Version:** 2.0.0-phase{phase}  
**Model Type:** Calibrated Random Forest Classifier (`RandomForestClassifier` + `IsotonicRegression`)  
**Evaluation Protocol:** StrictGroupSplitter (Zero subnet/IP spatial leakage, 60/20/20 split)  

---

## 1. Intended Use & Threat Coverage
This model detects {threat_title} passively from statistical packet/flow aggregations without payload decryption.

## 2. Input Features ({len(feature_names)} Dimensions)
{chr(10).join([f"- `{feat}`" for feat in feature_names])}

## 3. Performance Metrics (Held-Out Test Split, Cluster Bootstrap 95% CI){disclaimer}
- **Accuracy:** {metrics['accuracy']:.4f}
- **Precision:** {metrics['precision']:.4f} (95% CI: [{metrics['precision_ci'][0]:.4f}, {metrics['precision_ci'][1]:.4f}])
- **Recall:** {metrics['recall']:.4f} (95% CI: [{metrics['recall_ci'][0]:.4f}, {metrics['recall_ci'][1]:.4f}])
- **F1 Score:** {metrics['f1']:.4f} (95% CI: [{metrics['f1_ci'][0]:.4f}, {metrics['f1_ci'][1]:.4f}])
- **ROC-AUC:** {metrics['roc_auc']:.4f}
- **Brier Score (Calibrated):** {metrics['brier_score']:.4f}
- **Expected Calibration Error (ECE):** {metrics['expected_calibration_error']:.4f}

## 4. Anti-Leakage & Safety Verification
- **Group Splitting:** Partitioned strictly across independent /24 subnets.
- **Probe Scenario Leakage:** PASS (Feature space does not trivially predict scenario run IDs).
- **Deserialization Security:** Pre-load SHA-256 hash verified against signed Ed25519 manifest.
- **Pickle Risk:** joblib serialization uses Python's pickle protocol. Load ONLY from the signed
  manifest-verified path. Never load untrusted model files — pickle allows arbitrary code execution.
{data_section}"""
    out_path.write_text(content, encoding="utf-8")


def main() -> None:
    print("======================================================================")
    print("TRINETRA PHASE 2b + 2c: MODEL TRAINING, CALIBRATION & SIGNING PIPELINE")
    print("======================================================================")

    cfg = EnclaveConfig()
    priv_key, pub_key = generate_or_load_keypair(cfg.ledger_privkey_path, cfg.ledger_pubkey_path)

    artifacts_meta = []

    # 1. Train Threat T-a (DDoS)
    print("\n[1/6] Training Threat T-a (DDoS) Detector...")
    X_ddos, y_ddos, subnets_ddos = generate_ddos_dataset()
    pkg_ddos, met_ddos = train_and_evaluate_threat(
        threat_name="Volumetric DDoS",
        threat_code="T_A_DDOS",
        X=X_ddos,
        y=y_ddos,
        subnets=subnets_ddos,
        feature_names=["incoming_pps", "syn_to_ack_ratio", "src_ip_entropy", "udp_amplification_factor"],
    )
    ddos_path = MODELS_DIR / "t_a_ddos.joblib"
    joblib.dump(pkg_ddos, ddos_path)
    generate_model_card("T_A_DDOS", "Volumetric DDoS", pkg_ddos["feature_names"], met_ddos, MODEL_CARDS_DIR / "t_a_ddos.md")
    print(f"  -> T-a: F1={met_ddos['f1']:.4f} | ROC-AUC={met_ddos['roc_auc']:.4f} | Brier={met_ddos['brier_score']:.4f}")
    artifacts_meta.append({
        "filename": ddos_path.name,
        "threat_class": "T_A_DDOS",
        "sha256": compute_file_sha256(ddos_path),
        "model_type": "RandomForestClassifier",
        "calibrated": True,
    })

    # 2. Train Threat T-e (Port Scan)
    print("\n[2/6] Training Threat T-e (Port Scan) Detector...")
    X_ps, y_ps, subnets_ps = generate_portscan_dataset()
    pkg_ps, met_ps = train_and_evaluate_threat(
        threat_name="Port Scanning & Reconnaissance",
        threat_code="T_E_PORT_SCAN",
        X=X_ps,
        y=y_ps,
        subnets=subnets_ps,
        feature_names=["dst_port_count", "dst_ip_count", "syn_scan_ratio", "packet_count"],
    )
    ps_path = MODELS_DIR / "t_e_portscan.joblib"
    joblib.dump(pkg_ps, ps_path)
    generate_model_card("T_E_PORT_SCAN", "Port Scanning & Reconnaissance", pkg_ps["feature_names"], met_ps, MODEL_CARDS_DIR / "t_e_portscan.md")
    print(f"  -> T-e: F1={met_ps['f1']:.4f} | ROC-AUC={met_ps['roc_auc']:.4f} | Brier={met_ps['brier_score']:.4f}")
    artifacts_meta.append({
        "filename": ps_path.name,
        "threat_class": "T_E_PORT_SCAN",
        "sha256": compute_file_sha256(ps_path),
        "model_type": "RandomForestClassifier",
        "calibrated": True,
    })

    # 3. Train Threat T-f (Data Exfiltration)
    print("\n[3/6] Training Threat T-f (Data Exfiltration) Detector...")
    X_exfil, y_exfil, subnets_exfil = generate_exfil_dataset()
    pkg_exfil, met_exfil = train_and_evaluate_threat(
        threat_name="Data Exfiltration",
        threat_code="T_F_EXFIL",
        X=X_exfil,
        y=y_exfil,
        subnets=subnets_exfil,
        feature_names=["r_byte_ratio", "egress_bytes", "ingress_bytes", "duration_seconds", "egress_rate_bps"],
    )
    exfil_path = MODELS_DIR / "t_f_exfil.joblib"
    joblib.dump(pkg_exfil, exfil_path)
    generate_model_card("T_F_EXFIL", "Data Exfiltration", pkg_exfil["feature_names"], met_exfil, MODEL_CARDS_DIR / "t_f_exfil.md")
    print(f"  -> T-f: F1={met_exfil['f1']:.4f} | ROC-AUC={met_exfil['roc_auc']:.4f} | Brier={met_exfil['brier_score']:.4f}")
    artifacts_meta.append({
        "filename": exfil_path.name,
        "threat_class": "T_F_EXFIL",
        "sha256": compute_file_sha256(exfil_path),
        "model_type": "RandomForestClassifier",
        "calibrated": True,
    })

    # 4. Train Threat T-b (C2 Beaconing)
    print("\n[4/6] Training Threat T-b (C2 Beaconing) Detector...")
    X_beacon, y_beacon, subnets_beacon = generate_beacon_dataset()
    pkg_beacon, met_beacon = train_and_evaluate_threat(
        threat_name="Botnet C2 Beaconing",
        threat_code="T_B_BEACON",
        X=X_beacon,
        y=y_beacon,
        subnets=subnets_beacon,
        feature_names=["iat_mean", "iat_cv", "iat_autocorr", "iat_std", "sample_count"],
    )
    beacon_path = MODELS_DIR / "t_b_beacon.joblib"
    joblib.dump(pkg_beacon, beacon_path)
    generate_model_card(
        "T_B_BEACON", "Botnet C2 Beaconing", pkg_beacon["feature_names"], met_beacon,
        MODEL_CARDS_DIR / "t_b_beacon.md",
        phase="2c",
        data_note=(
            "Training data: synthetic simulator, fixed seed=45. IAT features drawn from "
            "parameterized distributions for rigid beacons (CV<0.18), Cobalt Strike-style "
            "jittered beacons (CV 0.18–0.42), and benign bursty/idle traffic. "
            "NOT from real captures. Separate CTU-13 binetflow evaluation is a future step "
            "(see capture_runbook.md). Independent tool evaluation: NOT RUN."
        ),
    )
    print(f"  -> T-b: F1={met_beacon['f1']:.4f} | ROC-AUC={met_beacon['roc_auc']:.4f} | Brier={met_beacon['brier_score']:.4f}")
    artifacts_meta.append({
        "filename": beacon_path.name,
        "threat_class": "T_B_BEACON",
        "sha256": compute_file_sha256(beacon_path),
        "model_type": "RandomForestClassifier",
        "calibrated": True,
    })

    # 5. Train Threat T-c DGA (Domain Generation Algorithms)
    print("\n[5/6] Training Threat T-c DGA Detector...")
    X_dga, y_dga, subnets_dga = generate_dga_dataset()
    pkg_dga, met_dga = train_and_evaluate_threat(
        threat_name="DGA Domains",
        threat_code="T_C_DGA",
        X=X_dga,
        y=y_dga,
        subnets=subnets_dga,
        feature_names=["domain_length", "char_entropy", "trigram_perplexity", "numeric_ratio", "vowel_ratio"],
    )
    dga_path = MODELS_DIR / "t_c_dga.joblib"
    joblib.dump(pkg_dga, dga_path)
    generate_model_card(
        "T_C_DGA", "DGA Domains", pkg_dga["feature_names"], met_dga,
        MODEL_CARDS_DIR / "t_c_dga.md",
        phase="2c",
        data_note=(
            "Training data: synthetic simulator, fixed seed=46. DGA domains are our own "
            "reimplementation of random-character and hex-alphabet generation algorithms "
            "(NOT from DGArchive — CC BY-NC-SA; we do not use DGArchive data). Benign "
            "domains drawn from Tranco-inspired vocabulary. Tri-gram LM trained on "
            "data/baselines/tranco_top1k.csv (curated 20-row sample). "
            "Independent DGArchive evaluation: NOT RUN (registration-gated)."
        ),
    )
    print(f"  -> T-c DGA: F1={met_dga['f1']:.4f} | ROC-AUC={met_dga['roc_auc']:.4f} | Brier={met_dga['brier_score']:.4f}")
    artifacts_meta.append({
        "filename": dga_path.name,
        "threat_class": "T_C_DGA",
        "sha256": compute_file_sha256(dga_path),
        "model_type": "RandomForestClassifier",
        "calibrated": True,
    })

    # 6. Train Threat T-c DNS Tunnel
    print("\n[6/6] Training Threat T-c DNS Tunnel Detector...")
    X_tunnel, y_tunnel, subnets_tunnel = generate_dns_tunnel_dataset()
    pkg_tunnel, met_tunnel = train_and_evaluate_threat(
        threat_name="DNS Tunnelling",
        threat_code="T_C_DNS_TUNNEL",
        X=X_tunnel,
        y=y_tunnel,
        subnets=subnets_tunnel,
        feature_names=["avg_query_length", "max_entropy", "txt_record_ratio", "query_count"],
    )
    tunnel_path = MODELS_DIR / "t_c_dns_tunnel.joblib"
    joblib.dump(pkg_tunnel, tunnel_path)
    generate_model_card(
        "T_C_DNS_TUNNEL", "DNS Tunnelling", pkg_tunnel["feature_names"], met_tunnel,
        MODEL_CARDS_DIR / "t_c_dns_tunnel.md",
        phase="2c",
        data_note=(
            "Training data: synthetic simulator, fixed seed=47. DNS tunnel patterns "
            "are parameterized approximations of dnscat2, Iodine, and dns2tcp traffic "
            "statistics from published papers. NOT captured from real tools. "
            "Independent dns2tcp/dnscat2 capture evaluation: NOT RUN."
        ),
    )
    print(f"  -> T-c Tunnel: F1={met_tunnel['f1']:.4f} | ROC-AUC={met_tunnel['roc_auc']:.4f} | Brier={met_tunnel['brier_score']:.4f}")
    artifacts_meta.append({
        "filename": tunnel_path.name,
        "threat_class": "T_C_DNS_TUNNEL",
        "sha256": compute_file_sha256(tunnel_path),
        "model_type": "RandomForestClassifier",
        "calibrated": True,
    })

    # 7. Cryptographic Manifest Creation & Signing
    print("\n[7/7] Cryptographically signing model artifacts with enclave Ed25519 key...")
    manifest = create_and_sign_manifest(artifacts=artifacts_meta, private_key=priv_key, version="2.0.0-phase2c")
    manifest_path = MODELS_DIR / "models_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"  -> Signed manifest generated -> {manifest_path}")
    print("======================================================================")
    print("[SUCCESS] All Phase 2b + 2c models trained, calibrated, and cryptographically signed.")
    print("WARNING: All F1 scores measured on SYNTHETIC data and are expected to be inflated.")
    print("         Do NOT cite these as performance claims. See model cards for details.")


if __name__ == "__main__":
    main()
