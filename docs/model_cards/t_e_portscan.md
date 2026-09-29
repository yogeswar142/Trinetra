# Model Card: Trinetra T_E_PORT_SCAN (Port Scanning & Reconnaissance)
**Model Version:** 2.0.0-phase2b  
**Model Type:** Calibrated Random Forest Classifier (`RandomForestClassifier` + `IsotonicRegression`)  
**Evaluation Protocol:** StrictGroupSplitter (Zero subnet/IP spatial leakage, 60/20/20 split)  

---

## 1. Intended Use & Threat Coverage
This model detects Port Scanning & Reconnaissance passively from statistical packet/flow aggregations without payload decryption.

## 2. Input Features (4 Dimensions)
- `dst_port_count`
- `dst_ip_count`
- `syn_scan_ratio`
- `packet_count`

## 3. Performance Metrics (Held-Out Test Split, Cluster Bootstrap 95% CI)
- **Accuracy:** 0.9845
- **Precision:** 0.9875 (95% CI: [0.9364, 1.0000])
- **Recall:** 0.9875 (95% CI: [0.9571, 1.0000])
- **F1 Score:** 0.9875 (95% CI: [0.9587, 1.0000])
- **ROC-AUC:** 0.9982
- **Brier Score (Calibrated):** 0.0150
- **Expected Calibration Error (ECE):** 0.0216

## 4. Anti-Leakage & Safety Verification
- **Group Splitting:** Partitioned strictly across independent /24 subnets.
- **Probe Scenario Leakage:** PASS (Feature space does not trivially predict scenario run IDs).
- **Deserialization Security:** Pre-load SHA-256 hash verified against signed Ed25519 manifest.
- **Pickle Risk:** joblib serialization uses Python's pickle protocol. Load ONLY from the signed
  manifest-verified path. Never load untrusted model files — pickle allows arbitrary code execution.
