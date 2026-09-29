# Model Card: Trinetra T_F_EXFIL (Data Exfiltration)
**Model Version:** 2.0.0-phase2b  
**Model Type:** Calibrated Random Forest Classifier (`RandomForestClassifier` + `IsotonicRegression`)  
**Evaluation Protocol:** StrictGroupSplitter (Zero subnet/IP spatial leakage, 60/20/20 split)  

---

## 1. Intended Use & Threat Coverage
This model detects Data Exfiltration passively from statistical packet/flow aggregations without payload decryption.

## 2. Input Features (5 Dimensions)
- `r_byte_ratio`
- `egress_bytes`
- `ingress_bytes`
- `duration_seconds`
- `egress_rate_bps`

## 3. Performance Metrics (Held-Out Test Split, Cluster Bootstrap 95% CI)
- **Accuracy:** 1.0000
- **Precision:** 1.0000 (95% CI: [1.0000, 1.0000])
- **Recall:** 1.0000 (95% CI: [1.0000, 1.0000])
- **F1 Score:** 1.0000 (95% CI: [1.0000, 1.0000])
- **ROC-AUC:** 1.0000
- **Brier Score (Calibrated):** 0.0000
- **Expected Calibration Error (ECE):** 0.0000

## 4. Anti-Leakage & Safety Verification
- **Group Splitting:** Partitioned strictly across independent /24 subnets.
- **Probe Scenario Leakage:** PASS (Feature space does not trivially predict scenario run IDs).
- **Deserialization Security:** Pre-load SHA-256 hash verified against signed Ed25519 manifest.
