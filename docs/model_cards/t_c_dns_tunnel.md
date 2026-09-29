# Model Card: Trinetra T_C_DNS_TUNNEL (DNS Tunnelling)
**Model Version:** 2.0.0-phase2c  
**Model Type:** Calibrated Random Forest Classifier (`RandomForestClassifier` + `IsotonicRegression`)  
**Evaluation Protocol:** StrictGroupSplitter (Zero subnet/IP spatial leakage, 60/20/20 split)  

---

## 1. Intended Use & Threat Coverage
This model detects DNS Tunnelling passively from statistical packet/flow aggregations without payload decryption.

## 2. Input Features (4 Dimensions)
- `avg_query_length`
- `max_entropy`
- `txt_record_ratio`
- `query_count`

## 3. Performance Metrics (Held-Out Test Split, Cluster Bootstrap 95% CI)

> **⚠ SIMULATOR-ONLY EVALUATION**: Metrics above were measured on synthetic simulator data. F1=1.0 is EXPECTED and is NOT a performance claim. Separate evaluation on CTU-13 Argus binetflow or independent captures is required before any production deployment claim.

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
- **Pickle Risk:** joblib serialization uses Python's pickle protocol. Load ONLY from the signed
  manifest-verified path. Never load untrusted model files — pickle allows arbitrary code execution.

## 5. Data Provenance
Training data: synthetic simulator, fixed seed=47. DNS tunnel patterns are parameterized approximations of dnscat2, Iodine, and dns2tcp traffic statistics from published papers. NOT captured from real tools. Independent dns2tcp/dnscat2 capture evaluation: NOT RUN.
