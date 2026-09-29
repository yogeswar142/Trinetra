# Model Card: Trinetra T_C_DGA (DGA Domains)
**Model Version:** 2.0.0-phase2c  
**Model Type:** Calibrated Random Forest Classifier (`RandomForestClassifier` + `IsotonicRegression`)  
**Evaluation Protocol:** StrictGroupSplitter (Zero subnet/IP spatial leakage, 60/20/20 split)  

---

## 1. Intended Use & Threat Coverage
This model detects DGA Domains passively from statistical packet/flow aggregations without payload decryption.

## 2. Input Features (5 Dimensions)
- `domain_length`
- `char_entropy`
- `trigram_perplexity`
- `numeric_ratio`
- `vowel_ratio`

## 3. Performance Metrics (Held-Out Test Split, Cluster Bootstrap 95% CI)

> **⚠ SIMULATOR-ONLY EVALUATION**: Metrics above were measured on synthetic simulator data. F1=1.0 is EXPECTED and is NOT a performance claim. Separate evaluation on CTU-13 Argus binetflow or independent captures is required before any production deployment claim.

- **Accuracy:** 1.0000
- **Precision:** 1.0000 (95% CI: [1.0000, 1.0000])
- **Recall:** 1.0000 (95% CI: [1.0000, 1.0000])
- **F1 Score:** 1.0000 (95% CI: [1.0000, 1.0000])
- **ROC-AUC:** 1.0000
- **Brier Score (Calibrated):** 0.0053
- **Expected Calibration Error (ECE):** 0.0146

## 4. Anti-Leakage & Safety Verification
- **Group Splitting:** Partitioned strictly across independent /24 subnets.
- **Probe Scenario Leakage:** PASS (Feature space does not trivially predict scenario run IDs).
- **Deserialization Security:** Pre-load SHA-256 hash verified against signed Ed25519 manifest.
- **Pickle Risk:** joblib serialization uses Python's pickle protocol. Load ONLY from the signed
  manifest-verified path. Never load untrusted model files — pickle allows arbitrary code execution.

## 5. Data Provenance
Training data: synthetic simulator, fixed seed=46. DGA domains are our own reimplementation of random-character and hex-alphabet generation algorithms (NOT from DGArchive — CC BY-NC-SA; we do not use DGArchive data). Benign domains drawn from Tranco-inspired vocabulary. Tri-gram LM trained on data/baselines/tranco_top1k.csv (curated 20-row sample). Independent DGArchive evaluation: NOT RUN (registration-gated).
