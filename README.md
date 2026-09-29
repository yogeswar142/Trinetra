<div align="center">

# 🛡️ TRINETRA (त्रिनेत्र)
### AI-Based Cyber Threat Detection in Unidirectional IP Traffic
**Smart India Hackathon (SIH) 2026 • Problem Statement ID: 26145 • NTRO**  
*Theme: Blockchain & Cybersecurity*

[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg?logo=python&logoColor=white)](https://python.org)
[![Tests Status](https://img.shields.io/badge/tests-214%20passed-success.svg?logo=pytest&logoColor=white)](tests/)
[![Passive Sensor](https://img.shields.io/badge/ingest-receive--only%20(air--gap)-red.svg?logo=shield&logoColor=white)](tests/test_no_transmit.py)
[![Forensic Ledger](https://img.shields.io/badge/ledger-Ed25519%20%2B%20Merkle%20Tree-orange.svg?logo=blockchaindotcom&logoColor=white)](backend/trinetra/ledger.py)
[![Compliance](https://img.shields.io/badge/compliance-PS%2026145%20Matrix-purple.svg)](ps_compliance_matrix.md)
[![License](https://img.shields.io/badge/license-Proprietary%20--%20SIH%202026-lightgrey.svg)](LICENSE)

<p align="center">
  <a href="#-problem-statement-context-sih-2026">Problem Statement</a> •
  <a href="#-key-architectural-pillars">Architecture</a> •
  <a href="#-threat-vectors-t-a--t-f">Threat Classes</a> •
  <a href="#-cryptographic-forensic-ledger">Forensic Ledger</a> •
  <a href="#-quickstart--verification">Quickstart</a> •
  <a href="#-repository-structure">Repository Layout</a> •
  <a href="#-ps-compliance-matrix">Compliance</a>
</p>

---

</div>

## 📌 Problem Statement Context (SIH 2026)

* **Problem Statement ID:** `26145`
* **Title:** AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
* **Organization:** National Technical Research Organisation (NTRO)
* **Domain / Theme:** Blockchain & Cybersecurity
* **Target Environment:** High-security critical infrastructure, isolated operational enclaves, and SCADA/OT network monitoring where data is extracted passively across an **optical TAP / physical data diode**.

### Physical Reality & Constraints
1. **Constraint C1 — Receive-Only (Passive):** The sensor enclave receives mirrored traffic via an optical photodiode with **no physical transmission line**. It cannot emit TCP resets, ICMP unreachables, or ARP/DNS inquiries.
2. **Constraint C2 — Metadata-Only (Zero Decryption):** Deep inspection must extract metadata from packet headers, TLS handshakes (`JA3`/`JA3S`/`PST`), and QUIC initial headers without attempting payload decryption.
3. **Constraint C3 — Total Air-Gap Isolation:** Zero external telemetry or cloud API calls. Narratives and inferences must operate 100% offline (deterministic templates + local Ollama adapter).
4. **Constraint C4 — Calibrated Heuristics:** Detection thresholds are never hardcoded. All parameters are dynamically loaded from [`config.py`](backend/trinetra/config.py) and marked as initial heuristics for data calibration.
5. **Constraint C5 — Measured Benchmark Discipline:** No fabricated performance claims. All throughput and latency numbers are benchmarked on live hardware.

---

## 🏛️ Key Architectural Pillars

```
 Monitored Network (Full-Duplex Link)
       │ (Tx Fiber)         │ (Rx Fiber)
       └─────────┬──────────┘
                 ▼
        [Optical Splitter / TAP]
                 │ (Combined Rx-Only Light)
                 ▼
        [Physical Hardware Diode]
                 │ (Unidirectional Egress Only)
┌────────────────┼────────────────────────────────────────────────────────┐
│ TRINETRA SENSOR ENCLAVE                                                 │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │ 1. INGEST ENGINE (Zero-Transmission Verified by AST & Runtime)   │   │
│   │    • dpkt PCAP Packet Stream & Live TAP Sniffer                 │   │
│   │    • Binary NetFlow v9 / IPFIX Parser (No JSONL shortcut)       │   │
│   └───────────────────────────────┬─────────────────────────────────┘   │
│                                   ▼                                     │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │ 2. FLOW TABLE & PASSIVE TCP STATE MACHINE                       │   │
│   │    • Mid-stream capture recovery & Out-of-Order de-duplication  │   │
│   │    • Per-Scenario Topology Overrides (INBOUND / OUTBOUND)       │   │
│   └───────────────────────────────┬─────────────────────────────────┘   │
│                                   ▼                                     │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │ 3. FEATURE EXTRACTION & AI INFERENCE PIPELINE                   │   │
│   │    • IAT Jitter, Lomb-Scargle FFT & Autocorrelation             │   │
│   │    • Shannon Entropy, Trigram Markov DGA Scoring                │   │
│   │    • TLS JA3/JA3S Fingerprinting & Packet Size/Timing (PST)     │   │
│   │    • QUIC Long-Header Metadata Parser                           │   │
│   │    • Random Forest + Isolation Forest Multi-class Classifiers   │   │
│   └───────────────────────────────┬─────────────────────────────────┘   │
│                                   ▼                                     │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │ 4. STANDARDIZED ALERT RECORD (NTRO 5-FIELD CONTRACT)           │   │
│   │    • alert_id • timestamp • threat_class • severity • evidence  │   │
│   └───────────────┬─────────────────────────────────┬───────────────┘   │
│                   │                                 │                   │
│                   ▼                                 ▼                   │
│   ┌───────────────────────────────┐ ┌───────────────────────────────┐   │
│   │ 5. CRYPTOGRAPHIC MERKLE LEDGER│ │ 6. LOCAL EXPLAINABILITY (AI)  │   │
│   │    • Append-Only Hash Chain   │ │    • Instant Offline Template │   │
│   │    • Ed25519 Enclave Signature│ │    • Non-blocking Local Ollama│   │
│   │    • Anti-Tamper Verification │ │    • MITRE ATT&CK Mapping     │   │
│   └───────────────────────────────┘ └───────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 🎯 Threat Vectors (T-a – T-f)

Trinetra specifically addresses the six critical cyber threats defined in PS 26145:

| Threat Class | Sub-Vectors | Statistical Evidence | ML Model / Strategy | MITRE ATT&CK |
|---|---|---|---|---|
| **T-a: Volumetric DDoS** | SYN Floods, UDP Amplification, Slowloris | SYN Ratio > 0.80, Source Entropy $H_{\text{src}}$, PPS/BPS spikes | Multi-variate Isolation Forest + Rate Anomaly Classifier | [T1498](https://attack.mitre.org/techniques/T1498/), [T1499](https://attack.mitre.org/techniques/T1499/) |
| **T-b: Botnet C2 Beaconing** | Periodic C2, Cobalt Strike (with jitter) | IAT Coefficient of Variation (CV < 0.22), FFT pulse frequency, Autocorr $R_{xx}(k)$ | Random Forest on IAT time-series dynamics | [T1071.001](https://attack.mitre.org/techniques/T1071/001/), [T1571](https://attack.mitre.org/techniques/T1571/) |
| **T-c: DGA & DNS Tunnelling** | Algorithmic domains, dnscat2, iodine | Query length > 35, Subdomain Shannon Entropy $H > 3.4$, TXT query burst | Character Trigram Language Model + Random Forest DNS classifier | [T1568.002](https://attack.mitre.org/techniques/T1568/002/), [T1071.004](https://attack.mitre.org/techniques/T1071/004/) |
| **T-d: Encrypted Malware** | C2 over TLS, JA3 spoofing | JA3/JA3S hash matching, Packet Size and Timing (PST) sequences | Supervised Classifier trained on PST sequence transitions | [T1573.002](https://attack.mitre.org/techniques/T1573/002/) |
| **T-e: Recon & Port Scanning** | Horizontal sweeps, Vertical scans, SYN scans | Distinct destination port/IP cardinality, SYN:ACK ratio skew | Isolation Forest anomaly detection on connection attempts | [T1595](https://attack.mitre.org/techniques/T1595/), [T1046](https://attack.mitre.org/techniques/T1046/) |
| **T-f: Data Exfiltration** | Large file exfil, Low & slow egress | Egress/Ingress byte ratio ($R_{\text{byte}} > 3.5$), Sustained cumulative volume | Random Forest on directional byte volume | [T1048](https://attack.mitre.org/techniques/T1048/) |

---

## 📊 Empirical Benchmark Results & Datasets Used

Trinetra's performance and accuracy metrics are strictly derived from hardware-stamped benchmarks and real-world cybersecurity datasets:

### Datasets Used for Training & Validation:
1. **CTU-13 Dataset:** Real-world botnet traffic captures parsed via Argus `.binetflow` ingestion engine (`T-b`, `T-c`).
2. **CICIDS2017 Dataset:** Baseline flow volume verification and directional traffic entropy validation.
3. **Scapy Tool-Realistic Attack Generator:** Custom synthetic attack vectors (`T-a` through `T-f`) calibrated to realistic protocol behaviors.

### Measured Hardware Benchmarks (Benchmark v5 Results):
* **Sustained Throughput:** `7,237.26 packets/sec` (`21.51 Mbps sustained`)
* **Service Time Latency (Packet Processing):**
  * `p50 (Median):` **103.96 µs**
  * `p95:` **188.50 µs**
  * `p99:` **243.64 µs**
* **End-to-End Alert Lag (Ingest to Dashboard):**
  * `p50 (Median):` **2.55 ms**
  * `p95:` **3.76 ms**
  * `p99:` **5.10 ms**
* **Memory Footprint & Eviction Bounding:**
  * `Peak RSS:` **351.9 MB** (LRU capacity bounding preserves memory plateau under extreme eviction stress).
* **Test Suite Pass Rate:** **214 / 214 Passed (100%)** including static AST socket safety verification (`test_no_transmit.py`).

---

## ⛓️ Cryptographic Forensic Ledger

Addressing the SIH theme **"Blockchain & Cybersecurity"** and NTRO's requirement for a **tamper-evident forensic chain-of-custody**:

### Architecture & Mathematical Formulation
Trinetra implements a **Hash-Chained, Ed25519-Signed Merkle Ledger** (strictly rejecting token-based hype or external proof-of-work in an air-gapped diode):

1. **Alert Canonicalization:** Every alert `A_k` is serialized to RFC 8785 deterministic canonical JSON.
2. **Leaf Hash Computation:**
   ```text
   leaf_hash_k = SHA-256(canonical_json(A_k))
   ```
3. **Merkle Root Commit:** Pending alerts are compiled into a balanced Merkle tree:
   ```text
   MerkleRoot_N = MerkleTree(leaf_hash_0, leaf_hash_1, ..., leaf_hash_M-1)
   ```
4. **Block Hash Preimage Invariant (Signature NOT in Preimage):**
   ```text
   Block_Hash_N = SHA-256(Prev_Block_Hash_N-1 || MerkleRoot_N || Timestamp || Canonical_Metadata)
   ```
5. **Enclave Signing:**
   ```text
   Signature_N = Ed25519_Sign(PrivateKey_enclave, Block_Hash_N)
   ```

> **Honest Forensic Guarantee:**
> * **Tamper Detection:** Modifying any historical alert breaks the Merkle root and invalidates all descendant block hashes and signatures.
> * **Tail Truncation Mitigation:** The ledger provides `get_head_hash()` to periodically anchor the head hash to a write-once physical medium, printer, or external syslog display.



---

## 🚀 Quickstart & Verification

### 1. Prerequisites
* Python 3.11+
* Docker & Docker Compose (Optional for container deployment)

### 2. Installation
```bash
git clone https://github.com/yogeswar142/Trinetra.git
cd Trinetra
pip install -e ".[dev,benchmark]"
```

### 3. Run Test Suite (214 Tests — Includes No-Transmit Static AST Analysis)
```bash
# Verify all 214 tests including safety, detector, and direction tests
pytest tests/ -v
# or via Makefile
make test
```

### 4. Run Reproducible Benchmark Harness
```bash
python scripts/benchmark_v5.py
# or via Makefile
make benchmark
```

### 5. Generate PCAP Training Data & Retrain Models
```bash
make generate-pcaps   # Generate Scapy tool-realistic attack PCAPs
make train            # Retrain all 6 ML models on PCAP-derived features
```

---

## 🖥️ SOC Dashboard & Terminal UI

Trinetra ships dual production interfaces for real-time threat monitoring and forensic review:

### 1. Next.js 15 Web SOC Dashboard (Production Ready)
A high-performance dark-mode SOC console built with **Next.js 15 (App Router)**, **TypeScript**, **Recharts**, and an interactive 3D WebGL globe (**Cobe**):
```bash
# Start Next.js Frontend (from root directory)
cd frontend
npm run dev
# Open http://localhost:3000 in your browser
```
Features:
- 🟠 **Live Alert Feed** — Real-time streaming of all 6 threat vectors (T-a through T-f) with severity tags.
- 📊 **Threat Distribution Donut Chart** — Live proportional breakdown of incoming attack classes.
- 🌐 **3D Threat Globe** — Interactive WebGL visualization mapping inbound/outbound IP vectors.
- 🔗 **Forensic Ledger Inspector** — Live Merkle root display, block height, and in-browser chain verification.
- 🔍 **Evidence Workbench** — Click any alert to inspect feature values, thresholds, and ML model justifications.

### 2. Rich Terminal CLI Dashboard
An operator CLI dashboard with Sanskrit branding (*"त्रि नेत्र - The Third Eye"*) for headless or SSH sessions:
```bash
trinetra
```

### 3. Docker Air-Gapped Deployment
Enforce physical network isolation using Docker bridge networks:
```bash
docker compose up -d
# Frontend: http://localhost:3000
# Backend API: http://localhost:8000
```
For full bare-metal and containerized deployment instructions, see the **[Production Deployment Guide](docs/deployment_guide.md)**.

---

## 📁 Repository Structure

```text
├── backend/
│   └── trinetra/
│       ├── __init__.py
│       ├── cli.py              # Sanskrit-branded Rich CLI terminal interface
│       ├── config.py           # EnclaveConfig & ScenarioTopology overrides
│       ├── schemas.py          # Pydantic v2 schemas: AlertRecord, FlowEvent, BlockRecord
│       ├── ledger.py           # Hash-chained Ed25519-signed Merkle forensic ledger
│       ├── simulator.py        # Synthetic test scenarios with direction assertions
│       ├── dashboard/          # FastAPI REST & WebSocket streaming server
│       ├── detectors/          # T-a through T-f Machine Learning threat detectors
│       └── features/           # Entropy, Periodicity (FFT), and TLS JA3/JA3S/PST parsers
├── frontend/                   # Next.js 15 + TypeScript SOC Dashboard UI
│   ├── src/app/                # App Router pages (Overview, Alerts, Globe, Ledger, Settings)
│   └── src/components/         # Reusable glassmorphic UI components & charts
├── config/                     # Enclave TOML runtime configurations
├── data/
│   ├── captures/               # Scapy tool-realistic attack PCAPs
│   ├── features/               # Extracted NPZ feature matrices
│   ├── models/                 # Calibrated & signed scikit-learn model artifacts
│   └── signatures/             # Sensor Ed25519 public/private keys
├── docs/
│   ├── deployment_guide.md     # Air-gapped production deployment guide
│   └── model_cards/            # ML feature documentation & train/val split cards
├── ppt/                        # Pitch deck assets & HTML tech-stack graphic
├── scripts/                    # PCAP generation, feature extraction, & benchmark runners
├── tests/                      # 214 passing unit, integration, & AST compliance tests
├── docker-compose.yml          # Enclave-isolated Docker bridge network
├── Makefile                    # Developer targets: test, benchmark, dashboard, train
├── ps_compliance_matrix.md     # Requirement-to-code traceability matrix
├── README.md                   # Project documentation
└── pyproject.toml              # Build metadata & dependency definitions
```

---

## 📋 PS Compliance Matrix

Every single requirement of PS 26145 is explicitly mapped to code locations in [`ps_compliance_matrix.md`](ps_compliance_matrix.md):
* **Ingest & Air-Gap Enforcement:** [`tests/test_no_transmit.py`](tests/test_no_transmit.py)
* **Standardized 5-Field Alert Schema:** [`backend/trinetra/schemas.py`](backend/trinetra/schemas.py)
* **Cryptographic Forensic Chain:** [`backend/trinetra/ledger.py`](backend/trinetra/ledger.py)
* **TLS Metadata & PST Sequences:** [`backend/trinetra/features/tls_parser.py`](backend/trinetra/features/tls_parser.py)

---

## 👥 Contributors & SIH 2026 Team

* **Yogeswar ([@yogeswar142](https://github.com/yogeswar142))** — Lead Architect & Core Developer
* **Anudeep ([@anudeep2006](https://github.com/anudeep2006))** — AI/ML Pipelines & Frontend SOC Engineering
* **Organization:** National Technical Research Organisation (NTRO) / Smart India Hackathon 2026

*Crafted with precision for national security network defense.*

