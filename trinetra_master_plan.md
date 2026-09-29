# Trinetra — Master Plan
**Project:** Trinetra (SIH 2026, PS 26145 — NTRO)  
**Theme:** Blockchain & Cybersecurity  
**Date:** 29 September 2026  
**Status:** Phase 0 — Scaffold  

---

## Executive Summary

Trinetra is a passive, air-gap-safe network threat detection system for unidirectional IP traffic received via an optical TAP / data diode. It detects six threat classes (T-a through T-f), maintains a hash-chained forensic audit ledger, and provides an AI/ML pipeline with interpretable evidence.

**Core constraints:**
- C1: Passive receive-only — the ingest layer MUST NOT open any transmitting socket (automated test enforced).
- C2: No decryption of payload — metadata-only analysis including TLS handshake fields and QUIC long-header fields.
- C3: Fully offline — no external API calls; LLM narration is optional local Ollama only.
- C4: All thresholds in config, never hard-coded; labeled as "initial heuristics — calibrate on data."
- C5: All performance numbers are MEASURED, not assumed. Phase 1 benchmark on actual hardware is mandatory.

---

## Threat Class Mapping (T-a through T-f)

| ID | Threat Class | MITRE ATT&CK | Detection Approach |
|----|---|---|---|
| T-a | Volumetric DDoS (SYN flood, UDP flood, Slowloris) | T1498, T1499 | IF + RF on [pps, bps, syn_ratio, src_entropy] + rules-as-evidence |
| T-b | Botnet C2 Beaconing | T1071.001, T1571 | RF + IF on IAT features (CV, autocorr, FFT) |
| T-c | DGA Domains + DNS Tunnelling | T1568.002, T1071.004 | Char n-gram classifier + RF on DNS flow features |
| T-d | Malware in Encrypted TLS Sessions | T1573.002 | RF on [JA3 blacklist, PST features, cert anomalies] |
| T-e | Port Scanning / Reconnaissance | T1595, T1046 | IF on [dst_port_count, dst_ip_count, SYN ratios] |
| T-f | Data Exfiltration | T1048 | RF on [r_byte, cumulative_out, session features] |

---

## Architecture

```
[Optical TAP / Data Diode]
        │ (packets only flow IN)
        ▼
[Ingest Layer — receive-only, no transmit sockets allowed]
   ├── PCAP ingest (dpkt, live pcap or file replay)
   └── Binary NetFlow v9/IPFIX ingest (python-netflow or struct parser)
        │
        ▼
[Flow Table + Passive TCP State Machine]
   • De-duplicate, handle out-of-order, mid-stream, half-open
   • Per-scenario INTERNAL_NETWORKS for direction labelling
        │
        ▼
[Feature Extraction Workers]
   • IAT / CV / FFT beaconing features
   • DNS entropy / n-gram / query features  
   • TLS: JA3 + JA3S (+ optional JA4 base) + PST + cert fields
   • QUIC: metadata-only (long-header fields, no key derivation)
   • Volume / rate metrics per sliding window
        │
        ▼
[ML Inference Engine]
   • Per threat class: trained RF/GBM/IF/n-gram model
   • Train/val/held-out splits documented
   • Rules produce evidence features fed into models
   • Fallback to rules if model unavailable
        │
        ▼
[Alert Assembler]
   • Pydantic AlertRecord (5 mandatory fields + evidence list)
   • Confidence score + MITRE mapping
        │
        ├── [Forensic Ledger]
        │     Hash-chained, Ed25519-signed
        │     block_hash = SHA-256(prev_hash||merkle_root||timestamp||metadata)
        │     signature  = Ed25519(block_hash)  [NOT in preimage]
        │
        ├── [Narration Engine — async, non-blocking]
        │     Primary: template engine (instant, offline)
        │     Secondary: Ollama qwen2.5 (optional, local)
        │
        └── [SOC Dashboard WebSocket — inside enclave only]
              Live alerts, Merkle root display, threat timeline
```

---

## Phase Plan

### Phase 0 — Scaffold (current)
**Goal:** Repo structure, config, schemas, tests infrastructure, compliance matrix, synthetic simulator design. No detectors.

**Deliverables:**
- `pyproject.toml` / `Makefile` with `make test`, `make lint`, `make benchmark`
- `docker-compose.yml` (dev environment, no external network dependencies)
- `trinetra/config.py` — `EnclaveConfig` with per-scenario `INTERNAL_NETWORKS`
- `trinetra/schemas.py` — `AlertRecord` (5 mandatory fields + evidence), `FlowEvent`, `BlockRecord`
- `trinetra/ledger.py` — correct hash construction (no signature in preimage)
- `trinetra/simulator.py` — synthetic feed design with per-scenario topology config
- `ps_compliance_matrix.md` — maps each PS requirement to code location
- `tests/` — `test_config.py`, `test_schemas.py`, `test_ledger.py`, `test_no_transmit.py`
- `test_no_transmit.py` — automated check that ingest never opens a transmitting socket

**Stop condition:** `make test` passes, Phase 0 report delivered.

### Phase 1 — Ingest + Flow Table + Benchmark
**Goal:** Working PCAP ingest and one real binary flow path (NetFlow v9), passive TCP state machine, benchmark harness with FIRST MEASURED throughput and latency numbers.

**Deliverables:**
- `trinetra/ingest/pcap.py` — dpkt-based PCAP ingest (live + file replay)
- `trinetra/ingest/netflow.py` — NetFlow v9 binary UDP ingest (real binary parser)
- `trinetra/ingest/flow_table.py` — flow table with passive TCP state machine
- `trinetra/benchmark.py` — full pipeline benchmark script
- Benchmark report: flows/sec, Mbps, p50/p95/p99 latency, hardware specs, timestamp
- All passive TCP edge cases (duplicates, out-of-order, mid-stream, half-open) tested with real pcaps

**Stop condition:** `make benchmark` produces JSON report; Phase 1 report delivered.

### Phase 2 — Detectors T-a through T-f (sequential, gated)
**Goal:** Each detector requires: features extracted, ML model trained with documented splits, unit tests, acceptance test against synthetic scenario. One detector at a time.

Each detector gate:
1. Feature extractor unit tests pass.
2. Model training script produces train/val/test metrics (incl. synthetic-data caveat).
3. Acceptance test with synthetic pcap: TP rate and FP rate measured and reported.
4. Direction logic test: correct label on DDoS (INBOUND), exfil (OUTBOUND), scan (LATERAL/OUTBOUND).

### Phase 3 — Dashboard, Narration, End-to-End
**Goal:** SOC dashboard WebSocket, template narration, optional Ollama, end-to-end acceptance tests against all T-a..T-f scenarios.

### Phase 4 — Extras (only after all T-a..T-f pass E2E)
- Threat-chain correlation
- Ollama integration polish
- Polished dashboard UI

---

## JA4 Licensing Decision (Verified)

| Fingerprint | License | Decision |
|---|---|---|
| JA3 / JA3S | BSD-3-Clause (salesforce/ja3 — archived 1 May 2025 [VERIFIED]) | **IMPLEMENT** — self-implement from spec |
| JA4 (base TLS client) | BSD-3-Clause (FoxIO — [VERIFIED 2026-09-29]) | **OPTIONAL EXTRA** — implement if time allows; clearly attributed |
| JA4+ suite (JA4S, JA4H, JA4L, JA4X, etc.) | FoxIO License 1.1 — non-commercial only [VERIFIED 2026-09-29] | **DO NOT IMPLEMENT** |

---

## QUIC Decision

**QUIC Initial key derivation:** DO NOT implement. Deriving QUIC Initial keys (RFC 9001 fixed salt) constitutes controlled decryption of connection setup, violating constraint C2. This choice is documented and must be in judge Q&A notes.

**QUIC metadata extracted (passive, no decryption):** version, connection-ID lengths, packet type (long/short header, Initial/Handshake/0-RTT/1-RTT), packet size/timing sequences.

---

## Forensic Ledger — Honest Judge Answers

**Q: Is this a blockchain?**  
A: No. It is a hash-chained, Ed25519-signed forensic ledger. No distributed consensus, no tokens. Appropriate for a single air-gapped enclave.

**Q: What can it NOT prevent?**  
A: Tail truncation — an attacker with access to the ledger file could delete the last N blocks and the ledger would still verify. Mitigation: periodically output/print the current head block hash to an external channel (printer, syslog, second screen). This is cheap and sufficient for forensic purposes.

**Q: Key storage?**  
A: Ed25519 private key stored in the enclave's protected key directory (filesystem permissions). Not HSM-backed in Phase 0. Production hardening would use a TPM or HSM.

**Q: Trusted timestamps?**  
A: Local system clock. Not RFC 3161 certified. Timestamps should be cross-referenced with network flow timestamps for validation.

**Q: Verify time?**  
A: To be measured in Phase 0 tests and reported in Phase 0 report. No pre-claimed number.

---

## Binary NetFlow / IPFIX Path

Primary for Phase 1: **NetFlow v9** via `python-netflow` library or custom struct parser.  
Secondary option: GoFlow2 sidecar (Apache-2.0) that receives NetFlow/IPFIX/sFlow and emits normalized JSONL to Trinetra.  
JSONL is **internal normalized format only** — external inputs must arrive in binary and be parsed at the ingest boundary.

---

## AI/ML Pipeline Requirements (Non-Negotiable)

Per PS requirement and project decisions:

1. **Each detector (T-a through T-f) requires a trained model** — not purely rule-based thresholds.
2. **Feature documentation:** Every feature fed to every model must be documented with units, extraction method, and statistical motivation.
3. **Train/val/held-out splits:** 60%/20%/20% minimum. Cross-dataset validation (e.g., train on CTU-13, validate on CIC-IDS) required for at least T-b and T-c.
4. **Synthetic-data caveat:** Metrics on synthetic data and real-PCAP data reported separately. Do not use synthetic metrics as the primary claim.
5. **Model artifacts:** Saved models (joblib/pickle) included in repo with version tag. Reproducible training script in `scripts/train/`.
6. **Interpretability:** Every alert must include the top evidence features that triggered the model, not just a binary verdict.

---

## No-Transmit Guarantee

The ingest package (`trinetra/ingest/`) MUST NEVER open transmitting sockets. Enforcement:
- `tests/test_no_transmit.py` uses `ast.parse` + static analysis to detect calls to `socket.connect()`, `socket.sendto()`, `socket.send()`, `socket.sendmsg()` within the ingest module.
- Test fails if any such call exists.
- CI/CD `make test` runs this check on every commit.

---

## PS Compliance Matrix

See `ps_compliance_matrix.md` for the full requirement-to-code mapping.

---

## Direction Labelling — Lab/Synthetic Scenario Rules

In lab and synthetic scenarios, attacker and victim are often both in private IP ranges (e.g., 10.0.0.0/8). Without a per-scenario `INTERNAL_NETWORKS` override, all traffic would be labelled LATERAL, breaking DDoS/exfil/scan detection logic.

**Mandatory requirement:** The simulator's per-scenario config must specify:
```yaml
scenario:
  internal_networks: ["10.0.1.0/24"]   # victim network only
  attacker_networks: ["10.0.2.0/24"]   # NOT in internal; treated as external threat
```

Tests must prove that:
- DDoS scenario: attack traffic is labelled INBOUND (attacker→victim).
- Exfil scenario: data transfer is labelled OUTBOUND (victim→attacker).  
- Scan scenario: probe traffic is labelled correctly per topology.

---

## Open Blocking Questions

_None currently. Next questions will be raised at end of Phase 1 report if needed._
