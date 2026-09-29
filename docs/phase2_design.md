# Trinetra — Phase 2 Architecture & Machine Learning Design Specification
**Document ID:** TRIN-DOC-PH2-DESIGN  
**Version:** 1.0.0-PROPOSED  
**Date:** 29 September 2026  
**Status:** DRAFT — PENDING USER APPROVAL  
**Author:** Trinetra Core Engineering Team  

---

> [!IMPORTANT]
> **PHASE 1.5 CONSTRAINTS OBSERVED:**  
> This document specifies the complete theoretical and practical architecture for Phase 2.  
> **NO detector or ML implementation code is included in this phase.**  
> Implementation begins only upon explicit user approval ("CONTINUE TO PHASE 2").

---

## 1. System Overview & Ingest-to-Detector Interface

In Phase 1 and 1.5, Trinetra established:
1. **Passive Ingest Engine:** Dual-mode streaming via `PcapIngest` (dpkt) and RFC 3954 `NetFlowV9Parser`.
2. **Deterministic Stateful Flow Table:** `FlowTable` maintaining bidirectional 5-tuple sessions (`FlowRecord`) driven by packet timestamps with bounded LRU eviction and zero transmit capability.
3. **Passive TCP State Machine:** `PassiveTcpTracker` handling duplicates, out-of-order sequences, mid-stream discovery, and asymmetric link loss.
4. **Forensic Cryptographic Ledger:** Tamper-evident, hash-chained Merkle ledger generating Ed25519 signatures and verification proofs.

```
       +-------------------------------------------------------+
       |             Passive Optical TAP / Data Diode          |
       +-------------------------------------------------------+
                                  |
                                  v
       +-------------------------------------------------------+
       |               Trinetra Ingest Engine                  |
       |     - PcapIngest (dpkt)    - NetFlowV9Parser (RFC 3954)
       +-------------------------------------------------------+
                                  |
                                  v
       +-------------------------------------------------------+
       |           Deterministic Stateful Flow Table           |
       |  - Bidirectional Key       - Passive TCP State Tracker|
       |  - Scenario Topology       - Timestamp-driven Expiry  |
       |  - Slots-backed Events     - Bounded Capacity Cache   |
       +-------------------------------------------------------+
                                  |
            [Active Flow Updates & Expired Session Records]
                                  |
                                  v
       +=======================================================+
       |               PHASE 2 DETECTION PIPELINE              |
       |                                                       |
       |  [Feature Extractor] ---> [Interpretable Evidence]    |
       |          |                              |             |
       |          v                              v             |
       |   [Trained ML Model]  ---> [Alert Generation Engine]  |
       |   (Scikit-Learn/LGBM)        (NTRO Pydantic Schema)   |
       +=======================================================+
                                  |
                                  v
       +-------------------------------------------------------+
       |            Offline Forensic Merkle Ledger             |
       |       - SHA-256 Leaves        - Ed25519 Signatures    |
       +-------------------------------------------------------+
```

---

## 2. Threat Class Specifications (T-a through T-f)

Each threat detector is architected with a dual layer:
1. **Interpretable Statistical Evidence Layer:** Human-verifiable features with calibrated alert-time thresholds (`EvidenceItem`).
2. **Trained ML Inference Layer:** Non-linear decision models (Random Forest, Isolation Forest, LightGBM) producing continuous confidence scores.
3. **Evidence vs. Score Rule:** Alerts require both an ML score meeting the classification threshold AND at least one primary `EvidenceItem` explaining *why* the traffic is anomalous.

---

### T-a: Volumetric DDoS & Resource Starvation
*Covers: SYN Flood, UDP Reflection/Amplification, Slowloris HTTP starvation.*

- **Unit of Prediction:** Destination IP entity per sliding window (aggregating all converging inbound flows).
- **Window Sizes:** 
  - Micro-window: 1.0 second (instantaneous volumetric spike detection).
  - Standard window: 10.0 seconds (ratio and entropy evaluation).
  - Macro-window: 60.0 seconds (slow connection accumulation).
- **Interpretable Evidence Features:**
  1. `syn_to_ack_ratio` ($R_{syn} = \frac{N_{SYN}}{N_{ACK} + 1}$): Ratio of inbound connection requests to completed acknowledgments. Normal: ~1.0; SYN flood: > 8.0.
  2. `src_ip_entropy` ($H_{src} = -\sum p_i \log_2 p_i$): Dispersion of source IPs converging on the victim. High entropy (> 4.5) indicates distributed spoofing.
  3. `incoming_pps` ($P_{in}$): Inbound packets per second targeting the destination IP.
  4. `udp_amplification_factor` ($A_{udp} = \frac{Bytes_{in}}{Bytes_{out} + 1}$ from standard UDP ports 53/123/1900/11211).
  5. `slow_connection_ratio`: Fraction of active sessions sending < 100 bytes over > 30 seconds with pending headers (Slowloris).
- **Model Architecture:** 
  - Anomaly Baseline: Isolation Forest trained on benign traffic rates.
  - Supervised Classifier: LightGBM / Random Forest Classifier (binary: Normal vs DDoS).
- **Evidence vs Score:** Model outputs confidence $P(DDoS) \in [0, 1]$. If $P \ge 0.85$, alert emits with top 2 anomalous features as `EvidenceItem`.
- **Label Sources:** 
  - Positives: CIC-DDoS2019, CTU-13 Scenario 10 (IRC DDoS), real Slowloris captures.
  - Negatives: iperf3 multi-stream benign baseline, high-throughput file transfers.

---

### T-b: Botnet C2 Beaconing
*Covers: Periodic heartbeat signals, persistent callback channels, jittered beacons.*

- **Unit of Prediction:** Host-pair session cluster (`src_ip` $\rightarrow$ `dst_ip` / `dst_port`) with $\ge 20$ observed inter-arrival intervals.
- **Window Sizes:** Rolling 15-minute, 1-hour, and 6-hour windows.
- **Interpretable Evidence Features:**
  1. `iat_coefficient_of_variation` ($CV = \frac{\sigma_{IAT}}{\mu_{IAT}}$): Ratio of standard deviation to mean of inter-arrival times. Rigid periodicity: $CV < 0.20$; jittered C2: $CV \in [0.20, 0.45]$.
  2. `iat_autocorrelation_lag1` ($r_1$): Autocorrelation of interval sequence at lag 1. High values (> 0.7) reveal cyclical scheduled callbacks.
  3. `spectral_power_ratio`: Maximum power spectral density peak from FFT divided by total spectral energy.
  4. `payload_size_stddev`: Standard deviation of beacon request and response byte sizes. Low deviation (< 30 bytes) signifies fixed heartbeat frames.
  5. `session_count_per_hour`: Cumulative callback attempts across the observation window.
- **Model Architecture:** Random Forest Classifier trained on interval distribution statistics + Isolation Forest for novel callback schedules.
- **Evidence vs Score:** Score indicates beaconing likelihood; `EvidenceItem` cites exact measured $CV$, median interval seconds, and spectral peak frequency.
- **Label Sources:**
  - Positives: CTU-13 botnet captures (Nerbot, Rbot, Virut), Bishop Fox Sliver C2 framework traffic with 0%, 25%, and 50% configured jitter.
  - Negatives: NTP client synchronization, browser long-polling, background email IMAP IDLE, benign push notifications.

---

### T-c: Domain Generation Algorithms (DGA) & DNS Tunnelling
*Covers: Malware DGA domain resolution, encoded exfiltration, and C2 via DNS records.*

#### Sub-Class 1: DGA Domains
- **Unit of Prediction:** Individual fully qualified domain name (FQDN) query string.
- **Window Size:** Instantaneous per unique DNS request.
- **Interpretable Evidence Features:**
  1. `domain_shannon_entropy`: Character-level Shannon entropy of the domain 2nd-level label.
  2. `vowel_consonant_ratio`: Extreme deviations from natural language linguistic distributions.
  3. `char_ngram_perplexity`: Negative log-likelihood against a benign character tri-gram language model trained on Tranco Top 1M.
  4. `numeric_ratio`: Proportion of digits in the domain name.
  5. `domain_length`: Length of the 2nd-level domain string.
- **Model Architecture:** Character-level Random Forest on extracted linguistic features + Char n-gram frequency classifier.
- **Label Sources:**
  - Positives: DGArchive (Fraunhofer FKIE CC BY-NC-SA 3.0) + built-in deterministic algorithmic generators (Conficker, Cryptolocker, Bamital, Doxrem).
  - Negatives: Tranco Top 1M domains, internal enclave reverse-DNS infrastructure.

#### Sub-Class 2: DNS Tunnelling
- **Unit of Prediction:** Aggregated client queries per parent domain (`client_ip` $\rightarrow$ `*.domain.tld`) per 5-minute window.
- **Window Size:** 5-minute rolling window.
- **Interpretable Evidence Features:**
  1. `max_query_length`: Longest sub-label length observed (> 35 characters strongly anomalous).
  2. `query_volume_rate`: Queries dispatched to specific authoritative nameserver per minute.
  3. `record_type_entropy`: Skewed distribution toward TXT, NULL, CNAME, or EDNS0 record queries.
  4. `subdomain_entropy_mean`: Mean Shannon entropy of dynamic query prefixes.
  5. `nxdomain_ratio`: Proportion of non-existent domain response codes returned.
- **Model Architecture:** LightGBM classifier on domain aggregation statistics.
- **Label Sources:** dnscat2 (TXT, CNAME, MX modes), iodine (DNS IP-over-DNS tunnel), benign enterprise DNS lookups.

---

### T-d: Malware in Encrypted Sessions (TLS & QUIC)
*Covers: Malicious TLS handshakes, Cobalt Strike beacons, C2 frameworks using HTTPS, QUIC metadata.*

- **Unit of Prediction:** Single TLS/QUIC flow session (handshake + first 20 data packets).
- **Window Size:** Per-flow duration (up to initial 20 packets or 60 seconds).
- **Interpretable Evidence Features:**
  1. `ja3_threat_intel_match`: Exact match against abuse.ch SSLBL malicious JA3 database (binary flag).
  2. `ja3s_threat_intel_match`: Exact match against known server response hashes.
  3. `pst_sequence`: Packet Size and Timing vector of first 10 data packets ($[\pm L_1, \Delta t_1, \dots, \pm L_{10}, \Delta t_{10}]$).
  4. `sni_tranco_rank`: Server Name Indication lookup against Tranco Top 1M (unranked/absent SNI is high risk).
  5. `cert_validity_anomaly`: Self-signed certificate, expired validity, or atypical subject CN.
  6. `quic_version_negotiation`: Long-header version fields and destination connection ID length variations.
- **Constraint C2 Compliance:**
  - **Zero Payload Decryption:** Analysis is strictly restricted to plaintext ClientHello/ServerHello fields and unencrypted transport metadata.
  - **Zero Key Derivation:** QUIC Initial keys are **explicitly not derived**, preserving strict optical diode passive receive guarantees.
- **Model Architecture:** Two-stage detector:
  1. Threat Intel Fast Path: Instant O(1) hash table lookup against verified SSLBL signatures.
  2. Machine Learning Fallback: Random Forest trained on normalized PST sequence vectors.
- **Label Sources:** Malware-traffic-analysis.net (Cobalt Strike, Qakbot, Ursnif), CTU-13 TLS botnets, benign Mozilla/Chrome browsing traces.

---

### T-e: Port Scanning & Reconnaissance
*Covers: Horizontal IP sweeps, vertical port scans, strobe scans, slow TCP SYN probes.*

- **Unit of Prediction:** Source IP address per sliding window.
- **Window Sizes:** 10-second fast window, 60-second standard window, 300-second slow-scan window.
- **Interpretable Evidence Features:**
  1. `distinct_dst_ports_contacted`: Number of distinct destination ports probed on a single host.
  2. `distinct_dst_ips_contacted`: Number of distinct internal hosts contacted.
  3. `unanswered_syn_ratio`: Fraction of SYN packets sent without receiving an ACK/SYN-ACK response.
  4. `scan_rate_hz`: Probe packets per second.
  5. `port_entropy`: Uniformity of contacted ports across the 0–65535 range.
- **Model Architecture:** Streaming Isolation Forest + adaptive heuristic thresholds.
- **Label Sources:** CIC-IDS2017 PortScan subset, nmap scans (`-sS`, `-sT`, `-sN`, `-sF`, `-sX`), benign network monitoring tools.

---

### T-f: Data Exfiltration
*Covers: Large outbound data transfers, asymmetric session uploads, slow trickle exfiltration.*

- **Unit of Prediction:** Directional host pair (`src_ip` $\rightarrow$ `dst_ip`) per 15-minute window.
- **Window Sizes:** 5-minute micro, 15-minute standard, 1-hour macro window.
- **Interpretable Evidence Features:**
  1. `r_byte_ratio` ($R_{byte} = \frac{Bytes_{out}}{Bytes_{in} + 1}$): Ratio of egress bytes to ingress bytes. High $R_{byte} > 3.0$ on protocols that are typically download-heavy (HTTP/HTTPS) indicates upload exfiltration.
  2. `cumulative_egress_bytes`: Absolute payload volume transferred outward.
  3. `transfer_duration_seconds`: Total active transfer time.
  4. `egress_burstiness`: Peak 1-second transfer rate divided by mean transfer rate.
  5. `off_hours_flag`: Contextual indicator if transfer occurs outside standard operational schedules.
- **Model Architecture:** Random Forest on session volume/ratio statistics + Local Outlier Factor (LOF).
- **Label Sources:** CIC-IDS2017 Exfiltration, scripted HTTPS/SFTP uploads, benign Google Drive/Dropbox uploads, normal internal downloads.

---

## 3. Evaluation Protocol & Anti-Leakage Guardrails

### 3.1 Strict Group-Split Evaluation
To prevent optimistic metric inflation and spatial/temporal data leakage:
- **No IP/Subnet Leakage:** All splits MUST use `GroupKFold` or `GroupShuffleSplit` partitioned strictly by `/24` subnet or scenario run ID.
- Under NO circumstances may flows originating from or targeting the same host IP appear in both training and test sets.
- **Temporal Splitting:** In multi-hour traces, train on the first 60% of temporal execution, validate on the next 20%, and hold out the final 20% for test evaluation.

### 3.2 Cross-Dataset Generalization Check
Every supervised model trained on one dataset (e.g. CIC-IDS2017) MUST undergo cross-dataset evaluation against a completely distinct real-world dataset (e.g. CTU-13 or malware-traffic-analysis.net). Performance drops must be reported honestly.

### 3.3 Independent Held-Out Generators & Evasion Stress Testing
For each threat category, detectors will be evaluated against attack generators completely unseen during training:

| Threat | Unseen Held-Out Generator | Evasion Technique Tested |
|---|---|---|
| **T-a (DDoS)** | TRex stateful generator | Mixed protocol flooding with randomized inter-arrival jitter |
| **T-b (Beaconing)** | Sliver C2 with 50% random jitter | Variable interval heartbeat deliberately breaking fixed periodicity |
| **T-c (DGA/Tunnel)** | Suppobox / Dictionary-DGA & Iodine base32 | Meaningful English dictionary word concatenation; high-density base32 DNS queries |
| **T-d (Encrypted TLS)** | Custom uTLS client | JA3 fingerprint randomized to match Google Chrome browser while executing C2 |
| **T-e (Scanning)** | Nmap slow scan (`-T1` Sneaky) | 1 probe every 15–30 seconds to bypass fast sliding windows |
| **T-f (Exfiltration)** | Encrypted trickle script | Outbound upload throttled to < 20 KB/min to evade burst detection |

### 3.4 Hard Negative Evaluation (False Positive Suppression)
Models must maintain low false alarm rates when evaluated against challenging benign traffic:
1. **Video Conferencing / WebRTC / YouTube Uploads:** High $R_{byte}$ and massive continuous outbound byte flow.
2. **NTP / Cloud Time Sync:** Extremely low IAT CV (regular periodic intervals).
3. **Authorized Vulnerability Scanners / Nessus:** Authorized high-rate internal sweeps.
4. **Legitimate CDN Encrypted Payloads:** High-entropy video streaming chunks.
5. **Breaking News Flash Crowds:** Sudden volumetric surge of incoming connections to internal servers.

### 3.5 Calibrated Reporting Metrics
- **Bootstrap 95% Confidence Intervals:** Every reported precision, recall, and F1 score must include bootstrap CI bounds (1,000 iterations).
- **False Alerts per Hour (FAR/hour):** Calculated across at least 12 hours of benign enterprise traffic baseline.
- **Time-to-Detect (TTD):** Measured from the arrival of the first attack packet at the sensor until the alert is committed to the ledger.

---

## 4. Phase 2 Sub-Phases & Implementation Roadmap

```
+--------------------------------------------------------------------------+
| Phase 2a: Datasets, Feature Extraction Engine & Model Pipeline Plumbing  |
| - scripts/train/ data downloaders & verification                         |
| - backend/trinetra/features/ (streaming windowed statistical extractors) |
| - Group-split cross-validation harness                                   |
+--------------------------------------------------------------------------+
                                    |
                                    v
+--------------------------------------------------------------------------+
| Phase 2b: Volumetric & Reconnaissance Detectors                          |
| - T-a: DDoS (SYN flood, UDP reflection, Slowloris)                       |
| - T-e: Port Scan & Horizontal Reconnaissance                             |
+--------------------------------------------------------------------------+
                                    |
                                    v
+--------------------------------------------------------------------------+
| Phase 2c: Command & Control and Infiltration Detectors                   |
| - T-b: Botnet C2 Beaconing (autocorrelation, FFT, CV)                    |
| - T-c: DGA Domain Classifier & DNS Tunnelling                            |
+--------------------------------------------------------------------------+
                                    |
                                    v
+--------------------------------------------------------------------------+
| Phase 2d: Encrypted Threats, Exfiltration & System Integration           |
| - T-d: Encrypted Session Classifier (JA3 threat intel + PST vectors)     |
| - T-f: Data Exfiltration Detector (R_byte, volume accumulation)          |
| - Model cards, explainability narration adapter, and end-to-end report   |
+--------------------------------------------------------------------------+
```

---

## 5. Architectural Decisions & Questions for User Confirmation

Prior to commencing Phase 2 implementation, the following architectural choices require alignment:

1. **Model Persistence Format:**
   - *Option A (Recommended):* Standard Python `joblib` / `pickle` artifacts with cryptographic SHA-256 integrity verification inside the enclave.
   - *Option B:* `ONNX` runtime export. Enables cross-language evaluation, but adds `onnxruntime` dependency.
2. **Target Operational False Alarm Rate (FAR):**
   - *Proposed Target:* $\le 1.0$ false alert per 12 hours of enterprise baseline traffic ($FAR \le 0.083 \text{ alerts/hour}$) at the nominal operating threshold.
3. **Execution Hardware Constraint:**
   - *Baseline Assumption:* Pure CPU execution on single core/multiprocess within the air-gapped container (zero CUDA/GPU dependency).
