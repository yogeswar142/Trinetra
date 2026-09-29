# Trinetra — Research Notes & Intelligence Dossier
**Project:** Trinetra (SIH 2026, PS 26145 - NTRO)  
**Date:** 29 September 2026 (last revised: 29 Sep 2026)  
**Author:** Senior Technical Lead & Network-Security / ML Specialist  

> **METHODOLOGY NOTE:** All license/status claims are tagged [VERIFIED] or [UNVERIFIED].  
> [VERIFIED] = checked directly against primary source on the date shown.  
> [UNVERIFIED] = secondary-source claim; treat as provisional.  
> Source URLs are provided for every claim.

---

## 1. Competitive Landscape Analysis (PS 26145 Repositories)

We conducted an audit of public GitHub repositories associated with SIH PS 26145 ("AI-Based Detection of Cyber Threats in Unidirectional IP Traffic" by NTRO):

| # | Repository URL | Last Commit (Verified) | Claimed Capabilities | Verifiably Present in Code (with File/Line Citations) | Verification Status & Gaps |
|---|---|---|---|---|---|
| 1 | `https://github.com/archduke1337/SIH26145` | 28 Sep 2026 | RF+IF, Ollama qwen2.5, WebSocket alert stream | `docs/ARCHITECTURE.md` (lines 14–34): *"Synthetic traffic generator / fixture -> Read-only JSONL replay -> Python streaming worker -> Appwrite Databases"*; `backend/pyproject.toml` lists `fastapi`, `pydantic`, `uvicorn`, `appwrite`, `httpx` | [VERIFIED] Pre-parsed JSONL replay only; zero raw packet or NetFlow binary parsing; no TLS JA3/JA4 byte extractor; no cryptographic ledger. |
| 2 | `https://github.com/xhhbbshbsj/SIH-2026-26145` | 27 Sep 2026 | SentryDiode: Packet capture, ML detection, FastAPI backend | `sentry-diode/requirements.txt` contains `scapy`, `dpkt`, `numpy`, `scikit-learn`, `fastapi`; `sniffer.py` uses Scapy `sniff()` loop | [VERIFIED] Slow Scapy packet capture loop; no RFC 3954 binary NetFlow v9 parser; no passive TCP session tracking state machine; no tamper-evident ledger. |
| 3 | `https://github.com/AtharvaSamant4/DrishtiGuard` | 24 Sep 2026 | Unidirectional privacy / network monitor | `apps/extension/manifest.json`, `apps/web/package.json` | [VERIFIED] Client-side Next.js / browser extension privacy utility, not an air-gapped network TAP / data diode IDS. |
| 4 | `https://github.com/Aman-Verma-28/SIH-2024-PS-26145` | 18 Aug 2024 | AI threat detector for diodes | Single README.md markdown file | [VERIFIED PLACEHOLDER] Empty repository stub. **Note on naming:** Student teams frequently branch, rename, or adapt earlier years' repository scaffolds (e.g. SIH 2024/2025) for SIH 2026 where similar problem statement numbers repeat. |
| 5 | `https://github.com/angadmaan/ntro-unidirectional-threat-detection` | UNVERIFIED | CLI monitor + Web SOC, IF+RF | Repository private or unresolvable at fetch time | [UNVERIFIED - EXCLUDED FROM COUNTS] |
| 6 | `https://github.com/sathwikgidijala-glitch/UniGuard-SIH26145` | UNVERIFIED | Web dashboard + AI classifier | Repository private or unresolvable at fetch time | [UNVERIFIED - EXCLUDED FROM COUNTS] |
| 7 | `https://github.com/cyber-sentinel-sih/unidirectional-traffic-monitor` | UNVERIFIED | Real-time packet inspector | Repository private or unresolvable at fetch time | [UNVERIFIED - EXCLUDED FROM COUNTS] |
| 8 | `https://github.com/team-diode-guard/ntro-diode-defense` | UNVERIFIED | Signature + Anomaly IDS | Repository private or unresolvable at fetch time | [UNVERIFIED - EXCLUDED FROM COUNTS] |
| 9 | `https://github.com/deep-packet-ai/sih-26145-ai-threat` | UNVERIFIED | PyTorch LSTM model | Repository private or unresolvable at fetch time | [UNVERIFIED - EXCLUDED FROM COUNTS] |
| 10 | `https://github.com/netsec-analyst/ja3-tls-analyzer` | UNVERIFIED | Batch JA3 script | Repository private or unresolvable at fetch time | [UNVERIFIED - EXCLUDED FROM COUNTS] |

### 1.1 Competitive Differentiation Claim (Evidence-Supported)
Across the verifiably audited repositories:
1. **Zero repos combine real binary dual-mode ingest:** Competitors rely either on pre-parsed JSONL replays (`archduke1337`), slow per-packet Scapy capture loops (`xhhbbshbsj`), or client-side web tools (`AtharvaSamant4`). None implement zero-copy/streaming dpkt PCAP parsing combined with an RFC 3954 binary NetFlow v9 parser.
2. **Zero repos implement an air-gap compliant forensic ledger:** None of the audited competitor repositories implement a signed, hash-chained Merkle ledger for alert non-repudiation. (Earlier secondary claims regarding external blockchain HTTP calls have been excluded as unverified).
3. **Zero repos handle passive bidirectional mirrored TAP dynamics with mid-stream recovery:** Competitors assume either simplex flows with zero ACKs or fail when asymmetric capture or mid-stream traffic arrives.
4. **Reconciliation with Public Claims:** While several public hackathon repos claim JA3/JA4 parsing, web dashboards, or AI analysts in high-level documentation, direct code audits reveal these to be either UI mockups, static placeholders, or pre-parsed batch scripts lacking a line-rate streaming engine.
5. **Scope Caveat:** Private or unindexed hackathon submissions are not evaluated; this differentiation claim is strictly bounded to the verified codebases listed above.

---

## 2. Passive Optical TAP & Data Diode Mechanics

### 2.1 Physical Reality: Simplex Egress vs. Mirrored Bidirectional Conversations
- A **hardware data diode** is a physical layer-1 device: LED/laser transmitter on sending side, photodiode receiver on receiving side, no return optical fiber.
- When critical infrastructure networks monitor core links (e.g. gateway router to ISP or IT/OT boundary), an **Optical TAP (Test Access Point)** splits the light from both directions (Tx and Rx fibers of the monitored full-duplex link).
- Both optical signals are combined onto the transmit fiber entering the data diode, passed into the isolated monitoring enclave.
- **What the sensor sees:** Packets from **both directions** of the conversation (A→B and B→A).
- **What the sensor cannot do:** No physical transmit path back to the network. Cannot send TCP resets, ICMP unreachable, ARP requests, DNS queries, or TCP handshakes.

### 2.2 Directionality Labeling (Inbound vs. Outbound)
Because the sensor receives packets from both sides of the tapped connection, directionality is determined without interface hints. **Critical for lab/synthetic scenarios:** both attacker and victim may be in private ranges, which would wrongly label all traffic LATERAL. Each scenario must supply its own `INTERNAL_NETWORKS` override in config.

Direction logic (per-scenario `INTERNAL_NETWORKS`):
- `Direction.OUTBOUND`: `src_ip` ∈ `INTERNAL` and `dst_ip` ∉ `INTERNAL`.
- `Direction.INBOUND`: `src_ip` ∉ `INTERNAL` and `dst_ip` ∈ `INTERNAL`.
- `Direction.LATERAL`: `src_ip` ∈ `INTERNAL` and `dst_ip` ∈ `INTERNAL`.
- `Direction.TRANSIT`: Neither in internal subnets.

Tests must verify that DDoS (INBOUND volumetric), exfil (OUTBOUND), and scan (LATERAL or OUTBOUND) direction logic produces the correct label on every canonical scenario.

### 2.3 Passive TCP State Machine
Without transmit capability, TCP tracking relies on passive observation. The implementation MUST handle:
- **Duplicates:** De-duplicate on (src_ip, src_port, dst_ip, dst_port, seq_no) within a bounded window.
- **Out-of-order packets:** Track per-flow sequence numbers without failing or blocking.
- **Mid-stream capture:** Packets observed without a preceding SYN are tracked as `MIDSTREAM_ESTABLISHED` using the first observed sequence number.
- **One-sided loss on mirrored link:** If only one direction of a flow is visible, track available half; flag as `HALF_OPEN_OBSERVED`.

State transitions (happy path):
- `SYN` (client→server): State → `SYN_SENT`, record ISN, start handshake timer.
- `SYN-ACK` (server→client): State → `SYN_RCVD`, record server ISN.
- `ACK` (client→server, matching ack seq): State → `ESTABLISHED`, calculate RTT.
- `FIN` / `RST`: State → `CLOSED`.

---

## 3. Datasets and Traffic Generation Tooling (Licensing Verified)

| Tool / Dataset | Coverage / Threat | Format | License & Primary Source Quote | Canonical URL | Verification Status (Fetched 29 Sep 2026) |
|---|---|---|---|---|---|
| **iperf3** | Benign baseline throughput (T-a) | TCP/UDP stream | BSD-3-Clause | https://github.com/esnet/iperf/blob/master/LICENSE | [VERIFIED] Actively maintained |
| **Ostinato** | Packet crafting & wire playback | PCAP / Ethernet | GPLv3 | https://github.com/pstavirs/ostinato | [VERIFIED] Actively maintained |
| **TRex (Cisco)** | High-speed stateful traffic generation | DPDK / PCAP | Apache-2.0 | https://github.com/cisco-system-traffic-generator/trex-core | [VERIFIED] Actively maintained |
| **hping3** | SYN, UDP, ICMP flooding (T-a) | Raw packets | GPLv2 | https://github.com/antirez/hping | [VERIFIED] Stable reference standard |
| **Slowloris** | Connection starvation / slow HTTP (T-a) | HTTP/TCP | MIT | https://github.com/gkbrk/slowloris | [VERIFIED] Stable standard |
| **dnscat2** | DNS tunnelling, C2, exfiltration (T-c) | DNS queries (TXT/MX/CNAME) | BSD-2-Clause | https://github.com/iagox86/dnscat2 | [VERIFIED] Maintained reference |
| **iodine** | IP over DNS tunnel (T-c) | DNS tunnel | ISC | https://github.com/yarrick/iodine | [VERIFIED] Stable standard |
| **DGArchive (Fraunhofer FKIE)** | Algorithmic domain queries (T-c) | Domain lists | CC BY-NC-SA 3.0 (*"The whole content of the website is released under Creative Common's CC BY-NC-SA 3.0 license... Our informal policy is that you can do pretty much what you want with it as long as you maintain the credits and you don't abuse it to make a profit off of our work."*) | https://dgarchive.caad.fkie.fraunhofer.de/terms.html | [VERIFIED GATED] Access gated via email request to `dgarchive@fkie.fraunhofer.de`. **Fallback:** Deterministic built-in algorithmic generators for Conficker, Cryptolocker, Bamital, Doxrem. |
| **Tranco List** | Top 1M benign domains baseline (T-c) | CSV (domain rankings) | Research-oriented composite license (Le Pochat et al. NDSS 2019): Cisco Umbrella (free research), Majestic (CC BY 3.0), CrUX (CC BY-SA 4.0), Cloudflare Radar (CC BY-NC 4.0). Over 600 citations. | https://tranco-list.eu/ | [VERIFIED] Permitted for non-commercial security research. |
| **Sliver (Bishop Fox)**| Modern C2 framework / beaconing (T-b, T-d) | TLS/HTTP/mTLS/DNS C2 | GPLv3 | https://github.com/BishopFox/sliver | [VERIFIED] Actively maintained |
| **CTU-13** | Botnet C2, scanning, DDoS (T-a, T-b, T-e) | PCAP + NetFlow | CC BY 2.0 (*"Creative Commons Attribution 2.0 Generic"*, Garcia et al. 2014, DOI: 10.1016/j.cose.2014.05.011) | https://www.stratosphereips.org/datasets-ctu13 | [VERIFIED] Stratosphere IPS Lab. |
| **CIC-IDS2017** | Multi-vector attack suites | PCAP + CSV flows | Academic Use License (UNB Canadian Institute for Cybersecurity) | https://www.unb.ca/cic/datasets/ids-2017.html | [VERIFIED] Free for educational & competition research. |
| **malware-traffic-analysis.net** | Real Cobalt Strike, Qakbot, RATs (T-d) | PCAPs | Educational / Security Research | https://www.malware-traffic-analysis.net | [VERIFIED] Continuously updated by Brad Duncan. |
| **abuse.ch SSLBL** | Malicious JA3/JA3S fingerprints (T-d) | CSV / JSON | CC0 1.0 Universal (Public Domain) | https://sslbl.abuse.ch/ja3-fingerprints/ | [VERIFIED] Actively maintained open threat feed. |
| **salesforce/ja3** | Reference JA3 TLS client fingerprinting | Python code | BSD-3-Clause | https://github.com/salesforce/ja3 | [VERIFIED] Archived 1 May 2025 (stable reference standard). |

### 3.1 Third-Party NetFlow Library Maintenance Audit
In accordance with Deviation #2, we evaluated third-party Python NetFlow implementations:
1. `bitkeks/python-netflow-v9-softflowd` (`https://github.com/bitkeks/python-netflow-v9-softflowd`): Last release Feb 22, 2024. Maintained as a basic reference collector, but lacks streaming buffer management, high-throughput batching, and integration with an in-memory session table.
2. `ipfix` on PyPI (`https://pypi.org/project/ipfix/`): Last released in 2020 (unmaintained for >5 years).
3. `phaag/nfdump` (`https://github.com/phaag/nfdump`): Actively maintained C tool suite, but introduces external C dependencies and requires a background daemon process rather than in-process zero-dependency pure Python streaming.
*Conclusion:* Building an original RFC 3954 NetFlow v9 parser in Trinetra (`trinetra.ingest.netflow`) guarantees zero external C dependencies, deterministic replay, native orphaned-template buffering, and direct integration with `FlowTable`.

---

## 4. UDP Reflection / Amplification Signatures

In a unidirectional tap, UDP reflection/amplification exhibits specific patterns:
1. **Asymmetric Volume (Amplification Factor):**
   - NTP `monlist`: Request ~234 bytes → Response up to 48,000 bytes (Factor: ~200x–1000x).
   - DNS `ANY` query: Request ~64 bytes → Response ~3,000–4,000 bytes (Factor: ~50x).
   - Memcached: Request ~15 bytes → Response up to 750,000 bytes (Factor: 10,000x–50,000x).
   - SSDP / SNMP: Factor 10x–35x.
2. **Directional Anomaly:** Massive incoming UDP traffic from static service ports (UDP 53, 123, 1900, 11211) toward internal ports, with no preceding outbound query in session cache.
3. **Source IP Entropy:** Extremely high source-IP entropy converging onto a single internal destination IP.

---

## 5. TLS / QUIC Metadata Analysis (JA3, JA4, and Evasion)

### 5.1 The Fingerprint Landscape
- **JA3 / JA3S:**
  - Developed at Salesforce (John Althouse, Jeff Atkinson, Josh Atkins).
  - ClientHello string: `TLSVersion,CipherSuites,Extensions,EllipticCurves,EllipticCurveFormats`. Hashed with MD5.
  - ServerHello string: `TLSVersion,CipherSuite,Extensions`. Hashed with MD5.
  - License: BSD-3-Clause [VERIFIED 2026-09-29, https://raw.githubusercontent.com/salesforce/ja3/master/LICENSE.txt].
  - **Repository Status:** The `salesforce/ja3` repo was archived on **1 May 2025** [VERIFIED 2026-09-29 via direct GitHub page check]. The specification is a published standard, implementable in ~50 lines of Python from the original paper/blog post without importing the archived repo.
- **JA4 (FoxIO) — Base TLS Client Fingerprint:**
  - Released late 2023 by FoxIO, LLC.
  - License: **BSD-3-Clause** [VERIFIED 2026-09-29 — https://github.com/FoxIO-LLC/ja4 README licensing section explicitly states JA4 TLS client fingerprint is BSD-3-Clause; FoxIO states no patent claims on this method].
  - **Decision:** Implement base JA4 as a low-priority optional extra, clearly attributed to FoxIO spec. BSD-3-Clause permits use without restriction.
- **JA4+ Suite (JA4S, JA4H, JA4L, JA4X, JA4SSH, JA4T, etc.):**
  - License: **FoxIO License 1.1** [VERIFIED 2026-09-29 — https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE].
  - Non-commercial/academic use permitted; monetization requires OEM license from FoxIO.
  - **Decision: DO NOT IMPLEMENT** any JA4+ variants. The PS accepts "JA3/JA3S or JA4"; JA3+JA3S is sufficient. JA4 base is optional extra only.
- **Summary of fingerprint strategy:** Primary = JA3 + JA3S (BSD-3, self-implemented from spec). Optional extra = base JA4 TLS client only (BSD-3, attributed). No JA4+ variants.

### 5.2 Evasion & Randomized Extension Ordering
- Since Chrome 110+ (early 2023), modern browsers randomize TLS extension ordering and inject GREASE values (`0x?a?a`), causing JA3 hashes to vary across connections.
- Sophisticated C2 implants can customize ClientHello parameters to spoof browser JA3s.
- **Countermeasure (PST — Packet Size and Timing Sequences):**
  - Extract the PST sequence of the first K packets of the TLS session (e.g. `[+517, -1430, -1430, +120, -84]`, sign = direction).
  - Features: client payload size mean/stddev, ratio of small packets (<150 bytes) to large transfers, directional burst transitions.
  - A C2 session disguised behind a browser JA3 will display rigid beacon timing and periodic 100-byte bursts, uncharacteristic of legitimate interactive browsing.

### 5.3 QUIC Protocol Handling
The PS explicitly names QUIC. Trinetra handles QUIC **metadata-only** (no decryption):
- **Fields extracted from QUIC long-header packets:** version, destination/source connection-ID lengths, packet type (Initial/Handshake/0-RTT/1-RTT), packet size/timing sequences.
- **Explicit design decision on QUIC Initial keys:** Deriving QUIC Initial keys is feasible from RFC 9001 (they use a fixed salt), but doing so constitutes **controlled decryption of connection setup** — this violates constraint C2 (passive-only, no active manipulation of traffic). **Decision: DO NOT derive QUIC Initial keys. Document this choice explicitly.** We can still fingerprint QUIC flows by: connection-ID length patterns, packet size sequences, version negotiation, and IAT timing.
- QUIC flows with an unrecognized/draft version are flagged for review.
- QUIC over non-standard ports (not 443) is elevated-suspicion.

---

## 6. Mathematical Detection Algorithms & AI/ML Requirements

> **IMPORTANT:** The PS requires an AI/ML pipeline. For EACH threat class T-a through T-f, we require BOTH:
> 1. Interpretable statistical features used as evidence (rules-as-evidence, not rules-as-verdict).
> 2. A trained model with documented train/validation/held-out splits and a cross-dataset validation.
>
> Rules act as evidence features fed into models, and as fallback when models are unavailable.

### 6.1 Beaconing (T-b): Features + ML Model
**Statistical features (evidence):**
- Inter-Arrival Time (IAT) Coefficient of Variation: CV = σ_Δt / μ_Δt. (Initial heuristic — calibrate on data: periodic beacons show CV < 0.2; jittered beacons show 0.15 ≤ CV ≤ 0.35. **No published ground truth for these exact thresholds; label as "initial heuristics to calibrate on CTU-13 and CIC-IDS data"**.)
- Autocorrelation at lag k: R_xx(k) = Σ(x_t - x̄)(x_{t+k} - x̄) / σ². Sharp peak at lag k > 0 confirms periodicity. (Heuristic threshold for "sharp peak" = initial heuristic — calibrate on data.)
- FFT on discretized event bins: dominant frequency, spectral flatness.
- Session count, unique destination count per source over sliding window.

**ML Model:**
- **Random Forest Classifier** (primary) trained on [cv, autocorr_peak, fft_dominant_freq, spectral_flatness, session_count, duration].
- **Isolation Forest** (anomaly) for zero-day patterns not in training data.
- Train/val/held-out splits: 60%/20%/20% per dataset. Cross-dataset check: train on CTU-13, validate on CIC-IDS2017 Botnet subset.
- **Synthetic-data metric-inflation caveat:** Report separately for synthetic vs. real-PCAP test sets. Metrics on synthetic data MUST NOT be used as the primary claim.

### 6.2 DGA & DNS Tunnelling (T-c): Features + ML Model
**Statistical features (evidence):**
- Shannon entropy: H = −Σ p(c_i) log₂ p(c_i). (Initial heuristic — calibrate on data: benign domains average H ≈ 2.4–3.1; DGAs exhibit H > 3.6. **Source: Leon et al., 2014 "EXPOSURE" paper and Schiavoni et al., 2014 "Phoenix" paper — cited as inspiration; exact thresholds must be recalibrated on our training data.**)
- Vowel-to-consonant ratio, hex-character concentration.
- Character n-gram log-likelihood vs. English transition matrix.
- Query length, subdomain label count, record type distribution.
- Query volume cardinality per domain per 30s window. (Initial heuristic — calibrate on data: > 50 distinct subdomains within 30s indicates tunnelling.)

**ML Models:**
- **Char n-gram classifier** (CNN or logistic regression on trigram features) for DGA domain classification. Train on DGArchive domains (if accessible) or synthesized DGA domains from published Conficker/Cryptolocker/DGA-Changer algorithms + Tranco Top-1M as negative class.
- **Random Forest** on DNS flow features for tunnelling detection.
- Train/val/held-out splits: 60%/20%/20%. Cross-dataset: validate DGA model on CTU-13 DNS traffic.

### 6.3 Volumetric DDoS & SYN Floods (T-a): Features + ML Model
**Statistical features (evidence):**
- SYN packet ratio ρ_SYN = N_SYN / N_total. (Initial heuristic — calibrate on data.)
- Source IP entropy H_src, destination IP entropy H_dst.
- Packets-per-second rate, bytes-per-second rate in sliding windows (1s, 5s, 60s).
- Response-to-request ratio (no responses = possible reflection attack).

**ML Model:**
- **Isolation Forest** on [pps, bps, syn_ratio, src_entropy, dst_entropy]. No supervised labels needed for baseline anomaly detection.
- **GBM / Random Forest** trained on CIC-IDS2017 DDoS class if labels available.
- Synthetic-data caveat applies.

### 6.4 Data Exfiltration (T-f): Features + ML Model
**Statistical features (evidence):**
- Egress/Ingress Byte Ratio R_byte = Bytes_out / Bytes_in. (Initial heuristic — calibrate on data: legitimate corporate traffic is download-heavy R_byte ≪ 1.0; exfiltration R_byte > 3.0. **No published peer-reviewed source for this exact value; label as initial heuristic.**)
- Cumulative outbound volume per external IP per session.
- Session duration, connection count, port distribution.
- DNS query volume to same domain preceding large outbound sessions (staging indicator).

**ML Model:**
- **Random Forest** on [r_byte, cumulative_out_bytes, session_duration, connection_count, entropy_payload].
- Train/val/held-out splits: 60%/20%/20%. Cross-dataset: CIC-IDS2017 Infiltration + exfil scenarios.

### 6.5 Encrypted Malware in TLS (T-d): Features + ML Model
**Statistical features (evidence):**
- JA3 hash match against abuse.ch SSLBL known-malicious list.
- PST sequence: dominant inter-packet interval, regularity metric.
- Certificate anomalies: self-signed, expired, subject CN mismatch, short validity period.
- Small-packet ratio (packets < 150 bytes / total packets).

**ML Model:**
- **Random Forest** on [ja3_blacklisted (bool), pst_cv, cert_self_signed (bool), cert_validity_days, small_pkt_ratio, session_byte_total].
- Cross-dataset: validate on malware-traffic-analysis.net PCAPs.

### 6.6 Port Scanning / Reconnaissance (T-e): Features + ML Model
**Statistical features (evidence):**
- Distinct destination ports per source IP per window (horizontal scan indicator).
- Distinct destination IPs per source IP per window (vertical scan indicator).
- SYN-to-SYN-ACK ratio (many SYN, few responses = scan).
- RST-to-SYN ratio.

**ML Model:**
- **Isolation Forest** on [dst_port_count, dst_ip_count, syn_ack_ratio, rst_syn_ratio].
- Train on CIC-IDS2017 Port Scan class.

---

## 7. Performance Benchmarking

> **POLICY:** All performance numbers in planning documents are **REMOVED** unless measured.  
> Phase 1 will produce the first measured numbers via a reproducible benchmark script.

**What Phase 1 benchmark must report (on actual hardware with specs documented):**
- Hardware: CPU model, core count, RAM, NIC model.
- Metric 1: Raw packet parse throughput (packets/sec and Mbps) — dpkt ingest only.
- Metric 2: Full pipeline throughput (parse + flow table + feature extraction + inference + alert emit) in flows/sec AND Mbps.
- Metric 3: Alert latency p50 / p95 / p99 (ms) from first packet of a flow to alert emit.
- Metric 4: NetFlow v9/IPFIX binary parse throughput (flows/sec).
- Benchmark must be a single `make benchmark` target, reproducible from a script, producing a timestamped JSON results file.

---

## 8. Hash-Chained, Ed25519-Signed Forensic Ledger (SIH Theme Alignment)

### 8.1 What It Is (and Is Not)
SIH 2026 PS 26145 falls under the theme **"Blockchain & Cybersecurity"**. The official text requires: *"clean chain of custody for forensic use."*

This is a **hash-chained, signed forensic ledger** — NOT a blockchain (no distributed consensus, no tokens). Honest judge answer:
- **What it provides:** Cryptographic proof that no alert was deleted, inserted, or modified after signing, within the ledger file.
- **What it cannot prevent:** Tail truncation (attacker deletes the last N blocks without an anchor). **Mitigation:** Periodically display/print the current head hash to an external log, printer, or second-channel syslog. Any truncation would be detectable by comparing against the most recent external record.
- **Key storage:** Ed25519 private key is generated at sensor initialization and stored in the enclave's protected key directory (not in the ledger file). Key rotation requires re-anchoring with a signed key-rollover block.
- **Trusted timestamps:** System clock is used. Not RFC 3161 certified. Flag as "local clock — not independently certified" in the judge answer.
- **Verify time:** Will be measured in Phase 0 tests once implemented. No claim until measured.

### 8.2 Block Construction (Corrected)
The signature CANNOT be part of the hash preimage of the block it signs. Correct construction:

```
leaf_hash_k  = SHA-256(canonical_json(alert_k))
merkle_root  = compute_merkle_tree([leaf_hash_0, ..., leaf_hash_M-1])
block_hash   = SHA-256(prev_block_hash || merkle_root || timestamp || metadata)
signature    = Ed25519_sign(private_key, block_hash)
```

Block record stored in ledger = `{block_hash, prev_block_hash, merkle_root, timestamp, metadata, signature, [leaf_hashes]}`.

### 8.3 Verification
`trinetra verify-chain` command:
1. Recomputes all leaf hashes from stored alert JSON.
2. Recomputes all Merkle roots.
3. Recomputes block hashes (without signature in preimage).
4. Verifies each Ed25519 signature against the sensor's public key.
5. Reports any break in the chain. Verify time to be measured and reported in Phase 0 test output.

---

## 9. LLM Narration & Enclave Isolation Reality

- **The Air-Gap Constraint:** The enclave has no outbound connection. External API calls are an architectural impossibility in a real data diode setup.
- **The Solution — Dual-Engine Narration:**
  1. **Primary:** Deterministic rule-based template engine (instant, zero overhead, 100% offline).
  2. **Secondary:** Local Ollama adapter running small quantized models (`qwen2.5:1.5b-instruct` or `qwen2.5:3b-instruct`), strictly optional (`ollama_enabled: false` default).
- **Non-blocking Guarantee:** Narration runs asynchronously in a detached task. Raw alert, evidence, and confidence score are emitted to SOC dashboard immediately. Narration attaches as enrichment if/when model completes.

---

## 10. Binary NetFlow Ingest (Real Binary Flow Path)

> The "NetFlow JSONL" input criticized in competitors repeats the weakness of pre-parsed-only ingest.  
> Trinetra MUST support at least one real binary flow protocol path.

**Approved binary flow paths (choose one primary for Phase 1):**
- **NetFlow v9** — binary UDP datagrams, parsed with `python-netflow` library (maintained) or custom struct-based parser.
  - Source: https://github.com/bitkeks/python-netflow [UNVERIFIED — verify maintenance status]
- **IPFIX (NetFlow v10)** — binary, parse with `python-netflow` (supports IPFIX) or `goflow2` (GoFlow2, Apache-2.0) as a sidecar that converts to JSONL.
  - GoFlow2: https://github.com/netsampler/goflow2 [UNVERIFIED — verify license/maintenance]
- **sFlow** — binary UDP, parsed with `sflowtool` or a Python struct parser.

**JSONL remains the internal normalized format** only — all external inputs must be parsed from binary at the boundary before normalization.

---

## 11. Notes on Thresholds and Calibration

All numerical thresholds in `config.py` are **initial heuristics — must be calibrated on actual data** before claiming detection performance. The following have no independent published source and are initial engineering estimates:
- `beacon_max_cv = 0.22` — initial heuristic.
- `dns_entropy_dga_threshold = 3.4` — inspired by Leon et al. 2014 / Schiavoni et al. 2014; recalibrate on our training split.
- `dns_tunnel_length_threshold = 35` — initial heuristic based on dnscat2/iodine typical label lengths.
- `exfil_byte_ratio_threshold = 3.5` — initial heuristic.
- `ddos_syn_ratio_threshold = 0.80` — initial heuristic.

Thresholds MUST remain in config, never hard-coded. Config validation must reject obviously invalid values (e.g. negative thresholds).
