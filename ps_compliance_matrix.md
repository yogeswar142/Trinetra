# Trinetra — PS 26145 Compliance Matrix

**PS:** SIH 2026 PS 26145 — AI-Based Detection of Cyber Threats in Unidirectional IP Traffic (NTRO)  
**Theme:** Blockchain & Cybersecurity  
**Last Updated:** 29 September 2026  

---

## How to Read This Matrix

| Column | Meaning |
|--------|---------|
| **PS Requirement** | Verbatim or paraphrased requirement from the problem statement |
| **Status** | `DONE` / `IN PROGRESS` / `PLANNED (PhN)` / `N/A` |
| **Code Location** | File and class/function where implemented |
| **Notes** | Clarifications, limitations, or decisions |

---

## Section 1: Ingest and Sensor Constraints

| PS Requirement | Status | Code Location | Notes |
|---|---|---|---|
| Passive receive-only (data diode / optical TAP) | `DONE` | [`config.py#EnclaveConfig.read_only_mode`](backend/trinetra/config.py) | Static analysis test enforces no transmit sockets |
| No payload decryption (metadata-only analysis) | `DONE` | [`schemas.py#FlowEvent`](backend/trinetra/schemas.py) — only metadata fields; [`tls_parser.py`](backend/trinetra/features/tls_parser.py) — handshake fields only | QUIC Initial key derivation explicitly NOT implemented (C2 constraint) |
| No transmitting sockets in ingest layer | `DONE` | [`tests/test_no_transmit.py`](tests/test_no_transmit.py) | Static AST scan + import-time socket patch; CI must pass |
| Support PCAP as input | `DONE` | [`backend/trinetra/ingest/pcap.py`](backend/trinetra/ingest/pcap.py) | dpkt-based, classic pcap & pcapng, 802.1Q & 802.1ad QinQ VLAN, IPv4/IPv6, fragment dropping with counters |
| Support live packet capture from TAP interface | `DONE` | [`backend/trinetra/ingest/pcap.py`](backend/trinetra/ingest/pcap.py) | Stream interface accepts binary stream from file or stdin/pipe from raw TAP |
| Support NetFlow / IPFIX binary flow records | `DONE` | [`backend/trinetra/ingest/netflow.py`](backend/trinetra/ingest/netflow.py) | Original binary RFC 3954 NetFlow v9 parser, out-of-order template queuing, options templates, unknown field tolerance |
| Stateful flow table & passive TCP state tracking | `DONE` | [`backend/trinetra/ingest/flow_table.py`](backend/trinetra/ingest/flow_table.py) & [`tcp_tracker.py`](backend/trinetra/ingest/tcp_tracker.py) | Bidirectional normalization, deterministic timestamp-driven expiry, bounded LRU eviction, duplicates & midstream handling |
| QUIC traffic handling | `DONE (metadata only)` | [`schemas.py#FlowEvent.quic_*`](backend/trinetra/schemas.py), [`pcap.py`](backend/trinetra/ingest/pcap.py) | Long-header fields, version, connection-ID lengths, packet size/timing. No key derivation. |

---

## Section 2: Threat Detection (T-a through T-f)

| PS Requirement | Status | Code Location | Notes |
|---|---|---|---|
| T-a: Volumetric DDoS detection (SYN flood, UDP flood, Slowloris) | `PLANNED (Ph2)` | `backend/trinetra/detectors/ddos.py` | IF + RF on rate/ratio features; all thresholds in config as initial heuristics |
| T-b: Botnet C2 beaconing detection | `PLANNED (Ph2)` | `backend/trinetra/detectors/beaconing.py` | RF + IF on IAT features (CV, autocorr, FFT) |
| T-c: DGA domain detection | `PLANNED (Ph2)` | `backend/trinetra/detectors/dga.py` | Char n-gram classifier + Shannon entropy |
| T-c: DNS tunnelling detection | `PLANNED (Ph2)` | `backend/trinetra/detectors/dns_tunnel.py` | RF on query length, entropy, record type distribution |
| T-d: Malware detection in encrypted TLS sessions | `PARTIAL (Ph0)` | [`features/tls_parser.py`](backend/trinetra/features/tls_parser.py) — JA3/JA3S parsing; [`features/tls_parser.py#extract_pst_sequence`](backend/trinetra/features/tls_parser.py) | Full detector (blacklist + RF on PST/cert features) in Ph2 |
| T-e: Port scanning / reconnaissance detection | `PLANNED (Ph2)` | `backend/trinetra/detectors/port_scan.py` | IF on dst_port_count, dst_ip_count, SYN ratios |
| T-f: Data exfiltration detection | `PLANNED (Ph2)` | `backend/trinetra/detectors/exfil.py` | RF on r_byte, cumulative_out_bytes, session features |

---

## Section 3: AI/ML Requirements

| PS Requirement | Status | Code Location | Notes |
|---|---|---|---|
| AI/ML pipeline (not purely rule-based) | `PLANNED (Ph2)` | `backend/trinetra/detectors/` | Each detector requires a trained model; see master_plan.md §AI/ML |
| Documented model features | `PLANNED (Ph2)` | `docs/model_features.md` | Per-detector feature tables |
| Train/validation/held-out splits documented | `PLANNED (Ph2)` | `scripts/train/` | 60%/20%/20% splits; cross-dataset check |
| Model artifacts reproducible | `PLANNED (Ph2)` | `scripts/train/*.py` | `make train-{detector}` target |
| Interpretable evidence per alert | `DONE` | [`schemas.py#EvidenceItem`](backend/trinetra/schemas.py) | Each alert has ≥1 EvidenceItem; feature + value + threshold + interpretation |
| Synthetic-data caveat documented | `DONE` | [`simulator.py`](backend/trinetra/simulator.py) — docstring; [`research_notes.md §6`](research_notes.md) | Synthetic vs. real-PCAP metrics always reported separately |

---

## Section 4: TLS / Fingerprinting

| PS Requirement | Status | Code Location | Notes |
|---|---|---|---|
| JA3 or JA4 TLS fingerprinting | `DONE (JA3+JA3S)` | [`features/tls_parser.py#parse_client_hello`](backend/trinetra/features/tls_parser.py) | Pure Python, no external library; self-implemented from specification |
| JA3S (server fingerprint) | `DONE` | [`features/tls_parser.py#parse_server_hello`](backend/trinetra/features/tls_parser.py) | — |
| JA4 base TLS client fingerprint (optional extra) | `PLANNED (Ph3, if time)` | `backend/trinetra/features/ja4.py` | BSD-3-Clause; lower priority than JA3/JA3S |
| PST (Packet Size & Timing) sequences | `DONE` | [`features/tls_parser.py#extract_pst_sequence`](backend/trinetra/features/tls_parser.py) | Defends against Chrome extension-order randomization |

---

## Section 5: Forensic Ledger (SIH Theme — Blockchain & Cybersecurity)

| PS Requirement | Status | Code Location | Notes |
|---|---|---|---|
| Chain of custody for forensic use | `DONE` | [`ledger.py#ForensicLedger`](backend/trinetra/ledger.py) | Hash-chained, Ed25519-signed forensic ledger |
| Cryptographic tamper evidence | `DONE` | [`ledger.py#verify_chain`](backend/trinetra/ledger.py) | Verifies block hash chain + Ed25519 signatures |
| Correct block hash construction (sig not in preimage) | `DONE` | [`ledger.py#compute_block_hash`](backend/trinetra/ledger.py) | Enforced in tests; see `test_ledger.py` |
| Dashboard Merkle root display | `PLANNED (Ph3)` | `frontend/` | Live head hash display; head hash also available via `ledger.get_head_hash()` |
| Tail truncation mitigation (head hash external log) | `DONE (design)` | [`ledger.py#ForensicLedger.get_head_hash`](backend/trinetra/ledger.py) | Design documented in master_plan.md. External log mechanism = Ph3. |
| `trinetra verify-chain` CLI command | `PLANNED (Ph0/Ph1)` | `backend/trinetra/cli.py` | Uses `verify_chain()` |

---

## Section 6: Alert Schema (5 Mandatory Fields)

| Mandatory Field | Status | Code Location | Notes |
|---|---|---|---|
| `alert_id` (unique identifier) | `DONE` | [`schemas.py#AlertRecord.alert_id`](backend/trinetra/schemas.py) | UUID-4, auto-generated |
| `timestamp` (ISO-8601 UTC) | `DONE` | [`schemas.py#AlertRecord.timestamp`](backend/trinetra/schemas.py) | Auto-generated from `datetime.now(utc)` |
| `threat_class` | `DONE` | [`schemas.py#ThreatClass`](backend/trinetra/schemas.py) | Enum; covers all T-a through T-f |
| `severity` | `DONE` | [`schemas.py#Severity`](backend/trinetra/schemas.py) | CRITICAL / HIGH / MEDIUM / LOW / INFO |
| `evidence` (non-empty list) | `DONE` | [`schemas.py#AlertRecord.evidence`](backend/trinetra/schemas.py) | Pydantic `min_length=1` enforced; `EvidenceItem` has feature+value+threshold+interpretation |

---

## Section 7: Direction Labelling and Topology

| PS Requirement | Status | Code Location | Notes |
|---|---|---|---|
| Passive direction classification (no interface hints) | `DONE` | [`config.py#EnclaveConfig.classify_direction`](backend/trinetra/config.py) | INBOUND / OUTBOUND / LATERAL / TRANSIT |
| Per-scenario topology override for lab data | `DONE` | [`config.py#ScenarioTopology`](backend/trinetra/config.py) | Prevents false-LATERAL in private-range lab scenarios |
| Direction correctness tests (DDoS=INBOUND, exfil=OUTBOUND, scan correct) | `DONE` | [`tests/test_simulator.py`](tests/test_simulator.py) | `assert_direction_correctness()` |

---

## Section 8: Performance Benchmarking

| PS Requirement | Status | Code Location | Notes |
|---|---|---|---|
| Full pipeline benchmark (measured, not assumed) | `DONE` | [`scripts/benchmark_pipeline.py`](scripts/benchmark_pipeline.py) | Reports packets/s, flows/s, Mbps, p50/p95/p99 latency + hardware specs |
| Benchmark reproducible from `make benchmark` | `DONE` | [`Makefile`](Makefile), [`scripts/benchmark_pipeline.py`](scripts/benchmark_pipeline.py) | Produces timestamped JSON in `benchmarks/results/` |
| All performance numbers from measured data | `DONE` | [`benchmarks/results/`](benchmarks/results/) | All unmeasured numbers removed; measured on Qualcomm Snapdragon ARM64 |

---

## Section 9: LLM Narration

| PS Requirement | Status | Code Location | Notes |
|---|---|---|---|
| Offline-capable narration (no external API calls) | `DONE (design)` | [`config.py#EnclaveConfig.ollama_*`](backend/trinetra/config.py) | Template engine primary; Ollama local secondary (disabled by default) |
| Non-blocking narration (alert emitted before narration) | `PLANNED (Ph3)` | `backend/trinetra/narration.py` | Async detached task; raw alert emitted immediately |

---

## Section 10: Sensor Transmit Prohibition

| PS Requirement | Status | Code Location | Notes |
|---|---|---|---|
| Ingest package never opens transmitting sockets | `DONE` | [`tests/test_no_transmit.py`](tests/test_no_transmit.py) | AST static scan + runtime socket patching; included in `make test` |
| Dashboard WebSocket is internal to enclave | `DONE (design)` | [`docker-compose.yml`](docker-compose.yml) — `internal: true` network; bound to `127.0.0.1` | Enforced at network layer |
