# 🚀 Trinetra Production Deployment Guide
**Target Environment:** NTRO High-Security Isolated Enclave (Air-Gapped Optical TAP)

---

## 🏛️ Deployment Architecture Overview

Trinetra is designed to be deployed inside an air-gapped monitoring enclave with zero egress channels back to the production network.

```
       [ Production Network TAP / Optical Diode ]
                           │ (Passive Rx Optical Light)
                           ▼
               [ Physical Diode NIC ]
                           │ (Inbound Traffic Only)
┌──────────────────────────┼────────────────────────────────────────┐
│ TRINETRA SENSOR HOST     │                                        │
│                          ▼                                        │
│             ┌─────────────────────────┐                           │
│             │ Passive Ingest Engine   │                           │
│             │ (No Transmit Sockets)   │                           │
│             └────────────┬────────────┘                           │
│                          ▼                                        │
│             ┌─────────────────────────┐                           │
│             │ AI Anomaly & ML Engine  │                           │
│             └────────────┬────────────┘                           │
│                          ▼                                        │
│             ┌─────────────────────────┐                           │
│             │ Ed25519 Merkle Ledger   │                           │
│             └────────────┬────────────┘                           │
│                          ▼                                        │
│             ┌─────────────────────────┐                           │
│             │ FastAPI + WebSockets    │                           │
│             └────────────┬────────────┘                           │
└──────────────────────────┼────────────────────────────────────────┘
                           │ (Internal Enclave Network Only)
                           ▼
          [ Operator SOC Console (Next.js 15) ]
```

---

## 📋 Hardware & OS Requirements

### Sensor Host Minimum Specs:
* **CPU:** 8 Cores (x86_64 or ARM64)
* **RAM:** 16 GB ECC RAM
* **Storage:** 256 GB High-Endurance NVMe SSD (for persistent Ed25519 Merkle ledger storage)
* **Network Interface Card (NIC):** Physical Optical TAP Card or Promiscuous Receive-Only NIC (No TX fiber connected).
* **Operating System:** Ubuntu 22.04 LTS / Debian 12 / Red Hat Enterprise Linux 9

---

## 📦 Option A: Containerized Docker Enclave Deployment (Recommended)

In a containerized setup, Docker networks enforce network segmentation between the ingest sensor and the operator dashboard.

### 1. Build & Spin Up Containers:
```bash
docker compose up -d --build
```

### 2. Verified Air-Gap Enclave Configuration (`docker-compose.yml`):
* `trinetra-sensor`: Runs on isolated `enclave-net` (`internal: true`), completely blocking external outbound routing.
* `trinetra-dashboard`: Runs Next.js 15 on `dashboard-net`, accessible only to SOC operators via port `3000`.

---

## ⚙️ Option B: Bare-Metal / Systemd Service Deployment

For bare-metal dedicated servers, Trinetra can run as systemd background daemons.

### 1. Installation:
```bash
cd /opt/trinetra
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### 2. Systemd Sensor Service (`/etc/systemd/system/trinetra-sensor.service`):
```ini
[Unit]
Description=Trinetra Passive Threat Sensor Engine
After=network.target

[Service]
Type=simple
User=trinetra
WorkingDirectory=/opt/trinetra
ExecStart=/opt/trinetra/.venv/bin/python -m trinetra.cli start --config /opt/trinetra/config/enclave.toml
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
```

### 3. Systemd Dashboard Service (`/etc/systemd/system/trinetra-dashboard.service`):
```ini
[Unit]
Description=Trinetra Next.js 15 SOC Dashboard
After=trinetra-sensor.service

[Service]
Type=simple
User=trinetra
WorkingDirectory=/opt/trinetra/frontend
ExecStart=/usr/bin/npm start
Restart=always
RestartSec=5
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
```

---

## 🔒 Verification & Compliance Checks

After deployment, verify that the sensor adheres to NTRO air-gap constraints:

### 1. Verify Zero Transmit Sockets:
```bash
pytest tests/test_no_transmit.py -v
```

### 2. Verify Forensic Ledger Integrity:
```bash
python3 -c "from trinetra.ledger import ForensicLedger; ledger = ForensicLedger(); print(ledger.verify_chain())"
```

### 3. Live Terminal Dashboard:
```bash
trinetra
```
