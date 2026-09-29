from pathlib import Path
from scapy.all import *
import numpy as np
import os
import time

np.random.seed(42)  # Reproducible PCAP generation
DEST_DIR = str(Path(__file__).resolve().parent.parent / "data" / "captures" / "synthetic_tool_realistic")
os.makedirs(DEST_DIR, exist_ok=True)

def generate_ddos_syn():
    print("Generating T_A_DDOS.pcap")
    pkts = []
    dst_ip = "192.168.1.100"
    for i in range(1000):
        # Attack
        src_ip = f"10.0.{i%20}.{np.random.randint(1, 255)}"
        pkt = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=RandShort(), dport=80, flags="S")
        pkt.time = time.time() + (i * 0.001)
        pkts.append(pkt)
    # Benign
    for i in range(500):
        src_ip = f"10.0.{i%20}.{np.random.randint(1, 255)}"
        pkt = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=RandShort(), dport=80, flags="PA")
        pkt.time = time.time() + (i * 0.1)
        pkts.append(pkt)
    wrpcap(os.path.join(DEST_DIR, "T_A_DDOS.pcap"), pkts)

def generate_portscan():
    print("Generating T_E_PORT_SCAN.pcap")
    pkts = []
    dst_ip = "192.168.1.100"
    for i in range(20):
        src_ip = f"10.0.{i}.50"
        # Attack
        for port in range(1, 100):
            pkt = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=RandShort(), dport=port, flags="S")
            pkt.time = time.time() + (i*10 + port * 0.01)
            pkts.append(pkt)
        # Benign
        src_ip_b = f"10.0.{i+20}.50"
        for port in [80, 443]:
            pkt = Ether()/IP(src=src_ip_b, dst=dst_ip)/TCP(sport=RandShort(), dport=port, flags="PA")
            pkt.time = time.time() + (i*10 + port * 0.01)
            pkts.append(pkt)
    wrpcap(os.path.join(DEST_DIR, "T_E_PORT_SCAN.pcap"), pkts)

def generate_exfil():
    print("Generating T_F_EXFIL.pcap")
    pkts = []
    for i in range(20):
        src_ip = f"172.16.{i}.20"
        dst_ip = "8.8.8.8"
        # Attack
        for j in range(200):
            if j % 10 == 0:
                pkt = Ether()/IP(src=dst_ip, dst=src_ip)/TCP(sport=443, dport=4444, flags="A")
            else:
                pkt = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=4444, dport=443, flags="PA")/Raw(load=b"X"*1400)
            pkt.time = time.time() + i*10 + (j * 0.01)
            pkts.append(pkt)
        # Benign
        src_ip_b = f"172.16.{i+20}.20"
        for j in range(200):
            if j % 2 == 0:
                pkt = Ether()/IP(src=dst_ip, dst=src_ip)/TCP(sport=443, dport=4444, flags="A")/Raw(load=b"X"*1400)
            else:
                pkt = Ether()/IP(src=src_ip_b, dst=dst_ip)/TCP(sport=4444, dport=443, flags="PA")
            pkt.time = time.time() + i*10 + (j * 0.01)
            pkts.append(pkt)
    wrpcap(os.path.join(DEST_DIR, "T_F_EXFIL.pcap"), pkts)

def generate_beacon():
    print("Generating T_B_BEACON.pcap")
    pkts = []
    dst_ip = "203.0.113.50"
    base_time = time.time()
    for i in range(20):
        src_ip = f"10.10.{i}.15"
        for j in range(60):
            jitter = np.random.uniform(-5, 5)
            base_time += (60.0 + jitter)
            pkt1 = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=4444, dport=80, flags="PA")/Raw(load=b"ping")
            pkt1.time = base_time
            pkts.append(pkt1)
        src_ip_b = f"10.10.{i+20}.15"
        for j in range(60):
            base_time += np.random.uniform(1, 300)
            pkt1 = Ether()/IP(src=src_ip_b, dst=dst_ip)/TCP(sport=4444, dport=80, flags="PA")/Raw(load=b"ping")
            pkt1.time = base_time
            pkts.append(pkt1)
    wrpcap(os.path.join(DEST_DIR, "T_B_BEACON.pcap"), pkts)

def generate_dga():
    print("Generating T_C_DGA.pcap")
    pkts = []
    dst_ip = "8.8.8.8"
    base_time = time.time()
    for i in range(20):
        src_ip = f"10.20.{i}.15"
        for j in range(20):
            charset = "abcdefghijklmnopqrstuvwxyz0123456789"
            length = np.random.randint(8, 18)
            label = "".join(np.random.choice(list(charset)) for _ in range(length))
            domain = f"{label}.evil.com"
            pkt = Ether()/IP(src=src_ip, dst=dst_ip)/UDP(sport=RandShort(), dport=53)/DNS(rd=1, qd=DNSQR(qname=domain, qtype="A"))
            pkt.time = base_time + (j * 1.5)
            pkts.append(pkt)
        src_ip_b = f"10.20.{i+20}.15"
        for j in range(20):
            domain = np.random.choice(["google.com", "apple.com", "microsoft.com", "example.com"])
            pkt = Ether()/IP(src=src_ip_b, dst=dst_ip)/UDP(sport=RandShort(), dport=53)/DNS(rd=1, qd=DNSQR(qname=domain, qtype="A"))
            pkt.time = base_time + (j * 1.5)
            pkts.append(pkt)
    wrpcap(os.path.join(DEST_DIR, "T_C_DGA.pcap"), pkts)

def generate_dns_tunnel():
    print("Generating T_C_DNS_TUNNEL.pcap")
    pkts = []
    dst_ip = "8.8.8.8"
    base_time = time.time()
    for i in range(20):
        src_ip = f"10.30.{i}.15"
        for j in range(40):
            length = np.random.randint(40, 70)
            charset = "abcdefghijklmnopqrstuvwxyz0123456789"
            label = "".join(np.random.choice(list(charset)) for _ in range(length))
            domain = f"{label}.c2.com"
            qtype = "TXT" if np.random.rand() > 0.5 else "A"
            pkt = Ether()/IP(src=src_ip, dst=dst_ip)/UDP(sport=RandShort(), dport=53)/DNS(rd=1, qd=DNSQR(qname=domain, qtype=qtype))
            pkt.time = base_time + (j * 0.1)
            pkts.append(pkt)
        src_ip_b = f"10.30.{i+20}.15"
        for j in range(40):
            domain = np.random.choice(["google.com", "apple.com", "microsoft.com", "example.com"])
            pkt = Ether()/IP(src=src_ip_b, dst=dst_ip)/UDP(sport=RandShort(), dport=53)/DNS(rd=1, qd=DNSQR(qname=domain, qtype="A"))
            pkt.time = base_time + (j * 0.1)
            pkts.append(pkt)
    wrpcap(os.path.join(DEST_DIR, "T_C_DNS_TUNNEL.pcap"), pkts)

if __name__ == "__main__":
    generate_ddos_syn()
    generate_portscan()
    generate_exfil()
    generate_beacon()
    generate_dga()
    generate_dns_tunnel()
