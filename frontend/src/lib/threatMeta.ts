import type { ThreatClass } from '@/types/trinetra';

export interface ThreatMeta {
  label: string;          // e.g. "T-a DDoS"
  shortLabel: string;     // e.g. "DDoS"
  color: string;          // CSS hex
  glow: string;           // box-shadow glow value
  bgAlpha: string;        // rgba for badge bg
  borderAlpha: string;    // rgba for badge border
  description: string;
  mitreTactics: string[];
}

export const THREAT_META: Record<ThreatClass, ThreatMeta> = {
  VOLUMETRIC_DDOS: {
    label: 'T-a DDoS',
    shortLabel: 'DDoS',
    color: '#E84545',
    glow: 'none',
    bgAlpha: 'rgba(232,69,69,0.12)',
    borderAlpha: 'rgba(232,69,69,0.35)',
    description: 'Volumetric Denial-of-Service',
    mitreTactics: ['T1498', 'T1499'],
  },
  UDP_AMPLIFICATION: {
    label: 'T-a UDP Amp',
    shortLabel: 'UDP Amp',
    color: '#E84545',
    glow: 'none',
    bgAlpha: 'rgba(232,69,69,0.12)',
    borderAlpha: 'rgba(232,69,69,0.35)',
    description: 'UDP Amplification Attack',
    mitreTactics: ['T1498.002'],
  },
  SLOWLORIS: {
    label: 'T-a Slowloris',
    shortLabel: 'Slowloris',
    color: '#E84545',
    glow: 'none',
    bgAlpha: 'rgba(232,69,69,0.12)',
    borderAlpha: 'rgba(232,69,69,0.35)',
    description: 'Slowloris HTTP DoS',
    mitreTactics: ['T1499.002'],
  },
  BOTNET_C2_BEACONING: {
    label: 'T-b Beacon',
    shortLabel: 'C2 Beacon',
    color: '#FF6B35',
    glow: 'none',
    bgAlpha: 'rgba(255,107,53,0.12)',
    borderAlpha: 'rgba(255,107,53,0.35)',
    description: 'Botnet C2 Periodic Beaconing',
    mitreTactics: ['T1071.001', 'T1571'],
  },
  DGA_DOMAINS: {
    label: 'T-c DGA',
    shortLabel: 'DGA',
    color: '#F5C518',
    glow: 'none',
    bgAlpha: 'rgba(245,197,24,0.12)',
    borderAlpha: 'rgba(245,197,24,0.35)',
    description: 'Domain Generation Algorithm',
    mitreTactics: ['T1568.002'],
  },
  DNS_TUNNELLING: {
    label: 'T-c DNS Tunnel',
    shortLabel: 'DNS Tunnel',
    color: '#F5C518',
    glow: 'none',
    bgAlpha: 'rgba(245,197,24,0.12)',
    borderAlpha: 'rgba(245,197,24,0.35)',
    description: 'DNS Data Tunnelling',
    mitreTactics: ['T1071.004'],
  },
  ENCRYPTED_MALWARE_TLS: {
    label: 'T-d TLS Malware',
    shortLabel: 'TLS',
    color: '#38BDF8',
    glow: 'none',
    bgAlpha: 'rgba(56,189,248,0.10)',
    borderAlpha: 'rgba(56,189,248,0.30)',
    description: 'Malware in Encrypted TLS Sessions',
    mitreTactics: ['T1573.002'],
  },
  PORT_SCANNING: {
    label: 'T-e Port Scan',
    shortLabel: 'Port Scan',
    color: '#94A3B8',
    glow: 'none',
    bgAlpha: 'rgba(148,163,184,0.10)',
    borderAlpha: 'rgba(148,163,184,0.25)',
    description: 'Port Scanning / Reconnaissance',
    mitreTactics: ['T1595', 'T1046'],
  },
  RECONNAISSANCE: {
    label: 'T-e Recon',
    shortLabel: 'Recon',
    color: '#94A3B8',
    glow: 'none',
    bgAlpha: 'rgba(148,163,184,0.10)',
    borderAlpha: 'rgba(148,163,184,0.25)',
    description: 'Active Reconnaissance',
    mitreTactics: ['T1595'],
  },
  DATA_EXFILTRATION: {
    label: 'T-f Exfil',
    shortLabel: 'Exfil',
    color: '#A855F7',
    glow: 'none',
    bgAlpha: 'rgba(168,85,247,0.12)',
    borderAlpha: 'rgba(168,85,247,0.35)',
    description: 'Data Exfiltration',
    mitreTactics: ['T1048'],
  },
  UNKNOWN_ANOMALY: {
    label: 'Unknown',
    shortLabel: 'Anomaly',
    color: '#64748B',
    glow: 'none',
    bgAlpha: 'rgba(100,116,139,0.10)',
    borderAlpha: 'rgba(100,116,139,0.20)',
    description: 'Unknown Anomaly',
    mitreTactics: [],
  },
};

export const DETECTOR_LIST = [
  { id: 'T-a', name: 'DDoS Detector',    keys: ['VOLUMETRIC_DDOS', 'UDP_AMPLIFICATION', 'SLOWLORIS'] as ThreatClass[] },
  { id: 'T-b', name: 'Beacon Detector',  keys: ['BOTNET_C2_BEACONING'] as ThreatClass[] },
  { id: 'T-c', name: 'DGA Detector',     keys: ['DGA_DOMAINS'] as ThreatClass[] },
  { id: 'T-c', name: 'DNS Tunnel',       keys: ['DNS_TUNNELLING'] as ThreatClass[] },
  { id: 'T-d', name: 'TLS Malware',      keys: ['ENCRYPTED_MALWARE_TLS'] as ThreatClass[] },
  { id: 'T-e', name: 'Port Scan Det.',   keys: ['PORT_SCANNING', 'RECONNAISSANCE'] as ThreatClass[] },
  { id: 'T-f', name: 'Exfil Detector',   keys: ['DATA_EXFILTRATION'] as ThreatClass[] },
] as const;
