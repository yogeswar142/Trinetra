// Trinetra TypeScript types — mirrors backend/trinetra/schemas.py exactly

export type ThreatClass =
  | 'VOLUMETRIC_DDOS'
  | 'UDP_AMPLIFICATION'
  | 'SLOWLORIS'
  | 'BOTNET_C2_BEACONING'
  | 'DGA_DOMAINS'
  | 'DNS_TUNNELLING'
  | 'ENCRYPTED_MALWARE_TLS'
  | 'PORT_SCANNING'
  | 'RECONNAISSANCE'
  | 'DATA_EXFILTRATION'
  | 'UNKNOWN_ANOMALY';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type Direction = 'INBOUND' | 'OUTBOUND' | 'LATERAL' | 'TRANSIT';

export interface Endpoint {
  ip: string;
  port: number;
  internal: boolean;
}

export interface EvidenceItem {
  feature: string;
  value: number | string | boolean;
  threshold: number | string | null;
  interpretation: string;
  source: 'rule' | 'model' | 'blacklist' | 'cert';
}

export interface MitreAttackRef {
  tactic: string;
  technique_id: string;
  technique_name: string;
}

export interface ThreatIntelRef {
  profile_match: string | null;
  intel_source: string | null;
  associated_playbooks: string[];
}

export interface AlertRecord {
  alert_id: string;
  timestamp: string;
  threat_class: ThreatClass;
  severity: Severity;
  evidence: EvidenceItem[];
  flow_id?: string;
  direction?: Direction;
  confidence: number;
  source?: Endpoint;
  destination?: Endpoint;
  protocol?: string;
  mitre_attack?: MitreAttackRef;
  threat_intel?: ThreatIntelRef;
  chain_id?: string;
  narration?: string;
  model_version: string;
  ledger_block_height?: number;
  ledger_leaf_hash?: string;
}

export interface LedgerSummary {
  block_height: number;
  head_hash: string | null;
  last_commit: string | null;
  chain_ok: boolean | null;
}

export interface BenchmarkStats {
  packets_per_second: number;
  throughput_mbps: number;
  packets_processed: number;
}

export interface AlertsResponse {
  alerts: AlertRecord[];
  threat_counts: Record<ThreatClass, number>;
  ledger: LedgerSummary;
  stats: BenchmarkStats & { total_alerts: number };
  generated_at: string;
}

export interface VerifyResponse {
  ok: boolean;
  blocks_verified: number;
  errors: string[];
  verify_time_ms: number;
  note?: string;
}

export interface HealthResponse {
  status: string;
  ledger_path: string;
  ledger_exists: boolean;
  timestamp: string;
}
