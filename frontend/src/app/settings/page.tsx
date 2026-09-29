import { AppShell } from '@/components/layout/AppShell';
import styles from './page.module.css';

const ROWS = [
  ['Sensor Mode', 'Receive-only / data-diode'],
  ['Decrypt', 'Disabled (metadata-only)'],
  ['Streaming', 'Windowed incremental alerts'],
  ['Ledger', 'Ed25519 + Merkle hash chain'],
  ['Ollama Narration', 'Disabled by default'],
  ['Dashboard Bind', '0.0.0.0:8765 (SOC net)'],
  ['Design', 'Geist Dark Ops · design.md'],
  ['Team', 'ThreatNexus · SIH26145'],
];

export default function SettingsPage() {
  return (
    <AppShell
      title="Settings"
      description="What posture is this enclave running under?"
    >
      <div className={styles.panel}>
        {ROWS.map(([k, v]) => (
          <div key={k} className={styles.row}>
            <span className={styles.k}>{k}</span>
            <span className={styles.v}>{v}</span>
          </div>
        ))}
      </div>
    </AppShell>
  );
}
