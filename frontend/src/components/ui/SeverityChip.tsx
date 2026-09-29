import type { Severity } from '@/types/trinetra';
import styles from './SeverityChip.module.css';

const SEV_STYLES: Record<Severity, { color: string; bg: string; border: string }> = {
  CRITICAL: { color: '#ee0000', bg: 'rgba(238,0,0,0.08)', border: 'rgba(238,0,0,0.25)' },
  HIGH:     { color: '#f5a623', bg: 'rgba(245,166,35,0.08)', border: 'rgba(245,166,35,0.25)' },
  MEDIUM:   { color: '#a1a1a1', bg: 'rgba(161,161,161,0.08)', border: 'rgba(161,161,161,0.25)' },
  LOW:      { color: '#0c8c4a', bg: 'rgba(12,140,74,0.08)', border: 'rgba(12,140,74,0.25)' },
  INFO:     { color: '#666666', bg: 'transparent', border: 'rgba(102,102,102,0.35)' },
};

export function SeverityChip({ severity }: { severity: Severity }) {
  const s = SEV_STYLES[severity] ?? SEV_STYLES.INFO;
  return (
    <span
      className={styles.chip}
      style={{ color: s.color, background: s.bg, border: `1px solid ${s.border}` }}
    >
      {severity}
    </span>
  );
}
