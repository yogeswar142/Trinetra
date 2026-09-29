import { formatConfidencePct } from '@/lib/formatters';
import styles from './ConfidenceBar.module.css';

export function ConfidenceBar({ confidence }: { confidence: number }) {
  const pct = formatConfidencePct(confidence);
  const color =
    pct >= 80 ? '#22C55E' :
    pct >= 60 ? '#F5C518' :
                '#E84545';
  return (
    <div className={styles.wrap}>
      <div className={styles.track}>
        <div
          className={styles.fill}
          style={{ width: `${pct}%`, background: color }}
        />
      </div>
      <span className={styles.label} style={{ color }}>{pct}%</span>
    </div>
  );
}
