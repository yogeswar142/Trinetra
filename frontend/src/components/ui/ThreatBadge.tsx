import type { ThreatClass } from '@/types/trinetra';
import { THREAT_META } from '@/lib/threatMeta';
import styles from './ThreatBadge.module.css';

interface Props {
  threatClass: ThreatClass;
  size?: 'sm' | 'md';
}

export function ThreatBadge({ threatClass, size = 'md' }: Props) {
  const meta = THREAT_META[threatClass] ?? THREAT_META.UNKNOWN_ANOMALY;
  return (
    <span
      className={`${styles.badge} ${size === 'sm' ? styles.sm : ''}`}
      style={{
        color: meta.color,
        background: meta.bgAlpha,
        border: `1px solid ${meta.borderAlpha}`,
      }}
    >
      {meta.label}
    </span>
  );
}
