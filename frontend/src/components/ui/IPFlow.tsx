import type { Endpoint } from '@/types/trinetra';
import styles from './IPFlow.module.css';

interface Props {
  source?: Endpoint;
  destination?: Endpoint;
}

export function IPFlow({ source, destination }: Props) {
  const src = source?.ip ?? '—';
  const dst = destination?.ip ?? '—';
  return (
    <div className={styles.flow}>
      <span className={styles.src}>{src}</span>
      <span className={styles.arrow}>→</span>
      <span className={styles.dst}>{dst}</span>
    </div>
  );
}
