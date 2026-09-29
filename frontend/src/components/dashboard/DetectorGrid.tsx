'use client';

import { useAlerts } from '@/hooks/useAlerts';
import { DETECTOR_LIST } from '@/lib/threatMeta';
import type { ThreatClass } from '@/types/trinetra';
import styles from './DetectorGrid.module.css';

interface Props {
  initialData?: import('@/types/trinetra').AlertsResponse;
}

export function DetectorGrid({ initialData }: Props) {
  const { data } = useAlerts(initialData);
  const counts = (data?.threat_counts ?? {}) as Partial<Record<ThreatClass, number>>;

  return (
    <div className={styles.card}>
      <div className={styles.header}>
        <div className={styles.title}>Detector Status</div>
      </div>
      <div className={styles.grid}>
        {DETECTOR_LIST.map((det, i) => {
          const totalHits = det.keys.reduce(
            (sum, k) => sum + (counts[k as ThreatClass] ?? 0),
            0,
          );
          const triggered = totalHits > 0;
          return (
            <div
              key={i}
              className={`${styles.detector} ${triggered ? styles.triggered : ''}`}
            >
              <div className={styles.detLeft}>
                <div
                  className={styles.dot}
                  style={{
                    background: triggered ? 'var(--accent-alert)' : 'var(--accent-ok)',
                    opacity: triggered ? 1 : 0.45,
                  }}
                />
                <div>
                  <div className={styles.detName}>{det.name}</div>
                  <div className={styles.detId}>{det.id}</div>
                </div>
              </div>
              {triggered && (
                <span className={styles.hitCount}>{totalHits}</span>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
