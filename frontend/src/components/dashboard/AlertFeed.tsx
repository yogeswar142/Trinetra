'use client';

import { useState, useCallback } from 'react';
import type { AlertRecord } from '@/types/trinetra';
import { useAlerts } from '@/hooks/useAlerts';
import { AlertRow } from './AlertRow';
import { EvidenceDrawer } from './EvidenceDrawer';
import { LiveIndicator } from '@/components/ui/LiveIndicator';
import styles from './AlertFeed.module.css';

interface Props {
  initialData?: import('@/types/trinetra').AlertsResponse;
}

const MAX_ROWS = 100;

export function AlertFeed({ initialData }: Props) {
  const { data, isConnected } = useAlerts(initialData);
  const [selected, setSelected] = useState<AlertRecord | null>(null);

  const alerts = data?.alerts ?? [];
  const recent = alerts.slice(-MAX_ROWS).reverse();

  const handleRowClick = useCallback((alert: AlertRecord) => {
    setSelected((prev) => (prev?.alert_id === alert.alert_id ? null : alert));
  }, []);

  const handleClose = useCallback(() => setSelected(null), []);

  return (
    <>
      <div className={styles.card}>
        {/* Header */}
        <div className={styles.header}>
          <div className={styles.title}>Live Alert Feed</div>
          <div className={styles.headerRight}>
            <LiveIndicator connected={isConnected} />
            <span className={styles.badge}>{alerts.length} alerts</span>
          </div>
        </div>

        {/* Table */}
        <div className={styles.tableWrap}>
          <table className={styles.table}>
            <thead>
              <tr>
                <th>Threat Class</th>
                <th>Sev</th>
                <th>Confidence</th>
                <th>Source → Destination</th>
                <th>MITRE</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {recent.length === 0 ? (
                <tr>
                  <td colSpan={6}>
                    <div className={styles.emptyState}>
                      <div className={styles.emptyTitle}>No alerts yet</div>
                      <div className={styles.emptyHint}>
                        Run the Trinetra pipeline to see live detections
                      </div>
                    </div>
                  </td>
                </tr>
              ) : (
                recent.map((alert, i) => (
                  <AlertRow
                    key={alert.alert_id}
                    alert={alert}
                    isNew={i === 0}
                    isSelected={selected?.alert_id === alert.alert_id}
                    onClick={handleRowClick}
                  />
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Evidence drawer slides in from right */}
      {selected && (
        <EvidenceDrawer alert={selected} onClose={handleClose} />
      )}
    </>
  );
}
