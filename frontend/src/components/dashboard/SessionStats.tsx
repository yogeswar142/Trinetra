'use client';

import { useEffect, useState } from 'react';
import { useAlerts } from '@/hooks/useAlerts';
import { formatUptime, formatPackets, formatMbps } from '@/lib/formatters';
import styles from './SessionStats.module.css';

const SESSION_START = Date.now();

interface Props {
  initialData?: import('@/types/trinetra').AlertsResponse;
}

export function SessionStats({ initialData }: Props) {
  const { data } = useAlerts(initialData);
  const [uptime, setUptime] = useState('00:00:00');

  useEffect(() => {
    const id = setInterval(() => setUptime(formatUptime(SESSION_START)), 1000);
    return () => clearInterval(id);
  }, []);

  const stats = data?.stats;

  const rows = [
    ['Uptime',         uptime],
    ['Total Alerts',   String(stats?.total_alerts ?? 0)],
    ['Pkts Processed', formatPackets(stats?.packets_processed ?? 0)],
    ['Throughput',     formatMbps(stats?.throughput_mbps ?? 0)],
    ['Ingest Mode',    'PCAP / NetFlow v9'],
    ['Model',          'trinetra-v0.2.0'],
  ] as const;

  return (
    <div className={styles.card}>
      <div className={styles.header}>
        <div className={styles.title}>Session Stats</div>
      </div>
      <div className={styles.body}>
        {rows.map(([label, value]) => (
          <div key={label} className={styles.row}>
            <span className={styles.label}>{label}</span>
            <span className={styles.value}>{value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
