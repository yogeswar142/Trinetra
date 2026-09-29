'use client';

import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import {
  Bar,
  BarChart,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { useAlerts } from '@/hooks/useAlerts';
import type { AlertsResponse, HealthResponse, ThreatClass } from '@/types/trinetra';
import { DETECTOR_LIST } from '@/lib/threatMeta';
import {
  formatMbps,
  formatPackets,
  formatPPS,
  formatUptime,
} from '@/lib/formatters';
import styles from './SensorDashboard.module.css';

const MODELS = [
  { id: 't_a_ddos', cls: 'T-a Volumetric DDoS', type: 'RandomForest', cal: true },
  { id: 't_b_beacon', cls: 'T-b C2 Beaconing', type: 'RandomForest', cal: true },
  { id: 't_c_dga', cls: 'T-c DGA Domains', type: 'RandomForest', cal: true },
  { id: 't_c_dns_tunnel', cls: 'T-c DNS Tunnel', type: 'RandomForest', cal: true },
  { id: 't_e_portscan', cls: 'T-e Port Scan', type: 'RandomForest', cal: true },
  { id: 't_f_exfil', cls: 'T-f Exfiltration', type: 'RandomForest', cal: true },
  { id: 't_d_tls', cls: 'T-d TLS Malware', type: 'JA3 + PST rules', cal: false },
] as const;

const tipStyle = {
  background: '#111',
  border: '1px solid #333',
  borderRadius: 8,
  fontFamily: 'var(--font-mono)',
  fontSize: 12,
  color: '#ededed',
};

const SESSION_START = Date.now();

interface Props {
  initialData?: AlertsResponse;
}

export function SensorDashboard({ initialData }: Props) {
  const { data, isConnected } = useAlerts(initialData);
  const stats = data?.stats;
  const counts = data?.threat_counts ?? {};
  const [uptime, setUptime] = useState('00:00:00');
  const [health, setHealth] = useState<HealthResponse | null>(null);

  useEffect(() => {
    const id = setInterval(() => setUptime(formatUptime(SESSION_START)), 1000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const res = await fetch('/api/health', { cache: 'no-store' });
        if (!res.ok) return;
        const json = (await res.json()) as HealthResponse;
        if (!cancelled) setHealth(json);
      } catch {
        /* ignore */
      }
    }
    load();
    const id = setInterval(load, 10000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  const detectors = useMemo(
    () =>
      DETECTOR_LIST.map((det) => {
        const hits = det.keys.reduce(
          (sum, k) => sum + ((counts as Record<string, number>)[k as ThreatClass] ?? 0),
          0,
        );
        return { ...det, hits };
      }),
    [counts],
  );

  const chartData = useMemo(
    () =>
      detectors.map((d) => ({
        name: d.id,
        full: d.name,
        hits: d.hits,
        fill: d.hits > 0 ? '#ee0000' : '#333333',
      })),
    [detectors],
  );

  const armed = detectors.length;
  const triggered = detectors.filter((d) => d.hits > 0).length;
  const calibrated = MODELS.filter((m) => m.cal).length;
  const healthOk = health?.status === 'ok' || health?.status === 'healthy';

  return (
    <div className={styles.page}>
      <section className={styles.kpiRow} aria-label="Sensor metrics">
        <div className={styles.kpi}>
          <div className={styles.kpiLabel}>Sustained PPS</div>
          <div className={styles.kpiValue}>
            {formatPPS(stats?.packets_per_second ?? 0)}
          </div>
          <div className={styles.kpiHint}>Benchmark v5 median</div>
        </div>
        <div className={styles.kpi}>
          <div className={styles.kpiLabel}>Throughput</div>
          <div className={styles.kpiValue}>
            {formatMbps(stats?.throughput_mbps ?? 0)}
          </div>
          <div className={styles.kpiHint}>
            {formatPackets(stats?.packets_processed ?? 0)} pkts sampled
          </div>
        </div>
        <div className={styles.kpi} data-tone="alert">
          <div className={styles.kpiLabel}>Transmit</div>
          <div className={styles.kpiValue}>Blocked</div>
          <div className={styles.kpiHint}>AST + runtime no-TX</div>
        </div>
        <div className={styles.kpi} data-tone={isConnected ? 'ok' : 'warn'}>
          <div className={styles.kpiLabel}>API / health</div>
          <div className={styles.kpiValue}>
            {isConnected ? (healthOk || !health ? 'Live' : health.status) : 'Offline'}
          </div>
          <div className={styles.kpiHint}>
            {health?.ledger_exists ? 'Ledger mounted' : 'Ledger check…'}
          </div>
        </div>
      </section>

      <section className={styles.mainGrid}>
        <div className={styles.panel}>
          <div className={styles.panelHead}>
            <div>
              <h2 className={styles.panelTitle}>Detector battery</h2>
              <p className={styles.panelSub}>
                {triggered} triggered · {armed} armed
              </p>
            </div>
            <Link href="/alerts" className={styles.panelLink}>
              Alerts
            </Link>
          </div>

          <div className={styles.chartPad}>
            <ResponsiveContainer width="100%" height={200}>
              <BarChart
                data={chartData}
                margin={{ top: 8, right: 12, left: -8, bottom: 0 }}
              >
                <XAxis
                  dataKey="name"
                  tickLine={false}
                  axisLine={false}
                  tick={{ fill: '#666', fontSize: 11, fontFamily: 'var(--font-mono)' }}
                />
                <YAxis
                  allowDecimals={false}
                  width={28}
                  tickLine={false}
                  axisLine={false}
                  tick={{ fill: '#666', fontSize: 11, fontFamily: 'var(--font-mono)' }}
                />
                <Tooltip
                  cursor={{ fill: 'rgba(255,255,255,0.03)' }}
                  contentStyle={tipStyle}
                  formatter={(v, _n, item) => [v, item?.payload?.full ?? 'Hits']}
                />
                <Bar dataKey="hits" radius={[4, 4, 0, 0]} barSize={28}>
                  {chartData.map((d) => (
                    <Cell key={d.name + d.full} fill={d.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          <ul className={styles.detList}>
            {detectors.map((d) => (
              <li key={`${d.id}-${d.name}`} className={styles.detRow}>
                <span className={styles.detDot} data-hot={d.hits > 0 ? '1' : '0'} />
                <div className={styles.detCopy}>
                  <span className={styles.detName}>{d.name}</span>
                  <span className={styles.detId}>{d.id}</span>
                </div>
                <span className={styles.detHits} data-hot={d.hits > 0 ? '1' : '0'}>
                  {d.hits}
                </span>
              </li>
            ))}
          </ul>
        </div>

        <aside className={styles.side}>
          <div className={styles.panel}>
            <div className={styles.panelHead}>
              <h2 className={styles.panelTitle}>Pipeline</h2>
            </div>
            <dl className={styles.stats}>
              <div>
                <dt>Uptime</dt>
                <dd className={styles.mono}>{uptime}</dd>
              </div>
              <div>
                <dt>Total alerts</dt>
                <dd className={styles.mono}>{stats?.total_alerts ?? 0}</dd>
              </div>
              <div>
                <dt>Packets</dt>
                <dd className={styles.mono}>
                  {formatPackets(stats?.packets_processed ?? 0)}
                </dd>
              </div>
              <div>
                <dt>Ingest</dt>
                <dd className={styles.mono}>PCAP / NetFlow v9</dd>
              </div>
              <div>
                <dt>Model set</dt>
                <dd className={styles.mono}>trinetra-v0.2.0</dd>
              </div>
              <div>
                <dt>Posture</dt>
                <dd className={styles.mono} data-tone="alert">
                  Receive-only
                </dd>
              </div>
            </dl>
          </div>

          <div className={styles.panel}>
            <div className={styles.panelHead}>
              <h2 className={styles.panelTitle}>Enclave health</h2>
            </div>
            <dl className={styles.stats}>
              <div>
                <dt>Status</dt>
                <dd className={styles.mono}>
                  {health?.status ?? (isConnected ? 'reachable' : 'unknown')}
                </dd>
              </div>
              <div>
                <dt>Ledger path</dt>
                <dd className={styles.monoSmall}>
                  {health?.ledger_path ?? '—'}
                </dd>
              </div>
              <div>
                <dt>Ledger exists</dt>
                <dd
                  className={styles.mono}
                  data-tone={health?.ledger_exists ? 'ok' : 'warn'}
                >
                  {health ? (health.ledger_exists ? 'Yes' : 'No') : '—'}
                </dd>
              </div>
              <div>
                <dt>Checked</dt>
                <dd className={styles.mono}>
                  {health?.timestamp
                    ? new Date(health.timestamp).toISOString().slice(11, 19) + 'Z'
                    : '—'}
                </dd>
              </div>
            </dl>
          </div>
        </aside>
      </section>

      <section className={styles.panel}>
        <div className={styles.panelHead}>
          <div>
            <h2 className={styles.panelTitle}>Model registry</h2>
            <p className={styles.panelSub}>
              Loaded only after Ed25519 manifest + SHA-256 verify · {calibrated}/
              {MODELS.length} calibrated
            </p>
          </div>
          <span className={styles.count}>{MODELS.length}</span>
        </div>

        <div className={styles.tableWrap}>
          <table className={styles.table}>
            <thead>
              <tr>
                <th>Artifact</th>
                <th>Class</th>
                <th>Engine</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {MODELS.map((m) => (
                <tr key={m.id}>
                  <td className={styles.mono}>{m.id}{m.cal ? '.joblib' : ''}</td>
                  <td className={styles.cls}>{m.cls}</td>
                  <td className={styles.mono}>{m.type}</td>
                  <td>
                    <span
                      className={styles.badge}
                      data-ok={m.cal ? '1' : '0'}
                    >
                      {m.cal ? 'Calibrated' : 'Heuristic'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
