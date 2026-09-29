'use client';

import { useMemo, useState } from 'react';
import Link from 'next/link';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { useAlerts } from '@/hooks/useAlerts';
import type { AlertsResponse, Severity } from '@/types/trinetra';
import { THREAT_META } from '@/lib/threatMeta';
import {
  bucketByMinute,
  formatTimeShort,
  formatTimestamp,
} from '@/lib/formatters';
import { HashDisplay } from '@/components/ui/HashDisplay';
import { API_BASE } from '@/lib/api';
import styles from './LedgerDashboard.module.css';


const SEV_COLOR: Record<Severity, string> = {
  CRITICAL: '#ee0000',
  HIGH: '#f5a623',
  MEDIUM: '#a1a1a1',
  LOW: '#0c8c4a',
  INFO: '#666666',
};

const tipStyle = {
  background: '#111',
  border: '1px solid #333',
  borderRadius: 8,
  fontFamily: 'var(--font-mono)',
  fontSize: 12,
  color: '#ededed',
};

interface Props {
  initialData?: AlertsResponse;
}

export function LedgerDashboard({ initialData }: Props) {
  const { data, isConnected } = useAlerts(initialData);
  const alerts = data?.alerts ?? [];
  const ledger = data?.ledger;

  const [verifyState, setVerifyState] = useState<'idle' | 'loading' | 'ok' | 'error'>('idle');
  const [verifyMsg, setVerifyMsg] = useState('');

  const sevData = useMemo(() => {
    const bag: Record<Severity, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    };
    for (const a of alerts) bag[a.severity] = (bag[a.severity] ?? 0) + 1;
    return (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as Severity[])
      .map((s) => ({ name: s.slice(0, 4), full: s, count: bag[s], fill: SEV_COLOR[s] }))
      .filter((d) => d.count > 0);
  }, [alerts]);

  const timeline = useMemo(
    () => bucketByMinute(alerts.map((a) => a.timestamp), 12),
    [alerts],
  );

  const sealed = useMemo(
    () =>
      [...alerts].sort((a, b) =>
        String(b.timestamp).localeCompare(String(a.timestamp)),
      ),
    [alerts],
  );

  const withLeaf = alerts.filter((a) => a.ledger_leaf_hash).length;
  const chainOk = ledger?.chain_ok === true;
  const height = ledger?.block_height ?? 0;

  async function runVerify() {
    setVerifyState('loading');
    setVerifyMsg('');
    try {
      const res = await fetch(`${API_BASE}/api/verify`);
      const d = await res.json();
      if (d.ok) {
        setVerifyState('ok');
        setVerifyMsg(
          `${d.blocks_verified} blocks verified · ${d.verify_time_ms?.toFixed?.(1) ?? '—'}ms`,
        );
      } else {
        setVerifyState('error');
        setVerifyMsg(`${d.errors?.length ?? '?'} error(s) found`);
      }
    } catch {
      setVerifyState('error');
      setVerifyMsg('API unavailable');
    }
  }

  return (
    <div className={styles.page}>
      <section className={styles.kpiRow} aria-label="Ledger metrics">
        <div className={styles.kpi}>
          <div className={styles.kpiLabel}>Block height</div>
          <div className={styles.kpiValue}>{height}</div>
          <div className={styles.kpiHint}>Merkle commits</div>
        </div>
        <div className={styles.kpi}>
          <div className={styles.kpiLabel}>Sealed alerts</div>
          <div className={styles.kpiValue}>{alerts.length}</div>
          <div className={styles.kpiHint}>{withLeaf} with leaf hash</div>
        </div>
        <div
          className={styles.kpi}
          data-tone={chainOk ? 'ok' : height ? 'warn' : ''}
        >
          <div className={styles.kpiLabel}>Chain</div>
          <div className={styles.kpiValue}>
            {chainOk ? 'Verified' : height ? 'Unverified' : 'Empty'}
          </div>
          <div className={styles.kpiHint}>Ed25519 + Merkle</div>
        </div>
        <div className={styles.kpi} data-tone={isConnected ? 'ok' : 'warn'}>
          <div className={styles.kpiLabel}>Feed</div>
          <div className={styles.kpiValue}>{isConnected ? 'Live' : 'Offline'}</div>
          <div className={styles.kpiHint}>Poll · 2.5s</div>
        </div>
      </section>

      <section className={styles.midGrid}>
        <div className={styles.panel}>
          <div className={styles.panelHead}>
            <div>
              <h2 className={styles.panelTitle}>Chain head</h2>
              <p className={styles.panelSub}>Current Merkle tip · copy to audit</p>
            </div>
            <div className={styles.actions}>
              <a className={styles.btn} href={`${API_BASE}/api/stix`} download="trinetra_stix21.json">
                Export STIX
              </a>

              <button
                type="button"
                className={styles.btnPrimary}
                onClick={runVerify}
                disabled={verifyState === 'loading'}
              >
                {verifyState === 'loading' ? 'Verifying…' : 'Verify chain'}
              </button>
            </div>
          </div>

          <div className={styles.headBody}>
            <div className={styles.headStat}>
              <span className={styles.k}>Head hash</span>
              {ledger?.head_hash ? (
                <HashDisplay hash={ledger.head_hash} chars={52} />
              ) : (
                <span className={styles.mono}>—</span>
              )}
            </div>
            <div className={styles.headMeta}>
              <div>
                <span className={styles.k}>Last commit</span>
                <span className={styles.mono}>{formatTimestamp(ledger?.last_commit)}</span>
              </div>
              <div>
                <span className={styles.k}>Algorithm</span>
                <span className={styles.mono}>Ed25519 + SHA-256 Merkle</span>
              </div>
              <div>
                <span className={styles.k}>Status</span>
                <span
                  className={styles.chain}
                  data-ok={chainOk ? '1' : '0'}
                >
                  {chainOk ? 'Verified' : height ? 'Verify required' : 'No blocks'}
                </span>
              </div>
            </div>
            {verifyMsg ? (
              <div
                className={styles.verifyMsg}
                data-ok={verifyState === 'ok' ? '1' : '0'}
              >
                {verifyMsg}
              </div>
            ) : null}
          </div>
        </div>

        <div className={styles.chartsCol}>
          <div className={styles.panel}>
            <div className={styles.panelHead}>
              <h2 className={styles.panelTitle}>Sealed by severity</h2>
            </div>
            <div className={styles.chartPad}>
              {sevData.length === 0 ? (
                <div className={styles.emptySm}>No sealed alerts.</div>
              ) : (
                <ResponsiveContainer width="100%" height={140}>
                  <BarChart
                    data={sevData}
                    layout="vertical"
                    margin={{ top: 0, right: 8, left: 0, bottom: 0 }}
                  >
                    <XAxis type="number" hide />
                    <YAxis
                      type="category"
                      dataKey="name"
                      width={44}
                      tickLine={false}
                      axisLine={false}
                      tick={{ fill: '#a1a1a1', fontSize: 11, fontFamily: 'var(--font-mono)' }}
                    />
                    <Tooltip
                      cursor={{ fill: 'rgba(255,255,255,0.03)' }}
                      contentStyle={tipStyle}
                      formatter={(v, _n, item) => [v, item?.payload?.full ?? '']}
                    />
                    <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={12}>
                      {sevData.map((d) => (
                        <Cell key={d.full} fill={d.fill} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>

          <div className={styles.panel}>
            <div className={styles.panelHead}>
              <div>
                <h2 className={styles.panelTitle}>Commit volume</h2>
                <p className={styles.panelSub}>Alerts / min · 12 min</p>
              </div>
            </div>
            <div className={styles.chartPadWide}>
              <ResponsiveContainer width="100%" height={120}>
                <AreaChart data={timeline} margin={{ top: 4, right: 8, left: -12, bottom: 0 }}>
                  <defs>
                    <linearGradient id="ledVol" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#0c8c4a" stopOpacity={0.28} />
                      <stop offset="100%" stopColor="#0c8c4a" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="#222" vertical={false} strokeDasharray="3 3" />
                  <XAxis
                    dataKey="time"
                    tickLine={false}
                    axisLine={false}
                    interval={2}
                    tick={{ fill: '#666', fontSize: 10, fontFamily: 'var(--font-mono)' }}
                  />
                  <YAxis
                    allowDecimals={false}
                    width={24}
                    tickLine={false}
                    axisLine={false}
                    tick={{ fill: '#666', fontSize: 10, fontFamily: 'var(--font-mono)' }}
                  />
                  <Tooltip contentStyle={tipStyle} />
                  <Area
                    type="monotone"
                    dataKey="count"
                    stroke="#0c8c4a"
                    strokeWidth={2}
                    fill="url(#ledVol)"
                    dot={false}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      </section>

      <section className={styles.panel}>
        <div className={styles.panelHead}>
          <div>
            <h2 className={styles.panelTitle}>Sealed alerts</h2>
            <p className={styles.panelSub}>
              Forensic chain-of-custody · leaf hashes when present
            </p>
          </div>
          <span className={styles.count}>{sealed.length}</span>
        </div>

        {sealed.length === 0 ? (
          <div className={styles.empty}>No alerts sealed to the ledger yet.</div>
        ) : (
          <div className={styles.tableWrap}>
            <table className={styles.table}>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Alert</th>
                  <th>Class</th>
                  <th>Sev</th>
                  <th>Conf</th>
                  <th>Leaf</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                {sealed.map((a, i) => {
                  const meta = THREAT_META[a.threat_class] ?? THREAT_META.UNKNOWN_ANOMALY;
                  return (
                    <tr key={a.alert_id}>
                      <td className={styles.num}>{sealed.length - i}</td>
                      <td>
                        <Link href={`/forensics/${a.alert_id}`} className={styles.idLink}>
                          {a.alert_id.slice(0, 18)}…
                        </Link>
                      </td>
                      <td className={styles.cls}>{meta.label}</td>
                      <td>
                        <span className={styles.sev} style={{ color: SEV_COLOR[a.severity] }}>
                          {a.severity}
                        </span>
                      </td>
                      <td className={styles.mono}>{Math.round(a.confidence * 100)}%</td>
                      <td>
                        {a.ledger_leaf_hash ? (
                          <HashDisplay hash={a.ledger_leaf_hash} chars={14} />
                        ) : (
                          <span className={styles.mono}>—</span>
                        )}
                      </td>
                      <td className={styles.mono}>{formatTimeShort(a.timestamp)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
