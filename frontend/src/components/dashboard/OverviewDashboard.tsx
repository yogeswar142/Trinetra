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
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import type { AlertsResponse, Severity, ThreatClass } from '@/types/trinetra';
import { useAlerts } from '@/hooks/useAlerts';
import { DETECTOR_LIST, THREAT_META } from '@/lib/threatMeta';
import {
  bucketByMinute,
  formatMbps,
  formatPPS,
  formatTimeShort,
  formatTimestamp,
} from '@/lib/formatters';
import { HashDisplay } from '@/components/ui/HashDisplay';
import { API_BASE } from '@/lib/api';
import styles from './OverviewDashboard.module.css';


const SEV_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
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
  boxShadow: 'none',
};

interface Props {
  initialData?: AlertsResponse;
}

export function OverviewDashboard({ initialData }: Props) {
  const { data, isConnected } = useAlerts(initialData);
  const alerts = data?.alerts ?? [];
  const stats = data?.stats;
  const ledger = data?.ledger;
  const counts = data?.threat_counts ?? {};

  const criticalHigh = useMemo(
    () =>
      [...alerts]
        .filter((a) => a.severity === 'CRITICAL' || a.severity === 'HIGH')
        .sort((a, b) => b.timestamp.localeCompare(a.timestamp))
        .slice(0, 8),
    [alerts],
  );

  const recent = useMemo(
    () => [...alerts].sort((a, b) => b.timestamp.localeCompare(a.timestamp)).slice(0, 8),
    [alerts],
  );

  const queue = criticalHigh.length > 0 ? criticalHigh : recent;
  const queueMode = criticalHigh.length > 0 ? 'critical/high' : 'latest';

  const severityData = useMemo(() => {
    const bag: Record<Severity, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    };
    for (const a of alerts) bag[a.severity] = (bag[a.severity] ?? 0) + 1;
    return SEV_ORDER.map((sev) => ({
      name: sev,
      count: bag[sev],
      fill: SEV_COLOR[sev],
    })).filter((d) => d.count > 0);
  }, [alerts]);

  const threatData = useMemo(
    () =>
      Object.entries(counts as Record<string, number>)
        .filter(([, v]) => v > 0)
        .map(([key, value]) => {
          const meta = THREAT_META[key as ThreatClass] ?? THREAT_META.UNKNOWN_ANOMALY;
          return { name: meta.shortLabel, full: meta.label, value, color: meta.color };
        })
        .sort((a, b) => b.value - a.value),
    [counts],
  );

  const timeline = useMemo(
    () => bucketByMinute(alerts.map((a) => a.timestamp), 12),
    [alerts],
  );

  const detectors = useMemo(
    () =>
      DETECTOR_LIST.map((det) => {
        const hits = det.keys.reduce(
          (sum, k) => sum + ((counts as Record<string, number>)[k] ?? 0),
          0,
        );
        return { ...det, hits };
      }),
    [counts],
  );

  const threatTotal = threatData.reduce((s, d) => s + d.value, 0);
  const pipelineOk = isConnected;

  return (
    <div className={styles.page}>
      {/* ── KPI strip ── */}
      <section className={styles.kpiRow} aria-label="Key metrics">
        <Kpi
          label="Packets / sec"
          value={formatPPS(stats?.packets_per_second ?? 0)}
          hint={formatMbps(stats?.throughput_mbps ?? 0)}
        />
        <Kpi
          label="Active alerts"
          value={String(stats?.total_alerts ?? alerts.length)}
          hint={`${criticalHigh.length} critical / high`}
          tone={criticalHigh.length > 0 ? 'alert' : undefined}
        />
        <Kpi
          label="Ledger height"
          value={String(ledger?.block_height ?? 0)}
          hint={ledger?.chain_ok ? 'Chain verified' : 'Verify required'}
        />
        <Kpi
          label="Pipeline"
          value={pipelineOk ? 'Nominal' : 'Degraded'}
          hint={pipelineOk ? 'Detectors armed' : 'API unreachable'}
          tone={pipelineOk ? 'ok' : 'warn'}
        />
      </section>

      {/* ── Triage + charts ── */}
      <section className={styles.mainGrid}>
        <div className={styles.panel}>
          <div className={styles.panelHead}>
            <div>
              <h2 className={styles.panelTitle}>Hot queue</h2>
              <p className={styles.panelSub}>
                {queue.length} {queueMode} · work these next
              </p>
            </div>
            <Link href="/alerts" className={styles.panelLink}>
              Open alerts
            </Link>
          </div>

          {queue.length === 0 ? (
            <div className={styles.empty}>No alerts in the ledger yet.</div>
          ) : (
            <div className={styles.tableWrap}>
              <table className={styles.table}>
                <thead>
                  <tr>
                    <th>Sev</th>
                    <th>Class</th>
                    <th>Flow</th>
                    <th>Conf</th>
                    <th>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {queue.map((a) => (
                    <tr key={a.alert_id}>
                      <td>
                        <span
                          className={styles.sev}
                          style={{ color: SEV_COLOR[a.severity] }}
                        >
                          {a.severity}
                        </span>
                      </td>
                      <td>
                        <Link href={`/forensics/${a.alert_id}`} className={styles.clsLink}>
                          {(THREAT_META[a.threat_class] ?? THREAT_META.UNKNOWN_ANOMALY).label}
                        </Link>
                      </td>
                      <td className={styles.mono}>
                        {a.source?.ip ?? '—'} → {a.destination?.ip ?? '—'}
                      </td>
                      <td className={styles.mono}>{Math.round(a.confidence * 100)}%</td>
                      <td className={styles.mono}>{formatTimeShort(a.timestamp)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className={styles.sideCharts}>
          <div className={styles.panel}>
            <div className={styles.panelHead}>
              <h2 className={styles.panelTitle}>Severity</h2>
            </div>
            <div className={styles.chartPad}>
              {severityData.length === 0 ? (
                <div className={styles.empty}>No severity data.</div>
              ) : (
                <ResponsiveContainer width="100%" height={160}>
                  <BarChart
                    data={severityData}
                    layout="vertical"
                    margin={{ top: 0, right: 12, left: 4, bottom: 0 }}
                  >
                    <XAxis type="number" hide />
                    <YAxis
                      type="category"
                      dataKey="name"
                      width={72}
                      tickLine={false}
                      axisLine={false}
                      tick={{ fill: '#a1a1a1', fontSize: 11, fontFamily: 'var(--font-mono)' }}
                    />
                    <Tooltip
                      cursor={{ fill: 'rgba(255,255,255,0.03)' }}
                      contentStyle={tipStyle}
                    />
                    <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={14}>
                      {severityData.map((d) => (
                        <Cell key={d.name} fill={d.fill} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>

          <div className={styles.panel}>
            <div className={styles.panelHead}>
              <h2 className={styles.panelTitle}>By threat class</h2>
              <span className={styles.panelMeta}>{threatTotal}</span>
            </div>
            <div className={styles.donutRow}>
              <div className={styles.donutWrap}>
                <ResponsiveContainer width="100%" height={140}>
                  <PieChart>
                    <Pie
                      data={
                        threatData.length > 0
                          ? threatData
                          : [{ name: 'None', value: 1, color: '#1a1a1a' }]
                      }
                      dataKey="value"
                      cx="50%"
                      cy="50%"
                      innerRadius={40}
                      outerRadius={58}
                      paddingAngle={threatData.length > 1 ? 2 : 0}
                      strokeWidth={0}
                    >
                      {(threatData.length > 0
                        ? threatData
                        : [{ name: 'None', value: 1, color: '#1a1a1a' }]
                      ).map((e, i) => (
                        <Cell key={i} fill={e.color} />
                      ))}
                    </Pie>
                    {threatTotal > 0 ? <Tooltip contentStyle={tipStyle} /> : null}
                  </PieChart>
                </ResponsiveContainer>
                <div className={styles.donutCenter}>
                  <span className={styles.donutValue}>{threatTotal}</span>
                </div>
              </div>
              <ul className={styles.legend}>
                {threatData.length === 0 ? (
                  <li className={styles.empty}>No classes yet</li>
                ) : (
                  threatData.slice(0, 5).map((d) => (
                    <li key={d.full}>
                      <span className={styles.dot} style={{ background: d.color }} />
                      <span className={styles.legName}>{d.name}</span>
                      <span className={styles.legVal}>{d.value}</span>
                    </li>
                  ))
                )}
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* ── Timeline ── */}
      <section className={styles.panel}>
        <div className={styles.panelHead}>
          <div>
            <h2 className={styles.panelTitle}>Alert volume</h2>
            <p className={styles.panelSub}>Alerts sealed per minute · last 12 min</p>
          </div>
        </div>
        <div className={styles.chartPadWide}>
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={timeline} margin={{ top: 8, right: 12, left: -8, bottom: 0 }}>
              <defs>
                <linearGradient id="ovVol" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#0070f3" stopOpacity={0.28} />
                  <stop offset="100%" stopColor="#0070f3" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="#222" vertical={false} strokeDasharray="3 3" />
              <XAxis
                dataKey="time"
                tickLine={false}
                axisLine={false}
                tick={{ fill: '#666', fontSize: 11, fontFamily: 'var(--font-mono)' }}
                interval={1}
              />
              <YAxis
                allowDecimals={false}
                width={28}
                tickLine={false}
                axisLine={false}
                tick={{ fill: '#666', fontSize: 11, fontFamily: 'var(--font-mono)' }}
              />
              <Tooltip contentStyle={tipStyle} />
              <Area
                type="monotone"
                dataKey="count"
                stroke="#0070f3"
                strokeWidth={2}
                fill="url(#ovVol)"
                dot={false}
                activeDot={{ r: 3, fill: '#0070f3', stroke: '#000', strokeWidth: 2 }}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </section>

      {/* ── Bottom: detectors + ledger ── */}
      <section className={styles.bottomGrid}>
        <div className={styles.panel}>
          <div className={styles.panelHead}>
            <h2 className={styles.panelTitle}>Detectors</h2>
            <Link href="/sensor" className={styles.panelLink}>
              Sensor
            </Link>
          </div>
          <ul className={styles.detList}>
            {detectors.map((d) => (
              <li key={`${d.id}-${d.name}`} className={styles.detRow}>
                <span
                  className={styles.detDot}
                  data-hot={d.hits > 0 ? '1' : '0'}
                />
                <div className={styles.detCopy}>
                  <span className={styles.detName}>{d.name}</span>
                  <span className={styles.detId}>{d.id}</span>
                </div>
                <span className={styles.detHits}>{d.hits}</span>
              </li>
            ))}
          </ul>
        </div>

        <LedgerPanel
          height={ledger?.block_height ?? 0}
          head={ledger?.head_hash ?? null}
          last={ledger?.last_commit ?? null}
          chainOk={ledger?.chain_ok ?? null}
        />
      </section>
    </div>
  );
}

function Kpi({
  label,
  value,
  hint,
  tone,
}: {
  label: string;
  value: string;
  hint?: string;
  tone?: 'alert' | 'ok' | 'warn';
}) {
  return (
    <div className={styles.kpi} data-tone={tone ?? ''}>
      <div className={styles.kpiLabel}>{label}</div>
      <div className={styles.kpiValue}>{value}</div>
      {hint ? <div className={styles.kpiHint}>{hint}</div> : null}
    </div>
  );
}

function LedgerPanel({
  height,
  head,
  last,
  chainOk,
}: {
  height: number;
  head: string | null;
  last: string | null;
  chainOk: boolean | null;
}) {
  const [state, setState] = useState<'idle' | 'loading' | 'ok' | 'error'>('idle');
  const [msg, setMsg] = useState('');

  async function verify() {
    setState('loading');
    setMsg('');
    try {
      const res = await fetch(`${API_BASE}/api/verify`);

      const d = await res.json();
      if (d.ok) {
        setState('ok');
        setMsg(`${d.blocks_verified} blocks · ${d.verify_time_ms?.toFixed?.(1) ?? '—'}ms`);
      } else {
        setState('error');
        setMsg(`${d.errors?.length ?? '?'} error(s)`);
      }
    } catch {
      setState('error');
      setMsg('API unavailable');
    }
  }

  return (
    <div className={styles.panel}>
      <div className={styles.panelHead}>
        <h2 className={styles.panelTitle}>Forensic ledger</h2>
        <Link href="/ledger" className={styles.panelLink}>
          Full ledger
        </Link>
      </div>

      <div className={styles.ledgerBody}>
        <div className={styles.ledgerStat}>
          <span className={styles.kpiLabel}>Block height</span>
          <span className={styles.ledgerHeight}>{height}</span>
        </div>
        <div className={styles.ledgerStat}>
          <span className={styles.kpiLabel}>Head hash</span>
          <HashDisplay hash={head} chars={22} />
        </div>
        <div className={styles.ledgerStat}>
          <span className={styles.kpiLabel}>Last commit</span>
          <span className={styles.mono}>{formatTimestamp(last)}</span>
        </div>
        <div className={styles.ledgerStat}>
          <span className={styles.kpiLabel}>Chain</span>
          <span
            className={styles.chain}
            data-ok={chainOk === true ? '1' : '0'}
          >
            {chainOk === true ? 'Verified' : height ? 'Unverified' : 'Empty'}
          </span>
        </div>

        <button
          type="button"
          className={styles.verify}
          onClick={verify}
          disabled={state === 'loading'}
        >
          {state === 'loading' ? 'Verifying…' : 'Verify chain'}
        </button>
        {msg ? (
          <div className={styles.verifyMsg} data-ok={state === 'ok' ? '1' : '0'}>
            {msg}
          </div>
        ) : null}
      </div>
    </div>
  );
}
