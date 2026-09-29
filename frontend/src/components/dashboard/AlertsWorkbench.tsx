'use client';

import { useMemo, useState } from 'react';
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
import type { AlertRecord, AlertsResponse, Severity } from '@/types/trinetra';
import { THREAT_META } from '@/lib/threatMeta';
import { formatTimeShort, formatTimestamp } from '@/lib/formatters';
import { HashDisplay } from '@/components/ui/HashDisplay';
import { MitreTag } from '@/components/ui/MitreTag';
import { API_BASE } from '@/lib/api';
import styles from './AlertsWorkbench.module.css';


const SEV_RANK: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

const SEV_COLOR: Record<Severity, string> = {
  CRITICAL: '#ee0000',
  HIGH: '#f5a623',
  MEDIUM: '#a1a1a1',
  LOW: '#0c8c4a',
  INFO: '#666666',
};

const SEV_FILTERS: Array<Severity | 'ALL'> = [
  'ALL',
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
  'INFO',
];

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

function matchesQuery(a: AlertRecord, q: string): boolean {
  const raw = q.trim();
  if (!raw) return true;
  const blob = JSON.stringify(a).toLowerCase();
  if (raw.startsWith('class=')) {
    return a.threat_class.toLowerCase().includes(raw.slice(6).trim().toLowerCase());
  }
  if (raw.startsWith('severity=')) {
    return (a.severity ?? '').toLowerCase() === raw.slice(9).trim().toLowerCase();
  }
  if (raw.startsWith('confidence>')) {
    const n = parseFloat(raw.slice(11));
    return !Number.isNaN(n) && a.confidence > n;
  }
  if (raw.startsWith('src=')) {
    return (a.source?.ip ?? '').includes(raw.slice(4).trim());
  }
  if (raw.startsWith('dst=')) {
    return (a.destination?.ip ?? '').includes(raw.slice(4).trim());
  }
  return blob.includes(raw.toLowerCase());
}

export function AlertsWorkbench({ initialData }: Props) {
  const { data, isConnected } = useAlerts(initialData);
  const [q, setQ] = useState('');
  const [sev, setSev] = useState<Severity | 'ALL'>('ALL');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const alerts = data?.alerts ?? [];

  const sevCounts = useMemo(() => {
    const bag: Record<Severity, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    };
    for (const a of alerts) bag[a.severity] = (bag[a.severity] ?? 0) + 1;
    return bag;
  }, [alerts]);

  const filtered = useMemo(
    () =>
      [...alerts]
        .filter((a) => (sev === 'ALL' ? true : a.severity === sev))
        .filter((a) => matchesQuery(a, q))
        .sort((a, b) => {
          const ra = SEV_RANK[a.severity] ?? 5;
          const rb = SEV_RANK[b.severity] ?? 5;
          if (ra !== rb) return ra - rb;
          return String(b.timestamp).localeCompare(String(a.timestamp));
        }),
    [alerts, q, sev],
  );

  const chartData = useMemo(
    () =>
      (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as Severity[])
        .map((s) => ({ name: s.slice(0, 4), full: s, count: sevCounts[s], fill: SEV_COLOR[s] }))
        .filter((d) => d.count > 0),
    [sevCounts],
  );

  const selected =
    filtered.find((a) => a.alert_id === selectedId) ?? filtered[0] ?? null;

  const criticalHigh = sevCounts.CRITICAL + sevCounts.HIGH;
  const avgConf =
    alerts.length === 0
      ? 0
      : Math.round(
          (alerts.reduce((s, a) => s + a.confidence, 0) / alerts.length) * 100,
        );

  return (
    <div className={styles.page}>
      <section className={styles.kpiRow} aria-label="Alert metrics">
        <div className={styles.kpi}>
          <div className={styles.kpiLabel}>Total alerts</div>
          <div className={styles.kpiValue}>{alerts.length}</div>
          <div className={styles.kpiHint}>{filtered.length} in view</div>
        </div>
        <div className={styles.kpi} data-tone={criticalHigh > 0 ? 'alert' : ''}>
          <div className={styles.kpiLabel}>Critical / high</div>
          <div className={styles.kpiValue}>{criticalHigh}</div>
          <div className={styles.kpiHint}>
            {sevCounts.CRITICAL} crit · {sevCounts.HIGH} high
          </div>
        </div>
        <div className={styles.kpi}>
          <div className={styles.kpiLabel}>Avg confidence</div>
          <div className={styles.kpiValue}>{avgConf}%</div>
          <div className={styles.kpiHint}>Across sealed alerts</div>
        </div>
        <div className={styles.kpi} data-tone={isConnected ? 'ok' : 'warn'}>
          <div className={styles.kpiLabel}>Feed</div>
          <div className={styles.kpiValue}>{isConnected ? 'Live' : 'Offline'}</div>
          <div className={styles.kpiHint}>Poll · 2.5s</div>
        </div>
      </section>

      <section className={styles.filterBar}>
        <div className={styles.chips} role="tablist" aria-label="Severity filter">
          {SEV_FILTERS.map((s) => {
            const count = s === 'ALL' ? alerts.length : sevCounts[s];
            const active = sev === s;
            return (
              <button
                key={s}
                type="button"
                role="tab"
                aria-selected={active}
                className={`${styles.chip} ${active ? styles.chipActive : ''}`}
                onClick={() => setSev(s)}
              >
                {s === 'ALL' ? 'All' : s}
                <span className={styles.chipCount}>{count}</span>
              </button>
            );
          })}
        </div>

        <div className={styles.searchRow}>
          <input
            className={styles.input}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Hunt · class=PORT_SCAN · severity=HIGH · confidence>0.8 · src=10. · dst="
            aria-label="Alert hunt query"
          />
          <a className={styles.action} href={`${API_BASE}/api/stix`} target="_blank" rel="noreferrer">
            Export STIX
          </a>

        </div>
      </section>

      <section className={styles.workbench}>
        <div className={styles.panel}>
          <div className={styles.panelHead}>
            <div>
              <h2 className={styles.panelTitle}>Queue</h2>
              <p className={styles.panelSub}>
                Severity-sorted · {filtered.length} match
                {q.trim() ? ` · “${q.trim()}”` : ''}
              </p>
            </div>
          </div>

          {filtered.length === 0 ? (
            <div className={styles.empty}>No alerts match this hunt.</div>
          ) : (
            <div className={styles.tableWrap}>
              <table className={styles.table}>
                <thead>
                  <tr>
                    <th>Sev</th>
                    <th>Class</th>
                    <th>Source → Dest</th>
                    <th>Conf</th>
                    <th>MITRE</th>
                    <th>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((a) => {
                    const active = selected?.alert_id === a.alert_id;
                    const meta = THREAT_META[a.threat_class] ?? THREAT_META.UNKNOWN_ANOMALY;
                    return (
                      <tr
                        key={a.alert_id}
                        className={active ? styles.rowActive : undefined}
                        onClick={() => setSelectedId(a.alert_id)}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' || e.key === ' ') {
                            e.preventDefault();
                            setSelectedId(a.alert_id);
                          }
                        }}
                        tabIndex={0}
                        aria-selected={active}
                      >
                        <td>
                          <span className={styles.sev} style={{ color: SEV_COLOR[a.severity] }}>
                            {a.severity}
                          </span>
                        </td>
                        <td className={styles.cls}>{meta.label}</td>
                        <td className={styles.mono}>
                          {a.source?.ip ?? '—'} → {a.destination?.ip ?? '—'}
                        </td>
                        <td>
                          <div className={styles.confCell}>
                            <div className={styles.confTrack}>
                              <div
                                className={styles.confFill}
                                style={{
                                  width: `${Math.round(a.confidence * 100)}%`,
                                  background:
                                    a.confidence >= 0.8
                                      ? 'var(--green)'
                                      : a.confidence >= 0.6
                                        ? 'var(--amber)'
                                        : 'var(--red)',
                                }}
                              />
                            </div>
                            <span className={styles.mono}>
                              {Math.round(a.confidence * 100)}%
                            </span>
                          </div>
                        </td>
                        <td className={styles.mono}>
                          {a.mitre_attack?.technique_id ?? '—'}
                        </td>
                        <td className={styles.mono}>{formatTimeShort(a.timestamp)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <aside className={styles.railCol}>
          <div className={styles.panel}>
            <div className={styles.panelHead}>
              <h2 className={styles.panelTitle}>Severity mix</h2>
            </div>
            <div className={styles.chartPad}>
              {chartData.length === 0 ? (
                <div className={styles.emptySm}>No severity data.</div>
              ) : (
                <ResponsiveContainer width="100%" height={120}>
                  <BarChart
                    data={chartData}
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
                      {chartData.map((d) => (
                        <Cell key={d.full} fill={d.fill} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>

          <div className={`${styles.panel} ${styles.rail}`}>
            {!selected ? (
              <div className={styles.empty}>Select an alert to investigate.</div>
            ) : (
              <>
                <div className={styles.railHead}>
                  <span
                    className={styles.sev}
                    style={{ color: SEV_COLOR[selected.severity] }}
                  >
                    {selected.severity}
                  </span>
                  <h2 className={styles.railTitle}>
                    {(THREAT_META[selected.threat_class] ?? THREAT_META.UNKNOWN_ANOMALY).label}
                  </h2>
                  <p className={styles.railId}>{selected.alert_id}</p>
                </div>

                <div className={styles.railGrid}>
                  <div className={styles.railBlock}>
                    <div className={styles.k}>Confidence</div>
                    <div className={styles.confCell}>
                      <div className={styles.confTrack}>
                        <div
                          className={styles.confFill}
                          style={{
                            width: `${Math.round(selected.confidence * 100)}%`,
                            background:
                              selected.confidence >= 0.8
                                ? 'var(--green)'
                                : selected.confidence >= 0.6
                                  ? 'var(--amber)'
                                  : 'var(--red)',
                          }}
                        />
                      </div>
                      <span className={styles.mono}>
                        {Math.round(selected.confidence * 100)}%
                      </span>
                    </div>
                  </div>

                  <div className={styles.railBlock}>
                    <div className={styles.k}>Time</div>
                    <div className={styles.mono}>{formatTimestamp(selected.timestamp)}</div>
                  </div>

                  <div className={styles.railBlock}>
                    <div className={styles.k}>Flow</div>
                    <div className={styles.flow}>
                      <div>
                        <span className={styles.flowLabel}>Src</span>
                        <span className={styles.mono}>
                          {selected.source?.ip ?? '—'}
                          {selected.source?.port != null ? `:${selected.source.port}` : ''}
                        </span>
                      </div>
                      <div>
                        <span className={styles.flowLabel}>Dst</span>
                        <span className={styles.mono}>
                          {selected.destination?.ip ?? '—'}
                          {selected.destination?.port != null
                            ? `:${selected.destination.port}`
                            : ''}
                        </span>
                      </div>
                    </div>
                  </div>

                  {selected.mitre_attack ? (
                    <div className={styles.railBlock}>
                      <div className={styles.k}>MITRE</div>
                      <MitreTag id={selected.mitre_attack.technique_id} />
                      <div className={styles.mitreName}>
                        {selected.mitre_attack.technique_name}
                      </div>
                      <div className={styles.mono}>{selected.mitre_attack.tactic}</div>
                    </div>
                  ) : null}

                  <div className={styles.railBlock}>
                    <div className={styles.k}>
                      Evidence
                      <span className={styles.evCount}>
                        {(selected.evidence ?? []).length}
                      </span>
                    </div>
                    {(selected.evidence ?? []).length === 0 ? (
                      <div className={styles.emptySm}>No evidence items.</div>
                    ) : (
                      <ul className={styles.ev}>
                        {(selected.evidence ?? []).map((e, i) => (
                          <li key={`${e.feature}-${i}`}>
                            <div className={styles.evTop}>
                              <span className={styles.feat}>{e.feature}</span>
                              <span className={styles.val}>{String(e.value)}</span>
                            </div>
                            <p>{e.interpretation}</p>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>

                  {selected.ledger_leaf_hash ? (
                    <div className={styles.railBlock}>
                      <div className={styles.k}>Ledger leaf</div>
                      <HashDisplay hash={selected.ledger_leaf_hash} chars={22} />
                    </div>
                  ) : null}
                </div>

                <Link className={styles.deep} href={`/forensics/${selected.alert_id}`}>
                  Open full forensics
                </Link>
              </>
            )}
          </div>
        </aside>
      </section>
    </div>
  );
}
