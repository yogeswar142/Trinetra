'use client';

import { useMemo } from 'react';
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer
} from 'recharts';
import type { ThreatClass } from '@/types/trinetra';
import { THREAT_META } from '@/lib/threatMeta';
import { useAlerts } from '@/hooks/useAlerts';
import styles from './ThreatDistribution.module.css';

interface Props {
  initialData?: import('@/types/trinetra').AlertsResponse;
}

export function ThreatDistribution({ initialData }: Props) {
  const { data } = useAlerts(initialData);
  const counts = data?.threat_counts ?? {};

  const chartData = useMemo(() => {
    return Object.entries(counts as Record<string, number>)
      .filter(([, v]) => v > 0)
      .map(([key, value]) => {
        const meta = THREAT_META[key as ThreatClass] ?? THREAT_META.UNKNOWN_ANOMALY;
        return { name: meta.label, value, color: meta.color };
      })
      .sort((a, b) => b.value - a.value);
  }, [counts]);

  const total = chartData.reduce((s, d) => s + d.value, 0);

  return (
    <div className={styles.card}>
      <div className={styles.header}>
        <div className={styles.title}>Threat Distribution</div>
      </div>

      <div className={styles.body}>
        {/* Donut chart */}
        <div className={styles.chartWrap}>
          <ResponsiveContainer width="100%" height={180}>
            <PieChart>
              <Pie
                data={chartData.length > 0 ? chartData : [{ name: 'None', value: 1, color: '#1e2d42' }]}
                cx="50%"
                cy="50%"
                innerRadius={54}
                outerRadius={80}
                paddingAngle={chartData.length > 1 ? 3 : 0}
                dataKey="value"
                startAngle={90}
                endAngle={-270}
                strokeWidth={0}
              >
                {(chartData.length > 0 ? chartData : [{ name: 'None', value: 1, color: '#1e2d42' }]).map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Pie>
              {total > 0 && (
                <Tooltip
                  contentStyle={{
                    background: 'var(--bg-2)',
                    border: '1px solid var(--border-bright)',
                    borderRadius: '8px',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '11px',
                    color: 'var(--text-primary)',
                  }}
                  itemStyle={{ color: 'var(--text-primary)' }}
                />
              )}
            </PieChart>
          </ResponsiveContainer>

          {/* Center label */}
          <div className={styles.centerLabel}>
            <span className={styles.centerValue}>{total}</span>
            <span className={styles.centerText}>ALERTS</span>
          </div>
        </div>

        {/* Legend */}
        <div className={styles.legend}>
          {chartData.length === 0 ? (
            <div className={styles.emptyLegend}>No alerts yet</div>
          ) : (
            chartData.map((item) => (
              <div key={item.name} className={styles.legendItem}>
                <div className={styles.legendLeft}>
                  <div
                    className={styles.legendDot}
                    style={{ background: item.color, boxShadow: `0 0 6px ${item.color}88` }}
                  />
                  <span className={styles.legendName}>{item.name}</span>
                </div>
                <div className={styles.legendBarWrap}>
                  <div
                    className={styles.legendBar}
                    style={{
                      width: `${Math.round((item.value / total) * 100)}%`,
                      background: item.color,
                    }}
                  />
                </div>
                <span className={styles.legendCount}>{item.value}</span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
