'use client';

import { useMemo } from 'react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer
} from 'recharts';
import type { ThreatClass } from '@/types/trinetra';
import { THREAT_META } from '@/lib/threatMeta';
import { bucketByMinute } from '@/lib/formatters';
import { useAlerts } from '@/hooks/useAlerts';
import styles from './AlertTimeline.module.css';

interface Props {
  initialData?: import('@/types/trinetra').AlertsResponse;
}

export function AlertTimeline({ initialData }: Props) {
  const { data } = useAlerts(initialData);
  const alerts = data?.alerts ?? [];

  const chartData = useMemo(() => {
    return bucketByMinute(alerts.map((a) => a.timestamp));
  }, [alerts]);

  const topClass = useMemo((): ThreatClass | null => {
    const counts = data?.threat_counts ?? {};
    const sorted = Object.entries(counts as Record<string, number>).sort(([, a], [, b]) => b - a);
    return sorted[0]?.[0] as ThreatClass ?? null;
  }, [data]);

  const areaColor = topClass
    ? THREAT_META[topClass]?.color ?? 'var(--accent-intel)'
    : 'var(--accent-intel)';

  return (
    <div className={styles.card}>
      <div className={styles.header}>
        <div className={styles.title}>Alert Timeline</div>
        <span className={styles.window}>Last 10 min</span>
      </div>

      <div className={styles.chartArea}>
        <ResponsiveContainer width="100%" height={120}>
          <AreaChart data={chartData} margin={{ top: 8, right: 16, left: -24, bottom: 0 }}>
            <defs>
              <linearGradient id="timelineGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%"  stopColor={areaColor} stopOpacity={0.3} />
                <stop offset="95%" stopColor={areaColor} stopOpacity={0.02} />
              </linearGradient>
            </defs>
            <CartesianGrid
              strokeDasharray="3 3"
              stroke="rgba(255,255,255,0.04)"
              horizontal={true}
              vertical={false}
            />
            <XAxis
              dataKey="time"
              tick={{ fontSize: 9, fill: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}
              tickLine={false}
              axisLine={false}
              interval={2}
            />
            <YAxis
              tick={{ fontSize: 9, fill: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}
              tickLine={false}
              axisLine={false}
              allowDecimals={false}
              width={30}
            />
            <Tooltip
              contentStyle={{
                background: 'var(--bg-2)',
                border: '1px solid var(--border-bright)',
                borderRadius: '8px',
                fontFamily: 'var(--font-mono)',
                fontSize: '11px',
                color: 'var(--text-primary)',
              }}
              itemStyle={{ color: areaColor }}
              labelStyle={{ color: 'var(--text-secondary)', fontSize: '10px' }}
            />
            <Area
              type="monotone"
              dataKey="count"
              stroke={areaColor}
              strokeWidth={1.5}
              fill="url(#timelineGrad)"
              dot={false}
              activeDot={{ r: 4, fill: areaColor, stroke: 'var(--bg-2)', strokeWidth: 2 }}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
