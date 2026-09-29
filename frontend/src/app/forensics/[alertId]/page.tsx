import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { api } from '@/lib/api';
import { AppShell } from '@/components/layout/AppShell';
import { ThreatBadge } from '@/components/ui/ThreatBadge';
import { SeverityChip } from '@/components/ui/SeverityChip';
import { ConfidenceBar } from '@/components/ui/ConfidenceBar';
import { IPFlow } from '@/components/ui/IPFlow';
import { MitreTag } from '@/components/ui/MitreTag';
import { HashDisplay } from '@/components/ui/HashDisplay';
import { formatTimestamp } from '@/lib/formatters';
import styles from './page.module.css';

export const metadata: Metadata = {
  title: 'Alert Deep Dive — TRINETRA',
};

export const revalidate = 30;

interface Props {
  params: Promise<{ alertId: string }>;
}

export default async function ForensicsPage({ params }: Props) {
  const { alertId } = await params;
  let data;
  try {
    data = await api.alerts();
  } catch {
    notFound();
  }

  const alert = data?.alerts.find((a) => a.alert_id === alertId);
  if (!alert) notFound();

  return (
    <AppShell
      connected
      title="Investigation"
      description={`${alert.threat_class.replaceAll('_', ' ')} · ${alert.severity} · ${Math.round(alert.confidence * 100)}%`}
      actions={
        <Link href="/alerts" className={styles.backLink}>
          ← Alerts
        </Link>
      }
    >
      <div className={styles.titleBar}>
        <div className={styles.badges}>
          <SeverityChip severity={alert.severity} />
          <ThreatBadge threatClass={alert.threat_class} />
        </div>
        <h2 className={styles.h1}>{alert.threat_class.replaceAll('_', ' ')}</h2>
        <div className={styles.metaLine}>
          <span className={styles.mono}>{alert.alert_id}</span>
          <span>·</span>
          <span>{formatTimestamp(alert.timestamp)}</span>
        </div>
      </div>

      <div className={styles.grid}>
        <section className={styles.card}>
          <h3>Flow</h3>
          <IPFlow source={alert.source} destination={alert.destination} />
          <ConfidenceBar confidence={alert.confidence} />
          {alert.mitre_attack ? <MitreTag id={alert.mitre_attack.technique_id} /> : null}
        </section>

        <section className={styles.card}>
          <h3>Evidence</h3>
          <ul className={styles.ev}>
            {(alert.evidence ?? []).map((e, i) => (
              <li key={`${e.feature}-${i}`}>
                <div className={styles.feat}>{e.feature}</div>
                <div className={styles.val}>{String(e.value)}</div>
                <p>{e.interpretation}</p>
              </li>
            ))}
          </ul>
        </section>

        <section className={styles.card}>
          <h3>Ledger</h3>
          <MetaRow label="Block" value={String(alert.ledger_block_height ?? '—')} />
          <MetaRow
            label="Leaf"
            value={<HashDisplay hash={alert.ledger_leaf_hash} chars={24} />}
          />
          <MetaRow label="Model" value={alert.model_version} />
        </section>
      </div>
    </AppShell>
  );
}

function MetaRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className={styles.metaRow}>
      <span className={styles.metaLabel}>{label}</span>
      <span className={styles.metaValue}>{value}</span>
    </div>
  );
}
