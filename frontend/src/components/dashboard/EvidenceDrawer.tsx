'use client';

import { useEffect, useRef } from 'react';
import type { AlertRecord } from '@/types/trinetra';
import { ThreatBadge } from '@/components/ui/ThreatBadge';
import { SeverityChip } from '@/components/ui/SeverityChip';
import { ConfidenceBar } from '@/components/ui/ConfidenceBar';
import { IPFlow } from '@/components/ui/IPFlow';
import { MitreTag } from '@/components/ui/MitreTag';
import { formatTimestamp } from '@/lib/formatters';
import styles from './EvidenceDrawer.module.css';

interface Props {
  alert: AlertRecord;
  onClose: () => void;
}

export function EvidenceDrawer({ alert, onClose }: Props) {
  const drawerRef = useRef<HTMLDivElement>(null);

  // Close on Escape
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [onClose]);

  return (
    <>
      <div className={styles.backdrop} onClick={onClose} aria-hidden="true" />
      <div
        ref={drawerRef}
        className={styles.drawer}
        role="dialog"
        aria-label="Alert evidence"
        aria-modal="true"
      >
        {/* Drawer header */}
        <div className={styles.header}>
          <div className={styles.headerLeft}>
            <ThreatBadge threatClass={alert.threat_class} />
            <SeverityChip severity={alert.severity} />
          </div>
          <button className={styles.closeBtn} onClick={onClose} aria-label="Close">✕</button>
        </div>

        <div className={styles.body}>
          {/* Alert meta */}
          <div className={styles.section}>
            <div className={styles.sectionTitle}>Alert Details</div>
            <div className={styles.metaGrid}>
              <MetaRow label="Alert ID"   value={<span className={styles.mono}>{alert.alert_id.slice(0, 20)}…</span>} />
              <MetaRow label="Timestamp"  value={formatTimestamp(alert.timestamp)} />
              <MetaRow label="Confidence" value={<ConfidenceBar confidence={alert.confidence} />} />
              <MetaRow label="Protocol"   value={alert.protocol ?? '—'} />
              <MetaRow label="Direction"  value={alert.direction ?? '—'} />
              <MetaRow label="Flow"       value={<IPFlow source={alert.source} destination={alert.destination} />} />
            </div>
          </div>

          {/* MITRE */}
          {alert.mitre_attack && (
            <div className={styles.section}>
              <div className={styles.sectionTitle}>MITRE ATT&CK</div>
              <div className={styles.mitreCard}>
                <div className={styles.mitreId}>
                  <MitreTag id={alert.mitre_attack.technique_id} />
                </div>
                <div className={styles.mitreName}>{alert.mitre_attack.technique_name}</div>
                <div className={styles.mitreTactic}>{alert.mitre_attack.tactic}</div>
              </div>
            </div>
          )}

          {/* Evidence items */}
          <div className={styles.section}>
            <div className={styles.sectionTitle}>
              Evidence Chain
              <span className={styles.evidenceCount}>{alert.evidence.length} items</span>
            </div>
            <div className={styles.evidenceList}>
              {alert.evidence.map((ev, i) => (
                <div key={i} className={styles.evidenceItem}>
                  <div className={styles.featureName}>{ev.feature}</div>
                  <div className={styles.interpretation}>{ev.interpretation}</div>
                  <div className={styles.evidenceVals}>
                    <span className={styles.evVal}>
                      Value: <strong>
                        {typeof ev.value === 'number' ? ev.value.toFixed(4) : String(ev.value)}
                      </strong>
                    </span>
                    {ev.threshold != null && (
                      <span className={styles.evVal}>
                        Threshold: <strong>{String(ev.threshold)}</strong>
                      </span>
                    )}
                    <span className={styles.evSource}>{ev.source}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Narration */}
          {alert.narration && (
            <div className={styles.section}>
              <div className={styles.sectionTitle}>AI Narration</div>
              <p className={styles.narration}>{alert.narration}</p>
            </div>
          )}

          {/* Ledger anchor */}
          {alert.ledger_block_height != null && (
            <div className={styles.section}>
              <div className={styles.sectionTitle}>Forensic Ledger</div>
              <div className={styles.metaGrid}>
                <MetaRow label="Block Height" value={String(alert.ledger_block_height)} />
                <MetaRow label="Leaf Hash"
                  value={<span className={styles.mono}>{(alert.ledger_leaf_hash ?? '—').slice(0, 24)}…</span>}
                />
              </div>
            </div>
          )}
        </div>
      </div>
    </>
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
