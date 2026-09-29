import type { AlertRecord } from '@/types/trinetra';
import { ThreatBadge } from '@/components/ui/ThreatBadge';
import { SeverityChip } from '@/components/ui/SeverityChip';
import { ConfidenceBar } from '@/components/ui/ConfidenceBar';
import { IPFlow } from '@/components/ui/IPFlow';
import { MitreTag } from '@/components/ui/MitreTag';
import { formatTimeShort } from '@/lib/formatters';
import styles from './AlertRow.module.css';

interface Props {
  alert: AlertRecord;
  isNew: boolean;
  isSelected: boolean;
  onClick: (alert: AlertRecord) => void;
}

export function AlertRow({ alert, isNew, isSelected, onClick }: Props) {
  return (
    <tr
      className={`
        ${styles.row}
        ${isNew ? styles.newAlert : ''}
        ${isSelected ? styles.selected : ''}
      `}
      onClick={() => onClick(alert)}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => e.key === 'Enter' && onClick(alert)}
      aria-label={`Alert: ${alert.threat_class} – click to view evidence`}
    >
      <td className={styles.td}>
        <ThreatBadge threatClass={alert.threat_class} />
      </td>
      <td className={styles.td}>
        <SeverityChip severity={alert.severity} />
      </td>
      <td className={styles.td}>
        <ConfidenceBar confidence={alert.confidence} />
      </td>
      <td className={styles.td}>
        <IPFlow source={alert.source} destination={alert.destination} />
      </td>
      <td className={styles.td}>
        <MitreTag id={alert.mitre_attack?.technique_id} />
      </td>
      <td className={styles.td}>
        <span className={styles.ts}>{formatTimeShort(alert.timestamp)}</span>
      </td>
    </tr>
  );
}
