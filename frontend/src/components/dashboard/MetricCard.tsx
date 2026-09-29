import styles from './MetricCard.module.css';

export function MetricCard({
  label,
  value,
  subtext,
}: {
  label: string;
  value: string | number;
  subtext?: string;
  accent?: string;
  large?: boolean;
  sparklineData?: number[];
}) {
  return (
    <div className={styles.card}>
      <div className={styles.label}>{label}</div>
      <div className={styles.value}>{value}</div>
      {subtext ? <div className={styles.sub}>{subtext}</div> : null}
    </div>
  );
}
