import styles from './LiveIndicator.module.css';

interface Props {
  connected: boolean;
  label?: string;
}

export function LiveIndicator({ connected, label }: Props) {
  return (
    <div className={styles.wrap}>
      <div
        className={styles.dot}
        data-live={connected ? '1' : '0'}
      />
      <span className={styles.text}>
        {label ?? (connected ? 'Live' : 'Offline')}
      </span>
    </div>
  );
}
