import styles from './loading.module.css';

export default function DashboardLoading() {
  return (
    <div className={styles.shell}>
      <div className={styles.header} />
      <div className={styles.body}>
        <div className={styles.sidenav} />
        <div className={styles.main}>
          <div className={styles.metricsRow}>
            {[...Array(4)].map((_, i) => (
              <div key={i} className={styles.skeletonCard} />
            ))}
          </div>
          <div className={styles.contentGrid}>
            <div className={styles.skeletonFeed} />
            <div className={styles.skeletonSidebar}>
              <div className={styles.skeletonCard} style={{ height: 280 }} />
              <div className={styles.skeletonCard} style={{ height: 200 }} />
            </div>
          </div>
          <div className={styles.bottomRow}>
            {[...Array(3)].map((_, i) => (
              <div key={i} className={styles.skeletonCard} style={{ height: 180 }} />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
