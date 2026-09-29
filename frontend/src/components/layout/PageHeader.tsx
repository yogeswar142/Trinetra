'use client';

import styles from './PageHeader.module.css';

interface Props {
  eyebrow?: string;
  title: string;
  description?: string;
  actions?: React.ReactNode;
}

export function PageHeader({
  eyebrow = 'TRINETRA SOC',
  title,
  description,
  actions,
}: Props) {
  return (
    <header className={styles.wrap}>
      <div className={styles.copy}>
        <div className={styles.eyebrow}>{eyebrow}</div>
        <h1 className={styles.title}>{title}</h1>
        {description ? <p className={styles.desc}>{description}</p> : null}
      </div>
      {actions ? <div className={styles.actions}>{actions}</div> : null}
    </header>
  );
}
