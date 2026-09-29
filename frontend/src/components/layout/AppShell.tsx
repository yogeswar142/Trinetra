'use client';

import { Header } from '@/components/layout/Header';
import { SideNav } from '@/components/layout/SideNav';
import { PageHeader } from '@/components/layout/PageHeader';
import styles from './AppShell.module.css';

interface Props {
  children: React.ReactNode;
  connected?: boolean;
  sensorId?: string;
  title?: string;
  description?: string;
  eyebrow?: string;
  actions?: React.ReactNode;
}

export function AppShell({
  children,
  connected = true,
  sensorId = 'NTRO-ENCLAVE-ALPHA-01',
  title,
  description,
  eyebrow,
  actions,
}: Props) {
  return (
    <div className={styles.shell}>
      <Header connected={connected} sensorId={sensorId} />
      <div className={styles.body}>
        <SideNav />
        <main className={styles.main}>
          {title ? (
            <PageHeader
              eyebrow={eyebrow}
              title={title}
              description={description}
              actions={actions}
            />
          ) : null}
          <div className={styles.content}>{children}</div>
        </main>
      </div>
    </div>
  );
}
