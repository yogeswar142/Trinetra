'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { LiveIndicator } from '@/components/ui/LiveIndicator';
import { utcClock } from '@/lib/formatters';
import styles from './Header.module.css';

interface Props {
  connected?: boolean;
  sensorId?: string;
}

export function Header({ connected = false, sensorId = 'NTRO-ENCLAVE-ALPHA-01' }: Props) {
  const [clock, setClock] = useState('--:--:-- UTC');

  useEffect(() => {
    setClock(utcClock());
    const id = setInterval(() => setClock(utcClock()), 1000);
    return () => clearInterval(id);
  }, []);

  return (
    <header className={styles.header}>
      <div className={styles.left}>
        <Link href="/" className={styles.logo}>
          <span className={styles.mark}>T</span>
          <span className={styles.logoText}>Trinetra</span>
        </Link>
        <span className={styles.divider} />
        <span className={styles.meta}>{sensorId}</span>
        <span className={styles.chip}>Air-gap</span>
        <span className={styles.chipMuted}>Read-only</span>
      </div>

      <div className={styles.right}>
        <LiveIndicator connected={connected} />
        <span className={styles.clock}>{clock}</span>
      </div>
    </header>
  );
}
