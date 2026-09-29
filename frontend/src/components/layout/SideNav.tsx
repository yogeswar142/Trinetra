'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useAlerts } from '@/hooks/useAlerts';
import styles from './SideNav.module.css';

const NAV = [
  { href: '/', label: 'Overview', match: (p: string) => p === '/' },
  { href: '/alerts', label: 'Alerts', match: (p: string) => p.startsWith('/alerts') || p.startsWith('/forensics') },
  { href: '/globe', label: 'Globe', match: (p: string) => p.startsWith('/globe') },
  { href: '/ledger', label: 'Ledger', match: (p: string) => p.startsWith('/ledger') },
  { href: '/sensor', label: 'Sensor', match: (p: string) => p.startsWith('/sensor') },
  { href: '/settings', label: 'Settings', match: (p: string) => p.startsWith('/settings') },
];

export function SideNav() {
  const pathname = usePathname();
  const { data } = useAlerts();
  const alertCount = data?.stats?.total_alerts ?? 0;

  return (
    <nav className={styles.nav} aria-label="SOC navigation">
      <div className={styles.groupLabel}>Console</div>
      <div className={styles.section}>
        {NAV.map((item) => {
          const active = item.match(pathname);
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`${styles.item} ${active ? styles.active : ''}`}
            >
              <span>{item.label}</span>
              {item.href === '/alerts' && alertCount > 0 ? (
                <span className={styles.badge}>{alertCount}</span>
              ) : null}
            </Link>
          );
        })}
      </div>

      <div className={styles.footer}>
        <a href="/api/docs" target="_blank" rel="noopener noreferrer" className={styles.footerLink}>
          API Docs
        </a>
        <div className={styles.footerMeta}>Trinetra · v0.2</div>
      </div>
    </nav>
  );
}
