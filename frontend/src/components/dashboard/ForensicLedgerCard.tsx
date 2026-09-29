'use client';

import { useState } from 'react';
import { HashDisplay } from '@/components/ui/HashDisplay';
import { formatTimestamp } from '@/lib/formatters';
import { useAlerts } from '@/hooks/useAlerts';
import styles from './ForensicLedgerCard.module.css';

interface Props {
  initialData?: import('@/types/trinetra').AlertsResponse;
}

export function ForensicLedgerCard({ initialData }: Props) {
  const { data } = useAlerts(initialData);
  const ledger = data?.ledger;
  const [verifyState, setVerifyState] = useState<
    'idle' | 'loading' | 'ok' | 'error'
  >('idle');
  const [verifyMsg, setVerifyMsg] = useState('');

  async function runVerify() {
    setVerifyState('loading');
    setVerifyMsg('');
    try {
      const res = await fetch('/api/verify');
      const d = await res.json();
      if (d.ok) {
        setVerifyState('ok');
        setVerifyMsg(
          `✓ ${d.blocks_verified} blocks verified (${d.verify_time_ms?.toFixed(1)}ms)`
        );
      } else {
        setVerifyState('error');
        setVerifyMsg(`✗ ${d.errors?.length ?? '?'} error(s) found`);
      }
    } catch {
      setVerifyState('error');
      setVerifyMsg('API unavailable');
    }
  }

  return (
    <div className={styles.card}>
      <div className={styles.header}>
        <div className={styles.title}>Forensic Ledger</div>
        <span className={styles.algo}>Ed25519 + SHA-256</span>
      </div>

      <div className={styles.body}>
        <LedgerRow label="Block Height">
          <span className={styles.heightVal}>
            {ledger?.block_height ?? '—'}
          </span>
        </LedgerRow>
        <div className={styles.divider} />

        <LedgerRow label="Head Hash">
          <HashDisplay hash={ledger?.head_hash} chars={20} />
        </LedgerRow>
        <div className={styles.divider} />

        <LedgerRow label="Last Commit">
          <span className={styles.ts}>{formatTimestamp(ledger?.last_commit)}</span>
        </LedgerRow>
        <div className={styles.divider} />

        <LedgerRow label="Chain Status">
          <span
            className={styles.chainStatus}
            style={{
              color:
                ledger?.chain_ok === true
                  ? 'var(--accent-ok)'
                  : 'var(--text-secondary)',
            }}
          >
            {ledger?.chain_ok === true
              ? '✓ Verified'
              : ledger?.block_height
                ? '⚠ Verify Required'
                : '— No blocks'}
          </span>
        </LedgerRow>

        <button
          className={`${styles.verifyBtn} ${verifyState === 'loading' ? styles.loading : ''}`}
          onClick={runVerify}
          disabled={verifyState === 'loading'}
        >
          {verifyState === 'loading' ? '⏳ Verifying…' : '⛓ Verify Chain'}
        </button>

        {verifyMsg && (
          <div
            className={styles.verifyResult}
            style={{
              color:
                verifyState === 'ok' ? 'var(--accent-ok)' : 'var(--accent-alert)',
            }}
          >
            {verifyMsg}
          </div>
        )}
      </div>
    </div>
  );
}

function LedgerRow({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className={styles.row}>
      <span className={styles.key}>{label}</span>
      <span className={styles.val}>{children}</span>
    </div>
  );
}
