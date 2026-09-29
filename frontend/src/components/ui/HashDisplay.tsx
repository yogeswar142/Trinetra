'use client';
import { useState } from 'react';
import { formatHash } from '@/lib/formatters';
import styles from './HashDisplay.module.css';

interface Props {
  hash: string | null | undefined;
  chars?: number;
}

export function HashDisplay({ hash, chars = 28 }: Props) {
  const [copied, setCopied] = useState(false);

  if (!hash) return <span className={styles.dash}>—</span>;

  async function copy() {
    await navigator.clipboard.writeText(hash!).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <button className={styles.btn} onClick={copy} title="Copy full hash">
      <span className={styles.hash}>{formatHash(hash, chars)}</span>
      <span className={styles.icon}>{copied ? '✓' : '⧉'}</span>
    </button>
  );
}
