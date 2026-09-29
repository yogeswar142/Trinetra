// Formatting utilities for the Trinetra SOC dashboard

export function formatPPS(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(2)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return n.toFixed(0);
}

export function formatMbps(n: number): string {
  if (!n) return '—';
  return `${n.toFixed(2)} Mbps`;
}

export function formatHash(hash: string | null | undefined, chars = 24): string {
  if (!hash) return '—';
  if (hash.length <= chars) return hash;
  return hash.slice(0, chars) + '…';
}

export function formatTimestamp(ts: string | null | undefined): string {
  if (!ts) return '—';
  try {
    const d = new Date(ts);
    return d.toISOString().slice(11, 23) + 'Z';  // HH:MM:SS.mmm Z
  } catch {
    return ts.slice(0, 20);
  }
}

export function formatTimeShort(ts: string | null | undefined): string {
  if (!ts) return '—';
  try {
    return new Date(ts).toISOString().slice(11, 19);  // HH:MM:SS
  } catch {
    return '—';
  }
}

export function formatUptime(startMs: number): string {
  const elapsed = Math.floor((Date.now() - startMs) / 1000);
  const hh = String(Math.floor(elapsed / 3600)).padStart(2, '0');
  const mm = String(Math.floor((elapsed % 3600) / 60)).padStart(2, '0');
  const ss = String(elapsed % 60).padStart(2, '0');
  return `${hh}:${mm}:${ss}`;
}

export function formatPackets(n: number): string {
  if (!n) return '0';
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(2)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return n.toLocaleString();
}

export function formatConfidence(c: number): string {
  return `${Math.round(c * 100)}%`;
}

export function formatConfidencePct(c: number): number {
  return Math.round(c * 100);
}

export function utcClock(): string {
  return new Date().toUTCString().slice(17, 25) + ' UTC';
}

export function bucketByMinute(
  timestamps: string[],
  windowMinutes = 10,
): { time: string; count: number }[] {
  const now = Date.now();
  const buckets: Record<string, number> = {};

  // Create empty buckets for last N minutes
  for (let i = windowMinutes - 1; i >= 0; i--) {
    const t = new Date(now - i * 60_000);
    const key = t.toISOString().slice(11, 16); // HH:MM
    buckets[key] = 0;
  }

  for (const ts of timestamps) {
    try {
      const d = new Date(ts);
      if (now - d.getTime() <= windowMinutes * 60_000) {
        const key = d.toISOString().slice(11, 16);
        if (key in buckets) buckets[key]++;
      }
    } catch { /* skip */ }
  }

  return Object.entries(buckets).map(([time, count]) => ({ time, count }));
}
