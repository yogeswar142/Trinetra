'use client';

import useSWR from 'swr';
import type { AlertsResponse } from '@/types/trinetra';
import { API_BASE } from '@/lib/api';

const POLL_INTERVAL = 2500;

async function fetcher(url: string): Promise<AlertsResponse> {
  const res = await fetch(url, { cache: 'no-store' });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export function useAlerts(initialData?: AlertsResponse) {
  const { data, error, isLoading, mutate } = useSWR<AlertsResponse>(
    `${API_BASE}/api/alerts`,
    fetcher,

    {
      refreshInterval: POLL_INTERVAL,
      fallbackData: initialData,
      keepPreviousData: true,
      revalidateOnFocus: true,
      dedupingInterval: 1000,
    },
  );

  return {
    data,
    error,
    isLoading,
    isConnected: !error && !!data,
    mutate,
  };
}
