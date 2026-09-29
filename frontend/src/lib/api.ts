import type { AlertsResponse, VerifyResponse, HealthResponse } from '@/types/trinetra';

export const API_BASE = (process.env.NEXT_PUBLIC_API_BASE && process.env.NEXT_PUBLIC_API_BASE.length > 0)
  ? process.env.NEXT_PUBLIC_API_BASE
  : 'https://trinetra-backend-qhc9.onrender.com';

const BASE = API_BASE;


async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), 2000); // 2s timeout for build
  try {
    const res = await fetch(`${BASE}${path}`, {
      ...init,
      signal: controller.signal,
      headers: { 'Accept': 'application/json', ...(init?.headers ?? {}) },
    });
    if (!res.ok) {
      const text = await res.text().catch(() => res.statusText);
      throw new Error(`${path} → HTTP ${res.status}: ${text}`);
    }
    return res.json() as Promise<T>;
  } finally {
    clearTimeout(id);
  }
}

export const api = {
  alerts: (): Promise<AlertsResponse> =>
    apiFetch<AlertsResponse>('/api/alerts'),

  verify: (): Promise<VerifyResponse> =>
    apiFetch<VerifyResponse>('/api/verify'),

  health: (): Promise<HealthResponse> =>
    apiFetch<HealthResponse>('/api/health'),
};
