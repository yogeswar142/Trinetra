import { api } from '@/lib/api';
import { AppShell } from '@/components/layout/AppShell';
import { LedgerDashboard } from '@/components/dashboard/LedgerDashboard';

export const metadata = {
  title: 'Ledger — TRINETRA',
};

export const revalidate = 10;

export default async function LedgerPage() {
  let initialData;
  try {
    initialData = await api.alerts();
  } catch {
    initialData = undefined;
  }

  return (
    <AppShell
      connected={!!initialData}
      title="Ledger"
      description="Merkle chain-of-custody — prove the alert stream was not tampered."
    >
      <LedgerDashboard initialData={initialData} />
    </AppShell>
  );
}
