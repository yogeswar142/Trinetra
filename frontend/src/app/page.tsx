import { api } from '@/lib/api';
import { AppShell } from '@/components/layout/AppShell';
import { OverviewDashboard } from '@/components/dashboard/OverviewDashboard';

export const revalidate = 5;

export default async function OverviewPage() {
  let initialData;
  try {
    initialData = await api.alerts();
  } catch {
    initialData = undefined;
  }

  return (
    <AppShell
      connected={!!initialData}
      title="Overview"
      description="Enclave health and what to work next."
    >
      <OverviewDashboard initialData={initialData} />
    </AppShell>
  );
}
