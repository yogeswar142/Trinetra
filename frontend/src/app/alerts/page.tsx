import { api } from '@/lib/api';
import { AppShell } from '@/components/layout/AppShell';
import { AlertsWorkbench } from '@/components/dashboard/AlertsWorkbench';

export const revalidate = 5;

export default async function AlertsPage() {
  let initialData;
  try {
    initialData = await api.alerts();
  } catch {
    initialData = undefined;
  }

  return (
    <AppShell
      connected={!!initialData}
      title="Alerts"
      description="Triage queue — filter, hunt, investigate."
    >
      <AlertsWorkbench initialData={initialData} />
    </AppShell>
  );
}
