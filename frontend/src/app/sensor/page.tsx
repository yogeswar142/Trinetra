import { api } from '@/lib/api';
import { AppShell } from '@/components/layout/AppShell';
import { SensorDashboard } from '@/components/dashboard/SensorDashboard';

export const revalidate = 5;

export default async function SensorPage() {
  let initialData;
  try {
    initialData = await api.alerts();
  } catch {
    initialData = undefined;
  }

  return (
    <AppShell
      connected={!!initialData}
      title="Sensor"
      description="Ingest, detectors, and signed models — receive-only enclave posture."
    >
      <SensorDashboard initialData={initialData} />
    </AppShell>
  );
}
