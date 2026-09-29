import { api } from '@/lib/api';
import { AppShell } from '@/components/layout/AppShell';
import { ThreatGlobe } from '@/components/dashboard/ThreatGlobe';

export const revalidate = 5;

export default async function GlobePage() {
  let initialData;
  try {
    initialData = await api.alerts();
  } catch {
    initialData = undefined;
  }

  return (
    <AppShell
      connected={!!initialData}
      title="Globe"
      description="Offline geo projection of sealed vectors — orbit, zoom, focus."
    >
      <ThreatGlobe initialData={initialData} height={580} />
    </AppShell>
  );
}
