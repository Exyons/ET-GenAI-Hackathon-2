import { IncidentWorkspace } from "../../../components/IncidentWorkspace";

export const dynamic = "force-dynamic";

export default async function IncidentDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <IncidentWorkspace id={id} />;
}
