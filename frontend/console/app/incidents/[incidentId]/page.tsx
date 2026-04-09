import IncidentDetailView from "../../components/IncidentDetailView";

export default async function IncidentDetailPage({
  params
}: {
  params: Promise<{ incidentId: string }>;
}) {
  const { incidentId } = await params;
  return <IncidentDetailView incidentId={incidentId} />;
}
