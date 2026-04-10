import AlertDetailView from "../../components/AlertDetailView";

export default async function AlertPage({
  params
}: {
  params: Promise<{ alertId: string }>;
}) {
  const { alertId } = await params;
  return <AlertDetailView alertId={alertId} />;
}
