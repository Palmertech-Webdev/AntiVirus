import DeviceDetailView from "../../components/DeviceDetailView";

export default async function DevicePage({
  params
}: {
  params: Promise<{ deviceId: string }>;
}) {
  const { deviceId } = await params;
  return <DeviceDetailView deviceId={deviceId} />;
}
