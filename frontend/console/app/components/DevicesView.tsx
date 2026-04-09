"use client";

import Link from "next/link";
import { useState } from "react";

import ConsoleShell from "./ConsoleShell";
import { useConsoleData } from "./useConsoleData";
import { buildConsoleViewModel, filterDevices } from "../../lib/console-model";

function formatDateTime(value: string | null) {
  return value ? new Date(value).toLocaleString() : "Awaiting sync";
}

export default function DevicesView() {
  const { snapshot, source, refreshing, refreshSnapshot } = useConsoleData();
  const [query, setQuery] = useState("");
  const [selectedDeviceId, setSelectedDeviceId] = useState<string | null>(null);

  const model = buildConsoleViewModel(snapshot);
  const devices = filterDevices(snapshot.devices, query);
  const selectedDevice = devices.find((item) => item.id === selectedDeviceId) ?? devices[0] ?? snapshot.devices[0] ?? null;

  return (
    <ConsoleShell
      activeNav="devices"
      title="Devices"
      subtitle="Endpoint inventory, health, risk, and analyst actions."
      searchValue={query}
      searchPlaceholder="Search hostname, serial, policy, versions, or health state..."
      onSearchChange={setQuery}
      onRefresh={() => {
        void refreshSnapshot("manual");
      }}
      refreshing={refreshing}
      source={source}
      generatedAt={snapshot.generatedAt}
      policyRevision={snapshot.defaultPolicy.revision}
      statusItems={[
        { label: `${snapshot.devices.length} reporting devices` },
        { label: `${model.metrics.devicesAtRisk} at risk`, tone: model.metrics.devicesAtRisk > 0 ? "warning" : "default" }
      ]}
      drawer={
        selectedDevice ? (
          <div className="drawer-stack">
            <section className="drawer-panel">
              <p className="section-kicker">Device preview</p>
              <h3>{selectedDevice.hostname}</h3>
              <p className="muted-copy">{selectedDevice.osVersion}</p>
              <dl className="definition-grid">
                <div>
                  <dt>Health</dt>
                  <dd>{selectedDevice.healthState}</dd>
                </div>
                <div>
                  <dt>Posture</dt>
                  <dd>{selectedDevice.postureState}</dd>
                </div>
                <div>
                  <dt>Open alerts</dt>
                  <dd>{selectedDevice.openAlertCount}</dd>
                </div>
                <div>
                  <dt>Quarantine</dt>
                  <dd>{selectedDevice.quarantinedItemCount}</dd>
                </div>
              </dl>
            </section>

            <section className="drawer-panel">
              <p className="section-kicker">Actions</p>
              <div className="action-stack">
                <Link href={`/devices/${selectedDevice.id}`} className="primary-link">
                  Open device detail
                </Link>
              </div>
            </section>
          </div>
        ) : null
      }
    >
      <section className="surface-card">
        <div className="section-heading">
          <div>
            <p className="section-kicker">Endpoint inventory</p>
            <h3>Device list</h3>
          </div>
        </div>

        <div className="table-shell">
          <table className="ops-table">
            <thead>
              <tr>
                <th>Device name</th>
                <th>OS</th>
                <th>Sensor status</th>
                <th>Risk level</th>
                <th>Last seen</th>
                <th>Incidents</th>
                <th>Policy</th>
                <th>Isolation</th>
              </tr>
            </thead>
            <tbody>
              {devices.map((device) => (
                <tr
                  key={device.id}
                  className={selectedDevice?.id === device.id ? "is-selected" : ""}
                  onClick={() => {
                    setSelectedDeviceId(device.id);
                  }}
                >
                  <td>
                    <Link href={`/devices/${device.id}`} className="table-primary">
                      <strong>{device.hostname}</strong>
                      <span>{device.serialNumber}</span>
                    </Link>
                  </td>
                  <td>{device.osVersion}</td>
                  <td>
                    <span className={`state-chip tone-${device.healthState}`}>{device.healthState}</span>
                  </td>
                  <td>
                    <span className={`state-chip tone-${device.postureState}`}>{device.postureState}</span>
                  </td>
                  <td>{formatDateTime(device.lastSeenAt)}</td>
                  <td>{device.openAlertCount}</td>
                  <td>{device.policyName}</td>
                  <td>{device.isolated ? "isolated" : "connected"}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {devices.length === 0 ? <p className="empty-state">No devices match the current search.</p> : null}
        </div>
      </section>
    </ConsoleShell>
  );
}
