"use client";

import Link from "next/link";
import { useState } from "react";

import ConsoleShell from "./ConsoleShell";
import { useConsoleData } from "./useConsoleData";
import { filterAlerts } from "../../lib/console-model";

function formatDateTime(value: string) {
  return new Date(value).toLocaleString();
}

export default function AlertsView() {
  const { snapshot, source, refreshing, refreshSnapshot } = useConsoleData();
  const [query, setQuery] = useState("");

  const alerts = filterAlerts(snapshot.alerts, query);
  const selectedAlert = alerts[0] ?? null;

  return (
    <ConsoleShell
      activeNav="alerts"
      title="Alerts"
      subtitle="Detection-level evidence that supports incident triage and technical review."
      searchValue={query}
      searchPlaceholder="Search alert title, hostname, severity, technique, or status..."
      onSearchChange={setQuery}
      onRefresh={() => {
        void refreshSnapshot("manual");
      }}
      refreshing={refreshing}
      source={source}
      generatedAt={snapshot.generatedAt}
      policyRevision={snapshot.defaultPolicy.revision}
      statusItems={[
        { label: `${alerts.length} visible alerts`, tone: alerts.some((item) => item.severity === "critical") ? "warning" : "default" }
      ]}
      drawer={
        selectedAlert ? (
          <div className="drawer-stack">
            <section className="drawer-panel">
              <p className="section-kicker">Alert preview</p>
              <h3>{selectedAlert.title}</h3>
              <p className="muted-copy">{selectedAlert.summary}</p>
              <dl className="definition-grid">
                <div>
                  <dt>Severity</dt>
                  <dd>{selectedAlert.severity}</dd>
                </div>
                <div>
                  <dt>Status</dt>
                  <dd>{selectedAlert.status}</dd>
                </div>
                <div>
                  <dt>Device</dt>
                  <dd>{selectedAlert.hostname}</dd>
                </div>
                <div>
                  <dt>Technique</dt>
                  <dd>{selectedAlert.technique ?? "Pending mapping"}</dd>
                </div>
              </dl>
            </section>
            {selectedAlert.deviceId ? (
              <section className="drawer-panel">
                <Link href={`/devices/${selectedAlert.deviceId}`} className="primary-link">
                  Open device detail
                </Link>
              </section>
            ) : null}
          </div>
        ) : null
      }
    >
      <section className="surface-card">
        <div className="section-heading">
          <div>
            <p className="section-kicker">Alert list</p>
            <h3>Technical detection review</h3>
          </div>
        </div>

        <div className="table-shell">
          <table className="ops-table">
            <thead>
              <tr>
                <th>Alert title</th>
                <th>Severity</th>
                <th>Source</th>
                <th>Entity</th>
                <th>Status</th>
                <th>Classification</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((alert) => (
                <tr key={alert.id}>
                  <td>
                    <div className="table-primary">
                      <strong>{alert.title}</strong>
                      <span>{alert.summary}</span>
                    </div>
                  </td>
                  <td>
                    <span className={`state-chip tone-${alert.severity}`}>{alert.severity}</span>
                  </td>
                  <td>endpoint</td>
                  <td>{alert.hostname}</td>
                  <td>{alert.status}</td>
                  <td>{alert.technique ?? "Pending mapping"}</td>
                  <td>{formatDateTime(alert.detectedAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {alerts.length === 0 ? <p className="empty-state">No alerts match the current search.</p> : null}
        </div>
      </section>
    </ConsoleShell>
  );
}
