"use client";

import Link from "next/link";
import { useState } from "react";

import ConsoleShell from "./ConsoleShell";
import { useConsoleData } from "./useConsoleData";
import { buildConsoleViewModel, filterDevices, filterIncidents } from "../../lib/console-model";

function formatDateTime(value: string) {
  return new Date(value).toLocaleString();
}

export default function ReportsView() {
  const { snapshot, source, refreshing, refreshSnapshot } = useConsoleData();
  const [query, setQuery] = useState("");

  const model = buildConsoleViewModel(snapshot);
  const incidents = filterIncidents(model.incidents, query);
  const devices = filterDevices(snapshot.devices, query)
    .slice()
    .sort((left, right) => right.openAlertCount - left.openAlertCount)
    .slice(0, 8);

  return (
    <ConsoleShell
      activeNav="reports"
      title="Reports"
      subtitle="Operational reporting for incidents, affected assets, remediation, and response performance."
      searchValue={query}
      searchPlaceholder="Search report areas, incidents, techniques, devices, or protection outcomes..."
      onSearchChange={setQuery}
      onRefresh={() => {
        void refreshSnapshot("manual");
      }}
      refreshing={refreshing}
      source={source}
      generatedAt={snapshot.generatedAt}
      policyRevision={snapshot.defaultPolicy.revision}
      statusItems={[
        { label: `${model.metrics.openIncidents} open incidents`, tone: model.metrics.openIncidents > 0 ? "warning" : "default" },
        { label: `${snapshot.recentCommands.filter((item) => item.status === "completed").length} completed actions` }
      ]}
      drawer={
        <div className="drawer-stack">
          <section className="drawer-panel">
            <p className="section-kicker">Report scope</p>
            <h3>Live operational snapshot</h3>
            <p className="muted-copy">
              This reporting page is driven directly from the current dashboard, incident, device, and action data
              already exposed by the backend.
            </p>
          </section>
          <section className="drawer-panel">
            <p className="section-kicker">Next move</p>
            <div className="action-stack">
              <Link href="/incidents" className="primary-link">
                Review incidents
              </Link>
              <Link href="/devices" className="secondary-link">
                Review devices
              </Link>
            </div>
          </section>
        </div>
      }
    >
      <section className="summary-strip">
        <article className="metric-surface">
          <span className="metric-label">Incident volume</span>
          <strong className="metric-number">{model.metrics.openIncidents}</strong>
          <p className="muted-copy">Current open incidents in the live environment.</p>
        </article>
        <article className="metric-surface">
          <span className="metric-label">Contained devices</span>
          <strong className="metric-number">{snapshot.devices.filter((device) => device.isolated).length}</strong>
          <p className="muted-copy">Hosts currently isolated pending analyst review or follow-through.</p>
        </article>
        <article className="metric-surface">
          <span className="metric-label">Quarantine actions</span>
          <strong className="metric-number">
            {snapshot.quarantineItems.filter((item) => item.status === "quarantined").length}
          </strong>
          <p className="muted-copy">Artifacts currently held in local endpoint quarantine.</p>
        </article>
      </section>

      <section className="grid grid-2">
        <article className="surface-card">
          <div className="section-heading">
            <div>
              <p className="section-kicker">Incident trends</p>
              <h3>Current priority distribution</h3>
            </div>
          </div>
          <div className="list-stack">
            {model.severityTrends.map((item) => (
              <article key={item.label} className="mini-card">
                <div className="row-between">
                  <strong>{item.label}</strong>
                  <span className={`state-chip tone-${item.label.toLowerCase()}`}>{item.value}</span>
                </div>
                <p>Incidents currently visible at this severity level.</p>
              </article>
            ))}
          </div>
        </article>

        <article className="surface-card">
          <div className="section-heading">
            <div>
              <p className="section-kicker">Technique reporting</p>
              <h3>Most common mapped ATT&amp;CK techniques</h3>
            </div>
          </div>
          <div className="list-stack">
            {model.topTechniques.length === 0 ? (
              <p className="empty-state">No ATT&amp;CK techniques are visible in the current result set.</p>
            ) : (
              model.topTechniques.map((item) => (
                <article key={item.label} className="mini-card">
                  <div className="row-between">
                    <strong>{item.label}</strong>
                    <span className="state-chip tone-warning">{item.value}</span>
                  </div>
                  <p>Mapped incidents currently carrying this technique identifier.</p>
                </article>
              ))
            )}
          </div>
        </article>
      </section>

      <section className="grid grid-2">
        <article className="surface-card">
          <div className="section-heading">
            <div>
              <p className="section-kicker">Top incidents</p>
              <h3>Most urgent investigations</h3>
            </div>
          </div>
          <div className="list-stack">
            {incidents.slice(0, 6).map((incident) => (
              <article key={incident.id} className="mini-card">
                <div className="row-between">
                  <strong>{incident.title}</strong>
                  <span className={`state-chip tone-${incident.severity}`}>{incident.severity}</span>
                </div>
                <p>{incident.summary}</p>
                <span className="mini-meta">
                  {incident.deviceNames.join(", ")} · {formatDateTime(incident.lastActivityAt)}
                </span>
                <div className="action-stack">
                  <Link href={`/incidents/${incident.id}`} className="secondary-link">
                    Open incident
                  </Link>
                </div>
              </article>
            ))}
            {incidents.length === 0 ? <p className="empty-state">No incidents match the current search.</p> : null}
          </div>
        </article>

        <article className="surface-card">
          <div className="section-heading">
            <div>
              <p className="section-kicker">Top devices</p>
              <h3>Most affected endpoints</h3>
            </div>
          </div>
          <div className="list-stack">
            {devices.map((device) => (
              <article key={device.id} className="mini-card">
                <div className="row-between">
                  <strong>{device.hostname}</strong>
                  <span className={`state-chip tone-${device.healthState}`}>{device.healthState}</span>
                </div>
                <p>{device.osVersion}</p>
                <span className="mini-meta">
                  {device.openAlertCount} open alerts · {device.quarantinedItemCount} quarantined items
                </span>
                <div className="action-stack">
                  <Link href={`/devices/${device.id}`} className="secondary-link">
                    Open device
                  </Link>
                </div>
              </article>
            ))}
            {devices.length === 0 ? <p className="empty-state">No devices match the current search.</p> : null}
          </div>
        </article>
      </section>
    </ConsoleShell>
  );
}
