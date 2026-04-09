"use client";

import Link from "next/link";
import { useState } from "react";

import ConsoleShell from "./ConsoleShell";
import { useMailData } from "./useMailData";
import { useConsoleData } from "./useConsoleData";
import { buildConsoleViewModel, filterDevices, filterIncidents, summarizeTelemetrySources } from "../../lib/console-model";

function formatDateTime(value: string) {
  return new Date(value).toLocaleString();
}

function severityClassName(value: string) {
  return `tone-${value}`;
}

export default function ConsoleDashboard() {
  const { snapshot, source, loading, refreshing, refreshSnapshot } = useConsoleData();
  const { snapshot: mailSnapshot } = useMailData();
  const [query, setQuery] = useState("");
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);

  const model = buildConsoleViewModel(snapshot);
  const incidents = filterIncidents(model.incidents, query);
  const devices = filterDevices(snapshot.devices, query);
  const telemetrySources = summarizeTelemetrySources(snapshot.recentTelemetry);
  const maliciousEmails = mailSnapshot.recentMessages.filter(
    (item) => item.verdict === "malware" || item.verdict === "phish"
  ).length;

  const selectedIncident =
    incidents.find((item) => item.id === selectedIncidentId) ?? incidents[0] ?? model.incidents[0] ?? null;

  return (
    <ConsoleShell
      activeNav="dashboard"
      title="Dashboard"
      subtitle="Are we under attack, what needs attention now, and what should an analyst do next."
      searchValue={query}
      searchPlaceholder="Search incidents, hostnames, techniques, owners, hashes, or sources..."
      onSearchChange={setQuery}
      onRefresh={() => {
        void refreshSnapshot("manual");
      }}
      refreshing={refreshing}
      source={source}
      generatedAt={snapshot.generatedAt}
      policyRevision={snapshot.defaultPolicy.revision}
      statusItems={[
        { label: loading ? "loading snapshot" : `${model.metrics.openIncidents} open incidents`, tone: model.metrics.openIncidents > 0 ? "warning" : "default" },
        { label: `${snapshot.devices.length} devices` }
      ]}
      drawer={
        selectedIncident ? (
          <div className="drawer-stack">
            <section className="drawer-panel">
              <div className="row-between">
                <p className="section-kicker">Selected incident</p>
                <span className={`state-chip ${severityClassName(selectedIncident.severity)}`}>{selectedIncident.severity}</span>
              </div>
              <h3>{selectedIncident.title}</h3>
              <p className="muted-copy">{selectedIncident.summary}</p>
              <dl className="definition-grid">
                <div>
                  <dt>Status</dt>
                  <dd>{selectedIncident.status}</dd>
                </div>
                <div>
                  <dt>Priority</dt>
                  <dd>{selectedIncident.priorityScore}</dd>
                </div>
                <div>
                  <dt>Owner</dt>
                  <dd>{selectedIncident.owner}</dd>
                </div>
                <div>
                  <dt>Assets</dt>
                  <dd>{selectedIncident.deviceNames.join(", ")}</dd>
                </div>
                <div>
                  <dt>Confidence</dt>
                  <dd>{selectedIncident.confidenceScore}%</dd>
                </div>
              </dl>
              <div className="tag-row">
                <span className={`state-chip ${severityClassName(selectedIncident.highestDeviceRiskBand ?? "default")}`}>
                  {selectedIncident.highestDeviceRiskScore != null
                    ? `${selectedIncident.highestDeviceRiskScore}/100 ${selectedIncident.highestDeviceRiskBand ?? "pending"}`
                    : "risk pending"}
                </span>
              </div>
              <p className="muted-copy">{selectedIncident.deviceRiskSummary}</p>
            </section>

            <section className="drawer-panel">
              <p className="section-kicker">Recommended action</p>
              <p className="muted-copy">{selectedIncident.recommendedAction}</p>
              <div className="action-stack">
                <Link href={`/incidents/${selectedIncident.id}`} className="primary-link">
                  Open incident
                </Link>
                {selectedIncident.deviceIds[0] ? (
                  <Link href={`/devices/${selectedIncident.deviceIds[0]}`} className="secondary-link">
                    Open device
                  </Link>
                ) : null}
              </div>
            </section>

            <section className="drawer-panel">
              <p className="section-kicker">Latest event</p>
              <p className="muted-copy">{selectedIncident.latestEvent}</p>
              <span className="drawer-timestamp">{formatDateTime(selectedIncident.lastActivityAt)}</span>
            </section>
          </div>
        ) : (
          <div className="drawer-panel">
            <p className="section-kicker">Incident preview</p>
            <h3>No incident selected</h3>
            <p className="muted-copy">Choose an incident from the queue to preview scope, ownership, and next action.</p>
          </div>
        )
      }
    >
      <section className="grid executive-grid">
        <article className="metric-surface">
          <span className="metric-label">Open incidents</span>
          <strong className="metric-number">{model.metrics.openIncidents}</strong>
          <p className="muted-copy">Incidents still requiring analyst ownership or follow-through.</p>
        </article>
        <article className="metric-surface">
          <span className="metric-label">Critical incidents</span>
          <strong className="metric-number">{model.metrics.criticalIncidents}</strong>
          <p className="muted-copy">High-priority incidents that should be evaluated first.</p>
        </article>
        <article className="metric-surface">
          <span className="metric-label">Devices at risk</span>
          <strong className="metric-number">{model.metrics.devicesAtRisk}</strong>
          <p className="muted-copy">Endpoints with alerts, degraded posture, or active isolation.</p>
        </article>
        <article className="metric-surface">
          <span className="metric-label">Risky users</span>
          <strong className="metric-number">{model.metrics.riskyUsers}</strong>
          <p className="muted-copy">Identity connectors are not live yet, so this remains ready for correlation.</p>
        </article>
        <article className="metric-surface">
          <span className="metric-label">Malicious emails</span>
          <strong className="metric-number">{maliciousEmails}</strong>
          <p className="muted-copy">Mail verdicts now surface in the Email workspace and can be correlated back to incidents.</p>
        </article>
        <article className="metric-surface">
          <span className="metric-label">Endpoints unhealthy</span>
          <strong className="metric-number">{model.metrics.unhealthyEndpoints}</strong>
          <p className="muted-copy">Devices currently reporting degraded health or active containment.</p>
        </article>
      </section>

      <section className="grid dashboard-main-grid">
        <article className="surface-card">
          <div className="section-heading">
            <div>
              <p className="section-kicker">Incident queue</p>
              <h3>Top incidents</h3>
            </div>
            <Link href="/incidents" className="subtle-link">
              View all incidents
            </Link>
          </div>

          <div className="table-shell">
            <table className="ops-table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Title</th>
                  <th>Affected assets</th>
                  <th>Device risk</th>
                  <th>Status</th>
                  <th>Owner</th>
                  <th>Last activity</th>
                </tr>
              </thead>
              <tbody>
                {incidents.slice(0, 10).map((incident) => (
                  <tr
                    key={incident.id}
                    className={selectedIncident?.id === incident.id ? "is-selected" : ""}
                    onClick={() => {
                      setSelectedIncidentId(incident.id);
                    }}
                  >
                    <td>
                      <span className={`state-chip ${severityClassName(incident.severity)}`}>{incident.severity}</span>
                    </td>
                    <td>
                      <div className="table-primary">
                        <strong>{incident.title}</strong>
                        <span>{incident.sourceMix.join(" · ")}</span>
                      </div>
                    </td>
                    <td>{incident.deviceNames.join(", ")}</td>
                    <td>
                      <div className="table-primary">
                        <strong>
                          {incident.highestDeviceRiskScore != null
                            ? `${incident.highestDeviceRiskScore}/100`
                            : "--"}
                        </strong>
                        <span>{incident.highestDeviceRiskBand ?? "pending"}</span>
                      </div>
                    </td>
                    <td>{incident.status}</td>
                    <td>{incident.owner}</td>
                    <td>{formatDateTime(incident.lastActivityAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {incidents.length === 0 ? <p className="empty-state">No incidents match the current search.</p> : null}
          </div>
        </article>

        <article className="surface-card">
          <div className="section-heading">
            <div>
              <p className="section-kicker">Threat trends</p>
              <h3>What the environment is telling us</h3>
            </div>
          </div>

          <div className="stack-section">
            <div className="trend-panel">
              <h4>Incidents by severity</h4>
              {model.severityTrends.map((item) => (
                <div key={item.label} className="trend-row">
                  <span>{item.label}</span>
                  <div className="trend-bar-track">
                    <div className={`trend-bar ${severityClassName(item.label.toLowerCase())}`} style={{ width: `${Math.max(item.value * 18, item.value > 0 ? 12 : 0)}px` }} />
                  </div>
                  <strong>{item.value}</strong>
                </div>
              ))}
            </div>

            <div className="trend-panel">
              <h4>Detections by source</h4>
              {(model.sourceTrends.length > 0 ? model.sourceTrends : telemetrySources).map((item) => (
                <div key={item.label} className="trend-row">
                  <span>{item.label}</span>
                  <div className="trend-bar-track">
                    <div className="trend-bar tone-default" style={{ width: `${Math.max(item.value * 18, 12)}px` }} />
                  </div>
                  <strong>{item.value}</strong>
                </div>
              ))}
            </div>

            <div className="trend-panel">
              <h4>Top ATT&amp;CK techniques</h4>
              {model.topTechniques.length === 0 ? (
                <p className="muted-copy">ATT&amp;CK technique mapping will appear here as evidence and detections accumulate.</p>
              ) : (
                model.topTechniques.map((item) => (
                  <div key={item.label} className="trend-row">
                    <span>{item.label}</span>
                    <div className="trend-bar-track">
                      <div className="trend-bar tone-warning" style={{ width: `${Math.max(item.value * 18, 12)}px` }} />
                    </div>
                    <strong>{item.value}</strong>
                  </div>
                ))
              )}
            </div>
          </div>
        </article>
      </section>

      <section className="grid grid-4">
        {model.actionQueue.map((item) => (
          <article key={item.id} className="surface-card">
            <p className="section-kicker">Action panel</p>
            <h3>{item.title}</h3>
            <strong className="queue-number">{item.value}</strong>
            <p className="muted-copy">{item.detail}</p>
          </article>
        ))}
      </section>

      <section className="grid dashboard-bottom-grid">
        <article className="surface-card">
          <div className="section-heading">
            <div>
              <p className="section-kicker">Devices</p>
              <h3>Live device inventory</h3>
            </div>
            <Link href="/devices" className="subtle-link">
              View all devices
            </Link>
          </div>

          <div className="table-shell">
            <table className="ops-table">
              <thead>
                <tr>
                  <th>Device</th>
                  <th>Health</th>
                  <th>Risk</th>
                  <th>Policy</th>
                  <th>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {devices.slice(0, 12).map((device) => (
                  <tr key={device.id}>
                    <td>
                      <Link href={`/devices/${device.id}`} className="table-primary">
                        <strong>{device.hostname}</strong>
                        <span>{device.osVersion}</span>
                      </Link>
                    </td>
                    <td>
                      <span className={`state-chip tone-${device.healthState}`}>{device.healthState}</span>
                    </td>
                    <td>
                      <span className={`state-chip tone-${device.postureState}`}>{device.postureState}</span>
                    </td>
                    <td>{device.policyName}</td>
                    <td>{formatDateTime(device.lastSeenAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {devices.length === 0 ? <p className="empty-state">No reporting devices match the current search.</p> : null}
          </div>
        </article>

        <article className="surface-card">
          <div className="section-heading">
            <div>
              <p className="section-kicker">Pending actions</p>
              <h3>Response queue and evidence</h3>
            </div>
          </div>

          <div className="mini-card-list">
            {snapshot.recentCommands.slice(0, 5).map((command) => (
              <article key={command.id} className="mini-card">
                <div className="row-between">
                  <strong>{command.hostname}</strong>
                  <span className={`state-chip tone-${command.status}`}>{command.status.replaceAll("_", " ")}</span>
                </div>
                <p>{command.type.replaceAll(".", " ")}</p>
              </article>
            ))}
            {snapshot.recentEvidence.slice(0, 3).map((item) => (
              <article key={item.recordId} className="mini-card">
                <div className="row-between">
                  <strong>{item.hostname}</strong>
                  <span className="state-chip tone-default">{item.disposition}</span>
                </div>
                <p>{item.summary}</p>
              </article>
            ))}
          </div>
        </article>
      </section>
    </ConsoleShell>
  );
}
