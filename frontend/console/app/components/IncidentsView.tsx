"use client";

import Link from "next/link";
import { useState } from "react";

import ConsoleShell from "./ConsoleShell";
import { useConsoleData } from "./useConsoleData";
import { buildConsoleViewModel, filterIncidents } from "../../lib/console-model";

function formatDateTime(value: string) {
  return new Date(value).toLocaleString();
}

export default function IncidentsView() {
  const { snapshot, source, refreshing, refreshSnapshot } = useConsoleData();
  const [query, setQuery] = useState("");
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);

  const model = buildConsoleViewModel(snapshot);
  const incidents = filterIncidents(model.incidents, query);
  const selectedIncident =
    incidents.find((item) => item.id === selectedIncidentId) ?? incidents[0] ?? model.incidents[0] ?? null;

  return (
    <ConsoleShell
      activeNav="incidents"
      title="Incidents"
      subtitle="Correlated detections, scope, ownership, and response choices in one queue."
      searchValue={query}
      searchPlaceholder="Search incident ID, hostname, owner, technique, source, or status..."
      onSearchChange={setQuery}
      onRefresh={() => {
        void refreshSnapshot("manual");
      }}
      refreshing={refreshing}
      source={source}
      generatedAt={snapshot.generatedAt}
      policyRevision={snapshot.defaultPolicy.revision}
      statusItems={[
        { label: `${incidents.length} visible incidents`, tone: incidents.length > 0 ? "warning" : "default" }
      ]}
      drawer={
        selectedIncident ? (
          <div className="drawer-stack">
            <section className="drawer-panel">
              <p className="section-kicker">Incident preview</p>
              <h3>{selectedIncident.title}</h3>
              <p className="muted-copy">{selectedIncident.summary}</p>
            </section>
            <section className="drawer-panel">
              <dl className="definition-grid">
                <div>
                  <dt>Severity</dt>
                  <dd>{selectedIncident.severity}</dd>
                </div>
                <div>
                  <dt>Status</dt>
                  <dd>{selectedIncident.status}</dd>
                </div>
                <div>
                  <dt>Owner</dt>
                  <dd>{selectedIncident.owner}</dd>
                </div>
                <div>
                  <dt>Assets</dt>
                  <dd>{selectedIncident.deviceNames.join(", ")}</dd>
                </div>
              </dl>
            </section>
            <section className="drawer-panel">
              <p className="section-kicker">Next action</p>
              <p className="muted-copy">{selectedIncident.recommendedAction}</p>
              <Link href={`/incidents/${selectedIncident.id}`} className="primary-link">
                Open incident detail
              </Link>
            </section>
          </div>
        ) : null
      }
    >
      <section className="surface-card">
        <div className="section-heading">
          <div>
            <p className="section-kicker">Incident queue</p>
            <h3>Prioritise, assign, investigate</h3>
          </div>
        </div>

        <div className="table-shell">
          <table className="ops-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Title</th>
                <th>Affected assets</th>
                <th>Source mix</th>
                <th>Status</th>
                <th>Owner</th>
                <th>Last activity</th>
                <th>Confidence</th>
              </tr>
            </thead>
            <tbody>
              {incidents.map((incident) => (
                <tr
                  key={incident.id}
                  className={selectedIncident?.id === incident.id ? "is-selected" : ""}
                  onClick={() => {
                    setSelectedIncidentId(incident.id);
                  }}
                >
                  <td>
                    <span className={`state-chip tone-${incident.severity}`}>{incident.severity}</span>
                  </td>
                  <td>
                    <Link href={`/incidents/${incident.id}`} className="table-primary">
                      <strong>{incident.title}</strong>
                      <span>{incident.summary}</span>
                    </Link>
                  </td>
                  <td>{incident.deviceNames.join(", ")}</td>
                  <td>{incident.sourceMix.join(", ")}</td>
                  <td>{incident.status}</td>
                  <td>{incident.owner}</td>
                  <td>{formatDateTime(incident.lastActivityAt)}</td>
                  <td>{incident.confidenceScore}%</td>
                </tr>
              ))}
            </tbody>
          </table>
          {incidents.length === 0 ? <p className="empty-state">No incidents match the current search.</p> : null}
        </div>
      </section>
    </ConsoleShell>
  );
}
