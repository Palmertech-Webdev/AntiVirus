"use client";

import Link from "next/link";
import { useState } from "react";

import ConsoleShell from "./ConsoleShell";
import { useConsoleData } from "./useConsoleData";
import { buildConsoleViewModel } from "../../lib/console-model";

function formatDateTime(value: string) {
  return new Date(value).toLocaleString();
}

export default function IncidentDetailView({ incidentId }: { incidentId: string }) {
  const { snapshot, source, refreshing, refreshSnapshot } = useConsoleData();
  const [query, setQuery] = useState("");

  const model = buildConsoleViewModel(snapshot);
  const incident = model.incidents.find((item) => item.id === incidentId);

  if (!incident) {
    return (
      <ConsoleShell
        activeNav="incidents"
        title="Incident not found"
        subtitle="The current control-plane snapshot does not contain a matching incident."
        searchValue={query}
        searchPlaceholder="Search incidents, devices, techniques, or owners..."
        onSearchChange={setQuery}
        onRefresh={() => {
          void refreshSnapshot("manual");
        }}
        refreshing={refreshing}
        source={source}
        generatedAt={snapshot.generatedAt}
        policyRevision={snapshot.defaultPolicy.revision}
      >
        <section className="surface-card">
          <p className="section-kicker">Incident detail</p>
          <h3>No incident with this identifier is available right now.</h3>
          <p className="muted-copy">
            The incident may have aged out of the snapshot, been resolved, or been filtered out because the backing alert
            no longer exists in the current backend state.
          </p>
          <Link href="/incidents" className="primary-link">
            Return to incidents
          </Link>
        </section>
      </ConsoleShell>
    );
  }

  return (
    <ConsoleShell
      activeNav="incidents"
      title={incident.title}
      subtitle="Correlated evidence, attack timeline, and response choices for this incident."
      searchValue={query}
      searchPlaceholder="Search the incident timeline, entities, techniques, or action text..."
      onSearchChange={setQuery}
      onRefresh={() => {
        void refreshSnapshot("manual");
      }}
      refreshing={refreshing}
      source={source}
      generatedAt={snapshot.generatedAt}
      policyRevision={snapshot.defaultPolicy.revision}
      statusItems={[
        { label: incident.severity, tone: incident.severity === "critical" ? "danger" : "warning" },
        { label: incident.status }
      ]}
      drawer={
        <div className="drawer-stack">
          <section className="drawer-panel">
            <p className="section-kicker">Actions</p>
            <div className="action-stack">
              {incident.deviceIds[0] ? (
                <Link href={`/devices/${incident.deviceIds[0]}`} className="primary-link">
                  Open device
                </Link>
              ) : null}
              <span className="state-chip tone-warning">Isolate device path ready</span>
              <span className="state-chip tone-default">Evidence export next</span>
            </div>
          </section>

          <section className="drawer-panel">
            <p className="section-kicker">Latest event</p>
            <p className="muted-copy">{incident.latestEvent}</p>
            <span className="drawer-timestamp">{formatDateTime(incident.lastActivityAt)}</span>
          </section>
        </div>
      }
    >
      <section className="incident-detail-grid">
        <article className="surface-card">
          <p className="section-kicker">Summary</p>
          <h3>{incident.title}</h3>
          <p className="muted-copy">{incident.summary}</p>
          <dl className="definition-grid">
            <div>
              <dt>Severity</dt>
              <dd>{incident.severity}</dd>
            </div>
            <div>
              <dt>Status</dt>
              <dd>{incident.status}</dd>
            </div>
            <div>
              <dt>Confidence</dt>
              <dd>{incident.confidenceScore}%</dd>
            </div>
            <div>
              <dt>Owner</dt>
              <dd>{incident.owner}</dd>
            </div>
            <div>
              <dt>First seen</dt>
              <dd>{formatDateTime(incident.firstSeenAt)}</dd>
            </div>
            <div>
              <dt>Last seen</dt>
              <dd>{formatDateTime(incident.lastActivityAt)}</dd>
            </div>
          </dl>

          <div className="tag-row">
            {incident.tactics.map((item) => (
              <span key={item} className="state-chip tone-default">
                {item}
              </span>
            ))}
            {incident.techniques.map((item) => (
              <span key={item} className="state-chip tone-warning">
                {item}
              </span>
            ))}
          </div>

          <div className="surface-subsection">
            <p className="section-kicker">Recommended next action</p>
            <p className="muted-copy">{incident.recommendedAction}</p>
          </div>
        </article>

        <article className="surface-card">
          <p className="section-kicker">Timeline</p>
          <h3>Attack and response sequence</h3>
          <div className="timeline">
            {incident.timeline
              .filter((item) =>
                query
                  ? [item.title, item.summary, item.source, item.category].some((value) =>
                      value.toLowerCase().includes(query.trim().toLowerCase())
                    )
                  : true
              )
              .map((item) => (
                <article key={item.id} className="timeline-entry">
                  <span className={`timeline-dot tone-${item.severity}`} />
                  <div>
                    <div className="row-between">
                      <strong>{item.title}</strong>
                      <span className="timeline-time">{formatDateTime(item.occurredAt)}</span>
                    </div>
                    <p>{item.summary}</p>
                    <span className="timeline-meta">
                      {item.category} · {item.source}
                    </span>
                  </div>
                </article>
              ))}
          </div>
        </article>

        <article className="surface-card">
          <p className="section-kicker">Entities and scope</p>
          <h3>Impacted assets</h3>
          <div className="stack-section">
            <div className="entity-group">
              <h4>Devices</h4>
              <ul className="key-list">
                {incident.deviceIds.map((deviceId, index) => (
                  <li key={deviceId}>
                    <Link href={`/devices/${deviceId}`}>{incident.deviceNames[index] ?? deviceId}</Link>
                  </li>
                ))}
              </ul>
            </div>
            <div className="entity-group">
              <h4>Source mix</h4>
              <ul className="key-list">
                {incident.sourceMix.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </div>
            <div className="entity-group">
              <h4>Evidence coverage</h4>
              <ul className="key-list">
                <li>{incident.alertCount} alert-backed detection(s)</li>
                <li>{incident.evidenceCount} evidence record(s)</li>
                <li>{incident.commandCount} response action(s)</li>
              </ul>
            </div>
          </div>
        </article>
      </section>
    </ConsoleShell>
  );
}
