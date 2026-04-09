"use client";

import Link from "next/link";
import { useState } from "react";

import ConsoleShell from "./ConsoleShell";
import { useConsoleData } from "./useConsoleData";
import { buildConsoleViewModel, filterDevices, filterIncidents } from "../../lib/console-model";

function formatDateTime(value: string) {
  return new Date(value).toLocaleString();
}

export default function IdentitiesView() {
  const { snapshot, source, refreshing, refreshSnapshot } = useConsoleData();
  const [query, setQuery] = useState("");

  const model = buildConsoleViewModel(snapshot);
  const incidents = filterIncidents(model.incidents, query).slice(0, 6);
  const atRiskDevices = filterDevices(
    snapshot.devices.filter((device) => device.openAlertCount > 0 || device.postureState !== "ready"),
    query
  ).slice(0, 8);

  return (
    <ConsoleShell
      activeNav="identities"
      title="Identities"
      subtitle="User risk, sign-in anomalies, and identity-linked incident context."
      searchValue={query}
      searchPlaceholder="Search users, incidents, device associations, or identity onboarding actions..."
      onSearchChange={setQuery}
      onRefresh={() => {
        void refreshSnapshot("manual");
      }}
      refreshing={refreshing}
      source={source}
      generatedAt={snapshot.generatedAt}
      policyRevision={snapshot.defaultPolicy.revision}
      statusItems={[
        { label: "0 connected identity sources", tone: "warning" },
        { label: `${model.metrics.openIncidents} incidents awaiting enrichment` }
      ]}
      drawer={
        <div className="drawer-stack">
          <section className="drawer-panel">
            <p className="section-kicker">Identity status</p>
            <h3>No identity provider is connected yet</h3>
            <p className="muted-copy">
              The console is ready to correlate users, risky sign-ins, and response actions, but the control plane is
              not yet ingesting identity telemetry.
            </p>
          </section>
          <section className="drawer-panel">
            <p className="section-kicker">Next steps</p>
            <div className="action-stack">
              <Link href="/administration" className="primary-link">
                Open administration
              </Link>
              <Link href="/incidents" className="secondary-link">
                Review incidents
              </Link>
            </div>
          </section>
        </div>
      }
    >
      <section className="summary-strip">
        <article className="metric-surface">
          <span className="metric-label">Risky users</span>
          <strong className="metric-number">0</strong>
          <p className="muted-copy">Identity connectors are not yet reporting user risk into the platform.</p>
        </article>
        <article className="metric-surface">
          <span className="metric-label">Incidents awaiting identity context</span>
          <strong className="metric-number">{model.metrics.openIncidents}</strong>
          <p className="muted-copy">Current endpoint incidents that could be enriched by user or session context.</p>
        </article>
        <article className="metric-surface">
          <span className="metric-label">Devices awaiting owner mapping</span>
          <strong className="metric-number">{atRiskDevices.length}</strong>
          <p className="muted-copy">At-risk devices that would benefit from linked user visibility and sign-in history.</p>
        </article>
      </section>

      <section className="surface-card">
        <div className="section-heading">
          <div>
            <p className="section-kicker">Identity actions</p>
            <h3>Turn this into a working identity console</h3>
          </div>
        </div>

        <div className="row-card-list">
          <article className="row-card">
            <div className="row-card-copy">
              <p className="section-kicker">Connector onboarding</p>
              <h4>Connect Entra ID or another identity source</h4>
              <p className="muted-copy">
                Bring risky users, risky sign-ins, MFA posture, and session actions into the incident workflow.
              </p>
            </div>
            <div className="row-card-actions">
              <Link href="/administration" className="primary-link">
                Manage connectors
              </Link>
              <Link href="/reports" className="secondary-link">
                View coverage
              </Link>
            </div>
          </article>

          <article className="row-card">
            <div className="row-card-copy">
              <p className="section-kicker">Operational linkage</p>
              <h4>Investigate endpoint incidents that need identity context</h4>
              <p className="muted-copy">
                Start from active incidents and decide which ones should later pull in user, session, and sign-in data.
              </p>
            </div>
            <div className="row-card-actions">
              <Link href="/incidents" className="primary-link">
                Open incidents
              </Link>
              <Link href="/devices" className="secondary-link">
                Review devices
              </Link>
            </div>
          </article>
        </div>
      </section>

      <section className="grid grid-2">
        <article className="surface-card">
          <div className="section-heading">
            <div>
              <p className="section-kicker">Incidents waiting for enrichment</p>
              <h3>Where identity data would help next</h3>
            </div>
          </div>
          <div className="list-stack">
            {incidents.length === 0 ? (
              <p className="empty-state">No incidents match the current search.</p>
            ) : (
              incidents.map((incident) => (
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
              ))
            )}
          </div>
        </article>

        <article className="surface-card">
          <div className="section-heading">
            <div>
              <p className="section-kicker">At-risk endpoints</p>
              <h3>Devices that would benefit from user context</h3>
            </div>
          </div>
          <div className="list-stack">
            {atRiskDevices.length === 0 ? (
              <p className="empty-state">No devices match the current search.</p>
            ) : (
              atRiskDevices.map((device) => (
                <article key={device.id} className="mini-card">
                  <div className="row-between">
                    <strong>{device.hostname}</strong>
                    <span className={`state-chip tone-${device.postureState}`}>{device.postureState}</span>
                  </div>
                  <p>{device.osVersion}</p>
                  <span className="mini-meta">
                    {device.openAlertCount} open alerts · {formatDateTime(device.lastSeenAt)}
                  </span>
                  <div className="action-stack">
                    <Link href={`/devices/${device.id}`} className="secondary-link">
                      Open device
                    </Link>
                  </div>
                </article>
              ))
            )}
          </div>
        </article>
      </section>
    </ConsoleShell>
  );
}
