"use client";

import Link from "next/link";
import { useState } from "react";

import ConsoleShell from "./ConsoleShell";
import { useConsoleData } from "./useConsoleData";
import { filterDevices } from "../../lib/console-model";

function formatBoolean(value: boolean) {
  return value ? "Enabled" : "Disabled";
}

export default function PoliciesView() {
  const { snapshot, source, refreshing, refreshSnapshot } = useConsoleData();
  const [query, setQuery] = useState("");

  const assignedDevices = filterDevices(snapshot.devices, query);
  const protectedDevices = assignedDevices.filter((device) => device.policyName === snapshot.defaultPolicy.name).length;

  return (
    <ConsoleShell
      activeNav="policies"
      title="Policies"
      subtitle="Protection profiles, exclusions, automation, and device assignments."
      searchValue={query}
      searchPlaceholder="Search policies, device assignments, protections, or exclusions..."
      onSearchChange={setQuery}
      onRefresh={() => {
        void refreshSnapshot("manual");
      }}
      refreshing={refreshing}
      source={source}
      generatedAt={snapshot.generatedAt}
      policyRevision={snapshot.defaultPolicy.revision}
      statusItems={[
        { label: snapshot.defaultPolicy.name },
        { label: `${protectedDevices} assigned devices`, tone: "default" }
      ]}
      drawer={
        <div className="drawer-stack">
          <section className="drawer-panel">
            <p className="section-kicker">Active policy</p>
            <h3>{snapshot.defaultPolicy.name}</h3>
            <p className="muted-copy">Revision {snapshot.defaultPolicy.revision}</p>
          </section>
          <section className="drawer-panel">
            <p className="section-kicker">Policy actions</p>
            <div className="action-stack">
              <Link href="/devices" className="primary-link">
                Review assignments
              </Link>
              <Link href="/reports" className="secondary-link">
                View protection outcomes
              </Link>
            </div>
          </section>
        </div>
      }
    >
      <section className="summary-strip">
        <article className="metric-surface">
          <span className="metric-label">Realtime protection</span>
          <strong className="metric-number">{formatBoolean(snapshot.defaultPolicy.realtimeProtection)}</strong>
          <p className="muted-copy">Kernel and user-mode protection paths expected under the current baseline.</p>
        </article>
        <article className="metric-surface">
          <span className="metric-label">Script inspection</span>
          <strong className="metric-number">{formatBoolean(snapshot.defaultPolicy.scriptInspection)}</strong>
          <p className="muted-copy">AMSI-backed script inspection is part of the current protection posture.</p>
        </article>
        <article className="metric-surface">
          <span className="metric-label">Assigned devices</span>
          <strong className="metric-number">{protectedDevices}</strong>
          <p className="muted-copy">Endpoints currently reporting this policy name from the live backend.</p>
        </article>
      </section>

      <section className="surface-card">
        <div className="section-heading">
          <div>
            <p className="section-kicker">Policy profile</p>
            <h3>{snapshot.defaultPolicy.name}</h3>
          </div>
        </div>

        <div className="row-card-list">
          <article className="row-card">
            <div className="row-card-copy">
              <p className="section-kicker">Protection profile</p>
              <h4>Current baseline controls</h4>
              <div className="tag-row">
                <span className={`state-chip tone-${snapshot.defaultPolicy.realtimeProtection ? "default" : "low"}`}>
                  realtime {formatBoolean(snapshot.defaultPolicy.realtimeProtection).toLowerCase()}
                </span>
                <span className={`state-chip tone-${snapshot.defaultPolicy.cloudLookup ? "default" : "low"}`}>
                  cloud lookup {formatBoolean(snapshot.defaultPolicy.cloudLookup).toLowerCase()}
                </span>
                <span className={`state-chip tone-${snapshot.defaultPolicy.scriptInspection ? "default" : "low"}`}>
                  script inspection {formatBoolean(snapshot.defaultPolicy.scriptInspection).toLowerCase()}
                </span>
                <span className={`state-chip tone-${snapshot.defaultPolicy.networkContainment ? "default" : "warning"}`}>
                  network containment {formatBoolean(snapshot.defaultPolicy.networkContainment).toLowerCase()}
                </span>
              </div>
            </div>
            <div className="row-card-actions">
              <Link href="/reports" className="primary-link">
                View outcomes
              </Link>
              <Link href="/incidents" className="secondary-link">
                Open incidents
              </Link>
            </div>
          </article>

          <article className="row-card">
            <div className="row-card-copy">
              <p className="section-kicker">Assignment impact</p>
              <h4>Devices reporting this policy</h4>
              <p className="muted-copy">
                Use the device table below to see where the current policy is deployed and which endpoints remain
                degraded or isolated under it.
              </p>
            </div>
            <div className="row-card-actions">
              <Link href="/devices" className="primary-link">
                Open devices
              </Link>
            </div>
          </article>
        </div>
      </section>

      <section className="surface-card">
        <div className="section-heading">
          <div>
            <p className="section-kicker">Assignments</p>
            <h3>Devices and their current protection state</h3>
          </div>
        </div>

        <div className="table-shell">
          <table className="ops-table">
            <thead>
              <tr>
                <th>Device</th>
                <th>Policy</th>
                <th>Health</th>
                <th>Risk</th>
                <th>Open alerts</th>
                <th>Isolation</th>
              </tr>
            </thead>
            <tbody>
              {assignedDevices.map((device) => (
                <tr key={device.id}>
                  <td>
                    <Link href={`/devices/${device.id}`} className="table-primary">
                      <strong>{device.hostname}</strong>
                      <span>{device.osVersion}</span>
                    </Link>
                  </td>
                  <td>{device.policyName}</td>
                  <td>
                    <span className={`state-chip tone-${device.healthState}`}>{device.healthState}</span>
                  </td>
                  <td>
                    <span className={`state-chip tone-${device.postureState}`}>{device.postureState}</span>
                  </td>
                  <td>{device.openAlertCount}</td>
                  <td>{device.isolated ? "isolated" : "connected"}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {assignedDevices.length === 0 ? <p className="empty-state">No devices match the current search.</p> : null}
        </div>
      </section>
    </ConsoleShell>
  );
}
