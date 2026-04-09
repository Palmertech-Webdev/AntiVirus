"use client";

import Link from "next/link";
import { startTransition, useCallback, useEffect, useRef, useState } from "react";

import {
  isolateDevice,
  listScripts,
  queueProcessTreeTerminate,
  queueRemediatePath,
  queueRunScript,
  releaseDevice
} from "../../lib/api";
import { buildConsoleViewModel } from "../../lib/console-model";
import type { DeviceSummary, ScriptSummary } from "../../lib/types";
import ConsoleShell from "./ConsoleShell";
import { useConsoleData } from "./useConsoleData";

function formatDateTime(value: string) {
  return new Date(value).toLocaleString();
}

function matchesQuery(query: string, values: Array<string | undefined | null>) {
  if (!query.trim()) {
    return true;
  }

  const normalized = query.trim().toLowerCase();
  return values.some((value) => value?.toLowerCase().includes(normalized));
}

function riskTone(value: string | null | undefined) {
  switch (value) {
    case "critical":
    case "high":
      return "danger";
    case "elevated":
      return "warning";
    case "guarded":
      return "default";
    case "low":
      return "low";
    default:
      return "unknown";
  }
}

function confidenceTone(value: number | null | undefined) {
  if (value == null) {
    return "unknown";
  }

  if (value >= 85) {
    return "ready";
  }

  if (value >= 65) {
    return "warning";
  }

  return "failed";
}

function priorityTone(value: number) {
  if (value >= 350) {
    return "danger";
  }

  if (value >= 240) {
    return "warning";
  }

  return "default";
}

export default function IncidentDetailView({ incidentId }: { incidentId: string }) {
  const { snapshot, source, refreshing, refreshSnapshot } = useConsoleData();
  const [query, setQuery] = useState("");
  const [selectedDeviceId, setSelectedDeviceId] = useState("");
  const [targetPath, setTargetPath] = useState("");
  const [selectedScriptId, setSelectedScriptId] = useState("");
  const [scripts, setScripts] = useState<ScriptSummary[]>([]);
  const [actionBusy, setActionBusy] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const scriptRequestInFlightRef = useRef<Promise<void> | null>(null);

  const model = buildConsoleViewModel(snapshot);
  const incident = model.incidents.find((item) => item.id === incidentId);
  const devicesById = new Map(snapshot.devices.map((device) => [device.id, device]));
  const incidentDevices = incident
    ? incident.deviceIds
        .map((deviceId) => devicesById.get(deviceId))
        .filter((device): device is DeviceSummary => Boolean(device))
        .sort((left, right) => {
          const riskDelta = (right.riskScore ?? -1) - (left.riskScore ?? -1);
          if (riskDelta !== 0) {
            return riskDelta;
          }

          return left.hostname.localeCompare(right.hostname);
        })
    : [];
  const selectedDevice = incidentDevices.find((device) => device.id === selectedDeviceId) ?? incidentDevices[0] ?? null;
  const selectedScript = scripts.find((item) => item.id === selectedScriptId) ?? scripts[0] ?? null;
  const incidentDeviceKey = incident?.deviceIds.join("|") ?? "";
  const defaultDeviceId =
    incident?.primaryDeviceId && incidentDevices.some((device) => device.id === incident.primaryDeviceId)
      ? incident.primaryDeviceId
      : incidentDevices[0]?.id ?? "";

  useEffect(() => {
    if (incidentDevices.length === 0) {
      if (selectedDeviceId) {
        setSelectedDeviceId("");
      }
      return;
    }

    if (!selectedDeviceId || !incidentDevices.some((device) => device.id === selectedDeviceId)) {
      setSelectedDeviceId(defaultDeviceId);
    }
  }, [defaultDeviceId, incidentDeviceKey, selectedDeviceId]);

  const refreshScripts = useCallback(async () => {
    if (scriptRequestInFlightRef.current) {
      return scriptRequestInFlightRef.current;
    }

    const request = (async () => {
      try {
        const nextScripts = await listScripts();

        startTransition(() => {
          setScripts(nextScripts);
          setSelectedScriptId((current) => current || nextScripts[0]?.id || "");
        });
      } catch {
        // Keep the last known script list if the backend snapshot is unavailable.
      } finally {
        scriptRequestInFlightRef.current = null;
      }
    })();

    scriptRequestInFlightRef.current = request;
    return request;
  }, []);

  useEffect(() => {
    void refreshScripts();
  }, [refreshScripts]);

  const runAction = useCallback(
    async (label: string, action: () => Promise<unknown>) => {
      setActionBusy(label);
      setActionMessage(null);

      try {
        await action();
        setActionMessage(`${label} queued successfully for ${selectedDevice?.hostname ?? "the selected device"}.`);
        await Promise.all([refreshSnapshot("manual"), refreshScripts()]);
      } catch (error) {
        setActionMessage(`${label} failed: ${error instanceof Error ? error.message : "Request failed"}`);
      } finally {
        setActionBusy(null);
      }
    },
    [refreshScripts, refreshSnapshot, selectedDevice?.hostname]
  );

  if (!incident) {
    return (
      <ConsoleShell
        activeNav="incidents"
        title="Incident not found"
        subtitle="The current control-plane snapshot does not contain a matching incident."
        searchValue={query}
        searchPlaceholder="Search incidents, devices, techniques, or response actions..."
        onSearchChange={setQuery}
        onRefresh={() => {
          void Promise.all([refreshSnapshot("manual"), refreshScripts()]);
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

  const timeline = incident.timeline.filter((item) =>
    matchesQuery(query, [item.title, item.summary, item.source, item.category])
  );

  const drawer = (
    <div className="drawer-stack">
      <section className="drawer-panel">
        <p className="section-kicker">Analyst actions</p>
        <p className="muted-copy">
          Use the highest-risk impacted device as the default target, then queue containment or cleanup directly from this
          incident.
        </p>

        <div className="field-grid">
          <label className="field-group">
            <span>Target device</span>
            <select
              className="admin-input"
              value={selectedDeviceId}
              onChange={(event) => setSelectedDeviceId(event.target.value)}
              disabled={incidentDevices.length === 0 || Boolean(actionBusy)}
            >
              {incidentDevices.length === 0 ? (
                <option value="">No impacted device available</option>
              ) : (
                incidentDevices.map((device) => (
                  <option key={device.id} value={device.id}>
                    {device.hostname} · {device.riskScore != null ? `${device.riskScore}/100` : "score pending"} ·{' '}
                    {device.riskBand ?? "pending"}
                  </option>
                ))
              )}
            </select>
          </label>

          <label className="field-group">
            <span>Target path</span>
            <input
              className="admin-input"
              value={targetPath}
              onChange={(event) => setTargetPath(event.target.value)}
              placeholder="C:\\Users\\Public\\Downloads\\payload.exe"
            />
          </label>

          <label className="field-group">
            <span>Stored script</span>
            <select
              className="admin-input"
              value={selectedScript?.id ?? ""}
              onChange={(event) => setSelectedScriptId(event.target.value)}
              disabled={scripts.length === 0 || Boolean(actionBusy)}
            >
              {scripts.length === 0 ? (
                <option value="">No stored scripts available</option>
              ) : (
                scripts.map((script) => (
                  <option key={script.id} value={script.id}>
                    {script.name} ({script.language})
                  </option>
                ))
              )}
            </select>
          </label>
        </div>

        <dl className="definition-grid">
          <div>
            <dt>Hostname</dt>
            <dd>{selectedDevice?.hostname ?? "Awaiting selection"}</dd>
          </div>
          <div>
            <dt>Risk score</dt>
            <dd>{selectedDevice?.riskScore ?? "--"}</dd>
          </div>
          <div>
            <dt>Risk band</dt>
            <dd>{selectedDevice?.riskBand ?? "pending"}</dd>
          </div>
          <div>
            <dt>Confidence</dt>
            <dd>{selectedDevice?.confidenceScore != null ? `${selectedDevice.confidenceScore}%` : "--"}</dd>
          </div>
          <div>
            <dt>Last seen</dt>
            <dd>{selectedDevice ? formatDateTime(selectedDevice.lastSeenAt) : "--"}</dd>
          </div>
          <div>
            <dt>Isolation</dt>
            <dd>{selectedDevice ? (selectedDevice.isolated ? "contained" : "connected") : "--"}</dd>
          </div>
        </dl>

        <div className="tag-row">
          <span className={`state-chip tone-${riskTone(selectedDevice?.riskBand)}`}>
            {selectedDevice != null
              ? `${selectedDevice.riskScore != null ? `${selectedDevice.riskScore}/100` : "score pending"} ${
                  selectedDevice.riskBand ?? "pending"
                }`
              : "device missing"}
          </span>
          <span className={`state-chip ${selectedDevice?.isolated ? "tone-contained" : "tone-default"}`}>
            {selectedDevice?.isolated ? "contained" : "connected"}
          </span>
          {selectedDevice?.confidenceScore != null ? (
            <span className={`state-chip tone-${confidenceTone(selectedDevice.confidenceScore)}`}>
              {selectedDevice.confidenceScore}% confidence
            </span>
          ) : null}
        </div>

        {incidentDevices.length === 0 ? (
          <p className="empty-state">No impacted device is currently available in the snapshot, so direct actions are disabled.</p>
        ) : null}

        <div className="form-actions">
          <button
            type="button"
            className="primary-link"
            disabled={Boolean(actionBusy) || !selectedDevice}
            onClick={() =>
              selectedDevice &&
              void runAction(selectedDevice.isolated ? "Release device" : "Isolate device", () =>
                selectedDevice.isolated ? releaseDevice(selectedDevice.id) : isolateDevice(selectedDevice.id)
              )
            }
          >
            {selectedDevice?.isolated ? "Release device" : "Isolate device"}
          </button>
          <button
            type="button"
            className="secondary-link"
            disabled={Boolean(actionBusy) || !selectedDevice || !targetPath.trim()}
            onClick={() =>
              selectedDevice &&
              targetPath.trim() &&
              void runAction("Remediate path", () => queueRemediatePath(selectedDevice.id, targetPath.trim()))
            }
          >
            Remediate path
          </button>
          <button
            type="button"
            className="secondary-link"
            disabled={Boolean(actionBusy) || !selectedDevice || !targetPath.trim()}
            onClick={() =>
              selectedDevice &&
              targetPath.trim() &&
              void runAction("Terminate process tree", () =>
                queueProcessTreeTerminate(selectedDevice.id, targetPath.trim())
              )
            }
          >
            Kill process tree
          </button>
          <button
            type="button"
            className="secondary-link"
            disabled={Boolean(actionBusy) || !selectedDevice || !selectedScript}
            onClick={() =>
              selectedDevice &&
              selectedScript &&
              void runAction("Run script", () => queueRunScript(selectedDevice.id, selectedScript.id))
            }
          >
            Run script
          </button>
        </div>

        {actionMessage ? <p className="muted-copy">{actionMessage}</p> : <p className="muted-copy">{incident.recommendedAction}</p>}
      </section>

      <section className="drawer-panel">
        <p className="section-kicker">Risk context</p>
        <h3>Why this incident is at the top</h3>
        <p className="muted-copy">{incident.deviceRiskSummary}</p>
        <div className="tag-row">
          <span className={`state-chip tone-${priorityTone(incident.priorityScore)}`}>priority {incident.priorityScore}</span>
          <span className={`state-chip tone-${riskTone(incident.highestDeviceRiskBand)}`}>
            {incident.highestDeviceRiskScore != null
              ? `${incident.highestDeviceRiskScore}/100 ${incident.highestDeviceRiskBand ?? "pending"}`
              : "risk pending"}
          </span>
        </div>
        <p className="muted-copy">{incident.recommendedAction}</p>
      </section>

      <section className="drawer-panel">
        <p className="section-kicker">Latest event</p>
        <p className="muted-copy">{incident.latestEvent}</p>
        <span className="drawer-timestamp">{formatDateTime(incident.lastActivityAt)}</span>
      </section>
    </div>
  );

  return (
    <ConsoleShell
      activeNav="incidents"
      title={incident.title}
      subtitle="Correlated evidence, attack timeline, and response choices for this incident."
      searchValue={query}
      searchPlaceholder="Search the incident timeline, entities, techniques, or action text..."
      onSearchChange={setQuery}
      onRefresh={() => {
        void Promise.all([refreshSnapshot("manual"), refreshScripts()]);
      }}
      refreshing={refreshing}
      source={source}
      generatedAt={snapshot.generatedAt}
      policyRevision={snapshot.defaultPolicy.revision}
      statusItems={[
        { label: incident.severity, tone: incident.severity === "critical" ? "danger" : "warning" },
        { label: `priority ${incident.priorityScore}`, tone: priorityTone(incident.priorityScore) },
        { label: incident.status }
      ]}
      drawer={drawer}
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
              <dt>Priority</dt>
              <dd>{incident.priorityScore}</dd>
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
              <dt>Primary device</dt>
              <dd>{incident.primaryDeviceName ?? "Unknown"}</dd>
            </div>
            <div>
              <dt>Affected assets</dt>
              <dd>{incident.affectedAssetCount}</dd>
            </div>
            <div>
              <dt>Last seen</dt>
              <dd>{formatDateTime(incident.lastActivityAt)}</dd>
            </div>
          </dl>

          <div className="tag-row">
            <span className={`state-chip tone-${riskTone(incident.highestDeviceRiskBand)}`}>
              {incident.highestDeviceRiskScore != null
                ? `${incident.highestDeviceRiskScore}/100 ${incident.highestDeviceRiskBand ?? "pending"}`
                : "risk pending"}
            </span>
            <span className={`state-chip tone-${priorityTone(incident.priorityScore)}`}>priority {incident.priorityScore}</span>
            <span className="state-chip tone-default">{incident.sourceMix.join(" · ")}</span>
          </div>

          <div className="surface-subsection">
            <p className="section-kicker">Correlation</p>
            <p className="muted-copy">{incident.deviceRiskSummary}</p>
            <p className="muted-copy">{incident.recommendedAction}</p>
          </div>
        </article>

        <article className="surface-card">
          <p className="section-kicker">Timeline</p>
          <h3>Attack and response sequence</h3>
          <div className="timeline">
            {timeline.length === 0 ? (
              <p className="empty-state">No timeline entries match the current search.</p>
            ) : (
              timeline.map((item) => (
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
              ))
            )}
          </div>
        </article>

        <article className="surface-card">
          <p className="section-kicker">Entities and scope</p>
          <h3>Impacted assets</h3>
          <div className="stack-section">
            <div className="entity-group">
              <h4>Devices</h4>
              <ul className="key-list">
                {incident.deviceIds.map((deviceId, index) => {
                  const device = devicesById.get(deviceId);
                  return (
                    <li key={deviceId}>
                      <div className="row-between">
                        <Link href={`/devices/${deviceId}`}>{incident.deviceNames[index] ?? deviceId}</Link>
                        <span className={`state-chip tone-${riskTone(device?.riskBand)}`}>
                          {device?.riskScore != null
                            ? `${device.riskScore}/100 ${device.riskBand ?? "pending"}`
                            : "score pending"}
                        </span>
                      </div>
                    </li>
                  );
                })}
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