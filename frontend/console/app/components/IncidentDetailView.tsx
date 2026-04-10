"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";

import ConsoleShell from "./ConsoleShell";
import { useConsoleData } from "./useConsoleData";
import {
  deleteQuarantineItem,
  isolateDevice,
  listScripts,
  loadDeviceDetail,
  queueAgentUpdate,
  queueProcessTreeTerminate,
  queueRemediatePath,
  queueRunScript,
  releaseDevice,
  restoreQuarantineItem
} from "../../lib/api";
import { buildConsoleViewModel } from "../../lib/console-model";
import type { DeviceDetail, ScriptSummary } from "../../lib/types";

function formatDateTime(value: string | null | undefined) {
  return value ? new Date(value).toLocaleString() : "Awaiting first activity";
}

function riskTone(value: string | null | undefined) {
  switch (value) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "elevated":
      return "warning";
    default:
      return "default";
  }
}

function compactHash(value: string) {
  return value.length > 24 ? `${value.slice(0, 16)}...${value.slice(-8)}` : value;
}

function initialPath(detail: DeviceDetail | null) {
  return (
    detail?.quarantineItems.find((item) => item.status === "quarantined")?.originalPath ??
    detail?.evidence[0]?.subjectPath ??
    detail?.scanHistory[0]?.subjectPath ??
    ""
  );
}

export default function IncidentDetailView({ incidentId }: { incidentId: string }) {
  const { snapshot, source, loading, refreshing, refreshSnapshot } = useConsoleData();
  const [query, setQuery] = useState("");
  const [relatedDetails, setRelatedDetails] = useState<DeviceDetail[]>([]);
  const [scripts, setScripts] = useState<ScriptSummary[]>([]);
  const [selectedDeviceId, setSelectedDeviceId] = useState("");
  const [selectedScriptId, setSelectedScriptId] = useState("");
  const [remediationPath, setRemediationPath] = useState("");
  const [updatePackagePath, setUpdatePackagePath] = useState("");
  const [actionBusy, setActionBusy] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  const model = buildConsoleViewModel(snapshot);
  const incident = model.incidents.find((item) => item.id === incidentId) ?? null;
  const incidentDeviceKey = incident?.deviceIds.join("|") ?? "";

  const refreshIncidentContext = useCallback(async () => {
    if (!incident) {
      setRelatedDetails([]);
      setScripts([]);
      return;
    }

    try {
      const [detailResults, nextScripts] = await Promise.all([
        Promise.all(incident.deviceIds.map((deviceId) => loadDeviceDetail(deviceId))),
        listScripts().catch(() => [] as ScriptSummary[])
      ]);

      const nextDetails = detailResults.map((item) => item.data).filter((item): item is DeviceDetail => item !== null);
      setRelatedDetails(nextDetails);
      setScripts(nextScripts);
      setSelectedDeviceId((current) => current || incident.primaryDeviceId || nextDetails[0]?.device.id || "");
      setSelectedScriptId((current) => current || nextScripts[0]?.id || "");
      setRemediationPath((current) => current || initialPath(nextDetails[0] ?? null));
    } catch {
      setRelatedDetails([]);
      setScripts([]);
    }
  }, [incident, incidentDeviceKey]);

  useEffect(() => {
    void refreshIncidentContext();
  }, [refreshIncidentContext]);

  const selectedDeviceDetail =
    relatedDetails.find((item) => item.device.id === selectedDeviceId) ?? relatedDetails[0] ?? null;
  const selectedDevice = selectedDeviceDetail?.device ?? null;
  const selectedScore = selectedDeviceDetail?.latestScore ?? null;
  const selectedScript = scripts.find((item) => item.id === selectedScriptId) ?? scripts[0] ?? null;

  const impactedDevices = useMemo(
    () =>
      incident?.deviceIds.map((deviceId) => {
        const detail = relatedDetails.find((item) => item.device.id === deviceId);
        const device = detail?.device ?? snapshot.devices.find((item) => item.id === deviceId) ?? null;
        return { id: deviceId, device, score: detail?.latestScore ?? null };
      }) ?? [],
    [incident, relatedDetails, snapshot.devices]
  );

  const runAction = useCallback(
    async (label: string, action: () => Promise<unknown>) => {
      setActionBusy(label);
      setActionMessage(null);
      try {
        await action();
        setActionMessage(`${label} queued successfully.`);
        await Promise.all([refreshSnapshot("manual"), refreshIncidentContext()]);
      } catch (error) {
        setActionMessage(`${label} failed: ${error instanceof Error ? error.message : "Request failed"}`);
      } finally {
        setActionBusy(null);
      }
    },
    [refreshIncidentContext, refreshSnapshot]
  );

  if (!incident && loading) {
    return (
      <ConsoleShell
        activeNav="incidents"
        title="Loading incident"
        subtitle="Fenrir is loading the latest incident queue and device context."
        searchValue={query}
        searchPlaceholder="Search incidents, devices, techniques, or owners..."
        onSearchChange={setQuery}
        onRefresh={() => void refreshSnapshot("manual")}
        refreshing={refreshing}
        source={source}
        generatedAt={snapshot.generatedAt}
        policyRevision={snapshot.defaultPolicy.revision}
      >
        <section className="surface-card">
          <p className="section-kicker">Incident detail</p>
          <h3>Loading the latest Fenrir incident context.</h3>
        </section>
      </ConsoleShell>
    );
  }

  if (!incident) {
    return (
      <ConsoleShell
        activeNav="incidents"
        title="Incident not found"
        subtitle="The current control-plane snapshot does not contain a matching incident."
        searchValue={query}
        searchPlaceholder="Search incidents, devices, techniques, or owners..."
        onSearchChange={setQuery}
        onRefresh={() => void refreshSnapshot("manual")}
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
      subtitle="Correlated evidence, device risk, and direct response actions for this incident."
      searchValue={query}
      searchPlaceholder="Search the timeline, impacted devices, quarantine paths, evidence, or action text..."
      onSearchChange={setQuery}
      onRefresh={() => void refreshSnapshot("manual")}
      refreshing={refreshing}
      source={source}
      generatedAt={snapshot.generatedAt}
      policyRevision={snapshot.defaultPolicy.revision}
      statusItems={[
        { label: incident.severity, tone: incident.severity === "critical" ? "danger" : "warning" },
        { label: incident.status },
        {
          label:
            incident.highestDeviceRiskScore != null
              ? `${incident.highestDeviceRiskScore}/100 ${incident.highestDeviceRiskBand ?? "pending"}`
              : "risk pending",
          tone: incident.highestDeviceRiskBand === "critical" || incident.highestDeviceRiskBand === "high" ? "danger" : "default"
        }
      ]}
      drawer={
        <div className="drawer-stack">
          <section className="drawer-panel">
            <p className="section-kicker">Target device</p>
            <h3>{selectedDevice?.hostname ?? incident.primaryDeviceName ?? "No target device"}</h3>
            <dl className="definition-grid">
              <div>
                <dt>Priority</dt>
                <dd>{incident.priorityScore}</dd>
              </div>
              <div>
                <dt>Open alerts</dt>
                <dd>{selectedDevice?.openAlertCount ?? 0}</dd>
              </div>
              <div>
                <dt>Risk</dt>
                <dd>{selectedScore ? `${selectedScore.overallScore}/100 ${selectedScore.riskBand}` : "pending"}</dd>
              </div>
              <div>
                <dt>Confidence</dt>
                <dd>{selectedScore ? `${selectedScore.confidenceScore}%` : "pending"}</dd>
              </div>
            </dl>
            <p className="muted-copy">{selectedScore?.analystSummary ?? incident.deviceRiskSummary}</p>
          </section>

          <section className="drawer-panel">
            <p className="section-kicker">Quick actions</p>
            <div className="action-stack">
              {selectedDevice ? (
                <button
                  type="button"
                  className="primary-link"
                  disabled={Boolean(actionBusy)}
                  onClick={() =>
                    void runAction(selectedDevice.isolated ? "Release device" : "Isolate device", () =>
                      selectedDevice.isolated ? releaseDevice(selectedDevice.id) : isolateDevice(selectedDevice.id)
                    )
                  }
                >
                  {selectedDevice.isolated ? "Release device" : "Isolate device"}
                </button>
              ) : null}
              {selectedDevice ? (
                <Link href={`/devices/${selectedDevice.id}`} className="secondary-link">
                  Open device
                </Link>
              ) : null}
            </div>
            {actionMessage ? <p className="muted-copy">{actionMessage}</p> : null}
          </section>
        </div>
      }
    >
      {actionMessage ? (
        <section className="surface-card">
          <p className="section-kicker">Action status</p>
          <h3>{actionMessage}</h3>
        </section>
      ) : null}

      <section className="grid grid-6">
        <article className="metric-surface">
          <span className="metric-label">Priority</span>
          <strong className="metric-number">{incident.priorityScore}</strong>
          <p className="muted-copy">Fenrir’s triage rank for this incident.</p>
        </article>
        <article className="metric-surface">
          <span className="metric-label">Affected assets</span>
          <strong className="metric-number">{incident.affectedAssetCount}</strong>
          <p className="muted-copy">Devices currently linked to this incident.</p>
        </article>
        <article className="metric-surface">
          <span className="metric-label">Device risk</span>
          <strong className="metric-number">{incident.highestDeviceRiskScore ?? "--"}</strong>
          <p className="muted-copy">{incident.highestDeviceRiskBand ?? "pending"}.</p>
        </article>
        <article className="metric-surface">
          <span className="metric-label">Confidence</span>
          <strong className="metric-number">{incident.confidenceScore}%</strong>
          <p className="muted-copy">Incident confidence from the current snapshot.</p>
        </article>
        <article className="metric-surface">
          <span className="metric-label">Evidence</span>
          <strong className="metric-number">{incident.evidenceCount}</strong>
          <p className="muted-copy">Evidence records currently tied to this incident.</p>
        </article>
        <article className="metric-surface">
          <span className="metric-label">Queued actions</span>
          <strong className="metric-number">{incident.commandCount}</strong>
          <p className="muted-copy">Response actions already associated with this workflow.</p>
        </article>
      </section>

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
            <div>
              <dt>Primary device</dt>
              <dd>{incident.primaryDeviceName ?? "Not available"}</dd>
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
            <p className="section-kicker">Risk context</p>
            <p className="muted-copy">{incident.deviceRiskSummary}</p>
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
          <div className="section-heading">
            <div>
              <p className="section-kicker">Response workspace</p>
              <h3>Act on the incident from here</h3>
            </div>
          </div>

          <div className="field-grid">
            <label className="field-group field-span-2">
              <span>Target device</span>
              <select className="admin-input" value={selectedDeviceId} onChange={(event) => setSelectedDeviceId(event.target.value)}>
                {impactedDevices.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.device?.hostname ?? item.id}
                    {item.score ? ` · ${item.score.overallScore}/100 ${item.score.riskBand}` : " · score pending"}
                  </option>
                ))}
              </select>
            </label>
            <label className="field-group">
              <span>Stored script</span>
              <select className="admin-input" value={selectedScript?.id ?? ""} onChange={(event) => setSelectedScriptId(event.target.value)}>
                {scripts.map((script) => (
                  <option key={script.id} value={script.id}>
                    {script.name} ({script.language})
                  </option>
                ))}
              </select>
            </label>
            <label className="field-group">
              <span>Update package path</span>
              <input
                className="admin-input"
                value={updatePackagePath}
                onChange={(event) => setUpdatePackagePath(event.target.value)}
                placeholder="C:\\Packages\\fenrir-update.pkg"
              />
            </label>
            <label className="field-group field-span-2">
              <span>Target path</span>
              <input
                className="admin-input"
                value={remediationPath}
                onChange={(event) => setRemediationPath(event.target.value)}
                placeholder="C:\\Users\\Public\\Downloads\\payload.exe"
              />
            </label>
          </div>

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
              disabled={Boolean(actionBusy) || !selectedDevice || !selectedScript}
              onClick={() =>
                selectedDevice &&
                selectedScript &&
                void runAction("Run script", () => queueRunScript(selectedDevice.id, selectedScript.id))
              }
            >
              Run script
            </button>
            <button
              type="button"
              className="secondary-link"
              disabled={Boolean(actionBusy) || !selectedDevice || !updatePackagePath.trim()}
              onClick={() =>
                selectedDevice &&
                updatePackagePath.trim() &&
                void runAction("Queue update", () => queueAgentUpdate(selectedDevice.id, updatePackagePath.trim()))
              }
            >
              Queue update
            </button>
            <button
              type="button"
              className="secondary-link"
              disabled={Boolean(actionBusy) || !selectedDevice || !remediationPath.trim()}
              onClick={() =>
                selectedDevice &&
                remediationPath.trim() &&
                void runAction("Remediate path", () => queueRemediatePath(selectedDevice.id, remediationPath.trim()))
              }
            >
              Remediate path
            </button>
            <button
              type="button"
              className="secondary-link"
              disabled={Boolean(actionBusy) || !selectedDevice || !remediationPath.trim()}
              onClick={() =>
                selectedDevice &&
                remediationPath.trim() &&
                void runAction("Kill process tree", () => queueProcessTreeTerminate(selectedDevice.id, remediationPath.trim()))
              }
            >
              Kill process tree
            </button>
          </div>
        </article>
      </section>

      <section className="grid grid-2">
        <article className="surface-card">
          <p className="section-kicker">Selected device score</p>
          <h3>Why this asset is risky</h3>
          {selectedScore ? (
            <>
              <div className="tag-row">
                <span className={`state-chip tone-${riskTone(selectedScore.riskBand)}`}>
                  {selectedScore.overallScore}/100 {selectedScore.riskBand}
                </span>
                <span className="state-chip tone-default">{selectedScore.confidenceScore}% confidence</span>
                <span className="state-chip tone-default">{formatDateTime(selectedScore.calculatedAt)}</span>
              </div>
              <p className="muted-copy">{selectedScore.analystSummary}</p>
              <div className="mini-card-list">
                {selectedScore.topRiskDrivers.map((driver) => (
                  <article key={driver.id} className="mini-card">
                    <div className="row-between">
                      <strong>{driver.title}</strong>
                      <span className={`state-chip tone-${driver.severity}`}>{driver.severity}</span>
                    </div>
                    <p>{driver.detail}</p>
                  </article>
                ))}
              </div>
              {selectedScore.overrideReasons.length > 0 ? (
                <div className="surface-subsection">
                  <p className="section-kicker">Override reasons</p>
                  <div className="mini-card-list">
                    {selectedScore.overrideReasons.map((reason) => (
                      <article key={reason} className="mini-card">
                        <strong>Critical floor applied</strong>
                        <p>{reason}</p>
                      </article>
                    ))}
                  </div>
                </div>
              ) : null}
            </>
          ) : (
            <p className="empty-state">Fenrir has not loaded a device score for the selected asset yet.</p>
          )}
        </article>

        <article className="surface-card">
          <p className="section-kicker">Quarantine workbench</p>
          <h3>Contained artifacts and evidence</h3>
          <div className="mini-card-list">
            {(selectedDeviceDetail?.quarantineItems ?? []).length === 0 ? (
              <p className="empty-state">No quarantined artifacts are available for this device.</p>
            ) : (
              selectedDeviceDetail!.quarantineItems.map((item) => (
                <article key={item.recordId} className="mini-card">
                  <div className="row-between">
                    <strong>{item.originalPath}</strong>
                    <span className={`state-chip tone-${item.status}`}>{item.status}</span>
                  </div>
                  <p>{item.quarantinedPath}</p>
                  <code className="hash-line">{compactHash(item.sha256)}</code>
                  <div className="action-stack">
                    <button
                      type="button"
                      className="secondary-link"
                      disabled={Boolean(actionBusy) || item.status !== "quarantined" || !selectedDevice}
                      onClick={() =>
                        selectedDevice &&
                        void runAction("Restore quarantined item", () => restoreQuarantineItem(selectedDevice.id, item.recordId))
                      }
                    >
                      Restore
                    </button>
                    <button
                      type="button"
                      className="secondary-link"
                      disabled={Boolean(actionBusy) || item.status === "deleted" || !selectedDevice}
                      onClick={() =>
                        selectedDevice &&
                        void runAction("Delete quarantined item", () => deleteQuarantineItem(selectedDevice.id, item.recordId))
                      }
                    >
                      Delete
                    </button>
                  </div>
                </article>
              ))
            )}
          </div>

          <div className="surface-subsection">
            <p className="section-kicker">Evidence preview</p>
            <div className="mini-card-list">
              {(selectedDeviceDetail?.evidence ?? []).length === 0 ? (
                <p className="empty-state">No evidence items are available for this device.</p>
              ) : (
                selectedDeviceDetail!.evidence.map((item) => (
                  <article key={item.recordId} className="mini-card">
                    <div className="row-between">
                      <strong>{item.subjectPath}</strong>
                      <span className="state-chip tone-default">{item.disposition}</span>
                    </div>
                    <p>{item.summary}</p>
                    <span className="mini-meta">
                      {item.techniqueId ?? "Technique pending"} · {formatDateTime(item.recordedAt)}
                    </span>
                  </article>
                ))
              )}
            </div>
          </div>
        </article>
      </section>

      <section className="surface-card">
        <div className="section-heading">
          <div>
            <p className="section-kicker">Impacted assets</p>
            <h3>Devices in this incident</h3>
          </div>
        </div>
        <div className="mini-card-list">
          {impactedDevices.map((item) => (
            <article key={item.id} className="mini-card">
              <div className="row-between">
                <strong>{item.device?.hostname ?? item.id}</strong>
                <div className="tag-row">
                  <span className={`state-chip tone-${item.device?.healthState ?? "default"}`}>
                    {item.device?.healthState ?? "unknown"}
                  </span>
                  <span className={`state-chip tone-${riskTone(item.score?.riskBand ?? item.device?.riskBand ?? null)}`}>
                    {item.score
                      ? `${item.score.overallScore}/100 ${item.score.riskBand}`
                      : item.device?.riskScore != null
                        ? `${item.device.riskScore}/100 ${item.device.riskBand ?? "pending"}`
                        : "risk pending"}
                  </span>
                </div>
              </div>
              <p>{item.score?.summary ?? item.device?.osVersion ?? "Awaiting device context."}</p>
              <span className="mini-meta">
                Last seen {formatDateTime(item.device?.lastSeenAt)} · {item.device?.openAlertCount ?? 0} open alert(s)
              </span>
              <div className="action-stack">
                {item.device ? (
                  <Link href={`/devices/${item.device.id}`} className="secondary-link">
                    Open device
                  </Link>
                ) : null}
                <button
                  type="button"
                  className="secondary-link"
                  disabled={Boolean(actionBusy) || !item.device}
                  onClick={() =>
                    item.device &&
                    void runAction(item.device.isolated ? "Release device" : "Isolate device", () =>
                      item.device!.isolated ? releaseDevice(item.device!.id) : isolateDevice(item.device!.id)
                    )
                  }
                >
                  {item.device?.isolated ? "Release device" : "Isolate device"}
                </button>
              </div>
            </article>
          ))}
        </div>
      </section>
    </ConsoleShell>
  );
}
