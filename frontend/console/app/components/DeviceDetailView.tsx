"use client";

import Link from "next/link";
import { startTransition, useCallback, useEffect, useRef, useState, type ReactNode } from "react";

import ConsoleShell from "./ConsoleShell";
import {
  deleteQuarantineItem,
  enforceDevicePrivilegeHardening,
  isolateDevice,
  listScripts,
  loadDeviceDetail,
  queuePrivilegeElevation,
  queueAgentUpdate,
  queueProcessTreeTerminate,
  queueRemediatePath,
  queueRunScript,
  queueSoftwareBlock,
  queueSoftwareUninstall,
  queueSoftwareUpdate,
  queueSoftwareUpdateSearch,
  recoverDevicePrivilegeHardening,
  releaseDevice,
  restoreQuarantineItem,
  type DataSource
} from "../../lib/api";
import type { DeviceCommandSummary, DeviceDetail, InstalledSoftwareSummary, PrivilegeEventSummary, ScriptSummary } from "../../lib/types";

type DeviceTabKey = "overview" | "response" | "software" | "quarantine" | "telemetry" | "privilege";

const tabs: Array<{ key: DeviceTabKey; label: string; description: string }> = [
  { key: "overview", label: "Overview", description: "Health, identity, addresses, posture, and alert pressure." },
  { key: "response", label: "Response", description: "Containment, remediation, scripts, and agent maintenance." },
  { key: "software", label: "Software", description: "Installed software inventory with update and control actions." },
  { key: "quarantine", label: "Quarantine", description: "Contained artifacts and captured evidence records." },
  { key: "telemetry", label: "Telemetry", description: "Recent endpoint events, command history, and scan findings." },
  { key: "privilege", label: "Privilege", description: "Baseline admin posture, break-glass status, and just-in-time elevation." }
];

function formatDateTime(value: string | null | undefined) {
  return value ? new Date(value).toLocaleString() : "Awaiting first sync";
}

function compactHash(value: string) {
  return value.length > 24 ? `${value.slice(0, 16)}...${value.slice(-8)}` : value;
}

function joinValues(values: string[]) {
  return values.length > 0 ? values.join(", ") : "Not reported";
}

function commandLabel(value: string) {
  return value.replaceAll(".", " ");
}

function prettyPayload(payloadJson: string) {
  try {
    return JSON.stringify(JSON.parse(payloadJson) as unknown, null, 2);
  } catch {
    return payloadJson;
  }
}

function matchesQuery(query: string, values: Array<string | undefined | null>) {
  if (!query.trim()) {
    return true;
  }

  const normalized = query.trim().toLowerCase();
  return values.some((value) => value?.toLowerCase().includes(normalized));
}

function splitReputation(value: string | null | undefined) {
  return value?.split(";").map((segment) => segment.trim()).filter(Boolean) ?? [];
}

function reputationTone(value: string) {
  const normalized = value.toLowerCase();
  if (normalized.includes("hashlookup-known-good") || normalized.includes("trusted-signed") || normalized.includes("trusted-path")) {
    return "ready";
  }

  if (normalized.includes("hashlookup-unavailable")) {
    return "warning";
  }

  if (normalized.includes("hashlookup-unknown") || normalized.includes("hashlookup-skipped")) {
    return "unknown";
  }

  if (normalized.includes("ransom") || normalized.includes("malicious") || normalized.includes("known-bad") || normalized.includes("suspicious")) {
    return "danger";
  }

  if (normalized.includes("unsigned") || normalized.includes("user-writable")) {
    return "warning";
  }

  return "default";
}

function reputationLabel(value: string) {
  const normalized = value.toLowerCase();
  if (normalized === "hashlookup-known-good") {
    return "hash lookup known good";
  }
  if (normalized === "hashlookup-known-good-cache") {
    return "hash lookup known good (cached)";
  }
  if (normalized === "hashlookup-unknown") {
    return "hash lookup no match";
  }
  if (normalized === "hashlookup-unknown-cache") {
    return "hash lookup no match (cached)";
  }
  if (normalized === "hashlookup-unavailable") {
    return "hash lookup unavailable";
  }
  if (normalized === "hashlookup-unavailable-cache") {
    return "hash lookup unavailable (cached)";
  }
  if (normalized === "hashlookup-skipped") {
    return "hash lookup skipped";
  }

  return value.replaceAll("hashlookup", "hash lookup").replaceAll("-", " ").replaceAll("_", " ").replace(/\s+/g, " ").trim();
}

function softwarePayload(item: InstalledSoftwareSummary) {
  return {
    softwareId: item.id,
    displayName: item.displayName,
    displayVersion: item.displayVersion,
    publisher: item.publisher,
    installLocation: item.installLocation,
    uninstallCommand: item.uninstallCommand,
    quietUninstallCommand: item.quietUninstallCommand,
    executableNames: item.executableNames
  };
}

function riskTone(value: string | null | undefined) {
  switch (value) {
    case "critical":
      return "critical";
    case "high":
      return "high";
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

function shellRiskTone(value: string | null | undefined): "default" | "warning" | "danger" {
  if (value === "critical" || value === "high") {
    return "danger";
  }

  if (value === "elevated") {
    return "warning";
  }

  return "default";
}

function shellConfidenceTone(value: number | null | undefined): "default" | "warning" | "danger" {
  if (value == null) {
    return "default";
  }

  if (value < 65) {
    return "danger";
  }

  if (value < 85) {
    return "warning";
  }

  return "default";
}

function privilegeModeTone(value: string | null | undefined) {
  switch (value) {
    case "restricted":
    case "recovery":
      return "warning";
    case "enforce":
      return "danger";
    case "monitor_only":
      return "default";
    default:
      return "unknown";
  }
}

function privilegeEventTone(value: PrivilegeEventSummary["kind"]) {
  switch (value) {
    case "hardening.applied":
    case "recovery.applied":
      return "warning";
    case "breakglass.used":
      return "critical";
    case "elevation.denied":
    case "hardening.tamper":
      return "danger";
    case "elevation.approved":
    case "elevation.requested":
    case "admin.added":
    case "admin.removed":
    case "admin.reenabled":
    case "baseline.captured":
    default:
      return "default";
  }
}

function categoryLabel(value: string) {
  return value.replaceAll("_", " ");
}

function MiniCardList({ children }: { children: ReactNode }) {
  return <div className="list-stack">{children}</div>;
}

function CommandPreview({ command }: { command: DeviceCommandSummary }) {
  return (
    <article className="mini-card">
      <div className="row-between">
        <strong>{commandLabel(command.type)}</strong>
        <span className={`state-chip tone-${command.status}`}>{command.status.replaceAll("_", " ")}</span>
      </div>
      <p>{command.targetPath ?? command.recordId ?? "No extra parameters"}</p>
      <span className="mini-meta">
        {command.issuedBy} · {formatDateTime(command.updatedAt)}
      </span>
    </article>
  );
}

function renderOverviewTab(
  device: DeviceDetail["device"] | null,
  posture: DeviceDetail["posture"] | null,
  latestScore: DeviceDetail["latestScore"],
  riskTelemetry: DeviceDetail["riskTelemetry"],
  privilegeBaseline: DeviceDetail["privilegeBaseline"],
  privilegeState: DeviceDetail["privilegeState"]
) {
  return (
    <section className="grid grid-2">
      <article className="surface-card">
        <p className="section-kicker">Risk summary</p>
        <h3>Explainable device score</h3>
        {latestScore ? (
          <>
            <div className="row-between">
              <strong className="metric-number">{latestScore.overallScore}</strong>
              <div className="tag-row">
                <span className={`state-chip tone-${riskTone(latestScore.riskBand)}`}>{latestScore.riskBand}</span>
                <span className={`state-chip tone-${confidenceTone(latestScore.confidenceScore)}`}>
                  {latestScore.confidenceScore}% confidence
                </span>
              </div>
            </div>
            <p>{latestScore.summary}</p>
            <MiniCardList>
              {latestScore.topRiskDrivers.length === 0 ? (
                <p className="empty-state">No strong risk drivers were identified from the available telemetry.</p>
              ) : (
                latestScore.topRiskDrivers.map((driver) => (
                  <article key={driver.id} className="mini-card">
                    <div className="row-between">
                      <strong>{driver.title}</strong>
                      <span className={`state-chip tone-${driver.severity}`}>{driver.severity}</span>
                    </div>
                    <p>{driver.detail}</p>
                    <span className="mini-meta">
                      {categoryLabel(driver.category)} · impact {driver.scoreImpact}
                    </span>
                  </article>
                ))
              )}
            </MiniCardList>
          </>
        ) : (
          <p className="empty-state">Fenrir has not calculated a score for this device yet.</p>
        )}
      </article>

      <article className="surface-card">
        <p className="section-kicker">Recommended response</p>
        <h3>Next-best actions</h3>
        {latestScore ? (
          <>
            {latestScore.overrideReasons.length > 0 ? (
              <MiniCardList>
                {latestScore.overrideReasons.map((reason) => (
                  <article key={reason} className="mini-card">
                    <div className="row-between">
                      <strong>Override applied</strong>
                      <span className="state-chip tone-critical">critical floor</span>
                    </div>
                    <p>{reason}</p>
                  </article>
                ))}
              </MiniCardList>
            ) : null}

            <MiniCardList>
              {latestScore.recommendedActions.length === 0 ? (
                <p className="empty-state">No additional response actions were recommended.</p>
              ) : (
                latestScore.recommendedActions.map((action) => (
                  <article key={action} className="mini-card">
                    <strong>{action}</strong>
                  </article>
                ))
              )}
            </MiniCardList>
          </>
        ) : (
          <p className="empty-state">Response guidance will appear after the first score calculation.</p>
        )}
      </article>

      <article className="surface-card">
        <p className="section-kicker">Category breakdown</p>
        <h3>Weighted score contribution</h3>
        <MiniCardList>
          {latestScore?.categoryScores.length ? (
            latestScore.categoryScores.map((category) => (
              <article key={category.category} className="mini-card">
                <div className="row-between">
                  <strong>{categoryLabel(category.category)}</strong>
                  <span className={`state-chip tone-${riskTone(category.score >= 80 ? "critical" : category.score >= 60 ? "high" : category.score >= 40 ? "elevated" : category.score >= 20 ? "guarded" : "low")}`}>
                    {category.score}/100
                  </span>
                </div>
                <span className="mini-meta">
                  Weight {category.weight}% · contribution {category.contribution}
                </span>
              </article>
            ))
          ) : (
            <p className="empty-state">Category scoring is waiting on telemetry.</p>
          )}
        </MiniCardList>
      </article>

      <article className="surface-card">
        <p className="section-kicker">Telemetry completeness</p>
        <h3>Confidence and missing fields</h3>
        {latestScore ? (
          <>
            <div className="tag-row">
              <span className={`state-chip tone-${confidenceTone(latestScore.confidenceScore)}`}>
                {latestScore.confidenceScore}% confidence
              </span>
              <span className="state-chip tone-default">{latestScore.telemetrySource ?? "derived"}</span>
              <span className="state-chip tone-default">{formatDateTime(latestScore.telemetryUpdatedAt)}</span>
            </div>
            <MiniCardList>
              {latestScore.missingTelemetryFields.length === 0 ? (
                <article className="mini-card">
                  <strong>Telemetry coverage is complete for the current scoring model.</strong>
                </article>
              ) : (
                latestScore.missingTelemetryFields.map((field) => (
                  <article key={field} className="mini-card">
                    <strong>{field.replaceAll("_", " ")}</strong>
                  </article>
                ))
              )}
            </MiniCardList>
            {riskTelemetry ? (
              <pre className="payload-block">{JSON.stringify(riskTelemetry, null, 2)}</pre>
            ) : null}
          </>
        ) : (
          <p className="empty-state">No telemetry confidence data is available yet.</p>
        )}
      </article>

      <article className="surface-card">
        <p className="section-kicker">Device summary</p>
        <h3>Endpoint overview</h3>
        <dl className="definition-grid">
          <div>
            <dt>Hostname</dt>
            <dd>{device?.hostname}</dd>
          </div>
          <div>
            <dt>Serial number</dt>
            <dd>{device?.serialNumber}</dd>
          </div>
          <div>
            <dt>Fenrir version</dt>
            <dd>{device?.agentVersion}</dd>
          </div>
          <div>
            <dt>Platform version</dt>
            <dd>{device?.platformVersion}</dd>
          </div>
          <div>
            <dt>Last logged-in user</dt>
            <dd>{device?.lastLoggedOnUser ?? "Not reported"}</dd>
          </div>
          <div>
            <dt>Policy</dt>
            <dd>{device?.policyName}</dd>
          </div>
          <div>
            <dt>Privilege hardening</dt>
            <dd>
              {privilegeState ? (
                <span className={`state-chip tone-${privilegeModeTone(privilegeState.privilegeHardeningMode)}`}>
                  {privilegeState.privilegeHardeningMode.replaceAll("_", " ")}
                </span>
              ) : (
                "Not assessed"
              )}
            </dd>
          </div>
          <div>
            <dt>Recovery path</dt>
            <dd>{privilegeState ? (privilegeState.recoveryPathExists ? "Escrowed" : "Missing") : "Not assessed"}</dd>
          </div>
          <div>
            <dt>Standing admins</dt>
            <dd>
              {privilegeState
                ? `${privilegeState.standingAdminPresentFlag ? "Present" : "None"} (${privilegeState.unapprovedAdminAccountCount} unapproved)`
                : "Not assessed"}
            </dd>
          </div>
          <div>
            <dt>Private IP addresses</dt>
            <dd>{joinValues(device?.privateIpAddresses ?? [])}</dd>
          </div>
          <div>
            <dt>Public IP address</dt>
            <dd>{device?.publicIpAddress ?? "Not reported"}</dd>
          </div>
          <div>
            <dt>Last seen</dt>
            <dd>{formatDateTime(device?.lastSeenAt)}</dd>
          </div>
          <div>
            <dt>Open alerts</dt>
            <dd>{device?.openAlertCount ?? 0}</dd>
          </div>
          <div>
            <dt>Quarantined items</dt>
            <dd>{device?.quarantinedItemCount ?? 0}</dd>
          </div>
          <div>
            <dt>Last telemetry</dt>
            <dd>{formatDateTime(device?.lastTelemetryAt)}</dd>
          </div>
        </dl>
        {privilegeBaseline || privilegeState ? (
          <div className="tag-row">
            {privilegeBaseline ? <span className="state-chip tone-default">Baseline captured {formatDateTime(privilegeBaseline.capturedAt)}</span> : null}
            {privilegeState ? <span className={`state-chip tone-${privilegeModeTone(privilegeState.privilegeHardeningMode)}`}>{privilegeState.summary}</span> : null}
          </div>
        ) : null}
      </article>

      <article className="surface-card">
        <p className="section-kicker">Protection stack</p>
        <h3>Runtime posture</h3>
        <div className="tag-row">
          <span className={`state-chip tone-${posture?.overallState ?? "unknown"}`}>
            overall {posture?.overallState ?? "unknown"}
          </span>
          <span className={`state-chip tone-${posture?.tamperProtectionState ?? "unknown"}`}>
            tamper {posture?.tamperProtectionState ?? "unknown"}
          </span>
          <span className={`state-chip tone-${posture?.wscState ?? "unknown"}`}>
            wsc {posture?.wscState ?? "unknown"}
          </span>
          <span className={`state-chip tone-${posture?.etwState ?? "unknown"}`}>
            etw {posture?.etwState ?? "unknown"}
          </span>
          <span className={`state-chip tone-${posture?.wfpState ?? "unknown"}`}>
            wfp {posture?.wfpState ?? "unknown"}
          </span>
        </div>
        <dl className="definition-grid">
          <div>
            <dt>Tamper</dt>
            <dd>{posture?.tamperProtectionSummary ?? "No tamper telemetry yet."}</dd>
          </div>
          <div>
            <dt>WSC</dt>
            <dd>{posture?.wscSummary ?? "No WSC telemetry yet."}</dd>
          </div>
          <div>
            <dt>ETW</dt>
            <dd>{posture?.etwSummary ?? "No ETW telemetry yet."}</dd>
          </div>
          <div>
            <dt>WFP</dt>
            <dd>{posture?.wfpSummary ?? "No WFP telemetry yet."}</dd>
          </div>
        </dl>
      </article>
    </section>
  );
}

interface ResponseTabProps {
  actionBusy: string | null;
  commands: DeviceCommandSummary[];
  device: DeviceDetail["device"] | null;
  remediationPath: string;
  runAction: (label: string, action: () => Promise<unknown>) => Promise<void>;
  scripts: ScriptSummary[];
  selectedScript: ScriptSummary | null;
  setRemediationPath: (value: string) => void;
  setSelectedScriptId: (value: string) => void;
  setUpdatePackagePath: (value: string) => void;
  updatePackagePath: string;
}

function renderResponseTab({
  actionBusy,
  commands,
  device,
  remediationPath,
  runAction,
  scripts,
  selectedScript,
  setRemediationPath,
  setSelectedScriptId,
  setUpdatePackagePath,
  updatePackagePath
}: ResponseTabProps) {
  return (
    <section className="grid grid-2">
      <article className="surface-card">
        <div className="section-heading">
          <div>
            <p className="section-kicker">Containment and remediation</p>
            <h3>Drive endpoint response actions</h3>
          </div>
        </div>

        <div className="field-grid">
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
            disabled={Boolean(actionBusy) || !device}
            onClick={() =>
              device &&
              void runAction(device.isolated ? "Release device" : "Isolate device", () =>
                device.isolated ? releaseDevice(device.id) : isolateDevice(device.id)
              )
            }
          >
            {device?.isolated ? "Release device" : "Isolate device"}
          </button>
          <button
            type="button"
            className="secondary-link"
            disabled={Boolean(actionBusy) || !device || !remediationPath.trim()}
            onClick={() =>
              device &&
              remediationPath.trim() &&
              void runAction("Remediate path", () => queueRemediatePath(device.id, remediationPath.trim()))
            }
          >
            Remediate path
          </button>
          <button
            type="button"
            className="secondary-link"
            disabled={Boolean(actionBusy) || !device || !remediationPath.trim()}
            onClick={() =>
              device &&
              remediationPath.trim() &&
              void runAction("Terminate process tree", () =>
                queueProcessTreeTerminate(device.id, remediationPath.trim())
              )
            }
          >
            Kill process tree
          </button>
        </div>
      </article>

      <article className="surface-card">
        <div className="section-heading">
          <div>
            <p className="section-kicker">Automation and maintenance</p>
            <h3>Scripts and platform updates</h3>
          </div>
        </div>

        <div className="field-grid">
          <label className="field-group">
            <span>Stored script</span>
            <select
              className="admin-input"
              value={selectedScript?.id ?? ""}
              onChange={(event) => setSelectedScriptId(event.target.value)}
            >
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
        </div>

        <div className="form-actions">
          <button
            type="button"
            className="primary-link"
            disabled={Boolean(actionBusy) || !device || !selectedScript}
            onClick={() => device && selectedScript && void runAction("Run script", () => queueRunScript(device.id, selectedScript.id))}
          >
            Run script
          </button>
          <button
            type="button"
            className="secondary-link"
            disabled={Boolean(actionBusy) || !device || !updatePackagePath.trim()}
            onClick={() =>
              device &&
              updatePackagePath.trim() &&
              void runAction("Queue update", () => queueAgentUpdate(device.id, updatePackagePath.trim()))
            }
          >
            Queue update
          </button>
        </div>

        <MiniCardList>
          {commands.length === 0 ? (
            <p className="empty-state">No command history is available for this device yet.</p>
          ) : (
            commands.slice(0, 8).map((command) => <CommandPreview key={command.id} command={command} />)
          )}
        </MiniCardList>
      </article>
    </section>
  );
}

interface SoftwareTabProps {
  actionBusy: string | null;
  allVisibleSoftwareSelected: boolean;
  availableUpdateCount: number;
  blockedSoftwareCount: number;
  detail: DeviceDetail | null;
  device: DeviceDetail["device"] | null;
  runBatchSoftwareAction: (
    label: string,
    items: InstalledSoftwareSummary[],
    actionFactory: (item: InstalledSoftwareSummary) => Promise<unknown>
  ) => Promise<void>;
  selectVisibleSoftware: (checked: boolean) => void;
  selectedSoftware: InstalledSoftwareSummary[];
  selectedSoftwareIds: string[];
  softwareItems: InstalledSoftwareSummary[];
  toggleSoftwareSelection: (softwareId: string, checked: boolean) => void;
}

function renderSoftwareTab({
  actionBusy,
  allVisibleSoftwareSelected,
  availableUpdateCount,
  blockedSoftwareCount,
  detail,
  device,
  runBatchSoftwareAction,
  selectVisibleSoftware,
  selectedSoftware,
  selectedSoftwareIds,
  softwareItems,
  toggleSoftwareSelection
}: SoftwareTabProps) {
  return (
    <>
      <section className="grid grid-4">
        <article className="metric-surface">
          <span className="metric-label">Installed software</span>
          <strong className="metric-number">{detail?.installedSoftware.length ?? 0}</strong>
          <p className="muted-copy">Inventory rows currently reported by Fenrir.</p>
        </article>
        <article className="metric-surface">
          <span className="metric-label">Selected</span>
          <strong className="metric-number">{selectedSoftware.length}</strong>
          <p className="muted-copy">Software rows selected for the next bulk action.</p>
        </article>
        <article className="metric-surface">
          <span className="metric-label">Updates available</span>
          <strong className="metric-number">{availableUpdateCount}</strong>
          <p className="muted-copy">Packages with a discovered newer version.</p>
        </article>
        <article className="metric-surface">
          <span className="metric-label">Blocked</span>
          <strong className="metric-number">{blockedSoftwareCount}</strong>
          <p className="muted-copy">Applications blocked from normal endpoint use.</p>
        </article>
      </section>

      <section className="surface-card">
        <div className="section-heading">
          <div>
            <p className="section-kicker">Software automation</p>
            <h3>Installed software inventory</h3>
          </div>
        </div>

        <div className="form-actions">
          <button
            type="button"
            className="secondary-link"
            disabled={Boolean(actionBusy) || !device || selectedSoftware.length === 0}
            onClick={() =>
              device &&
              void runBatchSoftwareAction("Search updates", selectedSoftware, (item) =>
                queueSoftwareUpdateSearch(device.id, softwarePayload(item))
              )
            }
          >
            Search updates
          </button>
          <button
            type="button"
            className="secondary-link"
            disabled={Boolean(actionBusy) || !device || selectedSoftware.length === 0}
            onClick={() =>
              device &&
              void runBatchSoftwareAction("Apply updates", selectedSoftware, (item) =>
                queueSoftwareUpdate(device.id, softwarePayload(item))
              )
            }
          >
            Apply updates
          </button>
          <button
            type="button"
            className="secondary-link"
            disabled={Boolean(actionBusy) || !device || selectedSoftware.length === 0}
            onClick={() =>
              device &&
              void runBatchSoftwareAction("Uninstall software", selectedSoftware, (item) =>
                queueSoftwareUninstall(device.id, softwarePayload(item))
              )
            }
          >
            Uninstall software
          </button>
          <button
            type="button"
            className="primary-link"
            disabled={Boolean(actionBusy) || !device || selectedSoftware.length === 0}
            onClick={() =>
              device &&
              void runBatchSoftwareAction("Block software", selectedSoftware, (item) =>
                queueSoftwareBlock(device.id, softwarePayload(item))
              )
            }
          >
            Block software
          </button>
        </div>

        {softwareItems.length === 0 ? (
          <p className="empty-state">No installed software matches the current search.</p>
        ) : (
          <div className="software-table-shell">
            <table className="software-table">
              <thead>
                <tr>
                  <th>
                    <input
                      type="checkbox"
                      checked={allVisibleSoftwareSelected}
                      onChange={(event) => selectVisibleSoftware(event.target.checked)}
                    />
                  </th>
                  <th>Software</th>
                  <th>Version</th>
                  <th>Publisher</th>
                  <th>Updates</th>
                  <th>Blocked</th>
                  <th>Install location</th>
                </tr>
              </thead>
              <tbody>
                {softwareItems.map((item) => (
                  <tr key={item.id}>
                    <td>
                      <input
                        type="checkbox"
                        checked={selectedSoftwareIds.includes(item.id)}
                        onChange={(event) => toggleSoftwareSelection(item.id, event.target.checked)}
                      />
                    </td>
                    <td>
                      <strong>{item.displayName}</strong>
                      <div className="table-subcopy">
                        {item.executableNames.length > 0
                          ? item.executableNames.join(", ")
                          : "Executable names not reported"}
                      </div>
                    </td>
                    <td>{item.displayVersion}</td>
                    <td>{item.publisher}</td>
                    <td>
                      <span className={`state-chip tone-${item.blocked ? "failed" : item.updateState}`}>
                        {item.blocked ? "blocked" : item.updateState}
                      </span>
                      <div className="table-subcopy">{item.updateSummary ?? "No update insight recorded yet."}</div>
                    </td>
                    <td>{item.blocked ? "Yes" : "No"}</td>
                    <td>{item.installLocation ?? "Not reported"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}

interface QuarantineTabProps {
  actionBusy: string | null;
  detail: DeviceDetail | null;
  device: DeviceDetail["device"] | null;
  evidence: DeviceDetail["evidence"];
  quarantineItems: DeviceDetail["quarantineItems"];
  runAction: (label: string, action: () => Promise<unknown>) => Promise<void>;
}

function renderQuarantineTab({ actionBusy, device, evidence, quarantineItems, runAction }: QuarantineTabProps) {
  return (
    <section className="grid grid-2">
      <article className="surface-card">
        <div className="section-heading">
          <div>
            <p className="section-kicker">Quarantine</p>
            <h3>Contained files</h3>
          </div>
        </div>

        <MiniCardList>
          {quarantineItems.length === 0 ? (
            <p className="empty-state">No quarantine items match the current search.</p>
          ) : (
            quarantineItems.map((item) => (
              <article key={item.recordId} className="mini-card">
                <div className="row-between">
                  <strong>{item.originalPath}</strong>
                  <span className={`state-chip tone-${item.status}`}>{item.status}</span>
                </div>
                <p>{item.quarantinedPath}</p>
                <code className="hash-line">{compactHash(item.sha256)}</code>
                {item.status === "quarantined" && device ? (
                  <div className="form-actions">
                    <button
                      type="button"
                      className="secondary-link"
                      disabled={Boolean(actionBusy)}
                      onClick={() => void runAction("Restore quarantined item", () => restoreQuarantineItem(device.id, item.recordId))}
                    >
                      Restore
                    </button>
                    <button
                      type="button"
                      className="secondary-link"
                      disabled={Boolean(actionBusy)}
                      onClick={() => void runAction("Delete quarantined item", () => deleteQuarantineItem(device.id, item.recordId))}
                    >
                      Delete
                    </button>
                  </div>
                ) : null}
              </article>
            ))
          )}
        </MiniCardList>
      </article>

      <article className="surface-card">
        <div className="section-heading">
          <div>
            <p className="section-kicker">Evidence</p>
            <h3>Captured artifacts</h3>
          </div>
        </div>

        <MiniCardList>
          {evidence.length === 0 ? (
            <p className="empty-state">No evidence items match the current search.</p>
          ) : (
            evidence.map((item) => (
              <article key={item.recordId} className="mini-card">
                <div className="row-between">
                  <strong>{item.subjectPath}</strong>
                  <span className="state-chip tone-default">{item.disposition}</span>
                </div>
                <p>{item.summary}</p>
                {splitReputation(item.reputation).length > 0 ? (
                  <div className="tag-row">
                    {splitReputation(item.reputation).map((segment) => (
                      <span key={`${item.recordId}-${segment}`} className={`state-chip tone-${reputationTone(segment)}`}>
                        {reputationLabel(segment)}
                      </span>
                    ))}
                  </div>
                ) : null}
                <code className="hash-line">{compactHash(item.sha256)}</code>
              </article>
            ))
          )}
        </MiniCardList>
      </article>
    </section>
  );
}

function renderTelemetryTab(
  commands: DeviceDetail["commands"],
  detail: DeviceDetail | null,
  telemetry: DeviceDetail["telemetry"]
) {
  return (
    <section className="grid grid-3">
      <article className="surface-card">
        <div className="section-heading">
          <div>
            <p className="section-kicker">Telemetry</p>
            <h3>Recent activity</h3>
          </div>
        </div>

        <MiniCardList>
          {telemetry.length === 0 ? (
            <p className="empty-state">No telemetry records match the current search.</p>
          ) : (
            telemetry.slice(0, 12).map((record) => (
              <article key={record.eventId} className="mini-card">
                <div className="row-between">
                  <strong>{record.eventType}</strong>
                  <span className="state-chip tone-default">{record.source}</span>
                </div>
                <p>{record.summary}</p>
                <pre className="payload-block">{prettyPayload(record.payloadJson)}</pre>
              </article>
            ))
          )}
        </MiniCardList>
      </article>

      <article className="surface-card">
        <div className="section-heading">
          <div>
            <p className="section-kicker">Response</p>
            <h3>Command history</h3>
          </div>
        </div>

        <MiniCardList>
          {commands.length === 0 ? (
            <p className="empty-state">No commands match the current search.</p>
          ) : (
            commands.map((command) => <CommandPreview key={command.id} command={command} />)
          )}
        </MiniCardList>
      </article>

      <article className="surface-card">
        <div className="section-heading">
          <div>
            <p className="section-kicker">Scan history</p>
            <h3>Recent findings</h3>
          </div>
        </div>

        <MiniCardList>
          {(detail?.scanHistory.length ?? 0) === 0 ? (
            <p className="empty-state">No scan findings are recorded for this device.</p>
          ) : (
            detail?.scanHistory.slice(0, 12).map((item) => (
              <article key={item.eventId} className="mini-card">
                <div className="row-between">
                  <strong>{item.subjectPath}</strong>
                  <span className={`state-chip tone-${item.disposition}`}>{item.disposition}</span>
                </div>
                <p>{item.summary}</p>
                {splitReputation(item.reputation).length > 0 ? (
                  <div className="tag-row">
                    {splitReputation(item.reputation).map((segment) => (
                      <span key={`${item.eventId}-${segment}`} className={`state-chip tone-${reputationTone(segment)}`}>
                        {reputationLabel(segment)}
                      </span>
                    ))}
                  </div>
                ) : null}
                <span className="mini-meta">
                  {item.techniqueId ?? "Technique pending"} · {formatDateTime(item.scannedAt)}
                </span>
              </article>
            ))
          )}
        </MiniCardList>
      </article>
    </section>
  );
}

export default function DeviceDetailView({ deviceId }: { deviceId: string }) {
  const [detail, setDetail] = useState<DeviceDetail | null>(null);
  const [scripts, setScripts] = useState<ScriptSummary[]>([]);
  const [source, setSource] = useState<DataSource>("fallback");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [query, setQuery] = useState("");
  const [activeTab, setActiveTab] = useState<DeviceTabKey>("overview");
  const [selectedScriptId, setSelectedScriptId] = useState("");
  const [selectedSoftwareIds, setSelectedSoftwareIds] = useState<string[]>([]);
  const [remediationPath, setRemediationPath] = useState("");
  const [updatePackagePath, setUpdatePackagePath] = useState("");
  const [actionBusy, setActionBusy] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const requestInFlightRef = useRef<Promise<void> | null>(null);

  const refreshDetail = useCallback(
    async (mode: "initial" | "poll" | "manual") => {
      if (requestInFlightRef.current) {
        return requestInFlightRef.current;
      }

      if (mode !== "poll") {
        setRefreshing(true);
      }

      const request = (async () => {
        try {
          const [result, nextScripts] = await Promise.all([
            loadDeviceDetail(deviceId),
            listScripts().catch(() => [] as ScriptSummary[])
          ]);

          startTransition(() => {
            setDetail(result.data);
            setScripts(nextScripts);
            setSelectedScriptId((current) => current || nextScripts[0]?.id || "");
            setSelectedSoftwareIds((current) => {
              const validIds = new Set(result.data?.installedSoftware.map((item) => item.id) ?? []);
              return current.filter((id) => validIds.has(id));
            });
            setSource(result.source);
            setLoading(false);
          });
        } catch {
          startTransition(() => setLoading(false));
        } finally {
          requestInFlightRef.current = null;
          setRefreshing(false);
        }
      })();

      requestInFlightRef.current = request;
      return request;
    },
    [deviceId]
  );

  useEffect(() => {
    void refreshDetail("initial");
    const intervalId = window.setInterval(() => void refreshDetail("poll"), 60000);
    return () => window.clearInterval(intervalId);
  }, [refreshDetail]);

  const runAction = useCallback(
    async (label: string, action: () => Promise<unknown>) => {
      setActionBusy(label);
      setActionMessage(null);

      try {
        await action();
        setActionMessage(`${label} queued successfully.`);
        await refreshDetail("manual");
      } catch (error) {
        setActionMessage(`${label} failed: ${error instanceof Error ? error.message : "Request failed"}`);
      } finally {
        setActionBusy(null);
      }
    },
    [refreshDetail]
  );

  const runBatchSoftwareAction = useCallback(
    async (
      label: string,
      items: InstalledSoftwareSummary[],
      actionFactory: (item: InstalledSoftwareSummary) => Promise<unknown>
    ) => {
      if (items.length === 0) {
        return;
      }

      setActionBusy(label);
      setActionMessage(null);

      let successCount = 0;
      const failures: string[] = [];

      for (const item of items) {
        try {
          await actionFactory(item);
          successCount += 1;
        } catch (error) {
          failures.push(`${item.displayName}: ${error instanceof Error ? error.message : "Request failed"}`);
        }
      }

      setActionMessage(
        failures.length === 0
          ? `${label} queued for ${successCount} software item(s).`
          : `${label} queued for ${successCount} item(s); ${failures.length} failed. ${failures[0]}`
      );
      await refreshDetail("manual");
      setActionBusy(null);
    },
    [refreshDetail]
  );

  if (!loading && !detail) {
    return (
      <ConsoleShell
        activeNav="devices"
        title="Device not found"
        subtitle="The control plane does not currently have a matching endpoint record."
        searchValue={query}
        searchPlaceholder="Search devices, alerts, telemetry, or evidence..."
        onSearchChange={setQuery}
        onRefresh={() => void refreshDetail("manual")}
        refreshing={refreshing}
        source={source}
        generatedAt={null}
        policyRevision="unknown"
      >
        <section className="surface-card">
          <p className="section-kicker">Endpoint detail</p>
          <h3>This device is not present in the current backend snapshot.</h3>
          <p className="muted-copy">If the agent recently re-enrolled, refresh the console and check the device list again.</p>
          <Link href="/devices" className="primary-link">
            Back to devices
          </Link>
        </section>
      </ConsoleShell>
    );
  }

  const device = detail?.device ?? null;
  const posture = detail?.posture ?? null;
  const alerts =
    detail?.alerts.filter((item) =>
      matchesQuery(query, [item.title, item.summary, item.technique, item.severity, item.status])
    ) ?? [];
  const telemetry =
    detail?.telemetry.filter((item) =>
      matchesQuery(query, [item.eventType, item.summary, item.source, item.payloadJson])
    ) ?? [];
  const commands =
    detail?.commands.filter((item) =>
      matchesQuery(query, [item.type, item.status, item.targetPath, item.recordId, item.issuedBy])
    ) ?? [];
  const evidence =
    detail?.evidence.filter((item) =>
      matchesQuery(query, [item.subjectPath, item.summary, item.techniqueId, item.reputation, item.signer, item.sha256])
    ) ?? [];
  const quarantineItems =
    detail?.quarantineItems.filter((item) =>
      matchesQuery(query, [item.originalPath, item.quarantinedPath, item.status, item.technique, item.sha256])
    ) ?? [];
  const softwareItems =
    detail?.installedSoftware.filter((item) =>
      matchesQuery(query, [
        item.displayName,
        item.displayVersion,
        item.publisher,
        item.installLocation,
        item.updateSummary,
        item.executableNames.join(" ")
      ])
    ) ?? [];

  const selectedSoftware = (detail?.installedSoftware ?? []).filter((item) => selectedSoftwareIds.includes(item.id));
  const selectedScript = scripts.find((item) => item.id === selectedScriptId) ?? scripts[0] ?? null;
  const availableUpdateCount =
    (detail?.installedSoftware ?? []).filter((item) => item.updateState === "available").length;
  const blockedSoftwareCount = (detail?.installedSoftware ?? []).filter((item) => item.blocked).length;
  const latestScore = detail?.latestScore ?? null;
  const allVisibleSoftwareSelected =
    softwareItems.length > 0 && softwareItems.every((item) => selectedSoftwareIds.includes(item.id));

  const selectVisibleSoftware = (checked: boolean) => {
    setSelectedSoftwareIds((current) =>
      checked
        ? Array.from(new Set([...current, ...softwareItems.map((item) => item.id)]))
        : current.filter((id) => !softwareItems.some((item) => item.id === id))
    );
  };

  const toggleSoftwareSelection = (softwareId: string, checked: boolean) => {
    setSelectedSoftwareIds((current) =>
      checked ? Array.from(new Set([...current, softwareId])) : current.filter((id) => id !== softwareId)
    );
  };

  const drawer = device ? (
    <div className="drawer-stack">
      <section className="drawer-panel">
        <p className="section-kicker">Device summary</p>
        <h3>{device.hostname}</h3>
        <dl className="definition-grid">
          <div>
            <dt>OS</dt>
            <dd>{device.osVersion}</dd>
          </div>
          <div>
            <dt>Fenrir version</dt>
            <dd>{device.agentVersion}</dd>
          </div>
          <div>
            <dt>Last seen</dt>
            <dd>{formatDateTime(device.lastSeenAt)}</dd>
          </div>
          <div>
            <dt>Risk score</dt>
            <dd>{latestScore?.overallScore ?? "--"}</dd>
          </div>
          <div>
            <dt>Risk band</dt>
            <dd>{latestScore?.riskBand ?? "pending"}</dd>
          </div>
          <div>
            <dt>Confidence</dt>
            <dd>{latestScore ? `${latestScore.confidenceScore}%` : "--"}</dd>
          </div>
          <div>
            <dt>Last user</dt>
            <dd>{device.lastLoggedOnUser ?? "Not reported"}</dd>
          </div>
          <div>
            <dt>Private IPs</dt>
            <dd>{joinValues(device.privateIpAddresses)}</dd>
          </div>
          <div>
            <dt>Public IP</dt>
            <dd>{device.publicIpAddress ?? "Not reported"}</dd>
          </div>
        </dl>
      </section>

      <section className="drawer-panel">
        <p className="section-kicker">Operator actions</p>
        <div className="action-stack">
          <button
            type="button"
            className="primary-link"
            disabled={Boolean(actionBusy)}
            onClick={() =>
              void runAction(device.isolated ? "Release device" : "Isolate device", () =>
                device.isolated ? releaseDevice(device.id) : isolateDevice(device.id)
              )
            }
          >
            {device.isolated ? "Release device" : "Isolate device"}
          </button>
          <Link href="/incidents" className="secondary-link">
            Open incidents
          </Link>
        </div>
      </section>
    </div>
  ) : null;

  return (
    <ConsoleShell
      activeNav="devices"
      title={device?.hostname ?? "Endpoint detail"}
      subtitle="Endpoint investigation, response actions, software governance, and runtime telemetry."
      searchValue={query}
      searchPlaceholder="Search this endpoint for software, alerts, telemetry, paths, hashes, or commands..."
      onSearchChange={setQuery}
      onRefresh={() => void refreshDetail("manual")}
      refreshing={refreshing}
      source={source}
      generatedAt={device?.lastSeenAt ?? null}
      policyRevision={device?.policyName ?? "unknown"}
      statusItems={[
        {
          label: `${device?.openAlertCount ?? 0} open alert(s)`,
          tone: (device?.openAlertCount ?? 0) > 0 ? "warning" : "default"
        },
        {
          label: latestScore ? `${latestScore.overallScore}/100 ${latestScore.riskBand}` : "score pending",
          tone: latestScore ? shellRiskTone(latestScore.riskBand) : "default"
        },
        {
          label: latestScore ? `${latestScore.confidenceScore}% confidence` : "confidence pending",
          tone: latestScore ? shellConfidenceTone(latestScore.confidenceScore) : "default"
        }
      ]}
      drawer={drawer}
    >
      {actionMessage ? (
        <section className="surface-card">
          <p className="section-kicker">Action status</p>
          <h3>{actionMessage}</h3>
        </section>
      ) : null}

      <section className="grid grid-6">
        <article className="metric-surface">
          <span className="metric-label">Risk score</span>
          <strong className="metric-number">{latestScore?.overallScore ?? "--"}</strong>
          <p className="muted-copy">{latestScore?.riskBand ?? "Score pending"}.</p>
        </article>
        <article className="metric-surface">
          <span className="metric-label">Confidence</span>
          <strong className="metric-number">{latestScore ? `${latestScore.confidenceScore}%` : "--"}</strong>
          <p className="muted-copy">Telemetry completeness for this score snapshot.</p>
        </article>
        <article className="metric-surface">
          <span className="metric-label">Last seen</span>
          <strong className="metric-number">{device ? new Date(device.lastSeenAt).toLocaleTimeString() : "--"}</strong>
          <p className="muted-copy">Most recent endpoint check-in.</p>
        </article>
        <article className="metric-surface">
          <span className="metric-label">Open alerts</span>
          <strong className="metric-number">{device?.openAlertCount ?? 0}</strong>
          <p className="muted-copy">Uncontained alerts tied to this endpoint.</p>
        </article>
        <article className="metric-surface">
          <span className="metric-label">Quarantined</span>
          <strong className="metric-number">{device?.quarantinedItemCount ?? 0}</strong>
          <p className="muted-copy">Contained artifacts still held locally.</p>
        </article>
        <article className="metric-surface">
          <span className="metric-label">Installed software</span>
          <strong className="metric-number">{detail?.installedSoftware.length ?? 0}</strong>
          <p className="muted-copy">Inventory rows currently reported by Fenrir.</p>
        </article>
        <article className="metric-surface">
          <span className="metric-label">Updates available</span>
          <strong className="metric-number">{availableUpdateCount}</strong>
          <p className="muted-copy">Software items with a discovered newer version.</p>
        </article>
        <article className="metric-surface">
          <span className="metric-label">Blocked software</span>
          <strong className="metric-number">{blockedSoftwareCount}</strong>
          <p className="muted-copy">Applications Fenrir is actively suppressing.</p>
        </article>
      </section>

      <section className="surface-card">
        <div className="section-heading">
          <div>
            <p className="section-kicker">Endpoint workspace</p>
            <h3>Choose the operator view you need</h3>
          </div>
        </div>
        <div className="tab-strip">
          {tabs.map((tab) => (
            <button
              key={tab.key}
              type="button"
              className={`tab-chip${tab.key === activeTab ? " is-active" : ""}`}
              onClick={() => setActiveTab(tab.key)}
            >
              <strong>{tab.label}</strong>
              <small>{tab.description}</small>
            </button>
          ))}
        </div>
      </section>

      {activeTab === "overview"
        ? renderOverviewTab(
            device,
            posture,
            latestScore,
            detail?.riskTelemetry ?? null,
            detail?.privilegeBaseline ?? null,
            detail?.privilegeState ?? null
          )
        : null}
      {activeTab === "response"
        ? renderResponseTab({
            actionBusy,
            commands,
            device,
            remediationPath,
            runAction,
            scripts,
            selectedScript,
            setRemediationPath,
            setSelectedScriptId,
            setUpdatePackagePath,
            updatePackagePath
          })
        : null}
      {activeTab === "software"
        ? renderSoftwareTab({
            actionBusy,
            allVisibleSoftwareSelected,
            availableUpdateCount,
            blockedSoftwareCount,
            detail,
            device,
            runBatchSoftwareAction,
            selectVisibleSoftware,
            selectedSoftware,
            selectedSoftwareIds,
            softwareItems,
            toggleSoftwareSelection
          })
        : null}
      {activeTab === "quarantine"
        ? renderQuarantineTab({
            actionBusy,
            detail,
            device,
            evidence,
            quarantineItems,
            runAction
          })
        : null}
      {activeTab === "telemetry" ? renderTelemetryTab(commands, detail, telemetry) : null}
    </ConsoleShell>
  );
}
