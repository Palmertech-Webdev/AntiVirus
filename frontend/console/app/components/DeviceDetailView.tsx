"use client";

import Link from "next/link";
import { startTransition, useCallback, useEffect, useRef, useState } from "react";

import ConsoleShell from "./ConsoleShell";
import { loadDeviceDetail, type DataSource } from "../../lib/api";
import type { DeviceDetail } from "../../lib/types";

function formatDateTime(value: string | null) {
  return value ? new Date(value).toLocaleString() : "Awaiting first sync";
}

function compactHash(value: string) {
  return value.length > 24 ? `${value.slice(0, 16)}...${value.slice(-8)}` : value;
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

function commandLabel(value: string) {
  return value.replaceAll(".", " ");
}

export default function DeviceDetailView({ deviceId }: { deviceId: string }) {
  const [detail, setDetail] = useState<DeviceDetail | null>(null);
  const [source, setSource] = useState<DataSource>("fallback");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [query, setQuery] = useState("");
  const requestInFlightRef = useRef<Promise<void> | null>(null);

  const refreshDetail = useCallback(async (mode: "initial" | "poll" | "manual") => {
    if (requestInFlightRef.current) {
      return requestInFlightRef.current;
    }

    if (mode !== "poll") {
      setRefreshing(true);
    }

    const request = (async () => {
      try {
        const result = await loadDeviceDetail(deviceId);

        startTransition(() => {
          setDetail(result.data);
          setSource(result.source);
          setLoading(false);
        });
      } catch {
        startTransition(() => {
          setLoading(false);
        });
      } finally {
        requestInFlightRef.current = null;
        setRefreshing(false);
      }
    })();

    requestInFlightRef.current = request;
    return request;
  }, [deviceId]);

  useEffect(() => {
    void refreshDetail("initial");
    const intervalId = window.setInterval(() => {
      void refreshDetail("poll");
    }, 60000);

    return () => {
      window.clearInterval(intervalId);
    };
  }, [refreshDetail]);

  if (!loading && !detail) {
    return (
      <ConsoleShell
        activeNav="devices"
        title="Device not found"
        subtitle="The control plane does not currently have a matching endpoint record."
        searchValue={query}
        searchPlaceholder="Search devices, alerts, telemetry, or evidence..."
        onSearchChange={setQuery}
        onRefresh={() => {
          void refreshDetail("manual");
        }}
        refreshing={refreshing}
        source={source}
        generatedAt={new Date().toISOString()}
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

  const device = detail?.device;
  const posture = detail?.posture;
  const alerts =
    detail?.alerts.filter((item) =>
      matchesQuery(query, [item.title, item.summary, item.technique, item.severity, item.status])
    ) ?? [];
  const telemetry =
    detail?.telemetry.filter((item) => matchesQuery(query, [item.eventType, item.summary, item.source, item.payloadJson])) ??
    [];
  const commands =
    detail?.commands.filter((item) => matchesQuery(query, [item.type, item.status, item.targetPath, item.recordId, item.issuedBy])) ??
    [];
  const evidence =
    detail?.evidence.filter((item) =>
      matchesQuery(query, [item.subjectPath, item.summary, item.techniqueId, item.reputation, item.signer, item.sha256])
    ) ?? [];
  const quarantineItems =
    detail?.quarantineItems.filter((item) =>
      matchesQuery(query, [item.originalPath, item.quarantinedPath, item.status, item.technique, item.sha256])
    ) ?? [];

  return (
    <ConsoleShell
      activeNav="devices"
      title={device?.hostname ?? "Endpoint detail"}
      subtitle="Endpoint investigation, protection posture, evidence, telemetry, and response history."
      searchValue={query}
      searchPlaceholder="Search this device for alerts, telemetry, commands, evidence, paths, or hashes..."
      onSearchChange={setQuery}
      onRefresh={() => {
        void refreshDetail("manual");
      }}
      refreshing={refreshing}
      source={source}
      generatedAt={device?.lastSeenAt ?? new Date().toISOString()}
      policyRevision={device?.policyName ?? "unknown"}
      statusItems={[
        { label: loading ? "loading" : `${alerts.length} alert(s)`, tone: alerts.length > 0 ? "warning" : "default" },
        { label: device?.healthState ?? "unknown", tone: device?.healthState === "degraded" || device?.healthState === "isolated" ? "warning" : "default" }
      ]}
      drawer={
        <div className="drawer-stack">
          <section className="drawer-panel">
            <p className="section-kicker">Device summary</p>
            <h3>{device?.hostname}</h3>
            <dl className="definition-grid">
              <div>
                <dt>OS</dt>
                <dd>{device?.osVersion}</dd>
              </div>
              <div>
                <dt>Policy</dt>
                <dd>{device?.policyName}</dd>
              </div>
              <div>
                <dt>Last seen</dt>
                <dd>{formatDateTime(device?.lastSeenAt ?? null)}</dd>
              </div>
              <div>
                <dt>Isolation</dt>
                <dd>{device?.isolated ? "active" : "inactive"}</dd>
              </div>
            </dl>
          </section>

          <section className="drawer-panel">
            <p className="section-kicker">Operator actions</p>
            <div className="action-stack">
              <Link href="/incidents" className="secondary-link">
                Open incidents
              </Link>
              <Link href="/alerts" className="secondary-link">
                Review alerts
              </Link>
            </div>
          </section>
        </div>
      }
    >
      <section className="grid grid-4">
        <article className="metric-surface">
          <span className="metric-label">Open alerts</span>
          <strong className="metric-number">{device?.openAlertCount ?? 0}</strong>
          <p className="muted-copy">Current incident pressure affecting this endpoint.</p>
        </article>
        <article className="metric-surface">
          <span className="metric-label">Quarantined items</span>
          <strong className="metric-number">{device?.quarantinedItemCount ?? 0}</strong>
          <p className="muted-copy">Artifacts currently held in containment.</p>
        </article>
        <article className="metric-surface">
          <span className="metric-label">Commands</span>
          <strong className="metric-number">{detail?.commands.length ?? 0}</strong>
          <p className="muted-copy">Queued and completed response actions.</p>
        </article>
        <article className="metric-surface">
          <span className="metric-label">Evidence items</span>
          <strong className="metric-number">{detail?.evidence.length ?? 0}</strong>
          <p className="muted-copy">Analyst artifacts and scan findings tied to this host.</p>
        </article>
      </section>

      <section className="grid device-detail-grid">
        <article className="surface-card">
          <p className="section-kicker">Device summary</p>
          <h3>Endpoint profile</h3>
          <dl className="definition-grid">
            <div>
              <dt>Hostname</dt>
              <dd>{device?.hostname}</dd>
            </div>
            <div>
              <dt>Serial</dt>
              <dd>{device?.serialNumber}</dd>
            </div>
            <div>
              <dt>Agent version</dt>
              <dd>{device?.agentVersion}</dd>
            </div>
            <div>
              <dt>Platform version</dt>
              <dd>{device?.platformVersion}</dd>
            </div>
            <div>
              <dt>Enrolled</dt>
              <dd>{formatDateTime(device?.enrolledAt ?? null)}</dd>
            </div>
            <div>
              <dt>Last policy sync</dt>
              <dd>{formatDateTime(device?.lastPolicySyncAt ?? null)}</dd>
            </div>
            <div>
              <dt>Last telemetry</dt>
              <dd>{formatDateTime(device?.lastTelemetryAt ?? null)}</dd>
            </div>
            <div>
              <dt>Isolation</dt>
              <dd>{device?.isolated ? "active" : "inactive"}</dd>
            </div>
          </dl>
        </article>

        <article className="surface-card">
          <p className="section-kicker">Protection stack</p>
          <h3>Runtime posture</h3>
          <div className="tag-row">
            <span className={`state-chip tone-${posture?.overallState ?? "unknown"}`}>overall {posture?.overallState ?? "unknown"}</span>
            <span className={`state-chip tone-${posture?.tamperProtectionState ?? "unknown"}`}>
              tamper {posture?.tamperProtectionState ?? "unknown"}
            </span>
            <span className={`state-chip tone-${posture?.wscState ?? "unknown"}`}>wsc {posture?.wscState ?? "unknown"}</span>
            <span className={`state-chip tone-${posture?.etwState ?? "unknown"}`}>etw {posture?.etwState ?? "unknown"}</span>
            <span className={`state-chip tone-${posture?.wfpState ?? "unknown"}`}>wfp {posture?.wfpState ?? "unknown"}</span>
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

      <section className="grid grid-2">
        <article className="surface-card">
          <div className="section-heading">
            <div>
              <p className="section-kicker">Alerts</p>
              <h3>Recent detections</h3>
            </div>
          </div>
          <div className="list-stack">
            {alerts.length === 0 ? (
              <p className="empty-state">No alerts match the current search.</p>
            ) : (
              alerts.map((alert) => (
                <article key={alert.id} className="mini-card">
                  <div className="row-between">
                    <strong>{alert.title}</strong>
                    <span className={`state-chip tone-${alert.severity}`}>{alert.severity}</span>
                  </div>
                  <p>{alert.summary}</p>
                  <span className="mini-meta">
                    {alert.technique ?? "Technique pending"} · {formatDateTime(alert.detectedAt)}
                  </span>
                </article>
              ))
            )}
          </div>
        </article>

        <article className="surface-card">
          <div className="section-heading">
            <div>
              <p className="section-kicker">Response</p>
              <h3>Command history</h3>
            </div>
          </div>
          <div className="list-stack">
            {commands.length === 0 ? (
              <p className="empty-state">No commands match the current search.</p>
            ) : (
              commands.map((command) => (
                <article key={command.id} className="mini-card">
                  <div className="row-between">
                    <strong>{commandLabel(command.type)}</strong>
                    <span className={`state-chip tone-${command.status}`}>{command.status.replaceAll("_", " ")}</span>
                  </div>
                  <p>{command.targetPath ?? command.recordId ?? "No extra parameters"}</p>
                  <span className="mini-meta">
                    {command.issuedBy} · {formatDateTime(command.updatedAt)}
                  </span>
                </article>
              ))
            )}
          </div>
        </article>
      </section>

      <section className="grid grid-3">
        <article className="surface-card">
          <div className="section-heading">
            <div>
              <p className="section-kicker">Evidence</p>
              <h3>Captured artifacts</h3>
            </div>
          </div>
          <div className="list-stack">
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
                  <code className="hash-line">{compactHash(item.sha256)}</code>
                </article>
              ))
            )}
          </div>
        </article>

        <article className="surface-card">
          <div className="section-heading">
            <div>
              <p className="section-kicker">Quarantine</p>
              <h3>Contained files</h3>
            </div>
          </div>
          <div className="list-stack">
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
                </article>
              ))
            )}
          </div>
        </article>

        <article className="surface-card">
          <div className="section-heading">
            <div>
              <p className="section-kicker">Telemetry</p>
              <h3>Recent activity</h3>
            </div>
          </div>
          <div className="list-stack">
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
          </div>
        </article>
      </section>
    </ConsoleShell>
  );
}
