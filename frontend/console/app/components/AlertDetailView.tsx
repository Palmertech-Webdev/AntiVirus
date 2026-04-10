"use client";

import Link from "next/link";
import { startTransition, useCallback, useEffect, useRef, useState, type ReactNode } from "react";

import { loadAlertDetail, queueDeviceCommand, type DataSource } from "../../lib/api";
import { buildConsoleViewModel } from "../../lib/console-model";
import type { AlertDetail as AlertDetailModel, TelemetryRecord } from "../../lib/types";
import ConsoleShell from "./ConsoleShell";
import { useConsoleData } from "./useConsoleData";

type TimelineSeverity = AlertDetailModel["alert"]["severity"];
type TimelineCategory = "alert" | "telemetry" | "response" | "evidence" | "quarantine" | "scan" | "posture";

interface TimelineEntry {
  id: string;
  occurredAt: string;
  category: TimelineCategory;
  title: string;
  summary: string;
  source: string;
  severity: TimelineSeverity;
}

function formatDateTime(value: string | null | undefined) {
  return value ? new Date(value).toLocaleString() : "Awaiting first sync";
}

function matchesQuery(query: string, values: Array<string | undefined | null>) {
  if (!query.trim()) {
    return true;
  }

  const normalized = query.trim().toLowerCase();
  return values.some((value) => value?.toLowerCase().includes(normalized));
}

function amsiContextTerms(item: {
  appName?: string;
  contentName?: string;
  sourceType?: string;
  sessionId?: number;
  preview?: string;
}) {
  return [
    item.appName,
    item.contentName,
    item.sourceType,
    typeof item.sessionId === "number" ? `session ${item.sessionId}` : undefined,
    item.preview
  ].filter((value): value is string => Boolean(value));
}

function amsiContextChips(item: {
  appName?: string;
  contentName?: string;
  sourceType?: string;
  sessionId?: number;
}) {
  return [
    item.appName ? `app: ${item.appName}` : undefined,
    item.contentName ? `content: ${item.contentName}` : undefined,
    item.sourceType ? `source: ${item.sourceType}` : undefined,
    typeof item.sessionId === "number" ? `session ${item.sessionId}` : undefined
  ].filter((value): value is string => Boolean(value));
}

function processTelemetryTerms(item: Pick<
  TelemetryRecord,
  | "processId"
  | "parentProcessId"
  | "processImageName"
  | "processImagePath"
  | "parentProcessImageName"
  | "parentProcessImagePath"
  | "processCommandLine"
  | "processUserSid"
  | "processIntegrityLevel"
  | "processSessionId"
  | "processSigner"
  | "processExitCode"
  | "moduleImageName"
  | "moduleImagePath"
  | "moduleImageBase"
  | "moduleImageSize"
>) {
  return [
    typeof item.processId === "number" ? item.processId.toString() : undefined,
    typeof item.parentProcessId === "number" ? item.parentProcessId.toString() : undefined,
    item.processImageName,
    item.processImagePath,
    item.parentProcessImageName,
    item.parentProcessImagePath,
    item.processCommandLine,
    item.processUserSid,
    item.processIntegrityLevel,
    item.processSessionId,
    item.processSigner,
    typeof item.processExitCode === "number" ? item.processExitCode.toString() : undefined,
    item.moduleImageName,
    item.moduleImagePath,
    item.moduleImageBase,
    item.moduleImageSize
  ].filter((value): value is string => Boolean(value));
}

function processTelemetryChips(item: Pick<
  TelemetryRecord,
  | "processId"
  | "parentProcessId"
  | "processImageName"
  | "processImagePath"
  | "parentProcessImageName"
  | "parentProcessImagePath"
  | "processCommandLine"
  | "processUserSid"
  | "processIntegrityLevel"
  | "processSessionId"
  | "processSigner"
  | "processExitCode"
  | "moduleImageName"
  | "moduleImagePath"
  | "moduleImageBase"
  | "moduleImageSize"
>) {
  return [
    typeof item.processId === "number" ? `pid ${item.processId}` : undefined,
    typeof item.parentProcessId === "number" ? `parent ${item.parentProcessId}` : undefined,
    item.processImageName ? `process: ${item.processImageName}` : undefined,
    item.parentProcessImageName ? `parent image: ${item.parentProcessImageName}` : undefined,
    item.processSessionId ? `session ${item.processSessionId}` : undefined,
    item.processIntegrityLevel ? `integrity: ${item.processIntegrityLevel}` : undefined,
    item.processSigner ? `signer: ${item.processSigner}` : undefined,
    typeof item.processExitCode === "number" ? `exit ${item.processExitCode}` : undefined,
    item.moduleImageName ? `module: ${item.moduleImageName}` : undefined
  ].filter((value): value is string => Boolean(value));
}

function processTelemetryTitle(item: Pick<TelemetryRecord, "eventType" | "processImageName" | "moduleImageName">) {
  return item.processImageName ?? item.moduleImageName ?? item.eventType;
}

function processTelemetrySummary(
  item: Pick<TelemetryRecord, "processCommandLine" | "moduleImagePath" | "processImagePath" | "parentProcessImagePath">
) {
  if (item.processCommandLine) {
    return `Command line: ${item.processCommandLine}`;
  }

  if (item.moduleImagePath) {
    return `Module path: ${item.moduleImagePath}`;
  }

  if (item.processImagePath) {
    return `Image path: ${item.processImagePath}`;
  }

  if (item.parentProcessImagePath) {
    return `Parent path: ${item.parentProcessImagePath}`;
  }

  return undefined;
}

const attackTacticLabels: Record<string, string> = {
  TA0002: "Execution",
  TA0008: "Lateral Movement",
  TA0011: "Command and Control",
  TA0040: "Impact"
};

function formatAttackTactic(value: string) {
  return attackTacticLabels[value] ? `${value} · ${attackTacticLabels[value]}` : value;
}

function behaviorScoreTone(score: number) {
  if (score >= 80) {
    return "danger";
  }

  if (score >= 60) {
    return "warning";
  }

  return "default";
}

function behaviorStepTone(category: string) {
  switch (category) {
    case "alert":
      return "danger";
    case "process":
    case "module":
      return "warning";
    case "script":
    case "file":
      return "high";
    case "network":
      return "danger";
    case "quarantine":
      return "contained";
    case "response":
      return "ready";
    default:
      return "default";
  }
}

function playbookActionTone(category: string) {
  switch (category) {
    case "containment":
      return "danger";
    case "cleanup":
      return "warning";
    case "investigation":
      return "high";
    case "monitoring":
      return "default";
    default:
      return "default";
  }
}

function playbookModeTone(mode: string) {
  switch (mode) {
    case "containment":
      return "danger";
    case "cleanup":
      return "warning";
    default:
      return "default";
  }
}

function playbookActionLabel(action: NonNullable<AlertDetailModel["playbook"]>["actions"][number]) {
  if (action.commandType) {
    return action.commandType.replaceAll(".", " ");
  }

  return action.category;
}

function MiniCardList({ children }: { children: ReactNode }) {
  return <div className="list-stack">{children}</div>;
}

function postureTone(value: string) {
  if (value === "failed") {
    return "danger";
  }

  if (value === "degraded") {
    return "warning";
  }

  return "default";
}

function postureSeverity(value: NonNullable<AlertDetailModel["posture"]>["overallState"]): TimelineSeverity {
  if (value === "failed") {
    return "high";
  }

  if (value === "degraded") {
    return "medium";
  }

  return "low";
}

function buildAlertTimeline(detail: AlertDetailModel, sourceTelemetry: AlertDetailModel["matchingTelemetry"]): TimelineEntry[] {
  const timeline: TimelineEntry[] = [
    {
      id: `alert-${detail.alert.id}`,
      occurredAt: detail.alert.detectedAt,
      category: "alert",
      title: detail.alert.title,
      summary: detail.alert.summary,
      source: "endpoint-alert",
      severity: detail.alert.severity
    }
  ];

  for (const record of sourceTelemetry.slice(0, 10)) {
    timeline.push({
      id: `telemetry-${record.eventId}`,
      occurredAt: record.occurredAt,
      category: "telemetry",
      title: processTelemetryTitle(record),
      summary: record.summary,
      source: record.source,
      severity: detail.alert.severity
    });
  }

  for (const command of detail.commands.slice(0, 6)) {
    timeline.push({
      id: `command-${command.id}`,
      occurredAt: command.updatedAt,
      category: "response",
      title: command.type.replaceAll(".", " "),
      summary: `${command.status.replaceAll("_", " ")} by ${command.issuedBy}`,
      source: "response",
      severity: detail.alert.severity
    });
  }

  for (const item of detail.evidence.slice(0, 4)) {
    timeline.push({
      id: `evidence-${item.recordId}`,
      occurredAt: item.recordedAt,
      category: "evidence",
      title: item.disposition,
      summary: item.summary,
      source: item.source,
      severity: detail.alert.severity
    });
  }

  for (const item of detail.quarantineItems.slice(0, 4)) {
    timeline.push({
      id: `quarantine-${item.recordId}`,
      occurredAt: item.lastUpdatedAt,
      category: "quarantine",
      title: item.status,
      summary: `${item.originalPath} -> ${item.quarantinedPath}`,
      source: "quarantine",
      severity: detail.alert.severity
    });
  }

  for (const item of detail.scanHistory.slice(0, 4)) {
    timeline.push({
      id: `scan-${item.eventId}`,
      occurredAt: item.scannedAt,
      category: "scan",
      title: item.disposition,
      summary: item.summary,
      source: item.source,
      severity: detail.alert.severity
    });
  }

  if (detail.posture) {
    timeline.push({
      id: `posture-${detail.posture.deviceId}`,
      occurredAt: detail.posture.updatedAt,
      category: "posture",
      title: `posture ${detail.posture.overallState}`,
      summary:
        detail.posture.tamperProtectionSummary ??
        detail.posture.etwSummary ??
        detail.posture.wfpSummary ??
        "Protection state updated.",
      source: "posture",
      severity: postureSeverity(detail.posture.overallState)
    });
  }

  return timeline.sort((left, right) => left.occurredAt.localeCompare(right.occurredAt));
}

export default function AlertDetailView({ alertId }: { alertId: string }) {
  const { snapshot, source: dashboardSource, refreshing: dashboardRefreshing, refreshSnapshot } = useConsoleData();
  const [detail, setDetail] = useState<AlertDetailModel | null>(null);
  const [source, setSource] = useState<DataSource>("live");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [query, setQuery] = useState("");
  const [playbookActionBusy, setPlaybookActionBusy] = useState<string | null>(null);
  const [playbookMessage, setPlaybookMessage] = useState<string | null>(null);
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
          const result = await loadAlertDetail(alertId);

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
    },
    [alertId]
  );

  const runPlaybookAction = useCallback(
    async (action: NonNullable<AlertDetailModel["playbook"]>["actions"][number]) => {
      const deviceId = detail?.device?.id ?? detail?.alert.deviceId;
      if (!deviceId || action.commandType !== "scan.targeted" || !action.targetPath) {
        return;
      }

      setPlaybookMessage(null);
      setPlaybookActionBusy(action.id);

      try {
        await queueDeviceCommand(deviceId, {
          type: action.commandType,
          targetPath: action.targetPath,
          issuedBy: "console"
        });
        setPlaybookMessage(`Queued ${action.commandType.replaceAll(".", " ")} for ${action.targetPath}.`);
        await refreshDetail("manual");
      } catch {
        setPlaybookMessage(`Could not queue ${action.commandType.replaceAll(".", " ")} right now.`);
      } finally {
        setPlaybookActionBusy(null);
      }
    },
    [detail?.alert.deviceId, detail?.device?.id, refreshDetail]
  );

  useEffect(() => {
    void refreshDetail("initial");
    const intervalId = window.setInterval(() => {
      void refreshDetail("poll");
    }, 60000);

    return () => {
      window.clearInterval(intervalId);
    };
  }, [refreshDetail]);

  const model = buildConsoleViewModel(snapshot);
  const relatedIncident = detail ? model.incidents.find((incident) => incident.relatedAlertIds.includes(detail.alert.id)) ?? null : null;
  const behaviorChain = detail?.behaviorChain ?? null;
  const playbook = detail?.playbook ?? null;
  const sourceTelemetry = detail ? (detail.matchingTelemetry.length > 0 ? detail.matchingTelemetry : detail.telemetry.slice(0, 5)) : [];
  const supportingTelemetry = detail
    ? detail.telemetry.filter((item) => !sourceTelemetry.some((candidate) => candidate.eventId === item.eventId))
    : [];
  const timeline = detail ? buildAlertTimeline(detail, sourceTelemetry) : [];
  const behaviorSteps = behaviorChain?.steps ?? [];
  const playbookActions = playbook?.actions ?? [];
  const filteredBehaviorSteps = behaviorSteps.filter((step) =>
    matchesQuery(query, [
      step.title,
      step.summary,
      step.source,
      step.category,
      step.tacticId,
      step.techniqueId,
      step.atRisk,
      behaviorChain?.narrative,
      behaviorChain?.whatHappened,
      behaviorChain?.whySuspicious,
      behaviorChain?.blocked,
      behaviorChain?.atRisk
    ])
  );
  const filteredPlaybookActions = playbookActions.filter((action) =>
    matchesQuery(query, [
      action.title,
      action.detail,
      action.reason,
      action.category,
      action.commandType,
      action.targetPath,
      playbook?.title,
      playbook?.summary,
      ...(playbook?.evidenceToPreserve ?? [])
    ])
  );
  const filteredTimeline = timeline.filter((entry) => matchesQuery(query, [entry.title, entry.summary, entry.source, entry.category, entry.occurredAt]));
  const filteredSourceTelemetry = sourceTelemetry.filter((record) =>
    matchesQuery(query, [record.eventType, record.summary, record.source, record.payloadJson, record.occurredAt, ...processTelemetryTerms(record)])
  );
  const filteredSupportingTelemetry = supportingTelemetry.filter((record) =>
    matchesQuery(query, [record.eventType, record.summary, record.source, record.payloadJson, record.occurredAt, ...processTelemetryTerms(record)])
  );
  const filteredEvidence = detail
    ? detail.evidence.filter((item) =>
        matchesQuery(query, [item.summary, item.subjectPath, ...amsiContextTerms(item), item.source, item.disposition, item.recordedAt])
      )
    : [];
  const filteredQuarantine = detail ? detail.quarantineItems.filter((item) => matchesQuery(query, [item.originalPath, item.quarantinedPath, item.status, item.technique, item.capturedAt])) : [];
  const filteredScanHistory = detail
    ? detail.scanHistory.filter((item) =>
        matchesQuery(query, [item.summary, item.subjectPath, ...amsiContextTerms(item), item.source, item.disposition, item.scannedAt])
      )
    : [];
  const filteredCommands = detail ? detail.commands.filter((item) => matchesQuery(query, [item.type, item.status, item.issuedBy, item.targetPath, item.recordId])) : [];
  const filteredRelatedAlerts = detail ? detail.relatedAlerts.filter((item) => matchesQuery(query, [item.title, item.summary, item.hostname, item.technique, item.status])) : [];
  const shellSource: DataSource = source === "fallback" || dashboardSource === "fallback" ? "fallback" : "live";
  const shellRefreshing = refreshing || dashboardRefreshing;

  if (!detail && !loading) {
    return (
      <ConsoleShell
        activeNav="alerts"
        title="Alert not found"
        subtitle="The current control-plane snapshot does not contain a matching alert."
        searchValue={query}
        searchPlaceholder="Search alert evidence, telemetry, or related records..."
        onSearchChange={setQuery}
        onRefresh={() => {
          void Promise.all([refreshSnapshot("manual"), refreshDetail("manual")]);
        }}
        refreshing={shellRefreshing}
        source={shellSource}
        generatedAt={snapshot.generatedAt}
        policyRevision={snapshot.defaultPolicy.revision}
      >
        <section className="surface-card">
          <p className="section-kicker">Alert detail</p>
          <h3>No alert with this identifier is available right now.</h3>
          <p className="muted-copy">
            The alert may have aged out of the current snapshot, been merged into a later detection, or simply does not exist in
            the backing store.
          </p>
          <Link href="/alerts" className="primary-link">
            Return to alerts
          </Link>
        </section>
      </ConsoleShell>
    );
  }

  if (!detail) {
    return (
      <ConsoleShell
        activeNav="alerts"
        title="Alert detail"
        subtitle="Telemetry, evidence, quarantine, and related context for a single alert."
        searchValue={query}
        searchPlaceholder="Search alert evidence, telemetry, or related records..."
        onSearchChange={setQuery}
        onRefresh={() => {
          void Promise.all([refreshSnapshot("manual"), refreshDetail("manual")]);
        }}
        refreshing={shellRefreshing}
        source={shellSource}
        generatedAt={snapshot.generatedAt}
        policyRevision={snapshot.defaultPolicy.revision}
      >
        <section className="surface-card">
          <p className="section-kicker">Alert detail</p>
          <h3>Loading alert evidence...</h3>
          <p className="muted-copy">Fetching the alert, related telemetry, and supporting records from the control plane.</p>
        </section>
      </ConsoleShell>
    );
  }

  return (
    <ConsoleShell
      activeNav="alerts"
      title={detail.alert.title}
      subtitle="Telemetry, evidence, quarantine, and related context for a single alert."
      searchValue={query}
      searchPlaceholder="Search alert evidence, telemetry, or related records..."
      onSearchChange={setQuery}
      onRefresh={() => {
        void Promise.all([refreshSnapshot("manual"), refreshDetail("manual")]);
      }}
      refreshing={shellRefreshing}
      source={shellSource}
      generatedAt={snapshot.generatedAt}
      policyRevision={snapshot.defaultPolicy.revision}
      statusItems={[
        { label: detail.alert.severity, tone: detail.alert.severity === "critical" ? "danger" : "warning" },
        { label: `${sourceTelemetry.length} source events`, tone: sourceTelemetry.length > 0 ? "warning" : "default" },
        { label: `${filteredEvidence.length} evidence records`, tone: filteredEvidence.length > 0 ? "warning" : "default" },
        {
          label: behaviorChain ? `${behaviorChain.score}/100 sequence` : "sequence pending",
          tone: behaviorChain ? behaviorScoreTone(behaviorChain.score) : "default"
        },
        {
          label: playbook ? `${playbook.actions.length} playbook steps` : "playbook pending",
          tone: playbook ? playbookModeTone(playbook.mode) : "default"
        }
      ]}
    >
      <section className="surface-card">
        <div className="section-heading">
          <div>
            <p className="section-kicker">Alert detail</p>
            <h3>{detail.alert.summary}</h3>
          </div>
          <div className="tag-row">
            <span className={`state-chip tone-${detail.alert.severity}`}>{detail.alert.severity}</span>
            <span className={`state-chip tone-${detail.alert.status}`}>{detail.alert.status}</span>
            <span className="state-chip tone-default">{detail.alert.technique ?? "Technique pending"}</span>
          </div>
        </div>

        <dl className="definition-grid">
          <div>
            <dt>Alert ID</dt>
            <dd>{detail.alert.id}</dd>
          </div>
          <div>
            <dt>Device</dt>
            <dd>{detail.device?.hostname ?? detail.alert.hostname}</dd>
          </div>
          <div>
            <dt>Device id</dt>
            <dd>{detail.device?.id ?? detail.alert.deviceId ?? "Unassigned"}</dd>
          </div>
          <div>
            <dt>Detected</dt>
            <dd>{formatDateTime(detail.alert.detectedAt)}</dd>
          </div>
          <div>
            <dt>Fingerprint</dt>
            <dd>{detail.alert.fingerprint ?? "Not generated"}</dd>
          </div>
          <div>
            <dt>Correlated incident</dt>
            <dd>{relatedIncident ? relatedIncident.title : "No incident in the current snapshot"}</dd>
          </div>
        </dl>

        <div className="tag-row">
          <span className="state-chip tone-default">endpoint</span>
          <span className="state-chip tone-default">{detail.alert.hostname}</span>
          {detail.alert.tacticId ? <span className="state-chip tone-default">{formatAttackTactic(detail.alert.tacticId)}</span> : null}
          {behaviorChain?.tacticIds.map((tacticId) => (
            <span key={`chain-tactic-${tacticId}`} className="state-chip tone-default">
              {formatAttackTactic(tacticId)}
            </span>
          ))}
          {detail.device ? <span className="state-chip tone-default">{detail.device.policyName}</span> : null}
          {detail.posture ? <span className={`state-chip tone-${postureTone(detail.posture.overallState)}`}>posture {detail.posture.overallState}</span> : null}
        </div>
      </section>

      {behaviorChain ? (
        <section className="surface-card">
          <div className="section-heading">
            <div>
              <p className="section-kicker">Behavior chain</p>
              <h3>Sequence score {behaviorChain.score}/100</h3>
            </div>
            <div className="tag-row">
              {behaviorChain.techniqueIds.length > 0 ? (
                <span className="state-chip tone-default">{behaviorChain.techniqueIds.length} techniques</span>
              ) : null}
              {behaviorChain.tacticIds.length > 0 ? (
                <span className="state-chip tone-default">{behaviorChain.tacticIds.length} tactics</span>
              ) : null}
              {behaviorChain.steps.filter((step) => step.blocked).length > 0 ? (
                <span className="state-chip tone-danger">{behaviorChain.steps.filter((step) => step.blocked).length} blocked</span>
              ) : null}
            </div>
          </div>

          <p className="muted-copy">{behaviorChain.narrative}</p>

          <dl className="definition-grid">
            <div>
              <dt>What happened</dt>
              <dd>{behaviorChain.whatHappened}</dd>
            </div>
            <div>
              <dt>Why suspicious</dt>
              <dd>{behaviorChain.whySuspicious}</dd>
            </div>
            <div>
              <dt>Blocked</dt>
              <dd>{behaviorChain.blocked}</dd>
            </div>
            <div>
              <dt>At risk</dt>
              <dd>{behaviorChain.atRisk}</dd>
            </div>
          </dl>

          <MiniCardList>
            {filteredBehaviorSteps.length === 0 ? (
              <p className="empty-state">No chain steps matched the current search.</p>
            ) : (
              filteredBehaviorSteps.map((step, index) => (
                <article key={step.id} className="mini-card">
                  <div className="row-between">
                    <strong>{index + 1}. {step.title}</strong>
                    <span className={`state-chip tone-${behaviorStepTone(step.category)}`}>{step.category}</span>
                  </div>
                  <p>{step.summary}</p>
                  <div className="tag-row">
                    <span className="state-chip tone-default">{step.source}</span>
                    {step.tacticId ? <span className="state-chip tone-default">{formatAttackTactic(step.tacticId)}</span> : null}
                    {step.techniqueId ? <span className="state-chip tone-default">{step.techniqueId}</span> : null}
                    {step.blocked ? <span className="state-chip tone-danger">blocked</span> : null}
                    {step.atRisk ? <span className="state-chip tone-warning">at risk</span> : null}
                  </div>
                  {step.atRisk ? <p className="muted-copy">{step.atRisk}</p> : null}
                  <span className="mini-meta">{formatDateTime(step.occurredAt)}</span>
                </article>
              ))
            )}
          </MiniCardList>
        </section>
      ) : null}

      {playbook ? (
        <section className="surface-card">
          <div className="section-heading">
            <div>
              <p className="section-kicker">Guided response</p>
              <h3>{playbook.title}</h3>
            </div>
            <div className="tag-row">
              <span className={`state-chip tone-${playbookModeTone(playbook.mode)}`}>{playbook.mode}</span>
              <span className={`state-chip tone-${playbookActions.some((action) => action.automationEligible) ? "ready" : "default"}`}>
                {playbookActions.filter((action) => action.automationEligible).length} automation-ready
              </span>
              <span className={`state-chip tone-${playbookActions.some((action) => action.approvalRequired) ? "warning" : "default"}`}>
                {playbookActions.filter((action) => action.approvalRequired).length} approval-gated
              </span>
            </div>
          </div>

          <p className="muted-copy">{playbook.summary}</p>

          {playbookMessage ? <p className="muted-copy">{playbookMessage}</p> : null}

          <div className="drawer-panel">
            <p className="section-kicker">Preserve first</p>
            <div className="tag-row">
              {playbook.evidenceToPreserve.map((item) => (
                <span key={item} className="state-chip tone-default">
                  {item}
                </span>
              ))}
            </div>
          </div>

          <MiniCardList>
            {filteredPlaybookActions.length === 0 ? (
              <p className="empty-state">No playbook steps matched the current search.</p>
            ) : (
              filteredPlaybookActions.map((action) => (
                <article key={action.id} className="mini-card">
                  <div className="row-between">
                    <strong>{action.title}</strong>
                    <span className={`state-chip tone-${playbookActionTone(action.category)}`}>{action.category}</span>
                  </div>
                  <p>{action.detail}</p>
                  <p className="muted-copy">{action.reason}</p>
                  <div className="tag-row">
                    {action.commandType ? <span className="state-chip tone-default">{playbookActionLabel(action)}</span> : null}
                    {action.targetPath ? <span className="state-chip tone-default">{action.targetPath}</span> : null}
                    {action.automationEligible ? <span className="state-chip tone-ready">automation ready</span> : null}
                    {action.approvalRequired ? <span className="state-chip tone-warning">approval required</span> : null}
                  </div>
                  {action.commandType === "scan.targeted" && action.targetPath ? (
                    <div className="action-stack">
                      <button
                        type="button"
                        className="primary-link"
                        disabled={(!detail.device?.id && !detail.alert.deviceId) || playbookActionBusy === action.id}
                        onClick={() => void runPlaybookAction(action)}
                      >
                        {playbookActionBusy === action.id ? "Queuing scan..." : "Queue targeted scan"}
                      </button>
                      {detail.device ? (
                        <Link href={`/devices/${detail.device.id}`} className="secondary-link">
                          Open device detail
                        </Link>
                      ) : null}
                    </div>
                  ) : detail.device ? (
                    <Link href={`/devices/${detail.device.id}`} className="secondary-link">
                      Open device detail
                    </Link>
                  ) : null}
                </article>
              ))
            )}
          </MiniCardList>
        </section>
      ) : null}

      <section className="grid grid-2">
        <article className="surface-card">
          <div className="section-heading">
            <div>
              <p className="section-kicker">Source telemetry</p>
              <h3>{detail.matchingTelemetry.length > 0 ? "Direct detection records" : "Telemetry context"}</h3>
            </div>
          </div>

          <MiniCardList>
            {filteredSourceTelemetry.length === 0 ? (
              <p className="empty-state">No direct telemetry records matched this alert version.</p>
            ) : (
              filteredSourceTelemetry.map((record) => (
                <article key={record.eventId} className="mini-card">
                  <div className="row-between">
                    <strong>{processTelemetryTitle(record)}</strong>
                    <span className="state-chip tone-default">{record.source}</span>
                  </div>
                  <p>{record.summary}</p>
                  {processTelemetrySummary(record) ? <p className="muted-copy">{processTelemetrySummary(record)}</p> : null}
                  {processTelemetryChips(record).length > 0 ? (
                    <div className="tag-row">
                      {processTelemetryChips(record).map((chip) => (
                        <span key={`${record.eventId}-${chip}`} className="state-chip tone-default">
                          {chip}
                        </span>
                      ))}
                    </div>
                  ) : null}
                  <span className="mini-meta">{formatDateTime(record.occurredAt)}</span>
                </article>
              ))
            )}
          </MiniCardList>
        </article>

        <article className="surface-card">
          <div className="section-heading">
            <div>
              <p className="section-kicker">Device context</p>
              <h3>{detail.device?.hostname ?? "Endpoint summary"}</h3>
            </div>
          </div>

          {detail.device ? (
            <>
              <dl className="definition-grid">
                <div>
                  <dt>Health</dt>
                  <dd>{detail.device.healthState}</dd>
                </div>
                <div>
                  <dt>Risk band</dt>
                  <dd>{detail.device.riskBand ?? "pending"}</dd>
                </div>
                <div>
                  <dt>Risk score</dt>
                  <dd>{detail.device.riskScore ?? "--"}</dd>
                </div>
                <div>
                  <dt>Confidence</dt>
                  <dd>{detail.device.confidenceScore != null ? `${detail.device.confidenceScore}%` : "--"}</dd>
                </div>
                <div>
                  <dt>Open alerts</dt>
                  <dd>{detail.device.openAlertCount}</dd>
                </div>
                <div>
                  <dt>Quarantine</dt>
                  <dd>{detail.device.quarantinedItemCount}</dd>
                </div>
              </dl>
              <div className="tag-row">
                <span className={`state-chip tone-${detail.device.healthState}`}>{detail.device.healthState}</span>
                <span className={`state-chip tone-${detail.device.isolated ? "critical" : "default"}`}>
                  {detail.device.isolated ? "isolated" : "connected"}
                </span>
                <Link href={`/devices/${detail.device.id}`} className="primary-link">
                  Open device detail
                </Link>
              </div>
              {detail.posture ? (
                <div className="drawer-panel" style={{ marginTop: 16 }}>
                  <p className="section-kicker">Protection posture</p>
                  <dl className="definition-grid">
                    <div>
                      <dt>Overall</dt>
                      <dd>{detail.posture.overallState}</dd>
                    </div>
                    <div>
                      <dt>Tamper</dt>
                      <dd>{detail.posture.tamperProtectionState}</dd>
                    </div>
                    <div>
                      <dt>WSC</dt>
                      <dd>{detail.posture.wscState}</dd>
                    </div>
                    <div>
                      <dt>ETW</dt>
                      <dd>{detail.posture.etwState}</dd>
                    </div>
                    <div>
                      <dt>WFP</dt>
                      <dd>{detail.posture.wfpState}</dd>
                    </div>
                    <div>
                      <dt>Isolation</dt>
                      <dd>{detail.posture.isolationState}</dd>
                    </div>
                  </dl>
                  <p className="muted-copy">
                    {detail.posture.tamperProtectionSummary ?? detail.posture.etwSummary ?? detail.posture.wfpSummary ?? "Protection state updated."}
                  </p>
                </div>
              ) : null}
            </>
          ) : (
            <p className="empty-state">No device record is linked to this alert.</p>
          )}
        </article>

        <article className="surface-card">
          <div className="section-heading">
            <div>
              <p className="section-kicker">Evidence chain</p>
              <h3>Alert timeline</h3>
            </div>
          </div>

          <MiniCardList>
            {filteredTimeline.length === 0 ? (
              <p className="empty-state">No timeline entries matched the current search.</p>
            ) : (
              filteredTimeline.map((entry) => (
                <article key={entry.id} className="mini-card">
                  <div className="row-between">
                    <strong>{entry.title}</strong>
                    <span className={`state-chip tone-${entry.severity}`}>{entry.severity}</span>
                  </div>
                  <p>{entry.summary}</p>
                  <div className="tag-row">
                    <span className="state-chip tone-default">{entry.category.replaceAll("_", " ")}</span>
                    <span className="state-chip tone-default">{entry.source}</span>
                  </div>
                  <span className="mini-meta">{formatDateTime(entry.occurredAt)}</span>
                </article>
              ))
            )}
          </MiniCardList>
        </article>

        <article className="surface-card">
          <div className="section-heading">
            <div>
              <p className="section-kicker">Related telemetry</p>
              <h3>{supportingTelemetry.length > 0 ? "Surrounding endpoint activity" : "No extra telemetry"}</h3>
            </div>
          </div>

          <MiniCardList>
            {filteredSupportingTelemetry.length === 0 ? (
              <p className="empty-state">No additional telemetry records matched this alert snapshot.</p>
            ) : (
              filteredSupportingTelemetry.map((record) => (
                <article key={record.eventId} className="mini-card">
                  <div className="row-between">
                    <strong>{processTelemetryTitle(record)}</strong>
                    <span className="state-chip tone-default">{record.source}</span>
                  </div>
                  <p>{record.summary}</p>
                  {processTelemetrySummary(record) ? <p className="muted-copy">{processTelemetrySummary(record)}</p> : null}
                  {processTelemetryChips(record).length > 0 ? (
                    <div className="tag-row">
                      {processTelemetryChips(record).map((chip) => (
                        <span key={`${record.eventId}-${chip}`} className="state-chip tone-default">
                          {chip}
                        </span>
                      ))}
                    </div>
                  ) : null}
                  <span className="mini-meta">{formatDateTime(record.occurredAt)}</span>
                </article>
              ))
            )}
          </MiniCardList>
        </article>

        <article className="surface-card">
          <div className="section-heading">
            <div>
              <p className="section-kicker">Evidence records</p>
              <h3>Capture and quarantine trail</h3>
            </div>
          </div>

          <MiniCardList>
            {filteredEvidence.length + filteredQuarantine.length + filteredScanHistory.length + filteredCommands.length === 0 ? (
              <p className="empty-state">No supporting records were found for this alert.</p>
            ) : (
              <>
                {filteredEvidence.map((item) => (
                  <article key={item.recordId} className="mini-card">
                    <div className="row-between">
                      <strong>{item.contentName ?? item.subjectPath ?? item.disposition}</strong>
                      <span className="state-chip tone-default">evidence</span>
                    </div>
                    <p>{item.summary}</p>
                    {item.contentName && item.contentName !== item.subjectPath ? (
                      <p className="muted-copy">Subject: {item.subjectPath}</p>
                    ) : null}
                    {amsiContextChips(item).length > 0 ? (
                      <div className="tag-row">
                        {amsiContextChips(item).map((chip) => (
                          <span key={`${item.recordId}-${chip}`} className="state-chip tone-default">
                            {chip}
                          </span>
                        ))}
                      </div>
                    ) : null}
                    {item.preview ? <pre className="payload-block">{item.preview}</pre> : null}
                    <span className="mini-meta">
                      {item.subjectPath} · {formatDateTime(item.recordedAt)}
                    </span>
                  </article>
                ))}
                {filteredQuarantine.map((item) => (
                  <article key={item.recordId} className="mini-card">
                    <div className="row-between">
                      <strong>{item.status}</strong>
                      <span className="state-chip tone-default">quarantine</span>
                    </div>
                    <p>{item.originalPath}</p>
                    <span className="mini-meta">
                      {item.quarantinedPath} · {formatDateTime(item.lastUpdatedAt)}
                    </span>
                  </article>
                ))}
                {filteredScanHistory.map((item) => (
                  <article key={item.eventId} className="mini-card">
                    <div className="row-between">
                      <strong>{item.contentName ?? item.subjectPath ?? item.disposition}</strong>
                      <span className="state-chip tone-default">scan</span>
                    </div>
                    <p>{item.summary}</p>
                    {item.contentName && item.contentName !== item.subjectPath ? (
                      <p className="muted-copy">Subject: {item.subjectPath}</p>
                    ) : null}
                    {amsiContextChips(item).length > 0 ? (
                      <div className="tag-row">
                        {amsiContextChips(item).map((chip) => (
                          <span key={`${item.eventId}-${chip}`} className="state-chip tone-default">
                            {chip}
                          </span>
                        ))}
                      </div>
                    ) : null}
                    {item.preview ? <pre className="payload-block">{item.preview}</pre> : null}
                    <span className="mini-meta">
                      {item.subjectPath} · {formatDateTime(item.scannedAt)}
                    </span>
                  </article>
                ))}
                {filteredCommands.map((item) => (
                  <article key={item.id} className="mini-card">
                    <div className="row-between">
                      <strong>{item.type.replaceAll(".", " ")}</strong>
                      <span className={`state-chip tone-${item.status}`}>{item.status.replaceAll("_", " ")}</span>
                    </div>
                    <p>{item.targetPath ?? item.recordId ?? item.payloadJson ?? "No extra parameters"}</p>
                    <span className="mini-meta">
                      {item.issuedBy} · {formatDateTime(item.updatedAt)}
                    </span>
                  </article>
                ))}
              </>
            )}
          </MiniCardList>
        </article>

        <article className="surface-card">
          <div className="section-heading">
            <div>
              <p className="section-kicker">Related alerts</p>
              <h3>Other detections on this endpoint</h3>
            </div>
          </div>

          <MiniCardList>
            {filteredRelatedAlerts.length === 0 ? (
              <p className="empty-state">No related alerts are currently linked to this endpoint.</p>
            ) : (
              filteredRelatedAlerts.map((item) => (
                <article key={item.id} className="mini-card">
                  <div className="row-between">
                    <strong>{item.title}</strong>
                    <span className={`state-chip tone-${item.severity}`}>{item.severity}</span>
                  </div>
                  <p>{item.summary}</p>
                  <div className="action-stack">
                    <Link href={`/alerts/${item.id}`} className="primary-link">
                      Open alert detail
                    </Link>
                    {item.deviceId ? (
                      <Link href={`/devices/${item.deviceId}`} className="secondary-link">
                        Open device detail
                      </Link>
                    ) : null}
                  </div>
                </article>
              ))
            )}
          </MiniCardList>
        </article>

        {relatedIncident ? (
          <article className="surface-card">
            <div className="section-heading">
              <div>
                <p className="section-kicker">Correlated incident</p>
                <h3>{relatedIncident.title}</h3>
              </div>
            </div>
            <p className="muted-copy">{relatedIncident.recommendedAction}</p>
            <dl className="definition-grid">
              <div>
                <dt>Priority</dt>
                <dd>{relatedIncident.priorityScore}</dd>
              </div>
              <div>
                <dt>Status</dt>
                <dd>{relatedIncident.status}</dd>
              </div>
              <div>
                <dt>Confidence</dt>
                <dd>{relatedIncident.confidenceScore}%</dd>
              </div>
              <div>
                <dt>Affected assets</dt>
                <dd>{relatedIncident.affectedAssetCount}</dd>
              </div>
            </dl>
            <Link href={`/incidents/${relatedIncident.id}`} className="primary-link">
              Open incident detail
            </Link>
          </article>
        ) : null}
      </section>
    </ConsoleShell>
  );
}
