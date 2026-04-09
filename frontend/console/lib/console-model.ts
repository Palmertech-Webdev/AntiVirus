import type {
  AlertSeverity,
  AlertStatus,
  AlertSummary,
  DashboardSnapshot,
  DeviceCommandSummary,
  DevicePostureSummary,
  DeviceSummary,
  EvidenceSummary,
  QuarantineItemSummary,
  ScanHistorySummary,
  TelemetryRecord
} from "./types";
import type { NavigationIconName } from "../app/components/BrandSystem";

export type NavigationKey =
  | "dashboard"
  | "incidents"
  | "devices"
  | "identities"
  | "email"
  | "alerts"
  | "policies"
  | "reports"
  | "administration";

export type IncidentStatus = "new" | "investigating" | "contained" | "resolved";
export type TimelineCategory =
  | "alert"
  | "telemetry"
  | "response"
  | "evidence"
  | "quarantine"
  | "scan"
  | "posture";

export interface IncidentTimelineEntry {
  id: string;
  occurredAt: string;
  category: TimelineCategory;
  title: string;
  summary: string;
  source: string;
  severity: AlertSeverity;
}

export interface IncidentSummary {
  id: string;
  title: string;
  summary: string;
  severity: AlertSeverity;
  status: IncidentStatus;
  confidenceScore: number;
  owner: string;
  sourceMix: string[];
  deviceIds: string[];
  deviceNames: string[];
  affectedAssetCount: number;
  firstSeenAt: string;
  lastActivityAt: string;
  latestEvent: string;
  recommendedAction: string;
  tactics: string[];
  techniques: string[];
  relatedAlertIds: string[];
  alertCount: number;
  evidenceCount: number;
  commandCount: number;
  timeline: IncidentTimelineEntry[];
}

export interface TrendSummary {
  label: string;
  value: number;
}

export interface ConsoleMetrics {
  openIncidents: number;
  criticalIncidents: number;
  devicesAtRisk: number;
  riskyUsers: number;
  maliciousEmails: number;
  unhealthyEndpoints: number;
}

export interface ActionQueueSummary {
  id: string;
  title: string;
  value: number;
  detail: string;
}

export interface ConsoleViewModel {
  incidents: IncidentSummary[];
  metrics: ConsoleMetrics;
  severityTrends: TrendSummary[];
  sourceTrends: TrendSummary[];
  topTechniques: TrendSummary[];
  actionQueue: ActionQueueSummary[];
}

interface IncidentSeed {
  id: string;
  title: string;
  summary: string;
  severity: AlertSeverity;
  status: IncidentStatus;
  confidenceScore: number;
  owner: string;
  sourceMix: Set<string>;
  deviceIds: Set<string>;
  deviceNames: Set<string>;
  firstSeenAt: string;
  lastActivityAt: string;
  latestEvent: string;
  recommendedAction: string;
  tactics: Set<string>;
  techniques: Set<string>;
  relatedAlertIds: Set<string>;
  alertCount: number;
  evidenceCount: number;
  commandCount: number;
  timeline: IncidentTimelineEntry[];
}

const navItems: Array<{ key: NavigationKey; label: string; href: string; icon: NavigationIconName }> = [
  { key: "dashboard", label: "Dashboard", href: "/", icon: "dashboard" },
  { key: "incidents", label: "Incidents", href: "/incidents", icon: "incidents" },
  { key: "devices", label: "Devices", href: "/devices", icon: "devices" },
  { key: "identities", label: "Identities", href: "/identities", icon: "identities" },
  { key: "email", label: "Email", href: "/email", icon: "email" },
  { key: "alerts", label: "Alerts", href: "/alerts", icon: "alerts" },
  { key: "policies", label: "Policies", href: "/policies", icon: "policies" },
  { key: "reports", label: "Reports", href: "/reports", icon: "reports" },
  { key: "administration", label: "Administration", href: "/administration", icon: "administration" }
];

function severityWeight(value: AlertSeverity) {
  switch (value) {
    case "critical":
      return 4;
    case "high":
      return 3;
    case "medium":
      return 2;
    default:
      return 1;
  }
}

function severityFromPosture(value: DevicePostureSummary["overallState"]): AlertSeverity {
  if (value === "failed") {
    return "high";
  }

  if (value === "degraded") {
    return "medium";
  }

  return "low";
}

function parsePayload(payloadJson: string) {
  try {
    return JSON.parse(payloadJson) as Record<string, unknown>;
  } catch {
    return null;
  }
}

function formatCommandType(type: DeviceCommandSummary["type"]) {
  return type.replaceAll(".", " ");
}

function incidentStatusFromAlertStatus(status: AlertStatus, isolated: boolean): IncidentStatus {
  if (status === "contained" || isolated) {
    return "contained";
  }

  if (status === "triaged") {
    return "investigating";
  }

  return "new";
}

function recommendedActionForSeverity(severity: AlertSeverity, isolated: boolean) {
  if (isolated) {
    return "Review containment state, validate blast radius, and collect investigation evidence.";
  }

  if (severity === "critical") {
    return "Open the incident, confirm scope, and isolate the affected host immediately.";
  }

  if (severity === "high") {
    return "Validate the artifact or process chain and queue remediation if the signal is confirmed.";
  }

  return "Triage the alert, review the device timeline, and decide whether escalation is required.";
}

function computeConfidence(
  severity: AlertSeverity,
  relatedScanHistory: ScanHistorySummary[],
  relatedEvidence: EvidenceSummary[]
) {
  const scanConfidence =
    relatedScanHistory.length > 0
      ? Math.round(
          relatedScanHistory.reduce((total, item) => total + (item.confidence ?? 65), 0) / relatedScanHistory.length
        )
      : severityWeight(severity) * 22 + 10;

  return Math.min(99, scanConfidence + Math.min(relatedEvidence.length * 2, 8));
}

function buildTimelineFromAlert(
  alert: AlertSummary,
  relatedTelemetry: TelemetryRecord[],
  relatedCommands: DeviceCommandSummary[],
  relatedEvidence: EvidenceSummary[],
  relatedQuarantine: QuarantineItemSummary[],
  relatedScanHistory: ScanHistorySummary[],
  posture: DevicePostureSummary | undefined
) {
  const timeline: IncidentTimelineEntry[] = [
    {
      id: `alert-${alert.id}`,
      occurredAt: alert.detectedAt,
      category: "alert",
      title: alert.title,
      summary: alert.summary,
      source: "endpoint-alert",
      severity: alert.severity
    }
  ];

  for (const record of relatedTelemetry.slice(0, 10)) {
    timeline.push({
      id: `telemetry-${record.eventId}`,
      occurredAt: record.occurredAt,
      category: "telemetry",
      title: record.eventType,
      summary: record.summary,
      source: record.source,
      severity: alert.severity
    });
  }

  for (const command of relatedCommands.slice(0, 6)) {
    timeline.push({
      id: `command-${command.id}`,
      occurredAt: command.updatedAt,
      category: "response",
      title: formatCommandType(command.type),
      summary: `${command.status.replaceAll("_", " ")} by ${command.issuedBy}`,
      source: "response",
      severity: alert.severity
    });
  }

  for (const item of relatedEvidence.slice(0, 4)) {
    timeline.push({
      id: `evidence-${item.recordId}`,
      occurredAt: item.recordedAt,
      category: "evidence",
      title: item.disposition,
      summary: item.summary,
      source: item.source,
      severity: alert.severity
    });
  }

  for (const item of relatedQuarantine.slice(0, 4)) {
    timeline.push({
      id: `quarantine-${item.recordId}`,
      occurredAt: item.lastUpdatedAt,
      category: "quarantine",
      title: item.status,
      summary: item.originalPath,
      source: "quarantine",
      severity: alert.severity
    });
  }

  for (const item of relatedScanHistory.slice(0, 4)) {
    timeline.push({
      id: `scan-${item.eventId}`,
      occurredAt: item.scannedAt,
      category: "scan",
      title: item.disposition,
      summary: item.summary,
      source: item.source,
      severity: alert.severity
    });
  }

  if (posture) {
    timeline.push({
      id: `posture-${posture.deviceId}`,
      occurredAt: posture.updatedAt,
      category: "posture",
      title: `posture ${posture.overallState}`,
      summary: posture.tamperProtectionSummary ?? posture.etwSummary ?? posture.wfpSummary ?? "Protection state updated.",
      source: "posture",
      severity: severityFromPosture(posture.overallState)
    });
  }

  return timeline.sort((left, right) => left.occurredAt.localeCompare(right.occurredAt));
}

function seedToSummary(seed: IncidentSeed): IncidentSummary {
  return {
    id: seed.id,
    title: seed.title,
    summary: seed.summary,
    severity: seed.severity,
    status: seed.status,
    confidenceScore: seed.confidenceScore,
    owner: seed.owner,
    sourceMix: [...seed.sourceMix],
    deviceIds: [...seed.deviceIds],
    deviceNames: [...seed.deviceNames],
    affectedAssetCount: seed.deviceIds.size,
    firstSeenAt: seed.firstSeenAt,
    lastActivityAt: seed.lastActivityAt,
    latestEvent: seed.latestEvent,
    recommendedAction: seed.recommendedAction,
    tactics: [...seed.tactics],
    techniques: [...seed.techniques],
    relatedAlertIds: [...seed.relatedAlertIds],
    alertCount: seed.alertCount,
    evidenceCount: seed.evidenceCount,
    commandCount: seed.commandCount,
    timeline: seed.timeline
  };
}

function createAlertIncident(
  snapshot: DashboardSnapshot,
  alert: AlertSummary,
  devicesById: Map<string, DeviceSummary>,
  postureByDeviceId: Map<string, DevicePostureSummary>
) {
  const relatedDevice = alert.deviceId ? devicesById.get(alert.deviceId) : undefined;
  const deviceId = alert.deviceId ?? relatedDevice?.id ?? alert.hostname;
  const relatedTelemetry = snapshot.recentTelemetry.filter(
    (item) => item.deviceId === alert.deviceId || item.hostname === alert.hostname
  );
  const relatedCommands = snapshot.recentCommands.filter(
    (item) => item.deviceId === alert.deviceId || item.hostname === alert.hostname
  );
  const relatedEvidence = snapshot.recentEvidence.filter(
    (item) => item.deviceId === alert.deviceId || item.hostname === alert.hostname
  );
  const relatedQuarantine = snapshot.quarantineItems.filter(
    (item) => item.deviceId === alert.deviceId || item.hostname === alert.hostname
  );
  const relatedScanHistory = snapshot.recentScanHistory.filter(
    (item) => item.deviceId === alert.deviceId || item.hostname === alert.hostname
  );
  const posture = alert.deviceId ? postureByDeviceId.get(alert.deviceId) : undefined;
  const latestCommand = [...relatedCommands].sort((left, right) => right.updatedAt.localeCompare(left.updatedAt))[0];
  const timeline = buildTimelineFromAlert(
    alert,
    relatedTelemetry,
    relatedCommands,
    relatedEvidence,
    relatedQuarantine,
    relatedScanHistory,
    posture
  );

  const tactics = new Set<string>(
    [
      ...relatedEvidence.map((item) => item.tacticId),
      ...relatedScanHistory.map((item) => item.tacticId)
    ].filter((value): value is string => Boolean(value))
  );
  const techniques = new Set<string>(
    [alert.technique, ...relatedEvidence.map((item) => item.techniqueId), ...relatedScanHistory.map((item) => item.techniqueId)].filter(
      (value): value is string => Boolean(value)
    )
  );

  const payloadSources = new Set<string>(["endpoint"]);
  if (alert.title.toLowerCase().includes("powershell") || alert.summary.toLowerCase().includes("powershell")) {
    payloadSources.add("script");
  }
  if (relatedQuarantine.length > 0 || relatedEvidence.length > 0) {
    payloadSources.add("file");
  }
  if (relatedCommands.some((item) => item.type === "device.isolate")) {
    payloadSources.add("containment");
  }
  if (relatedTelemetry.some((item) => item.eventType.startsWith("process."))) {
    payloadSources.add("process");
  }

  const confidence = computeConfidence(alert.severity, relatedScanHistory, relatedEvidence);
  const latestTimelineEvent = timeline.at(-1);

  const seed: IncidentSeed = {
    id: `incident-${alert.id}`,
    title: alert.title,
    summary: alert.summary,
    severity: alert.severity,
    status: incidentStatusFromAlertStatus(alert.status, relatedDevice?.isolated ?? false),
    confidenceScore: confidence,
    owner: latestCommand?.issuedBy ?? "unassigned",
    sourceMix: payloadSources,
    deviceIds: new Set([deviceId]),
    deviceNames: new Set([alert.hostname]),
    firstSeenAt: alert.detectedAt,
    lastActivityAt: latestTimelineEvent?.occurredAt ?? alert.detectedAt,
    latestEvent: latestTimelineEvent?.summary ?? alert.summary,
    recommendedAction: recommendedActionForSeverity(alert.severity, relatedDevice?.isolated ?? false),
    tactics,
    techniques,
    relatedAlertIds: new Set([alert.id]),
    alertCount: 1,
    evidenceCount: relatedEvidence.length,
    commandCount: relatedCommands.length,
    timeline
  };

  return seedToSummary(seed);
}

function createPostureIncident(device: DeviceSummary, posture: DevicePostureSummary): IncidentSummary {
  const severity = severityFromPosture(posture.overallState);
  const title =
    posture.overallState === "failed"
      ? `Protection stack failure on ${device.hostname}`
      : `Protection stack degraded on ${device.hostname}`;
  const summary =
    posture.tamperProtectionSummary ??
    posture.wfpSummary ??
    posture.etwSummary ??
    posture.wscSummary ??
    "One or more protection layers are not reporting ready.";
  const latestEvent = posture.isolationSummary ?? summary;

  return {
    id: `incident-posture-${device.id}`,
    title,
    summary,
    severity,
    status: device.isolated ? "contained" : "investigating",
    confidenceScore: severity === "high" ? 86 : 72,
    owner: "platform-ops",
    sourceMix: ["endpoint", "posture"],
    deviceIds: [device.id],
    deviceNames: [device.hostname],
    affectedAssetCount: 1,
    firstSeenAt: posture.updatedAt,
    lastActivityAt: posture.updatedAt,
    latestEvent,
    recommendedAction:
      severity === "high"
        ? "Repair the sensor stack and validate that real-time enforcement and telemetry are healthy."
        : "Review degraded controls and confirm whether analyst intervention is needed.",
    tactics: [],
    techniques: [],
    relatedAlertIds: [],
    alertCount: 0,
    evidenceCount: 0,
    commandCount: 0,
    timeline: [
      {
        id: `posture-${device.id}`,
        occurredAt: posture.updatedAt,
        category: "posture",
        title: `posture ${posture.overallState}`,
        summary,
        source: "posture",
        severity
      }
    ]
  };
}

export function getNavigationItems() {
  return navItems;
}

export function buildConsoleViewModel(snapshot: DashboardSnapshot): ConsoleViewModel {
  const devicesById = new Map(snapshot.devices.map((item) => [item.id, item]));
  const postureByDeviceId = new Map(snapshot.postureOverview.map((item) => [item.deviceId, item]));

  const incidents = snapshot.alerts.map((alert) => createAlertIncident(snapshot, alert, devicesById, postureByDeviceId));
  const coveredDeviceIds = new Set(incidents.flatMap((item) => item.deviceIds));

  for (const posture of snapshot.postureOverview) {
    if (coveredDeviceIds.has(posture.deviceId)) {
      continue;
    }

    if (posture.overallState === "degraded" || posture.overallState === "failed") {
      const device = devicesById.get(posture.deviceId);
      if (device) {
        incidents.push(createPostureIncident(device, posture));
      }
    }
  }

  incidents.sort((left, right) => {
    const severityDelta = severityWeight(right.severity) - severityWeight(left.severity);
    if (severityDelta !== 0) {
      return severityDelta;
    }

    return right.lastActivityAt.localeCompare(left.lastActivityAt);
  });

  const techniqueCounts = new Map<string, number>();
  const sourceCounts = new Map<string, number>();

  for (const incident of incidents) {
    for (const source of incident.sourceMix) {
      sourceCounts.set(source, (sourceCounts.get(source) ?? 0) + 1);
    }

    for (const technique of incident.techniques) {
      techniqueCounts.set(technique, (techniqueCounts.get(technique) ?? 0) + 1);
    }
  }

  const severityTrends: TrendSummary[] = [
    { label: "Critical", value: incidents.filter((item) => item.severity === "critical").length },
    { label: "High", value: incidents.filter((item) => item.severity === "high").length },
    { label: "Medium", value: incidents.filter((item) => item.severity === "medium").length },
    { label: "Low", value: incidents.filter((item) => item.severity === "low").length }
  ];

  const sourceTrends = [...sourceCounts.entries()]
    .sort((left, right) => right[1] - left[1])
    .slice(0, 5)
    .map(([label, value]) => ({ label, value }));

  const topTechniques = [...techniqueCounts.entries()]
    .sort((left, right) => right[1] - left[1])
    .slice(0, 5)
    .map(([label, value]) => ({ label, value }));

  const devicesAtRisk = snapshot.devices.filter(
    (device) => device.openAlertCount > 0 || device.postureState !== "ready" || device.isolated
  ).length;
  const unhealthyEndpoints = snapshot.devices.filter((device) => device.healthState !== "healthy").length;

  return {
    incidents,
    metrics: {
      openIncidents: incidents.filter((item) => item.status !== "resolved").length,
      criticalIncidents: incidents.filter((item) => item.severity === "critical" && item.status !== "resolved").length,
      devicesAtRisk,
      riskyUsers: 0,
      maliciousEmails: 0,
      unhealthyEndpoints
    },
    severityTrends,
    sourceTrends,
    topTechniques,
    actionQueue: [
      {
        id: "triage",
        title: "Incidents needing triage",
        value: incidents.filter((item) => item.status === "new").length,
        detail: "New incidents that have not been assigned or worked yet."
      },
      {
        id: "remediation",
        title: "Pending remediation actions",
        value: snapshot.recentCommands.filter((item) => item.status === "pending").length,
        detail: "Queued response actions waiting for an agent to pick them up."
      },
      {
        id: "containment",
        title: "Isolation review",
        value: snapshot.devices.filter((item) => item.isolated).length,
        detail: "Hosts currently contained and needing analyst review."
      },
      {
        id: "coverage",
        title: "Protection concerns",
        value: snapshot.postureOverview.filter((item) => item.overallState !== "ready").length,
        detail: "Endpoints with degraded or failed protection stack health."
      }
    ]
  };
}

export function filterIncidents(incidents: IncidentSummary[], query: string) {
  const normalized = query.trim().toLowerCase();
  if (!normalized) {
    return incidents;
  }

  return incidents.filter((incident) =>
    [
      incident.id,
      incident.title,
      incident.summary,
      incident.owner,
      incident.severity,
      incident.status,
      incident.deviceNames.join(" "),
      incident.techniques.join(" "),
      incident.sourceMix.join(" "),
      incident.latestEvent
    ].some((value) => value.toLowerCase().includes(normalized))
  );
}

export function filterDevices(devices: DeviceSummary[], query: string) {
  const normalized = query.trim().toLowerCase();
  if (!normalized) {
    return devices;
  }

  return devices.filter((device) =>
    [
      device.hostname,
      device.osVersion,
      device.agentVersion,
      device.platformVersion,
      device.serialNumber,
      device.policyName,
      device.healthState,
      device.postureState
    ].some((value) => value.toLowerCase().includes(normalized))
  );
}

export function filterAlerts(alerts: AlertSummary[], query: string) {
  const normalized = query.trim().toLowerCase();
  if (!normalized) {
    return alerts;
  }

  return alerts.filter((alert) =>
    [alert.id, alert.hostname, alert.title, alert.summary, alert.technique ?? "", alert.severity, alert.status].some((value) =>
      value.toLowerCase().includes(normalized)
    )
  );
}

export function summarizeTelemetrySources(records: TelemetryRecord[]) {
  const counts = new Map<string, number>();

  for (const record of records) {
    const payload = parsePayload(record.payloadJson);
    const sourceLabel = typeof payload?.source === "string" ? payload.source : record.source;
    counts.set(sourceLabel, (counts.get(sourceLabel) ?? 0) + 1);
  }

  return [...counts.entries()]
    .sort((left, right) => right[1] - left[1])
    .slice(0, 5)
    .map(([label, value]) => ({ label, value }));
}
