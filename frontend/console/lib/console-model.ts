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
  RiskBand,
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
  priorityScore: number;
  status: IncidentStatus;
  confidenceScore: number;
  owner: string;
  sourceMix: string[];
  deviceIds: string[];
  deviceNames: string[];
  primaryDeviceId: string | null;
  primaryDeviceName: string | null;
  highestDeviceRiskScore: number | null;
  highestDeviceRiskBand: RiskBand | null;
  highestDeviceConfidenceScore: number | null;
  deviceRiskSummary: string;
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
  priorityScore: number;
  status: IncidentStatus;
  confidenceScore: number;
  owner: string;
  sourceMix: Set<string>;
  deviceIds: Set<string>;
  deviceNames: Set<string>;
  primaryDeviceId: string | null;
  primaryDeviceName: string | null;
  highestDeviceRiskScore: number | null;
  highestDeviceRiskBand: RiskBand | null;
  highestDeviceConfidenceScore: number | null;
  deviceRiskSummary: string;
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

export function getNavigationItems() {
  return navItems;
}

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

function riskBandWeight(value: RiskBand | null | undefined) {
  switch (value) {
    case "critical":
      return 5;
    case "high":
      return 4;
    case "elevated":
      return 3;
    case "guarded":
      return 2;
    case "low":
      return 1;
    default:
      return 0;
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

function describeRiskBand(value: RiskBand | null | undefined) {
  return value ? value.replaceAll("_", " ") : "pending";
}

function riskBandFloor(value: RiskBand | null | undefined) {
  switch (value) {
    case "critical":
      return 90;
    case "high":
      return 75;
    case "elevated":
      return 55;
    case "guarded":
      return 35;
    case "low":
      return 15;
    default:
      return 0;
  }
}

function devicePriorityContribution(device: DeviceSummary | undefined) {
  if (!device) {
    return 0;
  }

  const normalizedRisk = Math.max(device.riskScore ?? 0, riskBandFloor(device.riskBand));
  const bandBoost = riskBandWeight(device.riskBand) * 14;
  const isolationBoost = device.isolated ? 18 : 0;
  const confidenceBoost =
    device.confidenceScore == null ? 0 : device.confidenceScore >= 85 ? 10 : device.confidenceScore >= 65 ? 6 : 3;

  return Math.round(normalizedRisk * 1.3 + bandBoost + isolationBoost + confidenceBoost);
}

function buildIncidentRiskLead(device: DeviceSummary | undefined) {
  if (!device || device.riskScore == null || !device.riskBand) {
    return "";
  }

  const riskText = `${device.hostname} currently scores ${device.riskScore}/100 (${describeRiskBand(device.riskBand)} risk)`;

  if (device.riskBand === "critical") {
    return `${riskText}, so keep it at the front of triage and containment. `;
  }

  if (device.riskBand === "high") {
    return `${riskText}, so treat it as the primary response target. `;
  }

  if (device.riskBand === "elevated") {
    return `${riskText}, so confirm whether this incident is part of a broader compromise. `;
  }

  return `${riskText}, so keep its score in the triage order. `;
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

function recommendedActionForSeverity(severity: AlertSeverity, isolated: boolean, device?: DeviceSummary) {
  if (isolated) {
    return "Review containment state, validate blast radius, and collect investigation evidence.";
  }

  if (device?.riskBand === "critical") {
    return "Isolate the device, confirm the blast radius, and collect evidence before broader remediation.";
  }

  if (device?.riskBand === "high") {
    return "Validate the artifact or process chain and queue containment if the signal is confirmed.";
  }

  if (severity === "critical") {
    return "Open the incident, confirm scope, and isolate the affected host immediately.";
  }

  if (severity === "high") {
    return "Validate the artifact or process chain and queue remediation if the signal is confirmed.";
  }

  if (device?.riskBand === "elevated") {
    return "Review the risk drivers, compare them with the incident evidence, and escalate if the pattern spreads.";
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

function buildDeviceRiskSummary(
  device: DeviceSummary | undefined,
  score: number | null | undefined,
  band: RiskBand | null | undefined,
  confidenceScore: number | null | undefined
) {
  if (!device || score == null || !band) {
    return "Device risk telemetry is still being derived for the affected asset.";
  }

  const confidenceText =
    confidenceScore == null ? "confidence pending" : `${confidenceScore}% telemetry confidence`;
  const priorityText = score >= 75 ? " This score is materially influencing incident triage order." : "";
  return `${device.hostname} scores ${score}/100 (${describeRiskBand(band)} risk) with ${confidenceText}.${priorityText}`;
}

function computePriorityScore(
  severity: AlertSeverity,
  device: DeviceSummary | undefined,
  confidenceScore: number,
  alertCount: number,
  commandCount: number
) {
  const severityComponent = severityWeight(severity) * 100;
  const riskComponent = devicePriorityContribution(device);
  const exposureComponent = Math.min(alertCount * 6, 24);
  const commandComponent = Math.min(commandCount * 3, 12);
  const containmentPenalty = device?.isolated ? -18 : 0;
  const posturePenalty = device?.postureState === "failed" ? 16 : device?.postureState === "degraded" ? 8 : 0;
  const confidenceComponent = Math.round(confidenceScore / 12);

  return Math.max(
    0,
    severityComponent +
      riskComponent +
      exposureComponent +
      commandComponent +
      posturePenalty +
      confidenceComponent +
      containmentPenalty
  );
}

function seedToSummary(seed: IncidentSeed): IncidentSummary {
  return {
    id: seed.id,
    title: seed.title,
    summary: seed.summary,
    severity: seed.severity,
    priorityScore: seed.priorityScore,
    status: seed.status,
    confidenceScore: seed.confidenceScore,
    owner: seed.owner,
    sourceMix: [...seed.sourceMix],
    deviceIds: [...seed.deviceIds],
    deviceNames: [...seed.deviceNames],
    primaryDeviceId: seed.primaryDeviceId,
    primaryDeviceName: seed.primaryDeviceName,
    highestDeviceRiskScore: seed.highestDeviceRiskScore,
    highestDeviceRiskBand: seed.highestDeviceRiskBand,
    highestDeviceConfidenceScore: seed.highestDeviceConfidenceScore,
    deviceRiskSummary: seed.deviceRiskSummary,
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
  devicesByHostname: Map<string, DeviceSummary>,
  postureByDeviceId: Map<string, DevicePostureSummary>
) {
  const normalizedHostname = alert.hostname.toLowerCase();
  const relatedDevice = alert.deviceId
    ? devicesById.get(alert.deviceId) ?? devicesByHostname.get(normalizedHostname)
    : devicesByHostname.get(normalizedHostname);
  const deviceId = relatedDevice?.id ?? alert.deviceId ?? alert.hostname;
  const relatedTelemetry = snapshot.recentTelemetry.filter(
    (item) => item.deviceId === alert.deviceId || item.hostname.toLowerCase() === normalizedHostname
  );
  const relatedCommands = snapshot.recentCommands.filter(
    (item) => item.deviceId === alert.deviceId || item.hostname.toLowerCase() === normalizedHostname
  );
  const relatedEvidence = snapshot.recentEvidence.filter(
    (item) => item.deviceId === alert.deviceId || item.hostname.toLowerCase() === normalizedHostname
  );
  const relatedQuarantine = snapshot.quarantineItems.filter(
    (item) => item.deviceId === alert.deviceId || item.hostname.toLowerCase() === normalizedHostname
  );
  const relatedScanHistory = snapshot.recentScanHistory.filter(
    (item) => item.deviceId === alert.deviceId || item.hostname.toLowerCase() === normalizedHostname
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
  const priorityScore = computePriorityScore(
    alert.severity,
    relatedDevice,
    confidence,
    1 + relatedEvidence.length + relatedQuarantine.length,
    relatedCommands.length
  );
  const riskSummary = buildDeviceRiskSummary(
    relatedDevice,
    relatedDevice?.riskScore,
    relatedDevice?.riskBand,
    relatedDevice?.confidenceScore
  );
  const deviceActionLead = buildIncidentRiskLead(relatedDevice);

  const seed: IncidentSeed = {
    id: `incident-${alert.id}`,
    title: alert.title,
    summary: alert.summary,
    severity: alert.severity,
    priorityScore,
    status: incidentStatusFromAlertStatus(alert.status, relatedDevice?.isolated ?? false),
    confidenceScore: confidence,
    owner: latestCommand?.issuedBy ?? "unassigned",
    sourceMix: payloadSources,
    deviceIds: new Set([deviceId]),
    deviceNames: new Set([relatedDevice?.hostname ?? alert.hostname]),
    primaryDeviceId: relatedDevice?.id ?? deviceId ?? null,
    primaryDeviceName: relatedDevice?.hostname ?? alert.hostname,
    highestDeviceRiskScore: relatedDevice?.riskScore ?? null,
    highestDeviceRiskBand: relatedDevice?.riskBand ?? null,
    highestDeviceConfidenceScore: relatedDevice?.confidenceScore ?? null,
    deviceRiskSummary: riskSummary,
    firstSeenAt: alert.detectedAt,
    lastActivityAt: latestTimelineEvent?.occurredAt ?? alert.detectedAt,
    latestEvent: latestTimelineEvent?.summary ?? alert.summary,
    recommendedAction: `${deviceActionLead}${recommendedActionForSeverity(alert.severity, relatedDevice?.isolated ?? false)}`.trim(),
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
  const confidenceScore = severity === "high" ? 86 : 72;
  const priorityScore = computePriorityScore(severity, device, confidenceScore, 1, 0);
  const deviceActionLead = buildIncidentRiskLead(device);

  return {
    id: `incident-posture-${device.id}`,
    title,
    summary,
    severity,
    priorityScore,
    status: device.isolated ? "contained" : "investigating",
    confidenceScore,
    owner: "platform-ops",
    sourceMix: ["endpoint", "posture"],
    deviceIds: [device.id],
    deviceNames: [device.hostname],
    primaryDeviceId: device.id,
    primaryDeviceName: device.hostname,
    highestDeviceRiskScore: device.riskScore,
    highestDeviceRiskBand: device.riskBand,
    highestDeviceConfidenceScore: device.confidenceScore,
    deviceRiskSummary: buildDeviceRiskSummary(device, device.riskScore, device.riskBand, device.confidenceScore),
    affectedAssetCount: 1,
    firstSeenAt: posture.updatedAt,
    lastActivityAt: posture.updatedAt,
    latestEvent,
    recommendedAction: `${deviceActionLead}${
      severity === "high"
        ? "Repair the sensor stack and validate that real-time enforcement and telemetry are healthy."
        : "Review degraded controls and confirm whether analyst intervention is needed."
    }`,
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
export function buildConsoleViewModel(snapshot: DashboardSnapshot): ConsoleViewModel {
  const devicesById = new Map(snapshot.devices.map((item) => [item.id, item]));
  const devicesByHostname = new Map(snapshot.devices.map((item) => [item.hostname.toLowerCase(), item]));
  const postureByDeviceId = new Map(snapshot.postureOverview.map((item) => [item.deviceId, item]));

  const incidents = snapshot.alerts.map((alert) =>
    createAlertIncident(snapshot, alert, devicesById, devicesByHostname, postureByDeviceId)
  );
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
    const priorityDelta = right.priorityScore - left.priorityScore;
    if (priorityDelta !== 0) {
      return priorityDelta;
    }

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
    (device) =>
      device.openAlertCount > 0 ||
      device.postureState !== "ready" ||
      device.isolated ||
      (device.riskScore ?? 0) >= 40
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
      incident.primaryDeviceName ?? "",
      incident.techniques.join(" "),
      incident.sourceMix.join(" "),
      incident.latestEvent,
      incident.recommendedAction,
      incident.deviceRiskSummary,
      incident.highestDeviceRiskBand ?? "",
      String(incident.highestDeviceRiskScore ?? ""),
      String(incident.priorityScore)
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
      device.postureState,
      device.riskBand ?? "",
      String(device.riskScore ?? ""),
      String(device.confidenceScore ?? "")
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
