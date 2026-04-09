import { randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import { generateAlertsFromTelemetry, mergeGeneratedAlerts } from "./detectionEngine.js";
import { createEmptyState, createSeedState, DEMO_DEVICE_IDS, DEMO_HOSTNAMES } from "./seedState.js";
import type {
  AlertSummary,
  CommandStatus,
  CompleteCommandRequest,
  ControlPlaneState,
  DashboardSnapshot,
  DeviceCommandSummary,
  DeviceDetail,
  DevicePostureSummary,
  DeviceRecord,
  DeviceSummary,
  EnrollmentRequest,
  EnrollmentResponse,
  EvidenceSummary,
  HeartbeatRequest,
  HeartbeatResponse,
  IsolationState,
  PolicyCheckInRequest,
  PolicyCheckInResponse,
  PolicySummary,
  PollCommandsResponse,
  PostureState,
  QueueCommandRequest,
  QuarantineItemSummary,
  QuarantineStatus,
  ScanHistorySummary,
  TelemetryBatchRequest,
  TelemetryBatchResponse,
  TelemetryRecord
} from "./types.js";

const DEFAULT_STATE_FILE_PATH = join(process.cwd(), ".data", "control-plane-state.json");
const DEFAULT_COMMAND_CHANNEL_URL = "wss://localhost:4000/api/v1/commands";

const MAX_ALERTS = 1_000;
const MAX_TELEMETRY = 5_000;
const MAX_COMMANDS = 2_000;
const MAX_QUARANTINE_ITEMS = 2_000;
const MAX_EVIDENCE_ITEMS = 2_000;
const MAX_SCAN_HISTORY = 5_000;

type ParsedPayload = Record<string, unknown>;

interface CreateFileBackedControlPlaneStoreOptions {
  stateFilePath?: string;
  commandChannelUrl?: string;
  now?: () => string;
  seedDemoData?: boolean;
}

export interface ControlPlaneStore {
  getDashboardSnapshot(): Promise<DashboardSnapshot>;
  getDeviceDetail(deviceId: string): Promise<DeviceDetail>;
  listDevices(): Promise<DeviceSummary[]>;
  listAlerts(): Promise<AlertSummary[]>;
  listTelemetry(deviceId?: string, limit?: number): Promise<TelemetryRecord[]>;
  listEvidence(deviceId?: string, limit?: number): Promise<EvidenceSummary[]>;
  listScanHistory(deviceId?: string, limit?: number): Promise<ScanHistorySummary[]>;
  listCommands(deviceId?: string, status?: CommandStatus, limit?: number): Promise<DeviceCommandSummary[]>;
  listQuarantineItems(deviceId?: string, status?: QuarantineStatus, limit?: number): Promise<QuarantineItemSummary[]>;
  getDefaultPolicy(): Promise<PolicySummary>;
  enrollDevice(request: EnrollmentRequest): Promise<EnrollmentResponse>;
  recordHeartbeat(deviceId: string, request: HeartbeatRequest): Promise<HeartbeatResponse>;
  policyCheckIn(deviceId: string, request: PolicyCheckInRequest): Promise<PolicyCheckInResponse>;
  ingestTelemetry(deviceId: string, request: TelemetryBatchRequest): Promise<TelemetryBatchResponse>;
  queueCommand(deviceId: string, request: QueueCommandRequest): Promise<DeviceCommandSummary>;
  pollPendingCommands(deviceId: string, limit?: number): Promise<PollCommandsResponse>;
  completeCommand(
    deviceId: string,
    commandId: string,
    request: CompleteCommandRequest
  ): Promise<DeviceCommandSummary>;
}

export class DeviceNotFoundError extends Error {
  constructor(deviceId: string) {
    super(`Device not found: ${deviceId}`);
    this.name = "DeviceNotFoundError";
  }
}

export class CommandNotFoundError extends Error {
  constructor(commandId: string) {
    super(`Command not found: ${commandId}`);
    this.name = "CommandNotFoundError";
  }
}

function parsePayload(payloadJson: string): ParsedPayload | null {
  try {
    const parsed = JSON.parse(payloadJson) as unknown;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as ParsedPayload;
    }
  } catch {
    return null;
  }

  return null;
}

function readString(payload: ParsedPayload | null, key: string) {
  const value = payload?.[key];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function readNumber(payload: ParsedPayload | null, key: string) {
  const value = payload?.[key];
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function readBoolean(payload: ParsedPayload | null, key: string) {
  const value = payload?.[key];
  return typeof value === "boolean" ? value : undefined;
}

function readOptionalString(value: unknown, fallback = "") {
  return typeof value === "string" ? value : fallback;
}

function readOptionalNullableString(value: unknown) {
  return typeof value === "string" ? value : null;
}

function clampPostureState(value: unknown): PostureState {
  return value === "ready" || value === "degraded" || value === "failed" ? value : "unknown";
}

function clampIsolationState(value: unknown): IsolationState {
  return value === "active" || value === "inactive" || value === "error" ? value : "unknown";
}

function sortByIsoDescending<T>(items: T[], getIso: (item: T) => string) {
  return [...items].sort((left, right) => getIso(right).localeCompare(getIso(left)));
}

function sortDevices(items: DeviceSummary[]) {
  return [...items].sort((left, right) => {
    const seenDelta = right.lastSeenAt.localeCompare(left.lastSeenAt);
    if (seenDelta !== 0) {
      return seenDelta;
    }

    return left.hostname.localeCompare(right.hostname);
  });
}

function sortAlerts(items: AlertSummary[]) {
  return sortByIsoDescending(items, (item) => item.detectedAt);
}

function sortTelemetry(items: TelemetryRecord[]) {
  return [...items].sort((left, right) => {
    const occurredDelta = right.occurredAt.localeCompare(left.occurredAt);
    if (occurredDelta !== 0) {
      return occurredDelta;
    }

    return right.ingestedAt.localeCompare(left.ingestedAt);
  });
}

function sortCommands(items: DeviceCommandSummary[]) {
  return sortByIsoDescending(items, (item) => item.updatedAt);
}

function sortQuarantineItems(items: QuarantineItemSummary[]) {
  return sortByIsoDescending(items, (item) => item.lastUpdatedAt);
}

function sortEvidence(items: EvidenceSummary[]) {
  return sortByIsoDescending(items, (item) => item.recordedAt);
}

function sortScanHistory(items: ScanHistorySummary[]) {
  return sortByIsoDescending(items, (item) => item.scannedAt);
}

function sortDevicePosture(items: DevicePostureSummary[]) {
  return sortByIsoDescending(items, (item) => item.updatedAt);
}

function normalizeDeviceRecord(raw: unknown, defaultPolicyName: string, nowIso: string): DeviceRecord {
  const record = (raw ?? {}) as Partial<DeviceRecord>;
  return {
    id: readOptionalString(record.id, randomUUID()),
    hostname: readOptionalString(record.hostname, "UNKNOWN-HOST"),
    osVersion: readOptionalString(record.osVersion, "unknown"),
    agentVersion: readOptionalString(record.agentVersion, "pending-first-heartbeat"),
    platformVersion: readOptionalString(record.platformVersion, "platform-pending"),
    serialNumber: readOptionalString(record.serialNumber, "unknown-serial"),
    enrolledAt: readOptionalString(record.enrolledAt, readOptionalString(record.lastSeenAt, nowIso)),
    lastSeenAt: readOptionalString(record.lastSeenAt, nowIso),
    lastPolicySyncAt: readOptionalNullableString(record.lastPolicySyncAt),
    lastTelemetryAt: readOptionalNullableString(record.lastTelemetryAt),
    healthState:
      record.healthState === "degraded" || record.healthState === "isolated" ? record.healthState : "healthy",
    isolated: record.isolated === true,
    policyName: readOptionalString(record.policyName, defaultPolicyName)
  };
}

function normalizeTelemetryRecord(raw: unknown, hostnameByDeviceId: Map<string, string>, nowIso: string): TelemetryRecord {
  const record = (raw ?? {}) as Partial<TelemetryRecord>;
  return {
    eventId: readOptionalString(record.eventId, randomUUID()),
    deviceId: readOptionalString(record.deviceId),
    hostname: readOptionalString(record.hostname, hostnameByDeviceId.get(readOptionalString(record.deviceId)) ?? "UNKNOWN-HOST"),
    eventType: readOptionalString(record.eventType, "unknown"),
    source: readOptionalString(record.source, "unknown"),
    summary: readOptionalString(record.summary),
    occurredAt: readOptionalString(record.occurredAt, nowIso),
    ingestedAt: readOptionalString(record.ingestedAt, nowIso),
    payloadJson: readOptionalString(record.payloadJson, "{}")
  };
}

function normalizeAlert(raw: unknown): AlertSummary {
  const alert = (raw ?? {}) as Partial<AlertSummary>;
  return {
    id: readOptionalString(alert.id, randomUUID()),
    deviceId: typeof alert.deviceId === "string" ? alert.deviceId : undefined,
    title: readOptionalString(alert.title, "Untitled alert"),
    severity:
      alert.severity === "low" || alert.severity === "medium" || alert.severity === "critical"
        ? alert.severity
        : "high",
    status: alert.status === "triaged" || alert.status === "contained" ? alert.status : "new",
    hostname: readOptionalString(alert.hostname, "UNKNOWN-HOST"),
    detectedAt: readOptionalString(alert.detectedAt, new Date().toISOString()),
    technique: typeof alert.technique === "string" ? alert.technique : undefined,
    summary: readOptionalString(alert.summary, "No summary available."),
    fingerprint: typeof alert.fingerprint === "string" ? alert.fingerprint : undefined
  };
}

function normalizeCommand(raw: unknown, hostnameByDeviceId: Map<string, string>, nowIso: string): DeviceCommandSummary {
  const command = (raw ?? {}) as Partial<DeviceCommandSummary>;
  const deviceId = readOptionalString(command.deviceId);
  return {
    id: readOptionalString(command.id, randomUUID()),
    deviceId,
    hostname: readOptionalString(command.hostname, hostnameByDeviceId.get(deviceId) ?? "UNKNOWN-HOST"),
    type: readOptionalString(command.type, "scan.targeted") as DeviceCommandSummary["type"],
    status:
      command.status === "in_progress" || command.status === "completed" || command.status === "failed"
        ? command.status
        : "pending",
    createdAt: readOptionalString(command.createdAt, nowIso),
    updatedAt: readOptionalString(command.updatedAt, nowIso),
    issuedBy: readOptionalString(command.issuedBy, "system"),
    targetPath: typeof command.targetPath === "string" ? command.targetPath : undefined,
    recordId: typeof command.recordId === "string" ? command.recordId : undefined,
    resultJson: typeof command.resultJson === "string" ? command.resultJson : undefined
  };
}

function normalizeQuarantineItem(
  raw: unknown,
  hostnameByDeviceId: Map<string, string>,
  nowIso: string
): QuarantineItemSummary {
  const item = (raw ?? {}) as Partial<QuarantineItemSummary>;
  const deviceId = readOptionalString(item.deviceId);
  return {
    recordId: readOptionalString(item.recordId, randomUUID()),
    deviceId,
    hostname: readOptionalString(item.hostname, hostnameByDeviceId.get(deviceId) ?? "UNKNOWN-HOST"),
    originalPath: readOptionalString(item.originalPath, "unknown"),
    quarantinedPath: readOptionalString(item.quarantinedPath, "unknown"),
    sha256: readOptionalString(item.sha256, "unknown"),
    sizeBytes: typeof item.sizeBytes === "number" ? item.sizeBytes : 0,
    capturedAt: readOptionalString(item.capturedAt, nowIso),
    lastUpdatedAt: readOptionalString(item.lastUpdatedAt, nowIso),
    evidenceRecordId: typeof item.evidenceRecordId === "string" ? item.evidenceRecordId : undefined,
    technique: typeof item.technique === "string" ? item.technique : undefined,
    status: item.status === "restored" || item.status === "deleted" ? item.status : "quarantined"
  };
}

function normalizeEvidence(raw: unknown, hostnameByDeviceId: Map<string, string>, nowIso: string): EvidenceSummary {
  const item = (raw ?? {}) as Partial<EvidenceSummary>;
  const deviceId = readOptionalString(item.deviceId);
  return {
    recordId: readOptionalString(item.recordId, randomUUID()),
    deviceId,
    hostname: readOptionalString(item.hostname, hostnameByDeviceId.get(deviceId) ?? "UNKNOWN-HOST"),
    recordedAt: readOptionalString(item.recordedAt, nowIso),
    source: readOptionalString(item.source, "unknown"),
    subjectPath: readOptionalString(item.subjectPath, "unknown"),
    sha256: readOptionalString(item.sha256, "unknown"),
    disposition: readOptionalString(item.disposition, "unknown"),
    tacticId: typeof item.tacticId === "string" ? item.tacticId : undefined,
    techniqueId: typeof item.techniqueId === "string" ? item.techniqueId : undefined,
    contentType: typeof item.contentType === "string" ? item.contentType : undefined,
    reputation: typeof item.reputation === "string" ? item.reputation : undefined,
    signer: typeof item.signer === "string" ? item.signer : undefined,
    quarantineRecordId: typeof item.quarantineRecordId === "string" ? item.quarantineRecordId : undefined,
    summary: readOptionalString(item.summary, "No evidence summary available.")
  };
}

function normalizeScanHistory(
  raw: unknown,
  hostnameByDeviceId: Map<string, string>,
  nowIso: string
): ScanHistorySummary {
  const item = (raw ?? {}) as Partial<ScanHistorySummary>;
  const deviceId = readOptionalString(item.deviceId);
  return {
    eventId: readOptionalString(item.eventId, randomUUID()),
    deviceId,
    hostname: readOptionalString(item.hostname, hostnameByDeviceId.get(deviceId) ?? "UNKNOWN-HOST"),
    scannedAt: readOptionalString(item.scannedAt, nowIso),
    source: readOptionalString(item.source, "unknown"),
    subjectPath: readOptionalString(item.subjectPath, "unknown"),
    sha256: readOptionalString(item.sha256, "unknown"),
    contentType: typeof item.contentType === "string" ? item.contentType : undefined,
    reputation: typeof item.reputation === "string" ? item.reputation : undefined,
    signer: typeof item.signer === "string" ? item.signer : undefined,
    heuristicScore: typeof item.heuristicScore === "number" ? item.heuristicScore : undefined,
    archiveEntryCount: typeof item.archiveEntryCount === "number" ? item.archiveEntryCount : undefined,
    disposition: readOptionalString(item.disposition, "unknown"),
    confidence: typeof item.confidence === "number" ? item.confidence : undefined,
    tacticId: typeof item.tacticId === "string" ? item.tacticId : undefined,
    techniqueId: typeof item.techniqueId === "string" ? item.techniqueId : undefined,
    remediationStatus: typeof item.remediationStatus === "string" ? item.remediationStatus : undefined,
    remediationError: typeof item.remediationError === "string" ? item.remediationError : undefined,
    evidenceRecordId: typeof item.evidenceRecordId === "string" ? item.evidenceRecordId : undefined,
    quarantineRecordId: typeof item.quarantineRecordId === "string" ? item.quarantineRecordId : undefined,
    summary: readOptionalString(item.summary, "No scan history summary available.")
  };
}

function normalizeDevicePosture(
  raw: unknown,
  hostnameByDeviceId: Map<string, string>,
  nowIso: string
): DevicePostureSummary {
  const posture = (raw ?? {}) as Partial<DevicePostureSummary>;
  const deviceId = readOptionalString(posture.deviceId);
  return {
    deviceId,
    hostname: readOptionalString(posture.hostname, hostnameByDeviceId.get(deviceId) ?? "UNKNOWN-HOST"),
    updatedAt: readOptionalString(posture.updatedAt, nowIso),
    overallState: clampPostureState(posture.overallState),
    tamperProtectionState: clampPostureState(posture.tamperProtectionState),
    tamperProtectionSummary:
      typeof posture.tamperProtectionSummary === "string" ? posture.tamperProtectionSummary : undefined,
    wscState: clampPostureState(posture.wscState),
    wscSummary: typeof posture.wscSummary === "string" ? posture.wscSummary : undefined,
    etwState: clampPostureState(posture.etwState),
    etwSummary: typeof posture.etwSummary === "string" ? posture.etwSummary : undefined,
    wfpState: clampPostureState(posture.wfpState),
    wfpSummary: typeof posture.wfpSummary === "string" ? posture.wfpSummary : undefined,
    isolationState: clampIsolationState(posture.isolationState),
    isolationSummary: typeof posture.isolationSummary === "string" ? posture.isolationSummary : undefined,
    registryConfigured: typeof posture.registryConfigured === "boolean" ? posture.registryConfigured : undefined,
    runtimePathsProtected:
      typeof posture.runtimePathsProtected === "boolean" ? posture.runtimePathsProtected : undefined,
    uninstallProtectionEnabled:
      typeof posture.uninstallProtectionEnabled === "boolean" ? posture.uninstallProtectionEnabled : undefined,
    elamDriverPresent: typeof posture.elamDriverPresent === "boolean" ? posture.elamDriverPresent : undefined,
    elamCertificateInstalled:
      typeof posture.elamCertificateInstalled === "boolean" ? posture.elamCertificateInstalled : undefined,
    launchProtectedConfigured:
      typeof posture.launchProtectedConfigured === "boolean" ? posture.launchProtectedConfigured : undefined,
    wscAvailable: typeof posture.wscAvailable === "boolean" ? posture.wscAvailable : undefined,
    providerHealth: typeof posture.providerHealth === "string" ? posture.providerHealth : undefined
  };
}

function normalizeState(rawState: unknown, nowIso: string): ControlPlaneState {
  const defaults = createEmptyState(nowIso);
  const raw = (rawState ?? {}) as Partial<ControlPlaneState>;
  const devices = Array.isArray(raw.devices)
    ? raw.devices.map((item) => normalizeDeviceRecord(item, defaults.defaultPolicy.name, nowIso))
    : [];
  const hostnameByDeviceId = new Map(devices.map((item) => [item.id, item.hostname]));

  return {
    defaultPolicy: raw.defaultPolicy ?? defaults.defaultPolicy,
    devices,
    alerts: Array.isArray(raw.alerts) ? raw.alerts.map((item) => normalizeAlert(item)) : [],
    telemetry: Array.isArray(raw.telemetry)
      ? raw.telemetry.map((item) => normalizeTelemetryRecord(item, hostnameByDeviceId, nowIso))
      : [],
    commands: Array.isArray(raw.commands)
      ? raw.commands.map((item) => normalizeCommand(item, hostnameByDeviceId, nowIso))
      : [],
    quarantineItems: Array.isArray(raw.quarantineItems)
      ? raw.quarantineItems.map((item) => normalizeQuarantineItem(item, hostnameByDeviceId, nowIso))
      : [],
    evidence: Array.isArray(raw.evidence)
      ? raw.evidence.map((item) => normalizeEvidence(item, hostnameByDeviceId, nowIso))
      : [],
    scanHistory: Array.isArray(raw.scanHistory)
      ? raw.scanHistory.map((item) => normalizeScanHistory(item, hostnameByDeviceId, nowIso))
      : [],
    devicePosture: Array.isArray(raw.devicePosture)
      ? raw.devicePosture.map((item) => normalizeDevicePosture(item, hostnameByDeviceId, nowIso))
      : []
  };
}

function stripDemoRecords(state: ControlPlaneState) {
  const demoDeviceIds = new Set<string>(DEMO_DEVICE_IDS);
  const demoHostnames = new Set<string>(DEMO_HOSTNAMES);

  state.devices = state.devices.filter((item) => !demoDeviceIds.has(item.id) && !demoHostnames.has(item.hostname));
  state.alerts = state.alerts.filter(
    (item) => !(item.deviceId && demoDeviceIds.has(item.deviceId)) && !demoHostnames.has(item.hostname)
  );
  state.telemetry = state.telemetry.filter(
    (item) => !demoDeviceIds.has(item.deviceId) && !demoHostnames.has(item.hostname)
  );
  state.commands = state.commands.filter(
    (item) => !demoDeviceIds.has(item.deviceId) && !demoHostnames.has(item.hostname)
  );
  state.quarantineItems = state.quarantineItems.filter(
    (item) => !demoDeviceIds.has(item.deviceId) && !demoHostnames.has(item.hostname)
  );
  state.evidence = state.evidence.filter(
    (item) => !demoDeviceIds.has(item.deviceId) && !demoHostnames.has(item.hostname)
  );
  state.scanHistory = state.scanHistory.filter(
    (item) => !demoDeviceIds.has(item.deviceId) && !demoHostnames.has(item.hostname)
  );
  state.devicePosture = state.devicePosture.filter(
    (item) => !demoDeviceIds.has(item.deviceId) && !demoHostnames.has(item.hostname)
  );
}

function recomputePosture(posture: DevicePostureSummary) {
  const postureStates = [
    posture.tamperProtectionState,
    posture.wscState,
    posture.etwState,
    posture.wfpState
  ];

  if (posture.isolationState === "error" || postureStates.includes("failed")) {
    posture.overallState = "failed";
    return;
  }

  if (postureStates.includes("degraded")) {
    posture.overallState = "degraded";
    return;
  }

  if (postureStates.every((state) => state === "ready")) {
    posture.overallState = "ready";
    return;
  }

  posture.overallState = "unknown";
}

function trimState(state: ControlPlaneState) {
  state.alerts = sortAlerts(state.alerts).slice(0, MAX_ALERTS);
  state.telemetry = sortTelemetry(state.telemetry).slice(0, MAX_TELEMETRY);
  state.commands = sortCommands(state.commands).slice(0, MAX_COMMANDS);
  state.quarantineItems = sortQuarantineItems(state.quarantineItems).slice(0, MAX_QUARANTINE_ITEMS);
  state.evidence = sortEvidence(state.evidence).slice(0, MAX_EVIDENCE_ITEMS);
  state.scanHistory = sortScanHistory(state.scanHistory).slice(0, MAX_SCAN_HISTORY);
  state.devicePosture = sortDevicePosture(state.devicePosture);
}

function findDeviceOrThrow(state: ControlPlaneState, deviceId: string) {
  const device = state.devices.find((item) => item.id === deviceId);
  if (!device) {
    throw new DeviceNotFoundError(deviceId);
  }

  return device;
}

function findCommandOrThrow(state: ControlPlaneState, deviceId: string, commandId: string) {
  const command = state.commands.find((item) => item.deviceId === deviceId && item.id === commandId);
  if (!command) {
    throw new CommandNotFoundError(commandId);
  }

  return command;
}

function getOrCreateDevicePosture(state: ControlPlaneState, device: DeviceRecord, nowIso: string) {
  const existing = state.devicePosture.find((item) => item.deviceId === device.id);
  if (existing) {
    return existing;
  }

  const created: DevicePostureSummary = {
    deviceId: device.id,
    hostname: device.hostname,
    updatedAt: nowIso,
    overallState: "unknown",
    tamperProtectionState: "unknown",
    wscState: "unknown",
    etwState: "unknown",
    wfpState: "unknown",
    isolationState: device.isolated ? "active" : "inactive"
  };
  state.devicePosture.push(created);
  return created;
}

function toDeviceSummary(state: ControlPlaneState, device: DeviceRecord): DeviceSummary {
  const posture = state.devicePosture.find((item) => item.deviceId === device.id);
  const openAlertCount = state.alerts.filter((item) => {
    if (item.status === "contained") {
      return false;
    }

    return item.deviceId === device.id || item.hostname === device.hostname;
  }).length;
  const quarantinedItemCount = state.quarantineItems.filter(
    (item) => item.deviceId === device.id && item.status === "quarantined"
  ).length;

  return {
    id: device.id,
    hostname: device.hostname,
    osVersion: device.osVersion,
    agentVersion: device.agentVersion,
    platformVersion: device.platformVersion,
    serialNumber: device.serialNumber,
    enrolledAt: device.enrolledAt,
    lastSeenAt: device.lastSeenAt,
    lastPolicySyncAt: device.lastPolicySyncAt,
    lastTelemetryAt: device.lastTelemetryAt,
    healthState: device.healthState,
    isolated: device.isolated,
    policyName: device.policyName,
    openAlertCount,
    quarantinedItemCount,
    postureState: posture?.overallState ?? "unknown"
  };
}

function updateQuarantineInventory(state: ControlPlaneState, record: TelemetryRecord) {
  const payload = parsePayload(record.payloadJson);

  if (record.eventType === "scan.finding") {
    const quarantineRecordId = readString(payload, "quarantineRecordId");
    const remediationStatus = readString(payload, "remediationStatus");
    const disposition = readString(payload, "disposition");
    if (!quarantineRecordId || (remediationStatus !== "quarantined" && disposition !== "quarantine")) {
      return;
    }

    const existing = state.quarantineItems.find((item) => item.recordId === quarantineRecordId);
    const next: QuarantineItemSummary = {
      recordId: quarantineRecordId,
      deviceId: record.deviceId,
      hostname: record.hostname,
      originalPath: readString(payload, "path") ?? "unknown",
      quarantinedPath: readString(payload, "quarantinedPath") ?? "unknown",
      sha256: readString(payload, "sha256") ?? "unknown",
      sizeBytes: readNumber(payload, "sizeBytes") ?? 0,
      capturedAt: existing?.capturedAt ?? record.occurredAt,
      lastUpdatedAt: record.occurredAt,
      evidenceRecordId: readString(payload, "evidenceRecordId"),
      technique: readString(payload, "techniqueId"),
      status: "quarantined"
    };

    if (existing) {
      Object.assign(existing, next);
    } else {
      state.quarantineItems.push(next);
    }

    return;
  }

  if (record.eventType !== "quarantine.restored" && record.eventType !== "quarantine.deleted") {
    return;
  }

  const recordId = readString(payload, "recordId");
  if (!recordId) {
    return;
  }

  const status: QuarantineStatus = record.eventType === "quarantine.deleted" ? "deleted" : "restored";
  const existing = state.quarantineItems.find((item) => item.recordId === recordId);
  if (existing) {
    existing.status = status;
    existing.lastUpdatedAt = record.occurredAt;
    existing.originalPath = readString(payload, "originalPath") ?? existing.originalPath;
    existing.quarantinedPath = readString(payload, "quarantinedPath") ?? existing.quarantinedPath;
    return;
  }

  state.quarantineItems.push({
    recordId,
    deviceId: record.deviceId,
    hostname: record.hostname,
    originalPath: readString(payload, "originalPath") ?? "unknown",
    quarantinedPath: readString(payload, "quarantinedPath") ?? "unknown",
    sha256: "unknown",
    sizeBytes: 0,
    capturedAt: record.occurredAt,
    lastUpdatedAt: record.occurredAt,
    status
  });
}

function updateEvidenceInventory(state: ControlPlaneState, record: TelemetryRecord) {
  if (record.eventType !== "scan.finding") {
    return;
  }

  const payload = parsePayload(record.payloadJson);
  const recordId = readString(payload, "evidenceRecordId");
  if (!recordId) {
    return;
  }

  const existing = state.evidence.find((item) => item.recordId === recordId);
  const next: EvidenceSummary = {
    recordId,
    deviceId: record.deviceId,
    hostname: record.hostname,
    recordedAt: record.occurredAt,
    source: record.source,
    subjectPath: readString(payload, "path") ?? "unknown",
    sha256: readString(payload, "sha256") ?? "unknown",
    disposition: readString(payload, "disposition") ?? readString(payload, "remediationStatus") ?? "unknown",
    tacticId: readString(payload, "tacticId"),
    techniqueId: readString(payload, "techniqueId"),
    contentType: readString(payload, "contentType"),
    reputation: readString(payload, "reputation"),
    signer: readString(payload, "signer"),
    quarantineRecordId: readString(payload, "quarantineRecordId"),
    summary: record.summary
  };

  if (existing) {
    Object.assign(existing, next);
  } else {
    state.evidence.push(next);
  }
}

function updateScanHistory(state: ControlPlaneState, record: TelemetryRecord) {
  if (record.eventType !== "scan.finding") {
    return;
  }

  const payload = parsePayload(record.payloadJson);
  const existing = state.scanHistory.find((item) => item.eventId === record.eventId);
  const next: ScanHistorySummary = {
    eventId: record.eventId,
    deviceId: record.deviceId,
    hostname: record.hostname,
    scannedAt: record.occurredAt,
    source: record.source,
    subjectPath: readString(payload, "path") ?? "unknown",
    sha256: readString(payload, "sha256") ?? "unknown",
    contentType: readString(payload, "contentType"),
    reputation: readString(payload, "reputation"),
    signer: readString(payload, "signer"),
    heuristicScore: readNumber(payload, "heuristicScore"),
    archiveEntryCount: readNumber(payload, "archiveEntryCount"),
    disposition: readString(payload, "disposition") ?? "unknown",
    confidence: readNumber(payload, "confidence"),
    tacticId: readString(payload, "tacticId"),
    techniqueId: readString(payload, "techniqueId"),
    remediationStatus: readString(payload, "remediationStatus"),
    remediationError: readString(payload, "remediationError"),
    evidenceRecordId: readString(payload, "evidenceRecordId"),
    quarantineRecordId: readString(payload, "quarantineRecordId"),
    summary: record.summary
  };

  if (existing) {
    Object.assign(existing, next);
  } else {
    state.scanHistory.push(next);
  }
}

function updateDevicePosture(state: ControlPlaneState, device: DeviceRecord, record: TelemetryRecord) {
  const payload = parsePayload(record.payloadJson);
  const posture = getOrCreateDevicePosture(state, device, record.occurredAt);
  let touched = false;

  switch (record.eventType) {
    case "tamper.protection.ready":
    case "tamper.protection.degraded":
    case "tamper.protection.failed":
      posture.tamperProtectionState = clampPostureState(record.eventType.split(".").at(-1));
      posture.tamperProtectionSummary = record.summary;
      posture.registryConfigured = readBoolean(payload, "registryConfigured") ?? posture.registryConfigured;
      posture.runtimePathsProtected = readBoolean(payload, "runtimePathsProtected") ?? posture.runtimePathsProtected;
      posture.uninstallProtectionEnabled =
        readBoolean(payload, "uninstallProtectionEnabled") ?? posture.uninstallProtectionEnabled;
      posture.elamDriverPresent = readBoolean(payload, "elamDriverPresent") ?? posture.elamDriverPresent;
      posture.elamCertificateInstalled =
        readBoolean(payload, "elamCertificateInstalled") ?? posture.elamCertificateInstalled;
      posture.launchProtectedConfigured =
        readBoolean(payload, "launchProtectedConfigured") ?? posture.launchProtectedConfigured;
      touched = true;
      break;
    case "wsc.coexistence.ready":
    case "wsc.coexistence.degraded":
    case "wsc.coexistence.failed":
      posture.wscState = clampPostureState(record.eventType.split(".").at(-1));
      posture.wscSummary = record.summary;
      posture.wscAvailable = readBoolean(payload, "wscAvailable") ?? posture.wscAvailable;
      posture.providerHealth = readString(payload, "providerHealth") ?? posture.providerHealth;
      touched = true;
      break;
    case "process.etw.started":
      posture.etwState = "ready";
      posture.etwSummary = record.summary;
      touched = true;
      break;
    case "process.etw.failed":
      posture.etwState = "failed";
      posture.etwSummary = record.summary;
      touched = true;
      break;
    case "network.wfp.started":
      posture.wfpState = "ready";
      posture.wfpSummary = record.summary;
      touched = true;
      break;
    case "network.wfp.failed":
      posture.wfpState = "failed";
      posture.wfpSummary = record.summary;
      touched = true;
      break;
    case "network.isolation.applied":
      posture.isolationState = "active";
      posture.isolationSummary = record.summary;
      device.isolated = true;
      device.healthState = "isolated";
      touched = true;
      break;
    case "network.isolation.released":
      posture.isolationState = "inactive";
      posture.isolationSummary = record.summary;
      device.isolated = false;
      if (device.healthState === "isolated") {
        device.healthState = posture.overallState === "degraded" ? "degraded" : "healthy";
      }
      touched = true;
      break;
    case "network.isolation.failed":
      posture.isolationState = "error";
      posture.isolationSummary = record.summary;
      touched = true;
      break;
    default:
      break;
  }

  if (!touched) {
    return;
  }

  posture.updatedAt = record.occurredAt;
  posture.hostname = device.hostname;
  recomputePosture(posture);

  if (!device.isolated && (posture.overallState === "degraded" || posture.overallState === "failed")) {
    device.healthState = "degraded";
  }
}

function applyCommandCompletionEffects(
  state: ControlPlaneState,
  device: DeviceRecord,
  command: DeviceCommandSummary,
  completedAt: string
) {
  const payload = command.resultJson ? parsePayload(command.resultJson) : null;

  if (command.status !== "completed") {
    return;
  }

  if (command.type === "device.isolate") {
    device.isolated = true;
    device.healthState = "isolated";
    const posture = getOrCreateDevicePosture(state, device, completedAt);
    posture.isolationState = "active";
    posture.isolationSummary = readString(payload, "summary") ?? "Host isolation was applied.";
    posture.updatedAt = completedAt;
    recomputePosture(posture);
    return;
  }

  if (command.type === "device.release") {
    device.isolated = false;
    if (device.healthState === "isolated") {
      device.healthState = "healthy";
    }
    const posture = getOrCreateDevicePosture(state, device, completedAt);
    posture.isolationState = "inactive";
    posture.isolationSummary = readString(payload, "summary") ?? "Host isolation was released.";
    posture.updatedAt = completedAt;
    recomputePosture(posture);
    return;
  }

  if ((command.type === "quarantine.restore" || command.type === "quarantine.delete") && command.recordId) {
    const item = state.quarantineItems.find((entry) => entry.recordId === command.recordId);
    if (item) {
      item.status = command.type === "quarantine.delete" ? "deleted" : "restored";
      item.lastUpdatedAt = completedAt;
    }
  }
}

export function createFileBackedControlPlaneStore(
  options: CreateFileBackedControlPlaneStoreOptions = {}
): ControlPlaneStore {
  const stateFilePath = options.stateFilePath ?? DEFAULT_STATE_FILE_PATH;
  const commandChannelUrl = options.commandChannelUrl ?? DEFAULT_COMMAND_CHANNEL_URL;
  const now = options.now ?? (() => new Date().toISOString());
  const seedDemoData = options.seedDemoData ?? false;

  let cachedState: ControlPlaneState | null = null;

  async function persistState(state: ControlPlaneState) {
    await mkdir(dirname(stateFilePath), { recursive: true });
    await writeFile(stateFilePath, `${JSON.stringify(state, null, 2)}\n`, "utf8");
  }

  async function loadState() {
    if (cachedState) {
      return cachedState;
    }

    try {
      const rawText = await readFile(stateFilePath, "utf8");
      cachedState = normalizeState(JSON.parse(rawText) as unknown, now());
      if (!seedDemoData) {
        stripDemoRecords(cachedState);
      }
    } catch (error) {
      const maybeNodeError = error as NodeJS.ErrnoException;
      if (maybeNodeError.code !== "ENOENT") {
        throw error;
      }

      cachedState = seedDemoData ? createSeedState(now()) : createEmptyState(now());
    }

    trimState(cachedState);
    await persistState(cachedState);
    return cachedState;
  }

  async function mutateState<T>(mutator: (state: ControlPlaneState) => T | Promise<T>) {
    const state = await loadState();
    const result = await mutator(state);
    trimState(state);
    await persistState(state);
    return result;
  }

  return {
    async getDashboardSnapshot() {
      const state = await loadState();
      const devices = sortDevices(state.devices.map((item) => toDeviceSummary(state, item)));
      return {
        generatedAt: now(),
        devices,
        alerts: sortAlerts(state.alerts),
        recentTelemetry: sortTelemetry(state.telemetry).slice(0, 20),
        recentCommands: sortCommands(state.commands).slice(0, 20),
        quarantineItems: sortQuarantineItems(state.quarantineItems).slice(0, 20),
        recentEvidence: sortEvidence(state.evidence).slice(0, 20),
        recentScanHistory: sortScanHistory(state.scanHistory).slice(0, 20),
        postureOverview: sortDevicePosture(state.devicePosture).slice(0, 20),
        defaultPolicy: state.defaultPolicy
      };
    },

    async getDeviceDetail(deviceId: string) {
      const state = await loadState();
      const device = findDeviceOrThrow(state, deviceId);
      return {
        device: toDeviceSummary(state, device),
        posture: state.devicePosture.find((item) => item.deviceId === deviceId) ?? null,
        alerts: sortAlerts(state.alerts.filter((item) => item.deviceId === deviceId || item.hostname === device.hostname)),
        telemetry: sortTelemetry(state.telemetry.filter((item) => item.deviceId === deviceId)).slice(0, 200),
        commands: sortCommands(state.commands.filter((item) => item.deviceId === deviceId)).slice(0, 200),
        quarantineItems: sortQuarantineItems(state.quarantineItems.filter((item) => item.deviceId === deviceId)).slice(0, 200),
        evidence: sortEvidence(state.evidence.filter((item) => item.deviceId === deviceId)).slice(0, 200),
        scanHistory: sortScanHistory(state.scanHistory.filter((item) => item.deviceId === deviceId)).slice(0, 200)
      };
    },

    async listDevices() {
      const state = await loadState();
      return sortDevices(state.devices.map((item) => toDeviceSummary(state, item)));
    },

    async listAlerts() {
      const state = await loadState();
      return sortAlerts(state.alerts);
    },

    async listTelemetry(deviceId, limit = 50) {
      const state = await loadState();
      const filtered = deviceId ? state.telemetry.filter((item) => item.deviceId === deviceId) : state.telemetry;
      return sortTelemetry(filtered).slice(0, limit);
    },

    async listEvidence(deviceId, limit = 50) {
      const state = await loadState();
      const filtered = deviceId ? state.evidence.filter((item) => item.deviceId === deviceId) : state.evidence;
      return sortEvidence(filtered).slice(0, limit);
    },

    async listScanHistory(deviceId, limit = 50) {
      const state = await loadState();
      const filtered = deviceId ? state.scanHistory.filter((item) => item.deviceId === deviceId) : state.scanHistory;
      return sortScanHistory(filtered).slice(0, limit);
    },

    async listCommands(deviceId, status, limit = 50) {
      const state = await loadState();
      const filtered = state.commands.filter((item) => {
        if (deviceId && item.deviceId !== deviceId) {
          return false;
        }

        if (status && item.status !== status) {
          return false;
        }

        return true;
      });
      return sortCommands(filtered).slice(0, limit);
    },

    async listQuarantineItems(deviceId, status, limit = 50) {
      const state = await loadState();
      const filtered = state.quarantineItems.filter((item) => {
        if (deviceId && item.deviceId !== deviceId) {
          return false;
        }

        if (status && item.status !== status) {
          return false;
        }

        return true;
      });
      return sortQuarantineItems(filtered).slice(0, limit);
    },

    async getDefaultPolicy() {
      const state = await loadState();
      return state.defaultPolicy;
    },

    async enrollDevice(request) {
      return mutateState(async (state) => {
        const issuedAt = now();
        const deviceId = randomUUID();
        state.devices.push({
          id: deviceId,
          hostname: request.hostname,
          osVersion: request.osVersion,
          agentVersion: "pending-first-heartbeat",
          platformVersion: "platform-pending",
          serialNumber: request.serialNumber,
          enrolledAt: issuedAt,
          lastSeenAt: issuedAt,
          lastPolicySyncAt: null,
          lastTelemetryAt: null,
          healthState: "healthy",
          isolated: false,
          policyName: state.defaultPolicy.name
        });

        return {
          deviceId,
          issuedAt,
          policy: state.defaultPolicy,
          commandChannelUrl
        };
      });
    },

    async recordHeartbeat(deviceId, request) {
      return mutateState(async (state) => {
        const device = findDeviceOrThrow(state, deviceId);
        const receivedAt = now();
        device.agentVersion = request.agentVersion;
        device.platformVersion = request.platformVersion;
        device.healthState = request.healthState;
        device.isolated = request.isolated;
        device.lastSeenAt = receivedAt;

        const posture = getOrCreateDevicePosture(state, device, receivedAt);
        posture.hostname = device.hostname;
        posture.updatedAt = receivedAt;
        posture.isolationState = request.isolated ? "active" : "inactive";
        posture.isolationSummary = request.isolated
          ? "Heartbeat reported that host isolation is active."
          : "Heartbeat reported that host isolation is inactive.";
        recomputePosture(posture);

        return {
          deviceId,
          receivedAt,
          effectivePolicyRevision: state.defaultPolicy.revision,
          commandsPending: state.commands.filter((item) => item.deviceId === deviceId && item.status === "pending").length
        };
      });
    },

    async policyCheckIn(deviceId, request) {
      return mutateState(async (state) => {
        const device = findDeviceOrThrow(state, deviceId);
        const retrievedAt = now();
        device.lastSeenAt = retrievedAt;
        device.lastPolicySyncAt = retrievedAt;
        if (request.agentVersion) {
          device.agentVersion = request.agentVersion;
        }
        if (request.platformVersion) {
          device.platformVersion = request.platformVersion;
        }

        return {
          deviceId,
          retrievedAt,
          changed: request.currentPolicyRevision !== state.defaultPolicy.revision,
          policy: state.defaultPolicy
        };
      });
    },

    async ingestTelemetry(deviceId, request) {
      return mutateState(async (state) => {
        const device = findDeviceOrThrow(state, deviceId);
        const receivedAt = now();
        const existingIds = new Set(
          state.telemetry.filter((item) => item.deviceId === deviceId).map((item) => item.eventId)
        );

        const acceptedRecords: TelemetryRecord[] = [];
        for (const event of request.events) {
          if (existingIds.has(event.eventId)) {
            continue;
          }

          const record: TelemetryRecord = {
            ...event,
            deviceId,
            hostname: device.hostname,
            ingestedAt: receivedAt
          };
          acceptedRecords.push(record);
          state.telemetry.push(record);
          updateQuarantineInventory(state, record);
          updateEvidenceInventory(state, record);
          updateScanHistory(state, record);
          updateDevicePosture(state, device, record);
        }

        if (acceptedRecords.length > 0) {
          const latestOccurredAt = acceptedRecords.reduce(
            (latest, record) => (record.occurredAt > latest ? record.occurredAt : latest),
            acceptedRecords[0].occurredAt
          );
          device.lastTelemetryAt = latestOccurredAt;
          device.lastSeenAt = receivedAt;
          mergeGeneratedAlerts(state, generateAlertsFromTelemetry(acceptedRecords));
        }

        return {
          deviceId,
          accepted: acceptedRecords.length,
          receivedAt,
          totalStored: state.telemetry.length
        };
      });
    },

    async queueCommand(deviceId, request) {
      return mutateState(async (state) => {
        const device = findDeviceOrThrow(state, deviceId);
        const createdAt = now();
        const command: DeviceCommandSummary = {
          id: randomUUID(),
          deviceId,
          hostname: device.hostname,
          type: request.type,
          status: "pending",
          createdAt,
          updatedAt: createdAt,
          issuedBy: request.issuedBy ?? "console",
          targetPath: request.targetPath,
          recordId: request.recordId
        };
        state.commands.push(command);
        return command;
      });
    },

    async pollPendingCommands(deviceId, limit = 20) {
      return mutateState(async (state) => {
        findDeviceOrThrow(state, deviceId);
        const polledAt = now();
        const items = sortCommands(
          state.commands.filter((item) => item.deviceId === deviceId && item.status === "pending")
        ).slice(0, limit);

        for (const item of items) {
          item.status = "in_progress";
          item.updatedAt = polledAt;
        }

        return {
          deviceId,
          polledAt,
          items
        };
      });
    },

    async completeCommand(deviceId, commandId, request) {
      return mutateState(async (state) => {
        const device = findDeviceOrThrow(state, deviceId);
        const command = findCommandOrThrow(state, deviceId, commandId);
        const completedAt = now();
        command.status = request.status;
        command.updatedAt = completedAt;
        command.resultJson = request.resultJson;
        applyCommandCompletionEffects(state, device, command, completedAt);
        return command;
      });
    }
  };
}
