import { randomUUID } from "node:crypto";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import {
  buildAdminActorContext,
  createAdminLoginResponse,
  createBootstrapAdminState,
  createSessionToken,
  DEFAULT_ADMIN_MFA_SECRET,
  DEFAULT_ADMIN_PASSWORD,
  hashSessionToken,
  hashPassword,
  hasAdminRole,
  toAdminApiKeySummary,
  toAdminPrincipalSummary,
  toAdminSessionSummary,
  verifyPassword,
  verifyTotpCode
} from "./adminAuth.ts";
import { generateAlertsFromTelemetry, mergeGeneratedAlerts } from "./detectionEngine.ts";
import { explainDeviceRisk, scoreDeviceRisk, summarizeDeviceRisk } from "./deviceRiskScoring.ts";
import { createEmptyState, createSeedState, DEMO_DEVICE_IDS, DEMO_HOSTNAMES } from "./seedState.ts";
import type {
  AdminActorContext,
  AdminApiKeyCreateRequest,
  AdminApiKeyCreateResponse,
  AdminApiKeyRecord,
  AdminApiKeySummary,
  AdminAuditEventSummary,
  AdminLoginRequest,
  AdminLoginResponse,
  AdminPrincipalRecord,
  AdminPrincipalSummary,
  AdminSessionRecord,
  AdminSessionSummary,
  AlertBehaviorChain,
  AlertBehaviorChainStep,
  AlertDetail,
  AlertResponsePlaybook,
  AlertResponsePlaybookAction,
  AlertSummary,
  AlertSeverity,
  CommandType,
  CommandStatus,
  CompleteCommandRequest,
  ControlPlaneState,
  CreatePolicyExclusionChangeRequest,
  CreatePolicyRequest,
  CreateScriptRequest,
  DashboardSnapshot,
  DeviceCommandSummary,
  DeviceDetail,
  DevicePostureSummary,
  DeviceRecord,
  DeviceRiskTelemetrySnapshot,
  DeviceScoreSnapshot,
  DeviceSummary,
  EnrollmentRequest,
  EnrollmentResponse,
  EvidenceSummary,
  HeartbeatRequest,
  HeartbeatResponse,
  InstalledSoftwareSummary,
  IsolationState,
  PolicyCheckInRequest,
  PolicyCheckInResponse,
  PolicyExclusionChangeEntry,
  PolicyExclusionChangeRequestSummary,
  PolicyExclusionListType,
  PolicyExclusionRequestStatus,
  PolicyProfile,
  PolicyAssignmentRequest,
  PolicySummary,
  PollCommandsResponse,
  PostureState,
  PrivilegeBaselineSnapshot,
  PrivilegeEventSummary,
  PrivilegeHardeningMode,
  PrivilegeStateSnapshot,
  QueueCommandRequest,
  QuarantineItemSummary,
  QuarantineStatus,
  ScanHistorySummary,
  ScriptSummary,
  SoftwareUpdateState,
  TelemetryBatchRequest,
  TelemetryBatchResponse,
  TelemetryRecord,
  UpsertDeviceRiskTelemetryRequest,
  ReviewPolicyExclusionChangeRequest,
  UpdatePolicyRequest,
  UpdateScriptRequest
} from "./types.ts";

const DEFAULT_STATE_FILE_PATH = join(process.cwd(), ".data", "control-plane-state.json");
const DEFAULT_COMMAND_CHANNEL_URL = "wss://localhost:4000/api/v1/commands";

const MAX_ALERTS = 1_000;
const MAX_TELEMETRY = 5_000;
const MAX_COMMANDS = 2_000;
const MAX_QUARANTINE_ITEMS = 2_000;
const MAX_EVIDENCE_ITEMS = 2_000;
const MAX_SCAN_HISTORY = 5_000;
const MAX_DEVICE_SCORE_HISTORY = 3_000;
const MAX_PRIVILEGE_EVENTS = 5_000;
const MAX_ADMIN_SESSIONS = 1_000;
const MAX_ADMIN_API_KEYS = 500;
const MAX_ADMIN_AUDIT_EVENTS = 5_000;
const MAX_POLICY_EXCLUSION_CHANGE_REQUESTS = 2_000;

type ParsedPayload = Record<string, unknown>;

interface CreateFileBackedControlPlaneStoreOptions {
  stateFilePath?: string;
  commandChannelUrl?: string;
  now?: () => string;
  seedDemoData?: boolean;
}

export interface ControlPlaneStore {
  listAdminPrincipals(): Promise<AdminPrincipalSummary[]>;
  listAdminSessions(): Promise<AdminSessionSummary[]>;
  listAdminApiKeys(): Promise<AdminApiKeySummary[]>;
  listAdminAuditEvents(limit?: number): Promise<AdminAuditEventSummary[]>;
  loginAdmin(request: AdminLoginRequest, observedRemoteAddress?: string, userAgent?: string): Promise<AdminLoginResponse>;
  resolveAdminSession(
    sessionToken: string,
    observedRemoteAddress?: string,
    userAgent?: string
  ): Promise<{ principal: AdminPrincipalSummary; session: AdminSessionSummary } | null>;
  logoutAdminSession(sessionToken: string, observedRemoteAddress?: string): Promise<boolean>;
  createAdminApiKey(
    request: AdminApiKeyCreateRequest,
    actor: AdminActorContext,
    observedRemoteAddress?: string
  ): Promise<AdminApiKeyCreateResponse>;
  revokeAdminApiKey(apiKeyId: string, actor: AdminActorContext): Promise<AdminApiKeySummary>;
  getDashboardSnapshot(): Promise<DashboardSnapshot>;
  getDeviceDetail(deviceId: string): Promise<DeviceDetail>;
  listDevices(): Promise<DeviceSummary[]>;
  listAlerts(): Promise<AlertSummary[]>;
  getAlertDetail(alertId: string): Promise<AlertDetail>;
  listTelemetry(deviceId?: string, limit?: number): Promise<TelemetryRecord[]>;
  listEvidence(deviceId?: string, limit?: number): Promise<EvidenceSummary[]>;
  listScanHistory(deviceId?: string, limit?: number): Promise<ScanHistorySummary[]>;
  listCommands(deviceId?: string, status?: CommandStatus, limit?: number): Promise<DeviceCommandSummary[]>;
  listQuarantineItems(deviceId?: string, status?: QuarantineStatus, limit?: number): Promise<QuarantineItemSummary[]>;
  getDefaultPolicy(): Promise<PolicySummary>;
  listPolicies(): Promise<PolicyProfile[]>;
  listPolicyExclusionChangeRequests(
    policyId?: string,
    status?: PolicyExclusionRequestStatus,
    limit?: number
  ): Promise<PolicyExclusionChangeRequestSummary[]>;
  createPolicyExclusionChangeRequest(
    policyId: string,
    request: CreatePolicyExclusionChangeRequest,
    actor?: AdminActorContext
  ): Promise<PolicyExclusionChangeRequestSummary>;
  reviewPolicyExclusionChangeRequest(
    requestId: string,
    request: ReviewPolicyExclusionChangeRequest,
    actor?: AdminActorContext
  ): Promise<PolicyExclusionChangeRequestSummary>;
  createPolicy(request: CreatePolicyRequest, actor?: AdminActorContext): Promise<PolicyProfile>;
  updatePolicy(policyId: string, request: UpdatePolicyRequest, actor?: AdminActorContext): Promise<PolicyProfile>;
  assignPolicy(policyId: string, request: PolicyAssignmentRequest, actor?: AdminActorContext): Promise<PolicyProfile>;
  listScripts(): Promise<ScriptSummary[]>;
  createScript(request: CreateScriptRequest, actor?: AdminActorContext): Promise<ScriptSummary>;
  updateScript(scriptId: string, request: UpdateScriptRequest, actor?: AdminActorContext): Promise<ScriptSummary>;
  upsertDeviceRiskTelemetry(deviceId: string, request: UpsertDeviceRiskTelemetryRequest): Promise<DeviceRiskTelemetrySnapshot>;
  recalculateDeviceScore(deviceId: string): Promise<DeviceScoreSnapshot>;
  getLatestDeviceScore(deviceId: string): Promise<DeviceScoreSnapshot>;
  listDeviceScoreHistory(deviceId: string, limit?: number): Promise<DeviceScoreSnapshot[]>;
  getDeviceRiskSummary(deviceId: string): Promise<{ deviceId: string; summary: string; explanation: string; score: DeviceScoreSnapshot }>;
  getDevicePrivilegeBaseline(deviceId: string): Promise<PrivilegeBaselineSnapshot | null>;
  getDevicePrivilegeState(deviceId: string): Promise<PrivilegeStateSnapshot | null>;
  listDevicePrivilegeEvents(deviceId: string, limit?: number): Promise<PrivilegeEventSummary[]>;
  enforceDevicePrivilegeHardening(
    deviceId: string,
    request: { issuedBy?: string; reason?: string },
    actor?: AdminActorContext
  ): Promise<PrivilegeStateSnapshot>;
  recoverDevicePrivilegeHardening(
    deviceId: string,
    request: { issuedBy?: string; reason?: string },
    actor?: AdminActorContext
  ): Promise<PrivilegeStateSnapshot>;
  enrollDevice(request: EnrollmentRequest, observedRemoteAddress?: string): Promise<EnrollmentResponse>;
  recordHeartbeat(deviceId: string, request: HeartbeatRequest, observedRemoteAddress?: string): Promise<HeartbeatResponse>;
  policyCheckIn(deviceId: string, request: PolicyCheckInRequest, observedRemoteAddress?: string): Promise<PolicyCheckInResponse>;
  ingestTelemetry(deviceId: string, request: TelemetryBatchRequest, observedRemoteAddress?: string): Promise<TelemetryBatchResponse>;
  queueCommand(deviceId: string, request: QueueCommandRequest, actor?: AdminActorContext): Promise<DeviceCommandSummary>;
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

export class AlertNotFoundError extends Error {
  constructor(alertId: string) {
    super(`Alert not found: ${alertId}`);
    this.name = "AlertNotFoundError";
  }
}

export class CommandNotFoundError extends Error {
  constructor(commandId: string) {
    super(`Command not found: ${commandId}`);
    this.name = "CommandNotFoundError";
  }
}

export class PolicyNotFoundError extends Error {
  constructor(policyId: string) {
    super(`Policy not found: ${policyId}`);
    this.name = "PolicyNotFoundError";
  }
}

export class PolicyExclusionChangeRequestNotFoundError extends Error {
  constructor(requestId: string) {
    super(`Policy exclusion request not found: ${requestId}`);
    this.name = "PolicyExclusionChangeRequestNotFoundError";
  }
}

export class PolicyExclusionChangeRequestStateError extends Error {
  constructor(requestId: string, status: PolicyExclusionRequestStatus) {
    super(`Policy exclusion request ${requestId} is already ${status}`);
    this.name = "PolicyExclusionChangeRequestStateError";
  }
}

export class PolicyExclusionWorkflowRequiredError extends Error {
  constructor(
    message =
      "Suppression list changes must be submitted and approved through the policy exclusion request workflow."
  ) {
    super(message);
    this.name = "PolicyExclusionWorkflowRequiredError";
  }
}

export class ScriptNotFoundError extends Error {
  constructor(scriptId: string) {
    super(`Script not found: ${scriptId}`);
    this.name = "ScriptNotFoundError";
  }
}

export class AdminAuthenticationError extends Error {
  constructor(message = "Invalid admin credentials") {
    super(message);
    this.name = "AdminAuthenticationError";
  }
}

export class AdminAuthorizationError extends Error {
  constructor(message = "Admin authorization failed") {
    super(message);
    this.name = "AdminAuthorizationError";
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

function readStringArray(payload: ParsedPayload | null, key: string) {
  const value = payload?.[key];
  if (!Array.isArray(value)) {
    return [];
  }

  return value.filter((item): item is string => typeof item === "string" && item.length > 0);
}

function readObjectArray(payload: ParsedPayload | null, key: string) {
  const value = payload?.[key];
  if (!Array.isArray(value)) {
    return [];
  }

  return value.filter((item): item is ParsedPayload => Boolean(item) && typeof item === "object" && !Array.isArray(item));
}

function readOptionalString(value: unknown, fallback = "") {
  return typeof value === "string" ? value : fallback;
}

function readOptionalNullableString(value: unknown) {
  return typeof value === "string" ? value : null;
}

function readOptionalStringArray(value: unknown) {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.filter((item): item is string => typeof item === "string");
}

function normalizePolicyStringArray(value: unknown, normalizer: (value: string) => string = (item) => item.trim()) {
  const results: string[] = [];
  const seen = new Set<string>();

  for (const item of readOptionalStringArray(value)) {
    const normalized = normalizer(item).trim();
    if (!normalized) {
      continue;
    }

    const dedupeKey = normalized.toLowerCase();
    if (seen.has(dedupeKey)) {
      continue;
    }

    seen.add(dedupeKey);
    results.push(normalized);
  }

  return results;
}

function normalizeTelemetryProcessContext(record: Partial<TelemetryRecord>, payload: ParsedPayload | null) {
  if (record.eventType === "process.started" || record.eventType === "process.exited") {
    return {
      processId: typeof record.processId === "number" ? record.processId : readNumber(payload, "pid"),
      parentProcessId: typeof record.parentProcessId === "number" ? record.parentProcessId : readNumber(payload, "parentPid"),
      processImageName:
        typeof record.processImageName === "string" && record.processImageName.length > 0
          ? record.processImageName
          : readString(payload, "imageName"),
      processImagePath:
        typeof record.processImagePath === "string" && record.processImagePath.length > 0
          ? record.processImagePath
          : readString(payload, "imagePath"),
      parentProcessImageName:
        typeof record.parentProcessImageName === "string" && record.parentProcessImageName.length > 0
          ? record.parentProcessImageName
          : readString(payload, "parentImageName"),
      parentProcessImagePath:
        typeof record.parentProcessImagePath === "string" && record.parentProcessImagePath.length > 0
          ? record.parentProcessImagePath
          : readString(payload, "parentImagePath"),
      processCommandLine:
        typeof record.processCommandLine === "string" && record.processCommandLine.length > 0
          ? record.processCommandLine
          : readString(payload, "commandLine"),
      processUserSid:
        typeof record.processUserSid === "string" && record.processUserSid.length > 0
          ? record.processUserSid
          : readString(payload, "userSid"),
      processIntegrityLevel:
        typeof record.processIntegrityLevel === "string" && record.processIntegrityLevel.length > 0
          ? record.processIntegrityLevel
          : readString(payload, "integrityLevel"),
      processSessionId:
        typeof record.processSessionId === "string" && record.processSessionId.length > 0
          ? record.processSessionId
          : readString(payload, "sessionId"),
      processSigner:
        typeof record.processSigner === "string" && record.processSigner.length > 0
          ? record.processSigner
          : readString(payload, "signer"),
      processExitCode: typeof record.processExitCode === "number" ? record.processExitCode : readNumber(payload, "exitCode")
    };
  }

  if (record.eventType === "image.loaded") {
    return {
      processId: typeof record.processId === "number" ? record.processId : readNumber(payload, "pid"),
      processImageName:
        typeof record.processImageName === "string" && record.processImageName.length > 0
          ? record.processImageName
          : readString(payload, "processImageName"),
      processImagePath:
        typeof record.processImagePath === "string" && record.processImagePath.length > 0
          ? record.processImagePath
          : readString(payload, "processImagePath"),
      processSessionId:
        typeof record.processSessionId === "string" && record.processSessionId.length > 0
          ? record.processSessionId
          : readString(payload, "sessionId"),
      processSigner:
        typeof record.processSigner === "string" && record.processSigner.length > 0
          ? record.processSigner
          : readString(payload, "signer"),
      moduleImageName:
        typeof record.moduleImageName === "string" && record.moduleImageName.length > 0
          ? record.moduleImageName
          : readString(payload, "imageName"),
      moduleImagePath:
        typeof record.moduleImagePath === "string" && record.moduleImagePath.length > 0
          ? record.moduleImagePath
          : readString(payload, "imagePath"),
      moduleImageBase:
        typeof record.moduleImageBase === "string" && record.moduleImageBase.length > 0
          ? record.moduleImageBase
          : readString(payload, "imageBase"),
      moduleImageSize:
        typeof record.moduleImageSize === "string" && record.moduleImageSize.length > 0
          ? record.moduleImageSize
          : readString(payload, "imageSize")
    };
  }

  return {};
}

function normalizeSoftwareUpdateState(value: unknown): SoftwareUpdateState {
  return value === "checking" || value === "available" || value === "current" || value === "error" ? value : "unknown";
}

function normalizeInstalledSoftware(raw: unknown): InstalledSoftwareSummary {
  const item = (raw ?? {}) as Partial<InstalledSoftwareSummary>;
  return {
    id: readOptionalString(item.id, randomUUID()),
    displayName: readOptionalString(item.displayName, "Unknown software"),
    displayVersion: readOptionalString(item.displayVersion, "unknown"),
    publisher: readOptionalString(item.publisher, "unknown"),
    installLocation: typeof item.installLocation === "string" && item.installLocation.length > 0 ? item.installLocation : undefined,
    uninstallCommand:
      typeof item.uninstallCommand === "string" && item.uninstallCommand.length > 0 ? item.uninstallCommand : undefined,
    quietUninstallCommand:
      typeof item.quietUninstallCommand === "string" && item.quietUninstallCommand.length > 0
        ? item.quietUninstallCommand
        : undefined,
    installDate: typeof item.installDate === "string" && item.installDate.length > 0 ? item.installDate : undefined,
    displayIconPath:
      typeof item.displayIconPath === "string" && item.displayIconPath.length > 0 ? item.displayIconPath : undefined,
    executableNames: readOptionalStringArray(item.executableNames),
    blocked: item.blocked === true,
    updateState: normalizeSoftwareUpdateState(item.updateState),
    lastUpdateCheckAt:
      typeof item.lastUpdateCheckAt === "string" && item.lastUpdateCheckAt.length > 0 ? item.lastUpdateCheckAt : undefined,
    updateSummary:
      typeof item.updateSummary === "string" && item.updateSummary.length > 0 ? item.updateSummary : undefined
  };
}

function sortInstalledSoftware(items: InstalledSoftwareSummary[]) {
  return [...items].sort((left, right) => {
    const nameDelta = left.displayName.localeCompare(right.displayName);
    if (nameDelta !== 0) {
      return nameDelta;
    }

    return left.publisher.localeCompare(right.publisher);
  });
}

function mergeInstalledSoftwareLists(
  existing: InstalledSoftwareSummary[],
  incoming: InstalledSoftwareSummary[]
) {
  const softwareById = new Map(existing.map((item) => [item.id, item]));

  for (const software of incoming) {
    softwareById.set(software.id, software);
  }

  return sortInstalledSoftware([...softwareById.values()]);
}

function normalizeDeviceSerialNumber(value: string) {
  const normalized = value.trim().toLowerCase();
  return normalized.length > 0 && normalized !== "unknown-serial" ? normalized : null;
}

function latestNullableIso(values: Array<string | null | undefined>) {
  let latest: string | null = null;

  for (const value of values) {
    if (!value) {
      continue;
    }

    if (latest === null || value > latest) {
      latest = value;
    }
  }

  return latest;
}

function mergeDeviceRecord(target: DeviceRecord, source: DeviceRecord) {
  const sourceIsNewer = source.lastSeenAt >= target.lastSeenAt;

  target.enrolledAt = source.enrolledAt < target.enrolledAt ? source.enrolledAt : target.enrolledAt;
  target.lastSeenAt = sourceIsNewer ? source.lastSeenAt : target.lastSeenAt;
  target.lastPolicySyncAt = latestNullableIso([target.lastPolicySyncAt, source.lastPolicySyncAt]);
  target.lastTelemetryAt = latestNullableIso([target.lastTelemetryAt, source.lastTelemetryAt]);

  if (sourceIsNewer) {
    target.hostname = source.hostname;
    target.osVersion = source.osVersion;
    target.agentVersion = source.agentVersion;
    target.platformVersion = source.platformVersion;
    target.healthState = source.healthState;
    target.isolated = source.isolated;
    target.policyId = source.policyId;
    target.policyName = source.policyName;
  }

  target.privateIpAddresses = mergeUniqueStrings([...target.privateIpAddresses, ...source.privateIpAddresses]);
  target.publicIpAddress = source.publicIpAddress ?? target.publicIpAddress;
  target.lastLoggedOnUser = source.lastLoggedOnUser ?? target.lastLoggedOnUser;
  target.installedSoftware = mergeInstalledSoftwareLists(target.installedSoftware, source.installedSoftware);
}

function reassignDeviceScopedRecords<T extends { deviceId?: string; hostname?: string }>(
  items: T[],
  deviceIdMap: Map<string, string>,
  hostnameByDeviceId: Map<string, string>
) {
  for (const item of items) {
    if (!item.deviceId) {
      continue;
    }

    const canonicalDeviceId = deviceIdMap.get(item.deviceId);
    if (!canonicalDeviceId) {
      continue;
    }

    item.deviceId = canonicalDeviceId;
    const canonicalHostname = hostnameByDeviceId.get(canonicalDeviceId);
    if (canonicalHostname) {
      item.hostname = canonicalHostname;
    }
  }
}

function dedupeDevicesBySerial(state: ControlPlaneState) {
  const canonicalBySerial = new Map<string, DeviceRecord>();
  const deviceIdMap = new Map<string, string>();
  const dedupedDevices: DeviceRecord[] = [];

  for (const device of state.devices) {
    const normalizedSerial = normalizeDeviceSerialNumber(device.serialNumber);
    if (!normalizedSerial) {
      dedupedDevices.push(device);
      continue;
    }

    const canonical = canonicalBySerial.get(normalizedSerial);
    if (!canonical) {
      canonicalBySerial.set(normalizedSerial, device);
      dedupedDevices.push(device);
      continue;
    }

    mergeDeviceRecord(canonical, device);
    deviceIdMap.set(device.id, canonical.id);
  }

  if (deviceIdMap.size === 0) {
    return;
  }

  state.devices = dedupedDevices;
  const hostnameByDeviceId = new Map(state.devices.map((item) => [item.id, item.hostname]));
  reassignDeviceScopedRecords(state.alerts, deviceIdMap, hostnameByDeviceId);
  reassignDeviceScopedRecords(state.telemetry, deviceIdMap, hostnameByDeviceId);
  reassignDeviceScopedRecords(state.commands, deviceIdMap, hostnameByDeviceId);
  reassignDeviceScopedRecords(state.quarantineItems, deviceIdMap, hostnameByDeviceId);
  reassignDeviceScopedRecords(state.evidence, deviceIdMap, hostnameByDeviceId);
  reassignDeviceScopedRecords(state.scanHistory, deviceIdMap, hostnameByDeviceId);
  reassignDeviceScopedRecords(state.devicePosture, deviceIdMap, hostnameByDeviceId);
  reassignDeviceScopedRecords(state.deviceRiskTelemetry, deviceIdMap, hostnameByDeviceId);
  reassignDeviceScopedRecords(state.deviceScoreHistory, deviceIdMap, hostnameByDeviceId);
  reassignDeviceScopedRecords(state.privilegeBaselines, deviceIdMap, hostnameByDeviceId);
  reassignDeviceScopedRecords(state.privilegeEvents, deviceIdMap, hostnameByDeviceId);
  reassignDeviceScopedRecords(state.privilegeStates, deviceIdMap, hostnameByDeviceId);
}

function isLoopbackAddress(value: string) {
  const normalized = value.toLowerCase();
  return (
    normalized === "127.0.0.1" ||
    normalized === "::1" ||
    normalized === "localhost" ||
    normalized.startsWith("127.") ||
    normalized === "::ffff:127.0.0.1"
  );
}

function isPrivateAddress(value: string) {
  const normalized = value.toLowerCase();
  if (normalized.startsWith("10.") || normalized.startsWith("192.168.") || normalized.startsWith("169.254.")) {
    return true;
  }

  if (normalized.startsWith("172.")) {
    const secondOctet = Number(normalized.split(".")[1]);
    return secondOctet >= 16 && secondOctet <= 31;
  }

  return normalized.startsWith("fc") || normalized.startsWith("fd") || normalized.startsWith("fe80:") || normalized === "::ffff";
}

function mergeUniqueStrings(values: string[]) {
  return [...new Set(values.filter((value) => value.length > 0 && !isLoopbackAddress(value)))];
}

function applyObservedRemoteAddress(device: DeviceRecord, observedRemoteAddress?: string) {
  if (!observedRemoteAddress || isLoopbackAddress(observedRemoteAddress)) {
    return;
  }

  if (isPrivateAddress(observedRemoteAddress)) {
    device.privateIpAddresses = mergeUniqueStrings([...device.privateIpAddresses, observedRemoteAddress]);
    return;
  }

  device.publicIpAddress = observedRemoteAddress;
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
    const rightScore = right.riskScore ?? -1;
    const leftScore = left.riskScore ?? -1;
    if (rightScore !== leftScore) {
      return rightScore - leftScore;
    }

    const rightConfidence = right.confidenceScore ?? -1;
    const leftConfidence = left.confidenceScore ?? -1;
    if (rightConfidence !== leftConfidence) {
      return rightConfidence - leftConfidence;
    }

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

function sortDeviceScoreHistory(items: DeviceScoreSnapshot[]) {
  return sortByIsoDescending(items, (item) => item.calculatedAt);
}

function sortPrivilegeBaselines(items: PrivilegeBaselineSnapshot[]) {
  return sortByIsoDescending(items, (item) => item.capturedAt);
}

function sortPrivilegeEvents(items: PrivilegeEventSummary[]) {
  return sortByIsoDescending(items, (item) => item.recordedAt);
}

function sortPrivilegeStates(items: PrivilegeStateSnapshot[]) {
  return sortByIsoDescending(items, (item) => item.updatedAt);
}

function clampPrivilegeHardeningMode(value: unknown): PrivilegeHardeningMode {
  return value === "monitor_only" || value === "enforce" || value === "restricted" || value === "recovery"
    ? value
    : "monitor_only";
}

function sortPolicies(items: PolicyProfile[]) {
  return [...items].sort((left, right) => {
    if (left.isDefault !== right.isDefault) {
      return left.isDefault ? -1 : 1;
    }

    return left.name.localeCompare(right.name);
  });
}

function sortScripts(items: ScriptSummary[]) {
  return sortByIsoDescending(items, (item) => item.updatedAt);
}

function sortPolicyExclusionChangeRequests(items: PolicyExclusionChangeRequestSummary[]) {
  return sortByIsoDescending(items, (item) => item.requestedAt);
}

function normalizePolicyExclusionValue(listType: PolicyExclusionListType, value: string) {
  const trimmed = value.trim();
  if (!trimmed) {
    return "";
  }

  if (listType === "sha256") {
    return trimmed.toLowerCase();
  }

  return trimmed;
}

function normalizePolicyExclusionEntry(raw: unknown): PolicyExclusionChangeEntry | null {
  const entry = (raw ?? {}) as Partial<PolicyExclusionChangeEntry>;
  const listType =
    entry.listType === "path_root" || entry.listType === "sha256" || entry.listType === "signer_name"
      ? entry.listType
      : null;
  const operation = entry.operation === "add" || entry.operation === "remove" ? entry.operation : null;
  const value = typeof entry.value === "string" && listType ? normalizePolicyExclusionValue(listType, entry.value) : "";
  if (!listType || !operation || !value) {
    return null;
  }

  return { listType, operation, value };
}

function normalizePolicyExclusionEntries(rawEntries: unknown) {
  const normalized: PolicyExclusionChangeEntry[] = [];
  const seen = new Set<string>();

  for (const rawEntry of Array.isArray(rawEntries) ? rawEntries : []) {
    const entry = normalizePolicyExclusionEntry(rawEntry);
    if (!entry) {
      continue;
    }

    const dedupeKey = `${entry.listType}|${entry.operation}|${entry.value.toLowerCase()}`;
    if (seen.has(dedupeKey)) {
      continue;
    }

    seen.add(dedupeKey);
    normalized.push(entry);
  }

  return normalized;
}

function normalizePolicyExclusionChangeRequestSummary(raw: unknown, nowIso: string): PolicyExclusionChangeRequestSummary {
  const request = (raw ?? {}) as Partial<PolicyExclusionChangeRequestSummary>;
  const status: PolicyExclusionRequestStatus =
    request.status === "approved" || request.status === "rejected" ? request.status : "pending";
  return {
    id: readOptionalString(request.id, randomUUID()),
    policyId: readOptionalString(request.policyId),
    policyName: readOptionalString(request.policyName, "Unknown policy"),
    status,
    reason: readOptionalString(request.reason, "No reason provided."),
    entries: normalizePolicyExclusionEntries(request.entries),
    requestedAt: readOptionalString(request.requestedAt, nowIso),
    requestedBy: readOptionalString(request.requestedBy, "Unknown operator"),
    requestedById: typeof request.requestedById === "string" ? request.requestedById : undefined,
    reviewedAt: typeof request.reviewedAt === "string" ? request.reviewedAt : undefined,
    reviewedBy: typeof request.reviewedBy === "string" ? request.reviewedBy : undefined,
    reviewedById: typeof request.reviewedById === "string" ? request.reviewedById : undefined,
    reviewComment: typeof request.reviewComment === "string" ? request.reviewComment : undefined
  };
}

function normalizeAdminRoles(rawRoles: unknown) {
  if (!Array.isArray(rawRoles)) {
    return ["admin"] as AdminPrincipalRecord["roles"];
  }

  const roles = rawRoles.filter(
    (role): role is AdminPrincipalRecord["roles"][number] =>
      role === "admin" || role === "analyst" || role === "operator" || role === "read_only" || role === "automation"
  );

  return roles.length > 0 ? [...new Set(roles)] : (["admin"] as AdminPrincipalRecord["roles"]);
}

function normalizeAdminPrincipalRecord(raw: unknown, nowIso: string): AdminPrincipalRecord {
  const principal = (raw ?? {}) as Partial<AdminPrincipalRecord>;
  const passwordSalt = readOptionalString(principal.passwordSalt, randomUUID().replace(/-/g, ""));
  const passwordHash = readOptionalString(principal.passwordHash, hashPassword(DEFAULT_ADMIN_PASSWORD, passwordSalt));

  return {
    id: readOptionalString(principal.id, randomUUID()),
    username: readOptionalString(principal.username, "admin@fenrir.local"),
    displayName: readOptionalString(principal.displayName, "Fenrir Platform Admin"),
    passwordSalt,
    passwordHash,
    mfaSecret: readOptionalString(principal.mfaSecret, DEFAULT_ADMIN_MFA_SECRET),
    roles: normalizeAdminRoles(principal.roles),
    enabled: principal.enabled !== false,
    createdAt: readOptionalString(principal.createdAt, nowIso),
    updatedAt: readOptionalString(principal.updatedAt, nowIso),
    lastLoginAt: typeof principal.lastLoginAt === "string" ? principal.lastLoginAt : undefined
  };
}

function normalizeAdminSessionRecord(raw: unknown, nowIso: string): AdminSessionRecord {
  const session = (raw ?? {}) as Partial<AdminSessionRecord>;
  return {
    id: readOptionalString(session.id, randomUUID()),
    principalId: readOptionalString(session.principalId),
    tokenHash: readOptionalString(session.tokenHash, randomUUID().replace(/-/g, "")),
    createdAt: readOptionalString(session.createdAt, nowIso),
    expiresAt: readOptionalString(session.expiresAt, nowIso),
    lastSeenAt: readOptionalString(session.lastSeenAt, nowIso),
    revokedAt: typeof session.revokedAt === "string" ? session.revokedAt : undefined,
    sourceIp: typeof session.sourceIp === "string" ? session.sourceIp : undefined,
    userAgent: typeof session.userAgent === "string" ? session.userAgent : undefined
  };
}

function normalizeAdminApiKeyRecord(raw: unknown, nowIso: string): AdminApiKeyRecord {
  const apiKey = (raw ?? {}) as Partial<AdminApiKeyRecord>;
  return {
    id: readOptionalString(apiKey.id, randomUUID()),
    principalId: readOptionalString(apiKey.principalId),
    name: readOptionalString(apiKey.name, "Unnamed API key"),
    scopes: readOptionalStringArray(apiKey.scopes),
    tokenHash: readOptionalString(apiKey.tokenHash, randomUUID().replace(/-/g, "")),
    createdAt: readOptionalString(apiKey.createdAt, nowIso),
    updatedAt: readOptionalString(apiKey.updatedAt, nowIso),
    revokedAt: typeof apiKey.revokedAt === "string" ? apiKey.revokedAt : undefined,
    lastUsedAt: typeof apiKey.lastUsedAt === "string" ? apiKey.lastUsedAt : undefined,
    sourceIp: typeof apiKey.sourceIp === "string" ? apiKey.sourceIp : undefined
  };
}

function normalizeAdminAuditEventSummary(raw: unknown, nowIso: string): AdminAuditEventSummary {
  const event = (raw ?? {}) as Partial<AdminAuditEventSummary>;
  const actorType =
    event.actorType === "user" || event.actorType === "api_key" || event.actorType === "session" || event.actorType === "system"
      ? event.actorType
      : "anonymous";

  return {
    id: readOptionalString(event.id, randomUUID()),
    occurredAt: readOptionalString(event.occurredAt, nowIso),
    actorId: typeof event.actorId === "string" ? event.actorId : undefined,
    actorName: readOptionalString(event.actorName, "system"),
    actorType,
    action: readOptionalString(event.action, "admin.activity"),
    resourceType: typeof event.resourceType === "string" ? event.resourceType : undefined,
    resourceId: typeof event.resourceId === "string" ? event.resourceId : undefined,
    outcome: event.outcome === "failure" ? "failure" : "success",
    severity:
      event.severity === "low" || event.severity === "medium" || event.severity === "critical" ? event.severity : "medium",
    details: readOptionalString(event.details, "Administrative event recorded."),
    source: readOptionalString(event.source, "control-plane"),
    sessionId: typeof event.sessionId === "string" ? event.sessionId : undefined,
    ipAddress: typeof event.ipAddress === "string" ? event.ipAddress : undefined
  };
}

function sortAdminPrincipals(items: AdminPrincipalRecord[]) {
  return [...items].sort((left, right) => left.username.localeCompare(right.username));
}

function sortAdminSessions(items: AdminSessionRecord[]) {
  return sortByIsoDescending(items, (item) => item.lastSeenAt);
}

function sortAdminApiKeys(items: AdminApiKeyRecord[]) {
  return sortByIsoDescending(items, (item) => item.updatedAt);
}

function sortAdminAuditEvents(items: AdminAuditEventSummary[]) {
  return sortByIsoDescending(items, (item) => item.occurredAt);
}

function findAdminPrincipalById(state: ControlPlaneState, principalId: string) {
  return state.adminPrincipals.find((item) => item.id === principalId) ?? null;
}

function findAdminPrincipalByUsername(state: ControlPlaneState, username: string) {
  return state.adminPrincipals.find((item) => item.username.toLowerCase() === username.toLowerCase()) ?? null;
}

function findAdminSessionByTokenHash(state: ControlPlaneState, tokenHash: string) {
  return state.adminSessions.find((item) => item.tokenHash === tokenHash) ?? null;
}

function findAdminApiKeyByTokenHash(state: ControlPlaneState, tokenHash: string) {
  return state.adminApiKeys.find((item) => item.tokenHash === tokenHash) ?? null;
}

function recordAdminAuditEvent(state: ControlPlaneState, event: Omit<AdminAuditEventSummary, "id"> & { id?: string }) {
  state.adminAuditEvents.push({
    id: event.id ?? randomUUID(),
    occurredAt: event.occurredAt,
    actorId: event.actorId,
    actorName: event.actorName,
    actorType: event.actorType,
    action: event.action,
    resourceType: event.resourceType,
    resourceId: event.resourceId,
    outcome: event.outcome,
    severity: event.severity,
    details: event.details,
    source: event.source,
    sessionId: event.sessionId,
    ipAddress: event.ipAddress
  });
}

function toPolicySummary(policy: PolicyProfile): PolicySummary {
  return {
    id: policy.id,
    name: policy.name,
    revision: policy.revision,
    realtimeProtection: policy.realtimeProtection,
    cloudLookup: policy.cloudLookup,
    scriptInspection: policy.scriptInspection,
    networkContainment: policy.networkContainment,
    quarantineOnMalicious: policy.quarantineOnMalicious,
    dnsGuardEnabled: policy.dnsGuardEnabled,
    trafficTelemetryEnabled: policy.trafficTelemetryEnabled,
    integrityWatchEnabled: policy.integrityWatchEnabled,
    privilegeHardeningEnabled: policy.privilegeHardeningEnabled,
    pamLiteEnabled: policy.pamLiteEnabled,
    denyHighRiskElevation: policy.denyHighRiskElevation,
    denyUnsignedElevation: policy.denyUnsignedElevation,
    requireBreakGlassEscrow: policy.requireBreakGlassEscrow,
    suppressionPathRoots: policy.suppressionPathRoots,
    suppressionSha256: policy.suppressionSha256,
    suppressionSignerNames: policy.suppressionSignerNames
  };
}

function normalizePolicyProfile(raw: unknown, fallback: PolicySummary, nowIso: string): PolicyProfile {
  const policy = (raw ?? {}) as Partial<PolicyProfile>;
  return {
    id: readOptionalString(policy.id, fallback.id),
    name: readOptionalString(policy.name, fallback.name),
    revision: readOptionalString(policy.revision, fallback.revision),
    realtimeProtection: typeof policy.realtimeProtection === "boolean" ? policy.realtimeProtection : fallback.realtimeProtection,
    cloudLookup: typeof policy.cloudLookup === "boolean" ? policy.cloudLookup : fallback.cloudLookup,
    scriptInspection: typeof policy.scriptInspection === "boolean" ? policy.scriptInspection : fallback.scriptInspection,
    networkContainment:
      typeof policy.networkContainment === "boolean" ? policy.networkContainment : fallback.networkContainment,
    quarantineOnMalicious:
      typeof policy.quarantineOnMalicious === "boolean" ? policy.quarantineOnMalicious : fallback.quarantineOnMalicious,
    dnsGuardEnabled: typeof policy.dnsGuardEnabled === "boolean" ? policy.dnsGuardEnabled : fallback.dnsGuardEnabled,
    trafficTelemetryEnabled:
      typeof policy.trafficTelemetryEnabled === "boolean" ? policy.trafficTelemetryEnabled : fallback.trafficTelemetryEnabled,
    integrityWatchEnabled:
      typeof policy.integrityWatchEnabled === "boolean" ? policy.integrityWatchEnabled : fallback.integrityWatchEnabled,
    privilegeHardeningEnabled:
      typeof policy.privilegeHardeningEnabled === "boolean"
        ? policy.privilegeHardeningEnabled
        : fallback.privilegeHardeningEnabled,
    pamLiteEnabled: typeof policy.pamLiteEnabled === "boolean" ? policy.pamLiteEnabled : fallback.pamLiteEnabled,
    denyHighRiskElevation:
      typeof policy.denyHighRiskElevation === "boolean" ? policy.denyHighRiskElevation : fallback.denyHighRiskElevation,
    denyUnsignedElevation:
      typeof policy.denyUnsignedElevation === "boolean" ? policy.denyUnsignedElevation : fallback.denyUnsignedElevation,
    requireBreakGlassEscrow:
      typeof policy.requireBreakGlassEscrow === "boolean"
        ? policy.requireBreakGlassEscrow
        : fallback.requireBreakGlassEscrow,
    suppressionPathRoots:
      Array.isArray(policy.suppressionPathRoots)
        ? normalizePolicyStringArray(policy.suppressionPathRoots)
        : fallback.suppressionPathRoots,
    suppressionSha256:
      Array.isArray(policy.suppressionSha256)
        ? normalizePolicyStringArray(policy.suppressionSha256, (item) => item.toLowerCase())
        : fallback.suppressionSha256,
    suppressionSignerNames:
      Array.isArray(policy.suppressionSignerNames)
        ? normalizePolicyStringArray(policy.suppressionSignerNames)
        : fallback.suppressionSignerNames,
    description: readOptionalString(policy.description, `${fallback.name} protection profile`),
    isDefault: policy.isDefault === true,
    assignedDeviceIds: readOptionalStringArray(policy.assignedDeviceIds),
    createdAt: readOptionalString(policy.createdAt, nowIso),
    updatedAt: readOptionalString(policy.updatedAt, nowIso)
  };
}

function normalizeScript(raw: unknown, nowIso: string): ScriptSummary {
  const script = (raw ?? {}) as Partial<ScriptSummary>;
  return {
    id: readOptionalString(script.id, randomUUID()),
    name: readOptionalString(script.name, "Untitled script"),
    description: readOptionalString(script.description, "No description provided."),
    language: script.language === "cmd" ? "cmd" : "powershell",
    content: readOptionalString(script.content),
    createdAt: readOptionalString(script.createdAt, nowIso),
    updatedAt: readOptionalString(script.updatedAt, nowIso),
    lastExecutedAt: typeof script.lastExecutedAt === "string" ? script.lastExecutedAt : undefined
  };
}

function buildPolicyRevision(nowIso: string) {
  const stamp = nowIso.replace(/[-:TZ]/g, "").replace(/\..+$/, "");
  return `${stamp.slice(0, 4)}.${stamp.slice(4, 6)}.${stamp.slice(6, 8)}.${stamp.slice(8)}`;
}

function normalizePrivilegeAccountSummary(raw: unknown, defaultName = "Unknown account"): PrivilegeBaselineSnapshot["localUsers"][number] {
  const account = (raw ?? {}) as Partial<PrivilegeBaselineSnapshot["localUsers"][number]>;
  return {
    name: readOptionalString(account.name, defaultName),
    source: account.source === "domain" || account.source === "service" ? account.source : "local",
    enabled: account.enabled !== false,
    authorized: account.authorized !== false
  };
}

function normalizePrivilegeBaselineSnapshot(
  raw: unknown,
  hostnameByDeviceId: Map<string, string>,
  nowIso: string
): PrivilegeBaselineSnapshot {
  const baseline = (raw ?? {}) as Partial<PrivilegeBaselineSnapshot>;
  const deviceId = readOptionalString(baseline.deviceId);

  return {
    deviceId,
    hostname: readOptionalString(baseline.hostname, hostnameByDeviceId.get(deviceId) ?? "UNKNOWN-HOST"),
    capturedAt: readOptionalString(baseline.capturedAt, nowIso),
    localUsers: Array.isArray(baseline.localUsers)
      ? baseline.localUsers.map((item) => normalizePrivilegeAccountSummary(item))
      : [],
    localAdministrators: Array.isArray(baseline.localAdministrators)
      ? baseline.localAdministrators.map((item) => normalizePrivilegeAccountSummary(item))
      : [],
    domainLinkedAdminMemberships: Array.isArray(baseline.domainLinkedAdminMemberships)
      ? baseline.domainLinkedAdminMemberships.filter(
          (item): item is PrivilegeBaselineSnapshot["domainLinkedAdminMemberships"][number] =>
            Boolean(item) && typeof item === "object" && !Array.isArray(item)
        ).map((item) => ({
          name: readOptionalString(item.name, "Unknown membership"),
          group: readOptionalString(item.group, "Local Administrators"),
          source: item.source === "domain" ? "domain" : "local"
        }))
      : [],
    breakGlassAccountName: readOptionalString(baseline.breakGlassAccountName, "Fenrir-BreakGlass"),
    breakGlassAccountEnabled: baseline.breakGlassAccountEnabled !== false,
    recoveryCredentialEscrowed: baseline.recoveryCredentialEscrowed !== false,
    recoveryCredentialLastRotatedAt:
      typeof baseline.recoveryCredentialLastRotatedAt === "string" ? baseline.recoveryCredentialLastRotatedAt : undefined
  };
}

function normalizePrivilegeEventSummary(
  raw: unknown,
  hostnameByDeviceId: Map<string, string>,
  nowIso: string
): PrivilegeEventSummary {
  const event = (raw ?? {}) as Partial<PrivilegeEventSummary>;
  const deviceId = readOptionalString(event.deviceId);
  const kind =
    event.kind === "baseline.captured" ||
    event.kind === "admin.added" ||
    event.kind === "admin.removed" ||
    event.kind === "admin.reenabled" ||
    event.kind === "elevation.requested" ||
    event.kind === "elevation.approved" ||
    event.kind === "elevation.denied" ||
    event.kind === "breakglass.used" ||
    event.kind === "hardening.applied" ||
    event.kind === "recovery.applied" ||
    event.kind === "hardening.tamper"
      ? event.kind
      : "baseline.captured";

  return {
    id: readOptionalString(event.id, randomUUID()),
    deviceId,
    hostname: readOptionalString(event.hostname, hostnameByDeviceId.get(deviceId) ?? "UNKNOWN-HOST"),
    recordedAt: readOptionalString(event.recordedAt, nowIso),
    kind,
    subject: typeof event.subject === "string" ? event.subject : undefined,
    actor: typeof event.actor === "string" ? event.actor : undefined,
    severity:
      event.severity === "low" || event.severity === "medium" || event.severity === "critical" ? event.severity : "high",
    source: readOptionalString(event.source, "console"),
    summary: readOptionalString(event.summary, "Privilege event recorded.")
  };
}

function normalizePrivilegeStateSnapshot(
  raw: unknown,
  hostnameByDeviceId: Map<string, string>,
  nowIso: string
): PrivilegeStateSnapshot {
  const state = (raw ?? {}) as Partial<PrivilegeStateSnapshot>;
  const deviceId = readOptionalString(state.deviceId);

  return {
    deviceId,
    hostname: readOptionalString(state.hostname, hostnameByDeviceId.get(deviceId) ?? "UNKNOWN-HOST"),
    updatedAt: readOptionalString(state.updatedAt, nowIso),
    privilegeHardeningMode: clampPrivilegeHardeningMode(state.privilegeHardeningMode),
    pamEnforcementEnabled: state.pamEnforcementEnabled === true,
    standingAdminPresentFlag: state.standingAdminPresentFlag === true,
    unapprovedAdminAccountCount:
      typeof state.unapprovedAdminAccountCount === "number" ? state.unapprovedAdminAccountCount : 0,
    adminGroupTamperIndicator: state.adminGroupTamperIndicator === true,
    directAdminLogonAttemptCount_7d:
      typeof state.directAdminLogonAttemptCount_7d === "number" ? state.directAdminLogonAttemptCount_7d : 0,
    breakGlassAccountUsageIndicator: state.breakGlassAccountUsageIndicator === true,
    unauthorisedAdminReenableIndicator: state.unauthorisedAdminReenableIndicator === true,
    recoveryPathExists: state.recoveryPathExists !== false,
    lastEnforcedAt: typeof state.lastEnforcedAt === "string" ? state.lastEnforcedAt : undefined,
    lastRecoveredAt: typeof state.lastRecoveredAt === "string" ? state.lastRecoveredAt : undefined,
    lastBreakGlassUsedAt: typeof state.lastBreakGlassUsedAt === "string" ? state.lastBreakGlassUsedAt : undefined,
    summary: readOptionalString(state.summary, "Privilege posture not yet assessed."),
    recommendedActions: readOptionalStringArray(state.recommendedActions)
  };
}

function createDefaultPrivilegeBaseline(device: DeviceRecord, nowIso: string): PrivilegeBaselineSnapshot {
  const lastLoggedOnUser = device.lastLoggedOnUser ?? `${device.hostname.toLowerCase()}\\local-user`;
  const breakGlassAccountName = `${device.hostname.toLowerCase()}-breakglass`;
  const localAdministrators = [
    {
      name: device.policyName.toLowerCase().includes("containment") ? "CORP\\Privileged Access" : "CORP\\IT Admins",
      source: "domain" as const,
      enabled: true,
      authorized: true
    },
    {
      name: breakGlassAccountName,
      source: "local" as const,
      enabled: true,
      authorized: true
    }
  ];

  return {
    deviceId: device.id,
    hostname: device.hostname,
    capturedAt: nowIso,
    localUsers: [
      {
        name: lastLoggedOnUser,
        source: lastLoggedOnUser.includes("\\") ? "domain" : "local",
        enabled: true,
        authorized: true
      },
      {
        name: breakGlassAccountName,
        source: "local",
        enabled: true,
        authorized: true
      }
    ],
    localAdministrators,
    domainLinkedAdminMemberships: lastLoggedOnUser.includes("\\")
      ? [
          {
            name: lastLoggedOnUser,
            group: "Local Administrators",
            source: "domain" as const
          }
        ]
      : [],
    breakGlassAccountName,
    breakGlassAccountEnabled: true,
    recoveryCredentialEscrowed: true,
    recoveryCredentialLastRotatedAt: nowIso
  };
}

function buildPrivilegeStateSummary(
  privilegeState: PrivilegeStateSnapshot,
  privilegeTelemetry: DeviceRiskTelemetrySnapshot | null,
  policy: PolicyProfile | undefined
) {
  const parts: string[] = [];

  if (privilegeState.privilegeHardeningMode === "monitor_only") {
    parts.push("PAM-lite monitoring only");
  } else if (privilegeState.privilegeHardeningMode === "restricted") {
    parts.push("Privileged access is restricted");
  } else if (privilegeState.privilegeHardeningMode === "recovery") {
    parts.push("Administrative recovery is in progress");
  } else {
    parts.push("Privileged access enforcement is active");
  }

  if (privilegeState.standingAdminPresentFlag) {
    parts.push(
      privilegeState.unapprovedAdminAccountCount > 0
        ? `${privilegeState.unapprovedAdminAccountCount} unapproved admin account(s) visible`
        : "Standing admin access remains present"
    );
  }

  if (privilegeState.adminGroupTamperIndicator) {
    parts.push("Administrator group tampering detected");
  }

  if (privilegeState.breakGlassAccountUsageIndicator) {
    parts.push("Break-glass access was used recently");
  }

  if (!privilegeState.recoveryPathExists || policy?.requireBreakGlassEscrow === true) {
    parts.push("A recoverable administrative path must remain escrowed");
  }

  return parts.join(". ") || "Privilege posture is being monitored.";
}

function buildPrivilegeRecommendations(
  privilegeState: PrivilegeStateSnapshot,
  policy: PolicyProfile | undefined
) {
  const recommendations = new Set<string>();

  if (privilegeState.standingAdminPresentFlag) {
    recommendations.add("Replace standing local admin access with just-in-time elevation.");
  }

  if (privilegeState.unapprovedAdminAccountCount > 0) {
    recommendations.add(`Review ${privilegeState.unapprovedAdminAccountCount} unapproved administrator account(s).`);
  }

  if (privilegeState.adminGroupTamperIndicator) {
    recommendations.add("Investigate local administrator group tampering.");
  }

  if (privilegeState.directAdminLogonAttemptCount_7d > 0) {
    recommendations.add("Review recent direct administrator logons and elevation requests.");
  }

  if (privilegeState.breakGlassAccountUsageIndicator) {
    recommendations.add("Rotate break-glass credentials after emergency use.");
  }

  if (!privilegeState.recoveryPathExists || policy?.requireBreakGlassEscrow === true) {
    recommendations.add("Verify break-glass escrow before enforcing additional hardening.");
  }

  if (!privilegeState.pamEnforcementEnabled && policy?.privilegeHardeningEnabled) {
    recommendations.add("Enable PAM-lite enforcement on this endpoint.");
  }

  return [...recommendations];
}

function findPrivilegeBaseline(state: ControlPlaneState, deviceId: string) {
  return state.privilegeBaselines.find((item) => item.deviceId === deviceId) ?? null;
}

function findPrivilegeState(state: ControlPlaneState, deviceId: string) {
  return state.privilegeStates.find((item) => item.deviceId === deviceId) ?? null;
}

function upsertPrivilegeBaseline(state: ControlPlaneState, device: DeviceRecord, nowIso: string) {
  const existing = findPrivilegeBaseline(state, device.id);
  if (existing) {
    existing.hostname = device.hostname;
    return existing;
  }

  const baseline = createDefaultPrivilegeBaseline(device, nowIso);
  state.privilegeBaselines.push(baseline);
  state.privilegeEvents.push({
    id: randomUUID(),
    deviceId: device.id,
    hostname: device.hostname,
    recordedAt: nowIso,
    kind: "baseline.captured",
    actor: "system",
    severity: "medium",
    source: "control-plane",
    summary: "Privilege baseline captured for this device."
  });
  return baseline;
}

function recalculatePrivilegeStateSnapshot(state: ControlPlaneState, device: DeviceRecord, nowIso: string) {
  const baseline = upsertPrivilegeBaseline(state, device, nowIso);
  const policy = state.policies.find((item) => item.id === device.policyId);
  const storedTelemetry = findDeviceRiskTelemetry(state, device.id);
  const recentTelemetry = state.telemetry.filter(
    (item) => item.deviceId === device.id && occurredWithinDays(item.occurredAt, nowIso, 7)
  );
  const recentPrivilegeEvents = state.privilegeEvents.filter(
    (item) => item.deviceId === device.id && occurredWithinDays(item.recordedAt, nowIso, 30)
  );
  const privilegeState = findPrivilegeState(state, device.id) ?? {
    deviceId: device.id,
    hostname: device.hostname,
    updatedAt: nowIso,
    privilegeHardeningMode: "monitor_only",
    pamEnforcementEnabled: false,
    standingAdminPresentFlag: false,
    unapprovedAdminAccountCount: 0,
    adminGroupTamperIndicator: false,
    directAdminLogonAttemptCount_7d: 0,
    breakGlassAccountUsageIndicator: false,
    unauthorisedAdminReenableIndicator: false,
    recoveryPathExists: true,
    summary: "Privilege posture not yet assessed.",
    recommendedActions: []
  };

  const standingAdminPresentFlag =
    storedTelemetry?.standing_admin_present_flag ?? baseline.localAdministrators.some((item) => item.enabled && item.authorized);
  const unapprovedAdminAccountCount =
    storedTelemetry?.unapproved_admin_account_count ?? baseline.localAdministrators.filter((item) => !item.authorized).length;
  const adminGroupTamperIndicator =
    storedTelemetry?.admin_group_tamper_indicator ??
    recentTelemetry.some(
      (item) =>
        item.eventType.includes("privilege.admin") ||
        includesKeyword(item.summary, ["administrator group", "admin group tamper", "local administrators changed"])
    );
  const directAdminLogonAttemptCount_7d =
    storedTelemetry?.direct_admin_logon_attempt_count_7d ??
    recentTelemetry.filter((item) => includesKeyword(item.summary, ["admin logon", "privileged logon", "elevated logon"])).length;
  const breakGlassAccountUsageIndicator =
    (storedTelemetry?.break_glass_account_usage_indicator ??
      recentPrivilegeEvents.some((item) => item.kind === "breakglass.used")) ||
    recentTelemetry.some((item) => includesKeyword(item.summary, ["break glass", "emergency admin", "recovery account"]));
  const unauthorisedAdminReenableIndicator =
    (storedTelemetry?.unauthorised_admin_reenable_indicator ??
      recentPrivilegeEvents.some((item) => item.kind === "admin.reenabled")) ||
    recentTelemetry.some((item) => includesKeyword(item.summary, ["unauthorised admin reenable", "unapproved admin re-enable"]));
  const recoveryPathExists =
    storedTelemetry?.recovery_path_exists ??
    (baseline.breakGlassAccountEnabled && baseline.recoveryCredentialEscrowed && policy?.requireBreakGlassEscrow !== false);
  const privilegeHardeningMode = clampPrivilegeHardeningMode(
    storedTelemetry?.privilege_hardening_mode ??
      (policy?.privilegeHardeningEnabled ? (policy.pamLiteEnabled ? "restricted" : "enforce") : "monitor_only")
  );
  const pamEnforcementEnabled =
    storedTelemetry?.pam_enforcement_enabled ?? policy?.privilegeHardeningEnabled ?? false;

  privilegeState.hostname = device.hostname;
  privilegeState.updatedAt = nowIso;
  privilegeState.privilegeHardeningMode = privilegeHardeningMode;
  privilegeState.pamEnforcementEnabled = pamEnforcementEnabled;
  privilegeState.standingAdminPresentFlag = standingAdminPresentFlag;
  privilegeState.unapprovedAdminAccountCount = unapprovedAdminAccountCount;
  privilegeState.adminGroupTamperIndicator = adminGroupTamperIndicator;
  privilegeState.directAdminLogonAttemptCount_7d = directAdminLogonAttemptCount_7d;
  privilegeState.breakGlassAccountUsageIndicator = breakGlassAccountUsageIndicator;
  privilegeState.unauthorisedAdminReenableIndicator = unauthorisedAdminReenableIndicator;
  privilegeState.recoveryPathExists = recoveryPathExists;
  privilegeState.lastEnforcedAt = latestPrivilegeEvent(state, device.id, ["hardening.applied"])?.recordedAt;
  privilegeState.lastRecoveredAt = latestPrivilegeEvent(state, device.id, ["recovery.applied"])?.recordedAt;
  privilegeState.lastBreakGlassUsedAt = latestPrivilegeEvent(state, device.id, ["breakglass.used"])?.recordedAt;
  privilegeState.summary = buildPrivilegeStateSummary(privilegeState, storedTelemetry, policy);
  privilegeState.recommendedActions = buildPrivilegeRecommendations(privilegeState, policy);

  const existing = findPrivilegeState(state, device.id);
  if (existing) {
    Object.assign(existing, privilegeState);
    return existing;
  }

  state.privilegeStates.push(privilegeState);
  return privilegeState;
}

function latestPrivilegeEvent(state: ControlPlaneState, deviceId: string, kinds: PrivilegeEventSummary["kind"][]) {
  return sortPrivilegeEvents(
    state.privilegeEvents.filter((item) => item.deviceId === deviceId && kinds.includes(item.kind))
  )[0];
}

function ensurePrivilegeRiskTelemetry(state: ControlPlaneState, device: DeviceRecord, nowIso: string) {
  const existing = findDeviceRiskTelemetry(state, device.id);
  if (existing) {
    return existing;
  }

  const snapshot: DeviceRiskTelemetrySnapshot = {
    deviceId: device.id,
    hostname: device.hostname,
    updatedAt: nowIso,
    source: "control-plane"
  };
  state.deviceRiskTelemetry.push(snapshot);
  return snapshot;
}

function applyPrivilegeHardeningAction(
  state: ControlPlaneState,
  device: DeviceRecord,
  nowIso: string,
  action: {
    type: "privilege.enforce" | "privilege.recover";
    kind: PrivilegeEventSummary["kind"];
    issuedBy?: string;
    reason?: string;
    mode: PrivilegeHardeningMode;
    summary: string;
    pamEnforcementEnabled: boolean;
  },
  actor?: AdminActorContext
) {
  const telemetry = ensurePrivilegeRiskTelemetry(state, device, nowIso);
  telemetry.privilege_hardening_mode = action.mode;
  telemetry.pam_enforcement_enabled = action.pamEnforcementEnabled;
  telemetry.recovery_path_exists = true;
  telemetry.standing_admin_present_flag = telemetry.standing_admin_present_flag ?? true;
  telemetry.updatedAt = nowIso;
  telemetry.source = telemetry.source || "control-plane";

  state.privilegeEvents.push({
    id: randomUUID(),
    deviceId: device.id,
    hostname: device.hostname,
    recordedAt: nowIso,
    kind: action.kind,
    actor: action.issuedBy ?? "console",
    severity: "high",
    source: "control-plane",
    summary: action.summary,
    subject: device.hostname
  });

  const privilegeState = recalculatePrivilegeStateSnapshot(state, device, nowIso);
  privilegeState.privilegeHardeningMode = action.mode;
  privilegeState.pamEnforcementEnabled = action.pamEnforcementEnabled;
  privilegeState.recoveryPathExists = true;
  privilegeState.summary = action.summary;
  privilegeState.recommendedActions = buildPrivilegeRecommendations(privilegeState, state.policies.find((item) => item.id === device.policyId));
  privilegeState.updatedAt = nowIso;

  const command: DeviceCommandSummary = {
    id: randomUUID(),
    deviceId: device.id,
    hostname: device.hostname,
    type: action.type,
    status: "completed",
    createdAt: nowIso,
    updatedAt: nowIso,
    issuedBy: action.issuedBy ?? "console",
    payloadJson: JSON.stringify({ reason: action.reason, mode: action.mode }),
    resultJson: JSON.stringify({ summary: action.summary, mode: action.mode })
  };
  state.commands.push(command);

  if (actor) {
    const principal = findAdminPrincipalById(state, actor.actorId);
    if (principal && principal.enabled) {
      recordAdminAuditEvent(state, {
        occurredAt: nowIso,
        actorId: principal.id,
        actorName: principal.displayName,
        actorType: actor.actorType,
        action: action.type,
        resourceType: "device",
        resourceId: device.id,
        outcome: "success",
        severity: "high",
        details: action.summary,
        source: "control-plane",
        sessionId: actor.sessionId
      });
    }
  }

  recalculateDeviceScoreSnapshot(state, device, nowIso);
  return privilegeState;
}

function normalizeDeviceRecord(
  raw: unknown,
  defaultPolicyId: string,
  defaultPolicyName: string,
  nowIso: string,
  policies: PolicyProfile[]
): DeviceRecord {
  const record = (raw ?? {}) as Partial<DeviceRecord>;
  const recordedPolicyName = readOptionalString(record.policyName, defaultPolicyName);
  const matchedPolicy =
    (typeof record.policyId === "string" ? policies.find((item) => item.id === record.policyId) : undefined) ??
    policies.find((item) => item.name === recordedPolicyName);

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
    policyId: matchedPolicy?.id ?? readOptionalString(record.policyId, defaultPolicyId),
    policyName: matchedPolicy?.name ?? recordedPolicyName,
    privateIpAddresses: mergeUniqueStrings(readOptionalStringArray(record.privateIpAddresses)),
    publicIpAddress: readOptionalNullableString(record.publicIpAddress),
    lastLoggedOnUser: readOptionalNullableString(record.lastLoggedOnUser),
    installedSoftware: sortInstalledSoftware(
      Array.isArray(record.installedSoftware) ? record.installedSoftware.map((item) => normalizeInstalledSoftware(item)) : []
    )
  };
}

function normalizeTelemetryRecord(raw: unknown, hostnameByDeviceId: Map<string, string>, nowIso: string): TelemetryRecord {
  const record = (raw ?? {}) as Partial<TelemetryRecord>;
  const payload = parsePayload(readOptionalString(record.payloadJson, "{}"));
  return {
    eventId: readOptionalString(record.eventId, randomUUID()),
    deviceId: readOptionalString(record.deviceId),
    hostname: readOptionalString(record.hostname, hostnameByDeviceId.get(readOptionalString(record.deviceId)) ?? "UNKNOWN-HOST"),
    eventType: readOptionalString(record.eventType, "unknown"),
    source: readOptionalString(record.source, "unknown"),
    summary: readOptionalString(record.summary),
    occurredAt: readOptionalString(record.occurredAt, nowIso),
    ingestedAt: readOptionalString(record.ingestedAt, nowIso),
    payloadJson: readOptionalString(record.payloadJson, "{}"),
    ...normalizeTelemetryProcessContext(record, payload)
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
    tacticId: typeof alert.tacticId === "string" ? alert.tacticId : undefined,
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
    payloadJson: typeof command.payloadJson === "string" ? command.payloadJson : undefined,
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
    appName: typeof item.appName === "string" ? item.appName : undefined,
    contentName: typeof item.contentName === "string" ? item.contentName : undefined,
    sourceType: typeof item.sourceType === "string" ? item.sourceType : undefined,
    sessionId: typeof item.sessionId === "number" ? item.sessionId : undefined,
    preview: typeof item.preview === "string" ? item.preview : undefined,
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
    appName: typeof item.appName === "string" ? item.appName : undefined,
    contentName: typeof item.contentName === "string" ? item.contentName : undefined,
    sourceType: typeof item.sourceType === "string" ? item.sourceType : undefined,
    sessionId: typeof item.sessionId === "number" ? item.sessionId : undefined,
    preview: typeof item.preview === "string" ? item.preview : undefined,
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

function clampRiskBand(value: unknown): DeviceScoreSnapshot["riskBand"] {
  return value === "low" || value === "guarded" || value === "elevated" || value === "high" ? value : "critical";
}

function normalizeRiskTelemetrySnapshot(
  raw: unknown,
  hostnameByDeviceId: Map<string, string>,
  nowIso: string
): DeviceRiskTelemetrySnapshot {
  const snapshot = (raw ?? {}) as Partial<DeviceRiskTelemetrySnapshot>;
  const deviceId = readOptionalString(snapshot.deviceId);
  return {
    deviceId,
    hostname: readOptionalString(snapshot.hostname, hostnameByDeviceId.get(deviceId) ?? "UNKNOWN-HOST"),
    updatedAt: readOptionalString(snapshot.updatedAt, nowIso),
    source: readOptionalString(snapshot.source, "manual"),
    os_patch_age_days: typeof snapshot.os_patch_age_days === "number" ? snapshot.os_patch_age_days : undefined,
    critical_patches_overdue_count:
      typeof snapshot.critical_patches_overdue_count === "number" ? snapshot.critical_patches_overdue_count : undefined,
    high_patches_overdue_count:
      typeof snapshot.high_patches_overdue_count === "number" ? snapshot.high_patches_overdue_count : undefined,
    known_exploited_vuln_count:
      typeof snapshot.known_exploited_vuln_count === "number" ? snapshot.known_exploited_vuln_count : undefined,
    internet_exposed_unpatched_critical_count:
      typeof snapshot.internet_exposed_unpatched_critical_count === "number"
        ? snapshot.internet_exposed_unpatched_critical_count
        : undefined,
    unsupported_software_count:
      typeof snapshot.unsupported_software_count === "number" ? snapshot.unsupported_software_count : undefined,
    outdated_browser_count:
      typeof snapshot.outdated_browser_count === "number" ? snapshot.outdated_browser_count : undefined,
    outdated_high_risk_app_count:
      typeof snapshot.outdated_high_risk_app_count === "number" ? snapshot.outdated_high_risk_app_count : undefined,
    untrusted_or_unsigned_software_count:
      typeof snapshot.untrusted_or_unsigned_software_count === "number"
        ? snapshot.untrusted_or_unsigned_software_count
        : undefined,
    active_malware_count: typeof snapshot.active_malware_count === "number" ? snapshot.active_malware_count : undefined,
    quarantined_threat_count_7d:
      typeof snapshot.quarantined_threat_count_7d === "number" ? snapshot.quarantined_threat_count_7d : undefined,
    persistent_threat_count:
      typeof snapshot.persistent_threat_count === "number" ? snapshot.persistent_threat_count : undefined,
    ransomware_behaviour_flag:
      typeof snapshot.ransomware_behaviour_flag === "boolean" ? snapshot.ransomware_behaviour_flag : undefined,
    lateral_movement_indicator:
      typeof snapshot.lateral_movement_indicator === "boolean" ? snapshot.lateral_movement_indicator : undefined,
    open_port_count: typeof snapshot.open_port_count === "number" ? snapshot.open_port_count : undefined,
    risky_open_port_count:
      typeof snapshot.risky_open_port_count === "number" ? snapshot.risky_open_port_count : undefined,
    internet_exposed_admin_service_count:
      typeof snapshot.internet_exposed_admin_service_count === "number"
        ? snapshot.internet_exposed_admin_service_count
        : undefined,
    smb_exposed_flag: typeof snapshot.smb_exposed_flag === "boolean" ? snapshot.smb_exposed_flag : undefined,
    rdp_exposed_flag: typeof snapshot.rdp_exposed_flag === "boolean" ? snapshot.rdp_exposed_flag : undefined,
    malicious_domain_contacts_7d:
      typeof snapshot.malicious_domain_contacts_7d === "number" ? snapshot.malicious_domain_contacts_7d : undefined,
    suspicious_domain_contacts_7d:
      typeof snapshot.suspicious_domain_contacts_7d === "number" ? snapshot.suspicious_domain_contacts_7d : undefined,
    c2_beacon_indicator:
      typeof snapshot.c2_beacon_indicator === "boolean" ? snapshot.c2_beacon_indicator : undefined,
    data_exfiltration_indicator:
      typeof snapshot.data_exfiltration_indicator === "boolean" ? snapshot.data_exfiltration_indicator : undefined,
    unusual_egress_indicator:
      typeof snapshot.unusual_egress_indicator === "boolean" ? snapshot.unusual_egress_indicator : undefined,
    edr_enabled: typeof snapshot.edr_enabled === "boolean" ? snapshot.edr_enabled : undefined,
    av_enabled: typeof snapshot.av_enabled === "boolean" ? snapshot.av_enabled : undefined,
    firewall_enabled: typeof snapshot.firewall_enabled === "boolean" ? snapshot.firewall_enabled : undefined,
    disk_encryption_enabled:
      typeof snapshot.disk_encryption_enabled === "boolean" ? snapshot.disk_encryption_enabled : undefined,
    tamper_protection_enabled:
      typeof snapshot.tamper_protection_enabled === "boolean" ? snapshot.tamper_protection_enabled : undefined,
    local_admin_users_count:
      typeof snapshot.local_admin_users_count === "number" ? snapshot.local_admin_users_count : undefined,
    risky_signin_indicator:
      typeof snapshot.risky_signin_indicator === "boolean" ? snapshot.risky_signin_indicator : undefined,
    stolen_token_indicator:
      typeof snapshot.stolen_token_indicator === "boolean" ? snapshot.stolen_token_indicator : undefined,
    mfa_gap_indicator: typeof snapshot.mfa_gap_indicator === "boolean" ? snapshot.mfa_gap_indicator : undefined,
    tacticIds: readOptionalStringArray(snapshot.tacticIds),
    techniqueIds: readOptionalStringArray(snapshot.techniqueIds)
  };
}

function normalizeDeviceScoreSnapshot(
  raw: unknown,
  hostnameByDeviceId: Map<string, string>,
  nowIso: string
): DeviceScoreSnapshot {
  const snapshot = (raw ?? {}) as Partial<DeviceScoreSnapshot>;
  const deviceId = readOptionalString(snapshot.deviceId);
  return {
    id: readOptionalString(snapshot.id, randomUUID()),
    deviceId,
    hostname: readOptionalString(snapshot.hostname, hostnameByDeviceId.get(deviceId) ?? "UNKNOWN-HOST"),
    calculatedAt: readOptionalString(snapshot.calculatedAt, nowIso),
    telemetryUpdatedAt:
      typeof snapshot.telemetryUpdatedAt === "string" && snapshot.telemetryUpdatedAt.length > 0
        ? snapshot.telemetryUpdatedAt
        : undefined,
    telemetrySource:
      typeof snapshot.telemetrySource === "string" && snapshot.telemetrySource.length > 0
        ? snapshot.telemetrySource
        : undefined,
    overallScore: typeof snapshot.overallScore === "number" ? snapshot.overallScore : 0,
    riskBand: clampRiskBand(snapshot.riskBand),
    confidenceScore: typeof snapshot.confidenceScore === "number" ? snapshot.confidenceScore : 0,
    categoryScores: Array.isArray(snapshot.categoryScores) ? snapshot.categoryScores : [],
    topRiskDrivers: Array.isArray(snapshot.topRiskDrivers) ? snapshot.topRiskDrivers : [],
    overrideReasons: readOptionalStringArray(snapshot.overrideReasons),
    recommendedActions: readOptionalStringArray(snapshot.recommendedActions),
    missingTelemetryFields: readOptionalStringArray(snapshot.missingTelemetryFields),
    tacticIds: readOptionalStringArray(snapshot.tacticIds),
    techniqueIds: readOptionalStringArray(snapshot.techniqueIds),
    summary: readOptionalString(snapshot.summary),
    analystSummary: readOptionalString(snapshot.analystSummary)
  };
}

function normalizeState(rawState: unknown, nowIso: string): ControlPlaneState {
  const defaults = createEmptyState(nowIso);
  const raw = (rawState ?? {}) as Partial<ControlPlaneState>;
  const defaultPolicy = {
    ...defaults.defaultPolicy,
    ...(raw.defaultPolicy ?? {})
  };
  const policies = Array.isArray(raw.policies) && raw.policies.length > 0
    ? raw.policies.map((item) => normalizePolicyProfile(item, defaultPolicy, nowIso))
    : [normalizePolicyProfile(raw.defaultPolicy, defaultPolicy, nowIso)];

  if (!policies.some((item) => item.isDefault)) {
    policies[0] = { ...policies[0], isDefault: true };
  }

  const defaultPolicyProfile = policies.find((item) => item.isDefault) ?? policies[0];
  const devices = Array.isArray(raw.devices)
    ? raw.devices.map((item) =>
        normalizeDeviceRecord(item, defaultPolicyProfile.id, defaultPolicyProfile.name, nowIso, policies)
      )
    : [];
  const hostnameByDeviceId = new Map(devices.map((item) => [item.id, item.hostname]));
  const scripts = Array.isArray(raw.scripts) ? raw.scripts.map((item) => normalizeScript(item, nowIso)) : [];
  const adminBootstrap = createBootstrapAdminState(nowIso);

  const state: ControlPlaneState = {
    defaultPolicy: toPolicySummary(defaultPolicyProfile),
    policies,
    policyExclusionChangeRequests: Array.isArray(raw.policyExclusionChangeRequests)
      ? raw.policyExclusionChangeRequests.map((item) => normalizePolicyExclusionChangeRequestSummary(item, nowIso))
      : [],
    scripts,
    adminPrincipals:
      Array.isArray(raw.adminPrincipals) && raw.adminPrincipals.length > 0
        ? raw.adminPrincipals.map((item) => normalizeAdminPrincipalRecord(item, nowIso))
        : adminBootstrap.adminPrincipals,
    adminSessions:
      Array.isArray(raw.adminSessions) && raw.adminSessions.length > 0
        ? raw.adminSessions.map((item) => normalizeAdminSessionRecord(item, nowIso))
        : adminBootstrap.adminSessions,
    adminApiKeys:
      Array.isArray(raw.adminApiKeys) && raw.adminApiKeys.length > 0
        ? raw.adminApiKeys.map((item) => normalizeAdminApiKeyRecord(item, nowIso))
        : adminBootstrap.adminApiKeys,
    adminAuditEvents:
      Array.isArray(raw.adminAuditEvents) && raw.adminAuditEvents.length > 0
        ? raw.adminAuditEvents.map((item) => normalizeAdminAuditEventSummary(item, nowIso))
        : adminBootstrap.adminAuditEvents,
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
      : [],
    deviceRiskTelemetry: Array.isArray(raw.deviceRiskTelemetry)
      ? raw.deviceRiskTelemetry.map((item) => normalizeRiskTelemetrySnapshot(item, hostnameByDeviceId, nowIso))
      : [],
    deviceScoreHistory: Array.isArray(raw.deviceScoreHistory)
      ? raw.deviceScoreHistory.map((item) => normalizeDeviceScoreSnapshot(item, hostnameByDeviceId, nowIso))
      : [],
    privilegeBaselines: Array.isArray(raw.privilegeBaselines)
      ? raw.privilegeBaselines.map((item) => normalizePrivilegeBaselineSnapshot(item, hostnameByDeviceId, nowIso))
      : [],
    privilegeEvents: Array.isArray(raw.privilegeEvents)
      ? raw.privilegeEvents.map((item) => normalizePrivilegeEventSummary(item, hostnameByDeviceId, nowIso))
      : [],
    privilegeStates: Array.isArray(raw.privilegeStates)
      ? raw.privilegeStates.map((item) => normalizePrivilegeStateSnapshot(item, hostnameByDeviceId, nowIso))
      : []
  };

  dedupeDevicesBySerial(state);
  syncPolicyAssignments(state);
  return state;
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
  state.deviceRiskTelemetry = state.deviceRiskTelemetry.filter(
    (item) => !demoDeviceIds.has(item.deviceId) && !demoHostnames.has(item.hostname)
  );
  state.deviceScoreHistory = state.deviceScoreHistory.filter(
    (item) => !demoDeviceIds.has(item.deviceId) && !demoHostnames.has(item.hostname)
  );
  state.privilegeBaselines = state.privilegeBaselines.filter(
    (item) => !demoDeviceIds.has(item.deviceId) && !demoHostnames.has(item.hostname)
  );
  state.privilegeEvents = state.privilegeEvents.filter(
    (item) => !demoDeviceIds.has(item.deviceId) && !demoHostnames.has(item.hostname)
  );
  state.privilegeStates = state.privilegeStates.filter(
    (item) => !demoDeviceIds.has(item.deviceId) && !demoHostnames.has(item.hostname)
  );
}

function syncPolicyAssignments(state: ControlPlaneState) {
  for (const policy of state.policies) {
    policy.assignedDeviceIds = [];
  }

  const defaultPolicy = state.policies.find((item) => item.isDefault) ?? state.policies[0];
  if (!defaultPolicy) {
    return;
  }

  for (const device of state.devices) {
    const assignedPolicy = state.policies.find((item) => item.id === device.policyId) ?? defaultPolicy;
    device.policyId = assignedPolicy.id;
    device.policyName = assignedPolicy.name;
    assignedPolicy.assignedDeviceIds.push(device.id);
  }

  state.defaultPolicy = toPolicySummary(defaultPolicy);
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
  dedupeDevicesBySerial(state);
  syncPolicyAssignments(state);
  state.policies = sortPolicies(state.policies).map((policy) => ({
    ...policy,
    assignedDeviceIds: [...policy.assignedDeviceIds].sort((left, right) => left.localeCompare(right))
  }));
  state.policyExclusionChangeRequests = sortPolicyExclusionChangeRequests(state.policyExclusionChangeRequests).slice(
    0,
    MAX_POLICY_EXCLUSION_CHANGE_REQUESTS
  );
  state.scripts = sortScripts(state.scripts);
  state.adminPrincipals = sortAdminPrincipals(state.adminPrincipals);
  state.adminSessions = sortAdminSessions(state.adminSessions).slice(0, MAX_ADMIN_SESSIONS);
  state.adminApiKeys = sortAdminApiKeys(state.adminApiKeys).slice(0, MAX_ADMIN_API_KEYS);
  state.adminAuditEvents = sortAdminAuditEvents(state.adminAuditEvents).slice(0, MAX_ADMIN_AUDIT_EVENTS);
  state.alerts = sortAlerts(state.alerts).slice(0, MAX_ALERTS);
  state.telemetry = sortTelemetry(state.telemetry).slice(0, MAX_TELEMETRY);
  state.commands = sortCommands(state.commands).slice(0, MAX_COMMANDS);
  state.quarantineItems = sortQuarantineItems(state.quarantineItems).slice(0, MAX_QUARANTINE_ITEMS);
  state.evidence = sortEvidence(state.evidence).slice(0, MAX_EVIDENCE_ITEMS);
  state.scanHistory = sortScanHistory(state.scanHistory).slice(0, MAX_SCAN_HISTORY);
  state.devicePosture = sortDevicePosture(state.devicePosture);
  state.deviceRiskTelemetry = sortByIsoDescending(state.deviceRiskTelemetry, (item) => item.updatedAt);
  state.deviceScoreHistory = sortDeviceScoreHistory(state.deviceScoreHistory).slice(0, MAX_DEVICE_SCORE_HISTORY);
  state.privilegeBaselines = sortPrivilegeBaselines(state.privilegeBaselines);
  state.privilegeEvents = sortPrivilegeEvents(state.privilegeEvents).slice(0, MAX_PRIVILEGE_EVENTS);
  state.privilegeStates = sortPrivilegeStates(state.privilegeStates);
}

function findDeviceOrThrow(state: ControlPlaneState, deviceId: string) {
  const device = state.devices.find((item) => item.id === deviceId);
  if (!device) {
    throw new DeviceNotFoundError(deviceId);
  }

  return device;
}

function findAlertOrThrow(state: ControlPlaneState, alertId: string) {
  const alert = state.alerts.find((item) => item.id === alertId);
  if (!alert) {
    throw new AlertNotFoundError(alertId);
  }

  return alert;
}

function findRelatedDeviceForAlert(state: ControlPlaneState, alert: AlertSummary) {
  const normalizedHostname = alert.hostname.toLowerCase();

  if (alert.deviceId) {
    return (
      state.devices.find((item) => item.id === alert.deviceId) ??
      state.devices.find((item) => item.hostname.toLowerCase() === normalizedHostname) ??
      null
    );
  }

  return state.devices.find((item) => item.hostname.toLowerCase() === normalizedHostname) ?? null;
}

function matchesGeneratedAlert(alert: AlertSummary, candidate: AlertSummary) {
  if (alert.fingerprint && candidate.fingerprint) {
    return alert.fingerprint === candidate.fingerprint;
  }

  return (
    alert.hostname.toLowerCase() === candidate.hostname.toLowerCase() &&
    alert.title === candidate.title &&
    (alert.technique ?? "") === (candidate.technique ?? "") &&
    alert.summary === candidate.summary
  );
}

function isWithinBehaviorWindow(referenceIso: string, candidateIso: string, windowMinutes = 30) {
  const referenceTime = Date.parse(referenceIso);
  const candidateTime = Date.parse(candidateIso);
  if (Number.isNaN(referenceTime) || Number.isNaN(candidateTime)) {
    return false;
  }

  return Math.abs(candidateTime - referenceTime) <= windowMinutes * 60 * 1000;
}

function truncateBehaviorText(value: string, maxLength: number) {
  if (value.length <= maxLength) {
    return value;
  }

  return `${value.slice(0, Math.max(0, maxLength - 3)).trimEnd()}...`;
}

function normalizeBehaviorPath(value: string | undefined) {
  return value?.replaceAll("/", "\\").toLowerCase() ?? "";
}

function looksLikeScriptPath(value: string | undefined) {
  return /\.(ps1|bat|cmd|js|jse|vbs|vbe|hta)$/i.test(normalizeBehaviorPath(value));
}

function looksLikeExecutablePath(value: string | undefined) {
  return /\.(exe|dll|scr|msi)$/i.test(normalizeBehaviorPath(value));
}

function isUserWritablePath(value: string | undefined) {
  const normalized = normalizeBehaviorPath(value);
  return normalized.includes("\\users\\") || normalized.includes("\\downloads\\") || normalized.includes("\\desktop\\") || normalized.includes("\\appdata\\");
}

function buildAlertBehaviorChain(
  alert: AlertSummary,
  matchingTelemetry: TelemetryRecord[],
  telemetry: TelemetryRecord[],
  commands: DeviceCommandSummary[],
  evidence: EvidenceSummary[],
  quarantineItems: QuarantineItemSummary[],
  scanHistory: ScanHistorySummary[]
): AlertBehaviorChain {
  const alertTime = alert.detectedAt;
  const uniqueSteps = new Map<string, AlertBehaviorChainStep>();
  const addStep = (step: AlertBehaviorChainStep | null | undefined) => {
    if (!step) {
      return;
    }

    const key = `${step.category}|${step.occurredAt}|${step.title}|${step.summary}`;
    if (!uniqueSteps.has(key)) {
      uniqueSteps.set(key, step);
    }
  };

  const commandLineSuspicion = (value: string | undefined) =>
    value && /encodedcommand|frombase64string|downloadstring|invoke-webrequest|\biwr\b|bitsadmin|certutil|mshta|wscript|cscript|rundll32|regsvr32/i.test(value)
      ? "The command line contains staged or obfuscated execution markers."
      : undefined;

  addStep({
    id: `alert-${alert.id}`,
    occurredAt: alert.detectedAt,
    category: "alert",
    title: alert.title,
    summary: alert.summary,
    source: "endpoint-alert",
    severity: alert.severity,
    tacticId: alert.tacticId,
    techniqueId: alert.technique,
    atRisk: "This alert anchors the chain but does not, by itself, explain the full execution path."
  });

  const orderedTelemetry = [...matchingTelemetry, ...telemetry.filter((record) => !matchingTelemetry.some((candidate) => candidate.eventId === record.eventId) && isWithinBehaviorWindow(alertTime, record.occurredAt))].sort(
    (left, right) => left.occurredAt.localeCompare(right.occurredAt)
  );

  for (const record of orderedTelemetry) {
    const payload = parsePayload(record.payloadJson);
    const processImageName = record.processImageName ?? readString(payload, "processImageName") ?? readString(payload, "imageName") ?? undefined;
    const processImagePath = record.processImagePath ?? readString(payload, "processImagePath") ?? readString(payload, "imagePath") ?? undefined;
    const parentProcessImageName = record.parentProcessImageName ?? readString(payload, "parentImageName") ?? undefined;
    const parentProcessImagePath = record.parentProcessImagePath ?? readString(payload, "parentImagePath") ?? undefined;
    const moduleImageName = record.moduleImageName ?? readString(payload, "imageName") ?? undefined;
    const moduleImagePath = record.moduleImagePath ?? readString(payload, "imagePath") ?? undefined;
    const remoteAddress = readString(payload, "remoteAddress");
    const remotePort = readNumber(payload, "remotePort");
    const localAddress = readString(payload, "localAddress");
    const localPort = readNumber(payload, "localPort");
    const commandLine = record.processCommandLine ?? readString(payload, "commandLine") ?? undefined;
    const summaryParts: string[] = [record.summary];

    if (record.eventType === "image.loaded") {
      summaryParts.push(`Module: ${moduleImageName ?? "unknown"}`);
      if (processImageName) {
        summaryParts.push(`Process: ${processImageName}`);
      }
      if (moduleImagePath) {
        summaryParts.push(`Module path: ${moduleImagePath}`);
      }

      addStep({
        id: record.eventId,
        occurredAt: record.occurredAt,
        category: "module",
        title: `${moduleImageName ?? "Module"} loaded into ${processImageName ?? "process"}`,
        summary: summaryParts.join(". "),
        source: record.source,
        severity: alert.severity,
        tacticId: alert.tacticId,
        techniqueId: alert.technique,
        atRisk: processImageName ? `The loader chain now runs inside ${processImageName}.` : undefined,
        linkedEventIds: record.processId != null ? [`process-${record.processId}`] : undefined
      });
      continue;
    }

    if (record.eventType.startsWith("process.")) {
      summaryParts.push(`Process: ${processImageName ?? "unknown"}`);
      if (processImagePath) {
        summaryParts.push(`Image path: ${processImagePath}`);
      }
      if (parentProcessImageName || parentProcessImagePath) {
        summaryParts.push(`Parent: ${parentProcessImageName ?? parentProcessImagePath}`);
      }
      if (record.processIntegrityLevel) {
        summaryParts.push(`Integrity: ${record.processIntegrityLevel}`);
      }
      if (record.processSigner) {
        summaryParts.push(`Signer: ${record.processSigner}`);
      }
      if (commandLine) {
        summaryParts.push(`Command line: ${truncateBehaviorText(commandLine, 120)}`);
      }

      addStep({
        id: record.eventId,
        occurredAt: record.occurredAt,
        category: "process",
        title: `${processImageName ?? "Process"} ${record.eventType === "process.exited" ? "exited" : "started"}`,
        summary: summaryParts.join(". "),
        source: record.source,
        severity: alert.severity,
        tacticId: alert.tacticId,
        techniqueId: alert.technique,
        atRisk: commandLineSuspicion(commandLine),
        linkedEventIds:
          record.processId != null
            ? [`process-${record.processId}`]
            : parentProcessImageName
              ? [`process-parent-${parentProcessImageName}`]
              : undefined
      });
      continue;
    }

    if (record.eventType.startsWith("network.")) {
      summaryParts.push(
        `Connection: ${localAddress ?? "unknown"}:${localPort ?? "?"} -> ${remoteAddress ?? "unknown"}:${remotePort ?? "?"}`
      );
      if (processImageName) {
        summaryParts.push(`Process: ${processImageName}`);
      }
      if (processImagePath) {
        summaryParts.push(`Process path: ${processImagePath}`);
      }

      const externalDestination = remoteAddress && !isPrivateAddress(remoteAddress);

      addStep({
        id: record.eventId,
        occurredAt: record.occurredAt,
        category: "network",
        title: `${processImageName ?? "Process"} network connection`,
        summary: summaryParts.join(". "),
        source: record.source,
        severity: alert.severity,
        tacticId: externalDestination ? "TA0011" : alert.tacticId,
        techniqueId: alert.technique,
        atRisk: externalDestination
          ? `${processImageName ?? "The process"} still has outbound network access to ${remoteAddress}${remotePort != null ? `:${remotePort}` : ""}.`
          : undefined,
        linkedEventIds: record.processId != null ? [`process-${record.processId}`] : undefined
      });
      continue;
    }

    if (record.eventType.startsWith("file.")) {
      const filePath = readString(payload, "path") ?? readString(payload, "filePath") ?? undefined;
      const lowerPath = normalizeBehaviorPath(filePath);
      const fileName = filePath ? filePath.split(/[/\\]/).filter(Boolean).at(-1) ?? filePath : "file";
      const suspiciousFile = isUserWritablePath(filePath) && (looksLikeExecutablePath(filePath) || looksLikeScriptPath(filePath));

      if (filePath) {
        summaryParts.push(`File: ${filePath}`);
      }
      if (readNumber(payload, "sizeBytes") != null) {
        summaryParts.push(`Size: ${readNumber(payload, "sizeBytes")}`);
      }
      if (lowerPath) {
        summaryParts.push(`Path: ${lowerPath}`);
      }

      addStep({
        id: record.eventId,
        occurredAt: record.occurredAt,
        category: "file",
        title: `${fileName} ${record.eventType.replace("file.", "")}`,
        summary: summaryParts.join(". "),
        source: record.source,
        severity: alert.severity,
        tacticId: alert.tacticId,
        techniqueId: alert.technique,
        blocked: false,
        atRisk: suspiciousFile ? `The staged file remains in a user-accessible location and can still be launched.` : undefined
      });
      continue;
    }

    if (record.eventType === "scan.finding") {
      const appName = readString(payload, "appName") ?? undefined;
      const contentName = readString(payload, "contentName") ?? readString(payload, "path") ?? undefined;
      const sourceType = readString(payload, "source") ?? undefined;
      const preview = readString(payload, "preview") ?? undefined;
      const techniqueId = readString(payload, "techniqueId") ?? undefined;
      const tacticId = readString(payload, "tacticId") ?? undefined;
      const disposition = readString(payload, "disposition") ?? readString(payload, "remediationStatus") ?? undefined;
      const blocked = disposition === "block" || disposition === "quarantine" || disposition === "quarantined";
      const scriptLike = record.source === "amsi-provider" || looksLikeScriptPath(contentName) || (contentName ? /powershell|wscript|cscript|hta/i.test(contentName) : false);

      if (appName) {
        summaryParts.push(`AMSI app: ${appName}`);
      }
      if (contentName) {
        summaryParts.push(`Content: ${contentName}`);
      }
      if (sourceType) {
        summaryParts.push(`Source: ${sourceType}`);
      }
      if (preview) {
        summaryParts.push(`Preview: ${truncateBehaviorText(preview, 120)}`);
      }
      if (disposition) {
        summaryParts.push(`Disposition: ${disposition}`);
      }

      addStep({
        id: record.eventId,
        occurredAt: record.occurredAt,
        category: scriptLike ? "script" : "file",
        title: blocked
          ? `${scriptLike ? "Script" : "File"} content blocked`
          : `${scriptLike ? "Script" : "File"} content inspected`,
        summary: summaryParts.join(". "),
        source: record.source,
        severity: blocked ? (alert.severity === "critical" ? "critical" : "high") : alert.severity,
        tacticId: tacticId ?? alert.tacticId,
        techniqueId: techniqueId ?? alert.technique,
        blocked,
        atRisk: blocked
          ? undefined
          : scriptLike
            ? "The script is still available for execution or reuse."
            : "The staged file remains available on disk."
      });
      continue;
    }
  }

  const hasTelemetryScanFinding = uniqueSteps.size > 0 && Array.from(uniqueSteps.values()).some((step) => step.category === "script" || step.category === "file");

  if (!hasTelemetryScanFinding) {
    for (const item of scanHistory) {
      if (!isWithinBehaviorWindow(alertTime, item.scannedAt)) {
        continue;
      }

      const contentName = item.contentName ?? item.subjectPath;
      const scriptLike = item.source === "amsi-provider" || looksLikeScriptPath(contentName) || (contentName ? /powershell|wscript|cscript|hta/i.test(contentName) : false);
      const blocked = item.disposition === "block" || item.disposition === "quarantine" || item.disposition === "quarantined";

      addStep({
        id: item.eventId,
        occurredAt: item.scannedAt,
        category: scriptLike ? "script" : "file",
        title: blocked ? `${scriptLike ? "Script" : "File"} content blocked` : `${scriptLike ? "Script" : "File"} content inspected`,
        summary: item.summary,
        source: item.source,
        severity: blocked ? (alert.severity === "critical" ? "critical" : "high") : alert.severity,
        tacticId: item.tacticId ?? alert.tacticId,
        techniqueId: item.techniqueId ?? alert.technique,
        blocked,
        atRisk: blocked ? undefined : scriptLike ? "The script is still available for execution or reuse." : "The staged file remains available on disk."
      });
    }

    for (const item of evidence) {
      if (!isWithinBehaviorWindow(alertTime, item.recordedAt)) {
        continue;
      }

      const contentName = item.contentName ?? item.subjectPath;
      const scriptLike = item.source === "amsi-provider" || looksLikeScriptPath(contentName) || (contentName ? /powershell|wscript|cscript|hta/i.test(contentName) : false);
      const blocked = item.disposition === "block" || item.disposition === "quarantine" || item.disposition === "quarantined";

      addStep({
        id: item.recordId,
        occurredAt: item.recordedAt,
        category: scriptLike ? "script" : "file",
        title: blocked ? `${scriptLike ? "Script" : "File"} content blocked` : `${scriptLike ? "Script" : "File"} content inspected`,
        summary: item.summary,
        source: item.source,
        severity: blocked ? (alert.severity === "critical" ? "critical" : "high") : alert.severity,
        tacticId: item.tacticId ?? alert.tacticId,
        techniqueId: item.techniqueId ?? alert.technique,
        blocked,
        atRisk: blocked ? undefined : scriptLike ? "The script is still available for execution or reuse." : "The staged file remains available on disk."
      });
    }
  }

  for (const item of quarantineItems) {
    if (!isWithinBehaviorWindow(alertTime, item.lastUpdatedAt) && !isWithinBehaviorWindow(alertTime, item.capturedAt)) {
      continue;
    }

    addStep({
      id: item.recordId,
      occurredAt: item.lastUpdatedAt,
      category: "quarantine",
      title: `${item.status} ${item.originalPath}`,
      summary: `${item.originalPath} -> ${item.quarantinedPath}`,
      source: "quarantine",
      severity: item.status === "quarantined" ? alert.severity : "medium",
      tacticId: item.technique ? alert.tacticId : undefined,
      techniqueId: item.technique,
      blocked: item.status === "quarantined",
      atRisk: item.status === "restored" ? "The file was restored and remains present on the endpoint." : undefined,
      linkedEventIds: item.evidenceRecordId ? [item.evidenceRecordId] : undefined
    });
  }

  for (const item of commands) {
    if (!isWithinBehaviorWindow(alertTime, item.updatedAt)) {
      continue;
    }

    addStep({
      id: item.id,
      occurredAt: item.updatedAt,
      category: "response",
      title: item.type.replaceAll(".", " "),
      summary: `${item.status.replaceAll("_", " ")} by ${item.issuedBy}${item.targetPath ? ` on ${item.targetPath}` : ""}`,
      source: "response",
      severity: alert.severity,
      blocked: item.status === "completed" && (item.type === "device.isolate" || item.type === "process.tree.terminate" || item.type === "quarantine.delete"),
      atRisk: item.status === "pending" || item.status === "in_progress" ? "The response action is still pending." : undefined,
      linkedEventIds: item.recordId ? [item.recordId] : undefined
    });
  }

  const steps = Array.from(uniqueSteps.values()).sort((left, right) => left.occurredAt.localeCompare(right.occurredAt));
  const tacticIds = [...new Set([alert.tacticId, ...steps.map((item) => item.tacticId)].filter((value): value is string => Boolean(value)))];
  const techniqueIds = [...new Set([alert.technique, ...steps.map((item) => item.techniqueId)].filter((value): value is string => Boolean(value)))];
  const chainSteps = steps.filter((item) => item.category !== "alert");
  const blockedSteps = chainSteps.filter((item) => item.blocked);
  const atRiskSteps = chainSteps.filter((item) => Boolean(item.atRisk));
  const sequenceCategories = new Set(steps.map((item) => item.category));
  const severityBase: Record<AlertSeverity, number> = { low: 28, medium: 38, high: 50, critical: 62 };
  const score = Math.min(
    100,
    severityBase[alert.severity] + sequenceCategories.size * 6 + blockedSteps.length * 10 + tacticIds.length * 4 + techniqueIds.length * 5 + (sequenceCategories.has("network") ? 8 : 0) + (sequenceCategories.has("module") ? 6 : 0) + (sequenceCategories.has("script") ? 8 : 0)
  );

  const whatHappened = chainSteps.length > 0 ? chainSteps.slice(0, 4).map((item) => `${item.title}: ${truncateBehaviorText(item.summary, 80)}`).join(" -> ") : alert.summary;
  const suspicionReasons = new Set<string>();

  if (alert.technique) {
    suspicionReasons.add(`ATT&CK ${alert.technique} is present in the alert mapping.`);
  }
  if (alert.tacticId) {
    suspicionReasons.add(`The chain maps to ATT&CK tactic ${alert.tacticId}.`);
  }
  if (chainSteps.some((item) => item.category === "process" && commandLineSuspicion(item.summary))) {
    suspicionReasons.add("The process command line includes staged or obfuscated execution markers.");
  }
  if (chainSteps.some((item) => item.category === "module")) {
    suspicionReasons.add("A module loaded into an executing process, which is consistent with loader chaining.");
  }
  if (chainSteps.some((item) => item.category === "network" && item.atRisk)) {
    suspicionReasons.add("The same process lineage retained outbound network reach.");
  }
  if (chainSteps.some((item) => item.category === "script" && item.blocked)) {
    suspicionReasons.add("Script content was blocked before the execution chain could advance.");
  }
  if (chainSteps.some((item) => item.category === "quarantine" && item.blocked)) {
    suspicionReasons.add("Quarantine interrupted the chain and preserved the artefact for review.");
  }

  const whySuspicious = suspicionReasons.size > 0 ? Array.from(suspicionReasons).join(" ") : "The sequence is suspicious because the alert correlates execution, payload staging, and follow-on activity rather than a single isolated event.";
  const blocked = blockedSteps.length > 0 ? Array.from(new Set(blockedSteps.map((item) => item.title))).join("; ") : "No block or containment action is recorded in this sequence.";
  const atRisk = atRiskSteps.length > 0 ? Array.from(new Set(atRiskSteps.map((item) => item.atRisk).filter((value): value is string => Boolean(value)))).join(" ") : "No obvious residual activity remains in the current snapshot.";

  return {
    score,
    narrative: `Sequence score ${score}/100. ${whatHappened}. ${whySuspicious} ${blocked} ${atRisk}`.trim(),
    whatHappened,
    whySuspicious,
    blocked,
    atRisk,
    tacticIds,
    techniqueIds,
    steps
  };
}

function buildAlertResponsePlaybook(
  alert: AlertSummary,
  relatedDevice: DeviceRecord | null,
  behaviorChain: AlertBehaviorChain,
  matchingTelemetry: TelemetryRecord[],
  evidence: EvidenceSummary[],
  quarantineItems: QuarantineItemSummary[],
  scanHistory: ScanHistorySummary[]
): AlertResponsePlaybook {
  const uniqueEvidencePaths = new Set<string>();
  const evidenceToPreserve: string[] = [];
  const addEvidenceNote = (value: string | undefined) => {
    if (!value || uniqueEvidencePaths.has(value)) {
      return;
    }

    uniqueEvidencePaths.add(value);
    evidenceToPreserve.push(value);
  };

  const processTelemetry = matchingTelemetry.find((record) => Boolean(record.processImagePath || record.processImageName));
  const networkTelemetry = matchingTelemetry.find((record) => record.eventType.startsWith("network."));
  const getArtifactId = (item: EvidenceSummary | ScanHistorySummary) => ("recordId" in item ? item.recordId : item.eventId);

  const processPath = processTelemetry?.processImagePath;
  const processName = processTelemetry?.processImageName ?? processTelemetry?.moduleImageName ?? processTelemetry?.eventType;
  const processLineageId = processTelemetry?.eventId;

  const alertArtifacts = [...scanHistory, ...evidence].map((item) => ({
    item,
    path: item.contentName ?? item.subjectPath
  }));

  const scriptArtifact = alertArtifacts.find(({ item, path }) => Boolean(path) && (item.source === "amsi-provider" || looksLikeScriptPath(path)));
  const fileArtifact = alertArtifacts.find(({ path }) => Boolean(path));
  const targetedScanPath = scriptArtifact?.path ?? fileArtifact?.path ?? processPath;
  const cleanupPath =
    scriptArtifact && scriptArtifact.path && isUserWritablePath(scriptArtifact.path)
      ? scriptArtifact.path
      : fileArtifact && fileArtifact.path && isUserWritablePath(fileArtifact.path)
        ? fileArtifact.path
        : undefined;

  addEvidenceNote("Alert detail, behavior chain, and linked telemetry");

  if (processTelemetry) {
    addEvidenceNote(
      processPath
        ? `Process lineage and command-line context for ${processName ?? processPath}`
        : `Process lineage and command-line context for ${processName ?? "the active process"}`
    );
  }

  if (networkTelemetry) {
    const payload = parsePayload(networkTelemetry.payloadJson);
    const remoteAddress = readString(payload, "remoteAddress");
    const remotePort = readNumber(payload, "remotePort");
    addEvidenceNote(
      remoteAddress
        ? `Network flow and remote endpoint details for ${remoteAddress}${remotePort != null ? `:${remotePort}` : ""}`
        : "Network flow and socket context"
    );
  }

  if (scriptArtifact?.path) {
    addEvidenceNote(`Script content and preview for ${scriptArtifact.path}`);
  }

  if (fileArtifact?.path && fileArtifact.path !== scriptArtifact?.path) {
    addEvidenceNote(`File artifact and hash for ${fileArtifact.path}`);
  }

  if (quarantineItems.length > 0) {
    addEvidenceNote("Quarantine records and restore/delete history");
  }

  if (scanHistory.length > 0) {
    addEvidenceNote("Scan verdict history and remediation status");
  }

  if (evidence.length > 0) {
    addEvidenceNote("Evidence record hashes and disposition history");
  }

  const hasExternalNetwork = Boolean(
    networkTelemetry &&
      (() => {
        const payload = parsePayload(networkTelemetry.payloadJson);
        const remoteAddress = readString(payload, "remoteAddress");
        return remoteAddress ? !isPrivateAddress(remoteAddress) : false;
      })()
  );
  const hasLiveProcessChain = Boolean(processTelemetry && processPath);
  const hasScriptOrFileArtifact = Boolean(targetedScanPath);
  const hasCleanupTarget = Boolean(cleanupPath);
  const suspiciousProcessStep = behaviorChain.steps.some(
    (step) =>
      step.category === "process" &&
      /encodedcommand|frombase64string|downloadstring|invoke-webrequest|\biwr\b|bitsadmin|certutil|mshta|wscript|cscript|rundll32|regsvr32/i.test(step.summary)
  );
  const suspiciousModuleStep = behaviorChain.steps.some(
    (step) => step.category === "module" && /powershell|pwsh|cmd|mshta|wscript|rundll32|regsvr32/i.test(step.summary)
  );
  const shouldContainmentFirst = alert.severity === "critical" || hasExternalNetwork || suspiciousProcessStep || suspiciousModuleStep;
  const playbookMode: AlertResponsePlaybook["mode"] = hasCleanupTarget && !shouldContainmentFirst ? "cleanup" : shouldContainmentFirst ? "containment" : "investigation";

  const actions: AlertResponsePlaybookAction[] = [];
  const addAction = (action: AlertResponsePlaybookAction) => {
    actions.push(action);
  };

  if (relatedDevice && !relatedDevice.isolated && shouldContainmentFirst) {
    addAction({
      id: `isolate-${alert.id}`,
      category: "containment",
      title: "Isolate the host",
      detail: "Use central containment to stop the chain from expanding while you preserve the artefact trail.",
      reason: hasExternalNetwork
        ? "The chain still has outbound reach, so host containment reduces blast radius before deeper remediation."
        : "The chain shows active process or loader behavior that is easier to stop with network containment first.",
      commandType: "device.isolate",
      automationEligible: false,
      approvalRequired: true,
        linkedEventIds: [alert.id, ...(processLineageId ? [processLineageId] : [])]
    });
  }

  if (processTelemetry && processPath) {
    addAction({
      id: `terminate-${alert.id}`,
      category: "containment",
      title: "Terminate the suspicious process tree",
      detail: `Queue a process-tree termination for ${processPath} so the lineage cannot keep staging or beaconing.`,
      reason: "The alert includes process lineage that should be stopped once evidence is preserved and containment is in place.",
      commandType: "process.tree.terminate",
      targetPath: processPath,
      automationEligible: false,
      approvalRequired: true,
      linkedEventIds: [processTelemetry.eventId]
    });
  }

  if (hasScriptOrFileArtifact && targetedScanPath) {
    const path = targetedScanPath;
    addAction({
      id: `scan-${alert.id}`,
      category: "investigation",
      title: "Queue a targeted scan",
      detail: `Run a targeted scan against ${path} to validate whether sibling artefacts or secondary payloads are still present.`,
      reason: "Targeted scans are repeatable and low-risk, so they are a good automated validation step after a suspicious drop or script event.",
      commandType: "scan.targeted",
      targetPath: path,
      automationEligible: true,
      approvalRequired: false,
      linkedEventIds: [
        ...(scriptArtifact ? [getArtifactId(scriptArtifact.item)] : []),
        ...(fileArtifact && fileArtifact !== scriptArtifact ? [getArtifactId(fileArtifact.item)] : [])
      ]
    });
  }

  if (hasCleanupTarget && cleanupPath) {
    addAction({
      id: `cleanup-${alert.id}`,
      category: "cleanup",
      title: "Clean up the drop location",
      detail: `Remove or clean up ${cleanupPath} and nearby user-writable artefacts after the evidence copy is secured.`,
      reason: "The artefact lives in a user-writable location, which is where persistence and re-execution commonly hide.",
      commandType: "persistence.cleanup",
      targetPath: cleanupPath,
      automationEligible: false,
      approvalRequired: true,
      linkedEventIds: [
        ...(scriptArtifact ? [getArtifactId(scriptArtifact.item)] : []),
        ...(fileArtifact && fileArtifact !== scriptArtifact ? [getArtifactId(fileArtifact.item)] : [])
      ]
    });
  }

  addAction({
    id: `bundle-${alert.id}`,
    category: "investigation",
    title: "Preserve an investigation bundle",
    detail: "Capture the alert detail, timeline, telemetry, evidence, quarantine, and command history before the working set changes.",
    reason: "The investigation bundle keeps the sequence explainable even if the endpoint state changes while the analyst is working.",
    automationEligible: false,
    approvalRequired: false,
    linkedEventIds: [alert.id]
  });

  const title =
    playbookMode === "containment"
      ? "Containment-first response playbook"
      : playbookMode === "cleanup"
        ? "Cleanup and validation playbook"
        : "Investigation playbook";

  const summary =
    playbookMode === "containment"
      ? relatedDevice?.isolated
        ? "The host is already isolated; keep it contained, preserve evidence, and validate whether the suspicious process chain is still active."
        : "The alert still shows live execution or network reach, so contain the host and stop the process chain before performing deeper cleanup."
      : playbookMode === "cleanup"
        ? "The suspicious artefact is in a user-writable location, so validate the drop, secure the evidence, and clean up the path once approved."
        : "The alert looks more like a focused validation problem than an active spread, so preserve the evidence bundle and run low-risk confirmation steps.";

  return {
    mode: playbookMode,
    title,
    summary,
    evidenceToPreserve,
    actions
  };
}

function findCommandOrThrow(state: ControlPlaneState, deviceId: string, commandId: string) {
  const command = state.commands.find((item) => item.deviceId === deviceId && item.id === commandId);
  if (!command) {
    throw new CommandNotFoundError(commandId);
  }

  return command;
}

function findPolicyOrThrow(state: ControlPlaneState, policyId: string) {
  const policy = state.policies.find((item) => item.id === policyId);
  if (!policy) {
    throw new PolicyNotFoundError(policyId);
  }

  return policy;
}

function findPolicyExclusionChangeRequestOrThrow(state: ControlPlaneState, requestId: string) {
  const request = state.policyExclusionChangeRequests.find((item) => item.id === requestId);
  if (!request) {
    throw new PolicyExclusionChangeRequestNotFoundError(requestId);
  }

  return request;
}

function applyPolicyExclusionChanges(policy: PolicyProfile, entries: PolicyExclusionChangeEntry[]) {
  const pathRoots = [...policy.suppressionPathRoots];
  const sha256 = [...policy.suppressionSha256];
  const signerNames = [...policy.suppressionSignerNames];
  const listsByType: Record<PolicyExclusionListType, string[]> = {
    path_root: pathRoots,
    sha256,
    signer_name: signerNames
  };

  for (const entry of entries) {
    const value = normalizePolicyExclusionValue(entry.listType, entry.value);
    if (!value) {
      continue;
    }

    const targetList = listsByType[entry.listType];
    const valueLower = value.toLowerCase();

    if (entry.operation === "add") {
      if (!targetList.some((item) => item.toLowerCase() === valueLower)) {
        targetList.push(value);
      }
      continue;
    }

    listsByType[entry.listType] = targetList.filter((item) => item.toLowerCase() !== valueLower);
  }

  policy.suppressionPathRoots = normalizePolicyStringArray(listsByType.path_root);
  policy.suppressionSha256 = normalizePolicyStringArray(listsByType.sha256, (item) => item.toLowerCase());
  policy.suppressionSignerNames = normalizePolicyStringArray(listsByType.signer_name);
}

function findScriptOrThrow(state: ControlPlaneState, scriptId: string) {
  const script = state.scripts.find((item) => item.id === scriptId);
  if (!script) {
    throw new ScriptNotFoundError(scriptId);
  }

  return script;
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

function findDeviceRiskTelemetry(state: ControlPlaneState, deviceId: string) {
  return state.deviceRiskTelemetry.find((item) => item.deviceId === deviceId) ?? null;
}

function findLatestDeviceScore(state: ControlPlaneState, deviceId: string) {
  return sortDeviceScoreHistory(state.deviceScoreHistory.filter((item) => item.deviceId === deviceId))[0] ?? null;
}

function latestIso(values: Array<string | null | undefined>, fallback: string) {
  return values.reduce<string>((latest, value) => {
    if (!value) {
      return latest;
    }

    return value > latest ? value : latest;
  }, fallback);
}

function coalesceDefined<T>(...values: Array<T | undefined>) {
  for (const value of values) {
    if (value !== undefined) {
      return value;
    }
  }

  return undefined;
}

function occurredWithinDays(value: string, baseIso: string, days: number) {
  const age = Date.parse(baseIso) - Date.parse(value);
  return age >= 0 && age <= days * 24 * 60 * 60 * 1_000;
}

function includesKeyword(value: string | undefined, keywords: string[]) {
  if (!value) {
    return false;
  }

  const normalized = value.toLowerCase();
  return keywords.some((keyword) => normalized.includes(keyword));
}

function buildEffectiveRiskTelemetry(state: ControlPlaneState, device: DeviceRecord, nowIso: string): DeviceRiskTelemetrySnapshot {
  const stored = findDeviceRiskTelemetry(state, device.id);
  const posture = state.devicePosture.find((item) => item.deviceId === device.id);
  const deviceAlerts = state.alerts.filter((item) => item.deviceId === device.id || item.hostname === device.hostname);
  const unresolvedAlerts = deviceAlerts.filter((item) => item.status !== "contained");
  const deviceQuarantine = state.quarantineItems.filter((item) => item.deviceId === device.id);
  const deviceScanHistory = state.scanHistory.filter((item) => item.deviceId === device.id);
  const deviceEvidence = state.evidence.filter((item) => item.deviceId === device.id);
  const deviceTelemetry = state.telemetry.filter((item) => item.deviceId === device.id);
  const policy = state.policies.find((item) => item.id === device.policyId);
  const privilegeState = findPrivilegeState(state, device.id);
  const privilegeBaseline = findPrivilegeBaseline(state, device.id);
  const recentQuarantine = deviceQuarantine.filter((item) => occurredWithinDays(item.lastUpdatedAt, nowIso, 7));
  const recentTelemetry = deviceTelemetry.filter((item) => occurredWithinDays(item.occurredAt, nowIso, 7));

  const browserNames = ["microsoft edge", "google chrome", "mozilla firefox"];
  const highRiskSoftwareNames = ["java", "acrobat", "reader", "vpn", "browser", "office", "7-zip"];
  const software = device.installedSoftware;
  const derivedOutdatedBrowsers = software.filter(
    (item) => item.updateState === "available" && includesKeyword(item.displayName, browserNames)
  ).length;
  const derivedOutdatedHighRiskApps = software.filter(
    (item) => (item.updateState === "available" || item.updateState === "error") && includesKeyword(item.displayName, highRiskSoftwareNames)
  ).length;
  const derivedUnsignedSoftware = software.filter(
    (item) => item.publisher.trim().length === 0 || item.publisher.toLowerCase() === "unknown"
  ).length;

  const alertAndEventText = [
    ...deviceAlerts.flatMap((item) => [item.title, item.summary, item.technique]),
    ...deviceEvidence.flatMap((item) => [item.summary, item.tacticId, item.techniqueId, item.subjectPath]),
    ...deviceScanHistory.flatMap((item) => [item.summary, item.tacticId, item.techniqueId, item.subjectPath]),
    ...recentTelemetry.flatMap((item) => [item.eventType, item.summary, item.payloadJson])
  ].filter((item): item is string => typeof item === "string" && item.length > 0);

  const ransomwareDetected = alertAndEventText.some((item) =>
    includesKeyword(item, ["ransom", "how_to_restore", "t1486", "encrypt"])
  );
  const lateralMovementDetected = alertAndEventText.some((item) =>
    includesKeyword(item, ["lateral", "psexec", "wmic", "t1021", "admin$"])
  );
  const c2Detected = alertAndEventText.some((item) => includesKeyword(item, ["c2", "beacon", "t1071", "command-and-control"]));
  const exfilDetected = alertAndEventText.some((item) => includesKeyword(item, ["exfil", "t1041", "data theft", "bulk upload"]));
  const unusualEgressDetected = alertAndEventText.some((item) => includesKeyword(item, ["unusual egress", "unexpected outbound", "suspicious domain"]));

  const dnsQueryCount = recentTelemetry.filter(
    (item) =>
      item.eventType.includes("dns") ||
      includesKeyword(item.summary, ["dns query", "dns resolution", "name resolution", "resolver"])
  ).length;
  const dnsBlockedCount = recentTelemetry.filter(
    (item) =>
      includesKeyword(item.eventType, ["dns.block"]) ||
      includesKeyword(item.summary, ["blocked dns", "dns blocked", "dns denied", "sinkhole"])
  ).length;
  const maliciousDestinationCount = recentTelemetry.filter(
    (item) =>
      includesKeyword(item.eventType, ["network.domain.malicious", "network.destination.malicious", "dns.block"]) ||
      includesKeyword(item.summary, ["malicious domain", "known bad domain", "command-and-control", "c2 beacon"])
  ).length;
  const suspiciousDestinationCount = recentTelemetry.filter(
    (item) => includesKeyword(item.summary, ["suspicious domain", "rare destination", "unexpected outbound", "unusual destination"])
  ).length;
  const fileIntegrityChangeCount = recentTelemetry.filter(
    (item) =>
      includesKeyword(item.eventType, ["file.integrity", "file.hash", "file.drift"]) ||
      includesKeyword(item.summary, ["file integrity", "hash mismatch", "integrity drift", "protected file change", "file baseline"])
  ).length;
  const protectedFileChangeCount = recentTelemetry.filter(
    (item) =>
      includesKeyword(item.summary, ["\\windows\\system32", "\\program files", "\\windows\\security", "\\syswow64"]) ||
      includesKeyword(item.payloadJson, ["\\windows\\system32", "\\program files", "\\windows\\security", "\\syswow64"])
  ).length;

  const maliciousDomainContacts = recentTelemetry.filter((item) =>
    includesKeyword(item.summary, ["malicious domain", "known bad domain"])
  ).length;
  const suspiciousDomainContacts = recentTelemetry.filter((item) =>
    includesKeyword(item.summary, ["suspicious domain", "unexpected outbound", "rare destination"])
  ).length;

  const openPorts = recentTelemetry
    .filter((item) => item.eventType === "network.port.snapshot")
    .reduce((highest, item) => Math.max(highest, readNumber(parsePayload(item.payloadJson), "open_port_count") ?? 0), 0);
  const riskyPorts = recentTelemetry
    .filter((item) => item.eventType === "network.port.snapshot")
    .reduce((highest, item) => Math.max(highest, readNumber(parsePayload(item.payloadJson), "risky_open_port_count") ?? 0), 0);
  const adminServices = recentTelemetry
    .filter((item) => item.eventType === "network.port.snapshot")
    .reduce(
      (highest, item) =>
        Math.max(highest, readNumber(parsePayload(item.payloadJson), "internet_exposed_admin_service_count") ?? 0),
      0
    );
  const smbExposed = recentTelemetry.some((item) => includesKeyword(item.summary, ["smb exposed", "port 445", "cifs"]));
  const rdpExposed = recentTelemetry.some((item) => includesKeyword(item.summary, ["rdp exposed", "port 3389", "remote desktop"]));

  const tacticIds = [
    ...new Set([
      ...(stored?.tacticIds ?? []),
      ...deviceEvidence.map((item) => item.tacticId).filter((item): item is string => Boolean(item)),
      ...deviceScanHistory.map((item) => item.tacticId).filter((item): item is string => Boolean(item))
    ])
  ];
  const techniqueIds = [
    ...new Set([
      ...(stored?.techniqueIds ?? []),
      ...deviceAlerts.map((item) => item.technique).filter((item): item is string => Boolean(item)),
      ...deviceEvidence.map((item) => item.techniqueId).filter((item): item is string => Boolean(item)),
      ...deviceScanHistory.map((item) => item.techniqueId).filter((item): item is string => Boolean(item))
    ])
  ];

  return {
    deviceId: device.id,
    hostname: device.hostname,
    updatedAt: latestIso(
      [
        stored?.updatedAt,
        device.lastTelemetryAt,
        device.lastSeenAt,
        posture?.updatedAt,
        deviceEvidence[0]?.recordedAt,
        deviceScanHistory[0]?.scannedAt
      ],
      nowIso
    ),
    source: stored?.source ?? "fenrir-derived",
    os_patch_age_days: stored?.os_patch_age_days,
    critical_patches_overdue_count: stored?.critical_patches_overdue_count,
    high_patches_overdue_count: stored?.high_patches_overdue_count,
    known_exploited_vuln_count: stored?.known_exploited_vuln_count,
    internet_exposed_unpatched_critical_count: stored?.internet_exposed_unpatched_critical_count,
    unsupported_software_count: stored?.unsupported_software_count,
    outdated_browser_count: coalesceDefined(stored?.outdated_browser_count, derivedOutdatedBrowsers),
    outdated_high_risk_app_count: coalesceDefined(stored?.outdated_high_risk_app_count, derivedOutdatedHighRiskApps),
    untrusted_or_unsigned_software_count: coalesceDefined(stored?.untrusted_or_unsigned_software_count, derivedUnsignedSoftware),
    active_malware_count: coalesceDefined(
      stored?.active_malware_count,
      unresolvedAlerts.filter((item) => item.severity === "high" || item.severity === "critical").length
    ),
    quarantined_threat_count_7d: coalesceDefined(stored?.quarantined_threat_count_7d, recentQuarantine.length),
    persistent_threat_count: coalesceDefined(
      stored?.persistent_threat_count,
      unresolvedAlerts.filter((item) => includesKeyword(item.title, ["persistent", "residual", "persistence"]) || includesKeyword(item.summary, ["persistent", "residual", "persistence"])).length
    ),
    ransomware_behaviour_flag: coalesceDefined(stored?.ransomware_behaviour_flag, ransomwareDetected),
    lateral_movement_indicator: coalesceDefined(stored?.lateral_movement_indicator, lateralMovementDetected),
    open_port_count: coalesceDefined(stored?.open_port_count, openPorts > 0 ? openPorts : undefined),
    risky_open_port_count: coalesceDefined(stored?.risky_open_port_count, riskyPorts > 0 ? riskyPorts : undefined),
    internet_exposed_admin_service_count: coalesceDefined(
      stored?.internet_exposed_admin_service_count,
      adminServices > 0 ? adminServices : undefined
    ),
    smb_exposed_flag: coalesceDefined(stored?.smb_exposed_flag, smbExposed ? true : undefined),
    rdp_exposed_flag: coalesceDefined(stored?.rdp_exposed_flag, rdpExposed ? true : undefined),
    malicious_domain_contacts_7d: coalesceDefined(
      stored?.malicious_domain_contacts_7d,
      maliciousDomainContacts > 0 ? maliciousDomainContacts : undefined
    ),
    suspicious_domain_contacts_7d: coalesceDefined(
      stored?.suspicious_domain_contacts_7d,
      suspiciousDomainContacts > 0 ? suspiciousDomainContacts : undefined
    ),
    dns_query_count_7d: coalesceDefined(stored?.dns_query_count_7d, dnsQueryCount > 0 ? dnsQueryCount : undefined),
    dns_blocked_count_7d: coalesceDefined(stored?.dns_blocked_count_7d, dnsBlockedCount > 0 ? dnsBlockedCount : undefined),
    malicious_destination_count_7d: coalesceDefined(
      stored?.malicious_destination_count_7d,
      maliciousDestinationCount > 0 ? maliciousDestinationCount : undefined
    ),
    suspicious_destination_count_7d: coalesceDefined(
      stored?.suspicious_destination_count_7d,
      suspiciousDestinationCount > 0 ? suspiciousDestinationCount : undefined
    ),
    c2_beacon_indicator: coalesceDefined(stored?.c2_beacon_indicator, c2Detected ? true : undefined),
    data_exfiltration_indicator: coalesceDefined(stored?.data_exfiltration_indicator, exfilDetected ? true : undefined),
    unusual_egress_indicator: coalesceDefined(stored?.unusual_egress_indicator, unusualEgressDetected ? true : undefined),
    file_integrity_change_count_7d: coalesceDefined(
      stored?.file_integrity_change_count_7d,
      fileIntegrityChangeCount > 0 ? fileIntegrityChangeCount : undefined
    ),
    protected_file_change_count_7d: coalesceDefined(
      stored?.protected_file_change_count_7d,
      protectedFileChangeCount > 0 ? protectedFileChangeCount : undefined
    ),
    edr_enabled: coalesceDefined(stored?.edr_enabled, posture ? posture.etwState === "ready" : undefined),
    av_enabled: coalesceDefined(stored?.av_enabled, policy ? policy.realtimeProtection && posture?.overallState !== "failed" : undefined),
    firewall_enabled: coalesceDefined(stored?.firewall_enabled, posture ? posture.wfpState === "ready" : undefined),
    disk_encryption_enabled: stored?.disk_encryption_enabled,
    tamper_protection_enabled: coalesceDefined(stored?.tamper_protection_enabled, posture ? posture.tamperProtectionState === "ready" : undefined),
    local_admin_users_count: coalesceDefined(
      stored?.local_admin_users_count,
      privilegeBaseline ? privilegeBaseline.localAdministrators.filter((item) => item.enabled).length : undefined,
      privilegeState?.standingAdminPresentFlag ? 1 : undefined
    ),
    standing_admin_present_flag: coalesceDefined(
      stored?.standing_admin_present_flag,
      privilegeState?.standingAdminPresentFlag,
      privilegeBaseline ? privilegeBaseline.localAdministrators.some((item) => item.enabled && item.authorized) : undefined
    ),
    unapproved_admin_account_count: coalesceDefined(
      stored?.unapproved_admin_account_count,
      privilegeState?.unapprovedAdminAccountCount,
      privilegeBaseline ? privilegeBaseline.localAdministrators.filter((item) => !item.authorized).length : undefined
    ),
    admin_group_tamper_indicator: coalesceDefined(
      stored?.admin_group_tamper_indicator,
      privilegeState?.adminGroupTamperIndicator,
      recentTelemetry.some((item) => includesKeyword(item.summary, ["administrator group", "admin group tamper", "local administrators changed"]))
        ? true
        : undefined
    ),
    direct_admin_logon_attempt_count_7d: coalesceDefined(
      stored?.direct_admin_logon_attempt_count_7d,
      privilegeState?.directAdminLogonAttemptCount_7d,
      recentTelemetry.filter((item) => includesKeyword(item.summary, ["admin logon", "privileged logon", "elevated logon"])).length
    ),
    break_glass_account_usage_indicator: coalesceDefined(
      stored?.break_glass_account_usage_indicator,
      privilegeState?.breakGlassAccountUsageIndicator,
      recentTelemetry.some((item) => includesKeyword(item.summary, ["break glass", "emergency admin", "recovery account"]))
        ? true
        : undefined
    ),
    pam_enforcement_enabled: coalesceDefined(stored?.pam_enforcement_enabled, privilegeState?.pamEnforcementEnabled, policy?.privilegeHardeningEnabled ?? undefined),
    privilege_hardening_mode: coalesceDefined(
      stored?.privilege_hardening_mode,
      privilegeState?.privilegeHardeningMode,
      policy?.privilegeHardeningEnabled ? (policy.pamLiteEnabled ? "restricted" : "enforce") : "monitor_only"
    ),
    unauthorised_admin_reenable_indicator: coalesceDefined(
      stored?.unauthorised_admin_reenable_indicator,
      privilegeState?.unauthorisedAdminReenableIndicator,
      recentTelemetry.some((item) => includesKeyword(item.summary, ["unauthorised admin reenable", "unapproved admin re-enable"]))
        ? true
        : undefined
    ),
    recovery_path_exists: coalesceDefined(
      stored?.recovery_path_exists,
      privilegeState?.recoveryPathExists,
      privilegeBaseline ? privilegeBaseline.breakGlassAccountEnabled && privilegeBaseline.recoveryCredentialEscrowed : undefined
    ),
    risky_signin_indicator: stored?.risky_signin_indicator,
    stolen_token_indicator: stored?.stolen_token_indicator,
    mfa_gap_indicator: stored?.mfa_gap_indicator,
    tacticIds,
    techniqueIds
  };
}

function recordDeviceScoreSnapshot(state: ControlPlaneState, score: DeviceScoreSnapshot) {
  const previous = findLatestDeviceScore(state, score.deviceId);
  if (
    previous &&
    previous.overallScore === score.overallScore &&
    previous.riskBand === score.riskBand &&
    previous.confidenceScore === score.confidenceScore &&
    JSON.stringify(previous.overrideReasons) === JSON.stringify(score.overrideReasons) &&
    JSON.stringify(previous.missingTelemetryFields) === JSON.stringify(score.missingTelemetryFields) &&
    JSON.stringify(previous.topRiskDrivers.map((item) => item.title)) === JSON.stringify(score.topRiskDrivers.map((item) => item.title))
  ) {
    previous.calculatedAt = score.calculatedAt;
    previous.telemetryUpdatedAt = score.telemetryUpdatedAt;
    previous.telemetrySource = score.telemetrySource;
    previous.categoryScores = score.categoryScores;
    previous.topRiskDrivers = score.topRiskDrivers;
    previous.overrideReasons = score.overrideReasons;
    previous.recommendedActions = score.recommendedActions;
    previous.missingTelemetryFields = score.missingTelemetryFields;
    previous.tacticIds = score.tacticIds;
    previous.techniqueIds = score.techniqueIds;
    previous.summary = score.summary;
    previous.analystSummary = score.analystSummary;
    return previous;
  }

  state.deviceScoreHistory.push(score);
  return score;
}

function recalculateDeviceScoreSnapshot(state: ControlPlaneState, device: DeviceRecord, nowIso: string) {
  recalculatePrivilegeStateSnapshot(state, device, nowIso);
  const effectiveTelemetry = buildEffectiveRiskTelemetry(state, device, nowIso);
  const score = scoreDeviceRisk({
    deviceId: device.id,
    hostname: device.hostname,
    telemetry: effectiveTelemetry,
    now: nowIso,
    inheritedTacticIds: effectiveTelemetry.tacticIds,
    inheritedTechniqueIds: effectiveTelemetry.techniqueIds
  });
  return recordDeviceScoreSnapshot(state, score);
}

function recalculateAllDeviceScores(state: ControlPlaneState, nowIso: string) {
  for (const device of state.devices) {
    recalculateDeviceScoreSnapshot(state, device, nowIso);
  }
}

function toDeviceSummary(state: ControlPlaneState, device: DeviceRecord): DeviceSummary {
  const posture = state.devicePosture.find((item) => item.deviceId === device.id);
  const latestScore = findLatestDeviceScore(state, device.id);
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
    policyId: device.policyId,
    policyName: device.policyName,
    openAlertCount,
    quarantinedItemCount,
    postureState: posture?.overallState ?? "unknown",
    privateIpAddresses: device.privateIpAddresses,
    publicIpAddress: device.publicIpAddress,
    lastLoggedOnUser: device.lastLoggedOnUser,
    riskScore: latestScore?.overallScore ?? null,
    riskBand: latestScore?.riskBand ?? null,
    confidenceScore: latestScore?.confidenceScore ?? null
  };
}

function findInstalledSoftware(device: DeviceRecord, payload: ParsedPayload | null) {
  const softwareId = readString(payload, "softwareId");
  if (softwareId) {
    const byId = device.installedSoftware.find((item) => item.id === softwareId);
    if (byId) {
      return byId;
    }
  }

  const displayName = readString(payload, "displayName");
  if (displayName) {
    return device.installedSoftware.find((item) => item.displayName === displayName);
  }

  return undefined;
}

function updateDeviceInventory(state: ControlPlaneState, device: DeviceRecord, record: TelemetryRecord) {
  const payload = parsePayload(record.payloadJson);

  if (record.eventType === "device.inventory.snapshot") {
    device.privateIpAddresses = mergeUniqueStrings(readStringArray(payload, "privateIpAddresses"));
    device.lastLoggedOnUser = readString(payload, "lastLoggedOnUser") ?? null;
    device.installedSoftware = sortInstalledSoftware(
      readObjectArray(payload, "installedSoftware").map((item) => normalizeInstalledSoftware(item))
    );
    return;
  }

  const software = findInstalledSoftware(device, payload);
  if (!software) {
    return;
  }

  switch (record.eventType) {
    case "software.update.search.completed":
      software.updateState = readBoolean(payload, "updateAvailable") ? "available" : "current";
      software.lastUpdateCheckAt = record.occurredAt;
      software.updateSummary = readString(payload, "summary") ?? record.summary;
      break;
    case "software.update.search.failed":
      software.updateState = "error";
      software.lastUpdateCheckAt = record.occurredAt;
      software.updateSummary = readString(payload, "error") ?? record.summary;
      break;
    case "software.updated":
      software.updateState = "current";
      software.lastUpdateCheckAt = record.occurredAt;
      software.updateSummary = record.summary;
      break;
    case "software.update.failed":
      software.updateState = "error";
      software.lastUpdateCheckAt = record.occurredAt;
      software.updateSummary = record.summary;
      break;
    case "software.uninstalled":
      device.installedSoftware = device.installedSoftware.filter((item) => item.id !== software.id);
      break;
    case "software.blocked":
      software.blocked = true;
      software.updateSummary = readString(payload, "summary") ?? "Software execution is blocked on this endpoint.";
      break;
    default:
      break;
  }
}

function updateRiskTelemetryFromTelemetry(state: ControlPlaneState, device: DeviceRecord, record: TelemetryRecord) {
  if (record.eventType !== "device.risk.snapshot") {
    return;
  }

  const payload = parsePayload(record.payloadJson);
  if (!payload) {
    return;
  }

  const existing = findDeviceRiskTelemetry(state, device.id);
  const next = normalizeRiskTelemetrySnapshot(
    {
      ...(existing ?? {}),
      ...payload,
      deviceId: device.id,
      hostname: device.hostname,
      updatedAt: record.occurredAt,
      source: readString(payload, "source") ?? record.source
    },
    new Map([[device.id, device.hostname]]),
    record.occurredAt
  );

  if (existing) {
    Object.assign(existing, next);
    return;
  }

  state.deviceRiskTelemetry.push(next);
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
    appName: readString(payload, "appName"),
    contentName: readString(payload, "contentName"),
    sourceType: readString(payload, "source"),
    sessionId: readNumber(payload, "sessionId"),
    preview: readString(payload, "preview"),
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
    appName: readString(payload, "appName"),
    contentName: readString(payload, "contentName"),
    sourceType: readString(payload, "source"),
    sessionId: readNumber(payload, "sessionId"),
    preview: readString(payload, "preview"),
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

  if (command.type === "script.run") {
    const payload = command.payloadJson ? parsePayload(command.payloadJson) : null;
    const scriptId = readString(payload, "scriptId");
    if (scriptId) {
      const script = state.scripts.find((item) => item.id === scriptId);
      if (script) {
        script.lastExecutedAt = completedAt;
        script.updatedAt = completedAt;
      }
    }
    return;
  }

  if (command.type === "privilege.enforce" || command.type === "privilege.recover") {
    const resultPayload = command.resultJson ? parsePayload(command.resultJson) : null;
    const requestPayload = command.payloadJson ? parsePayload(command.payloadJson) : null;
    const telemetry = ensurePrivilegeRiskTelemetry(state, device, completedAt);
    telemetry.privilege_hardening_mode =
      (readString(resultPayload, "mode") as PrivilegeHardeningMode | undefined) ??
      (readString(requestPayload, "mode") as PrivilegeHardeningMode | undefined) ??
      (command.type === "privilege.recover" ? "monitor_only" : "enforce");
    telemetry.pam_enforcement_enabled = command.type === "privilege.recover" ? telemetry.pam_enforcement_enabled ?? false : true;
    telemetry.recovery_path_exists = true;
    telemetry.updatedAt = completedAt;
    telemetry.source = "command";
    recalculatePrivilegeStateSnapshot(state, device, completedAt);
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
  let persistChain = Promise.resolve();

  async function persistState(state: ControlPlaneState) {
    await mkdir(dirname(stateFilePath), { recursive: true });
    const nextPayload = `${JSON.stringify(state, null, 2)}\n`;
    const tempPath = `${stateFilePath}.${process.pid}.${randomUUID()}.tmp`;
    await writeFile(tempPath, nextPayload, "utf8");

    try {
      await rename(tempPath, stateFilePath);
    } catch (error) {
      const nodeError = error as NodeJS.ErrnoException;
      if (nodeError.code === "EEXIST" || nodeError.code === "EPERM") {
        await rm(stateFilePath, { force: true });
        try {
          await rename(tempPath, stateFilePath);
        } catch (replaceError) {
          await rm(tempPath, { force: true });
          throw replaceError;
        }
      } else {
        await rm(tempPath, { force: true });
        throw error;
      }
    }
  }

  function isTransientJsonParseError(error: unknown) {
    return error instanceof SyntaxError && /Unexpected end of JSON input/i.test(error.message);
  }

  async function readStateFromDisk() {
    const rawText = await readFile(stateFilePath, "utf8");
    return normalizeState(JSON.parse(rawText) as unknown, now());
  }

  async function loadStateFromDiskWithRetry() {
    try {
      return await readStateFromDisk();
    } catch (error) {
      if (!isTransientJsonParseError(error)) {
        throw error;
      }

      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });

      return readStateFromDisk();
    }
  }

  async function backupCorruptStateFile() {
    const backupPath = `${stateFilePath}.corrupt-${Date.now()}.json`;
    try {
      await rename(stateFilePath, backupPath);
    } catch (error) {
      const nodeError = error as NodeJS.ErrnoException;
      if (nodeError.code !== "ENOENT" && nodeError.code !== "EPERM" && nodeError.code !== "EACCES") {
        throw error;
      }
    }
  }

  async function persistStateSerialized(state: ControlPlaneState) {
    persistChain = persistChain.then(() => persistState(state));
    await persistChain;
  }

  async function loadState() {
    if (cachedState) {
      return cachedState;
    }

    try {
      cachedState = await loadStateFromDiskWithRetry();
      if (!seedDemoData) {
        stripDemoRecords(cachedState);
      }
    } catch (error) {
      const maybeNodeError = error as NodeJS.ErrnoException;
      const isMissingStateFile = maybeNodeError.code === "ENOENT";
      const isCorruptStateFile = error instanceof SyntaxError;
      if (!isMissingStateFile && !isCorruptStateFile) {
        throw error;
      }

      if (isCorruptStateFile) {
        await backupCorruptStateFile();
      }

      cachedState = seedDemoData ? createSeedState(now()) : createEmptyState(now());
    }

    recalculateAllDeviceScores(cachedState, now());
    trimState(cachedState);
    await persistStateSerialized(cachedState);
    return cachedState;
  }

  async function mutateState<T>(mutator: (state: ControlPlaneState) => T | Promise<T>) {
    const state = await loadState();
    const result = await mutator(state);
    trimState(state);
    await persistStateSerialized(state);
    return result;
  }

  return {
    async listAdminPrincipals() {
      const state = await loadState();
      return sortAdminPrincipals(state.adminPrincipals).map((item) => toAdminPrincipalSummary(item));
    },

    async listAdminSessions() {
      const state = await loadState();
      return sortAdminSessions(state.adminSessions).map((item) => {
        const principal = findAdminPrincipalById(state, item.principalId);
        return toAdminSessionSummary(
          item,
          principal ?? {
            id: item.principalId,
            username: "unknown",
            displayName: "Unknown principal",
            passwordSalt: "",
            passwordHash: "",
            mfaSecret: "",
            roles: ["read_only"],
            enabled: false,
            createdAt: item.createdAt,
            updatedAt: item.createdAt
          }
        );
      });
    },

    async listAdminApiKeys() {
      const state = await loadState();
      return sortAdminApiKeys(state.adminApiKeys).map((item) => {
        const principal = findAdminPrincipalById(state, item.principalId);
        return toAdminApiKeySummary(
          item,
          principal ?? {
            id: item.principalId,
            username: "unknown",
            displayName: "Unknown principal",
            passwordSalt: "",
            passwordHash: "",
            mfaSecret: "",
            roles: ["read_only"],
            enabled: false,
            createdAt: item.createdAt,
            updatedAt: item.updatedAt
          }
        );
      });
    },

    async listAdminAuditEvents(limit = 100) {
      const state = await loadState();
      return sortAdminAuditEvents(state.adminAuditEvents).slice(0, limit);
    },

    async loginAdmin(request, observedRemoteAddress, userAgent) {
      const state = await loadState();
      const principal = findAdminPrincipalByUsername(state, request.username);
      const validPrincipal = principal && principal.enabled;
      const passwordValid = principal ? verifyPassword(request.password, principal.passwordSalt, principal.passwordHash) : false;
      const mfaValid = principal ? verifyTotpCode(principal.mfaSecret, request.mfaCode) : false;

      if (!validPrincipal || !passwordValid || !mfaValid) {
        recordAdminAuditEvent(state, {
          occurredAt: now(),
          actorName: request.username,
          actorType: "anonymous",
          action: "admin.login",
          resourceType: "admin_session",
          outcome: "failure",
          severity: "medium",
          details: "Admin login failed due to invalid credentials or MFA.",
          source: "control-plane",
          ipAddress: observedRemoteAddress,
          sessionId: undefined
        });
        trimState(state);
        await persistStateSerialized(state);
        throw new AdminAuthenticationError();
      }

      return mutateState(async (mutatedState) => {
        const resolvedPrincipal = findAdminPrincipalByUsername(mutatedState, request.username);
        if (!resolvedPrincipal || !resolvedPrincipal.enabled) {
          throw new AdminAuthenticationError();
        }

        const timestamp = now();
        const sessionToken = createSessionToken();
        const sessionMinutes = typeof request.sessionMinutes === "number" && Number.isFinite(request.sessionMinutes)
          ? Math.min(Math.max(Math.floor(request.sessionMinutes), 30), 24 * 60)
          : 480;
        const expiresAt = new Date(Date.parse(timestamp) + sessionMinutes * 60_000).toISOString();
        const session: AdminSessionRecord = {
          id: randomUUID(),
          principalId: resolvedPrincipal.id,
          tokenHash: hashSessionToken(sessionToken),
          createdAt: timestamp,
          expiresAt,
          lastSeenAt: timestamp,
          sourceIp: observedRemoteAddress,
          userAgent
        };

        mutatedState.adminSessions.push(session);
        resolvedPrincipal.lastLoginAt = timestamp;
        resolvedPrincipal.updatedAt = timestamp;
        recordAdminAuditEvent(mutatedState, {
          occurredAt: timestamp,
          actorId: resolvedPrincipal.id,
          actorName: resolvedPrincipal.displayName,
          actorType: "user",
          action: "admin.login",
          resourceType: "admin_session",
          resourceId: session.id,
          outcome: "success",
          severity: "medium",
          details: `Admin session started for ${resolvedPrincipal.username}.`,
          source: "control-plane",
          sessionId: session.id,
          ipAddress: observedRemoteAddress
        });

        return createAdminLoginResponse(sessionToken, resolvedPrincipal, session);
      });
    },

    async resolveAdminSession(sessionToken, observedRemoteAddress, userAgent) {
      const tokenHash = hashSessionToken(sessionToken);

      return mutateState(async (state) => {
        const currentIso = now();
        const currentTime = Date.parse(currentIso);
        const session = findAdminSessionByTokenHash(state, tokenHash);
        if (!session || session.revokedAt) {
          return null;
        }

        if (Date.parse(session.expiresAt) <= currentTime) {
          session.revokedAt = session.revokedAt ?? currentIso;
          recordAdminAuditEvent(state, {
            occurredAt: currentIso,
            actorId: session.principalId,
            actorName: findAdminPrincipalById(state, session.principalId)?.displayName ?? "Unknown principal",
            actorType: "session",
            action: "admin.session.expired",
            resourceType: "admin_session",
            resourceId: session.id,
            outcome: "failure",
            severity: "low",
            details: `Admin session ${session.id} expired before it could be used.`,
            source: "control-plane",
            sessionId: session.id,
            ipAddress: observedRemoteAddress
          });
          return null;
        }

        const principal = findAdminPrincipalById(state, session.principalId);
        if (!principal || !principal.enabled) {
          session.revokedAt = session.revokedAt ?? currentIso;
          return null;
        }

        session.lastSeenAt = currentIso;
        if (observedRemoteAddress) {
          session.sourceIp = observedRemoteAddress;
        }
        if (userAgent) {
          session.userAgent = userAgent;
        }

        return {
          principal: toAdminPrincipalSummary(principal),
          session: toAdminSessionSummary(session, principal)
        };
      });
    },

    async logoutAdminSession(sessionToken, observedRemoteAddress) {
      const tokenHash = hashSessionToken(sessionToken);

      return mutateState(async (state) => {
        const session = findAdminSessionByTokenHash(state, tokenHash);
        if (!session) {
          return false;
        }

        if (!session.revokedAt) {
          session.revokedAt = now();
          recordAdminAuditEvent(state, {
            occurredAt: session.revokedAt,
            actorId: session.principalId,
            actorName: findAdminPrincipalById(state, session.principalId)?.displayName ?? "Unknown principal",
            actorType: "session",
            action: "admin.logout",
            resourceType: "admin_session",
            resourceId: session.id,
            outcome: "success",
            severity: "low",
            details: `Admin session ${session.id} was revoked.`,
            source: "control-plane",
            sessionId: session.id,
            ipAddress: observedRemoteAddress
          });
        }

        return true;
      });
    },

    async createAdminApiKey(request, actor, observedRemoteAddress) {
      if (!hasAdminRole(actor, ["admin"])) {
        throw new AdminAuthorizationError();
      }

      return mutateState(async (state) => {
        const principal = findAdminPrincipalById(state, actor.actorId);
        if (!principal || !principal.enabled) {
          throw new AdminAuthorizationError();
        }

        const timestamp = now();
        const accessKey = `avk_${createSessionToken()}`;
        const apiKey: AdminApiKeyRecord = {
          id: randomUUID(),
          principalId: principal.id,
          name: request.name.trim(),
          scopes: [...new Set(request.scopes.filter((item) => item.trim().length > 0))],
          tokenHash: hashSessionToken(accessKey),
          createdAt: timestamp,
          updatedAt: timestamp,
          sourceIp: observedRemoteAddress
        };

        state.adminApiKeys.push(apiKey);
        recordAdminAuditEvent(state, {
          occurredAt: timestamp,
          actorId: principal.id,
          actorName: principal.displayName,
          actorType: actor.actorType,
          action: "admin.api_key.create",
          resourceType: "admin_api_key",
          resourceId: apiKey.id,
          outcome: "success",
          severity: "medium",
          details: `Created API key ${apiKey.name}.`,
          source: "control-plane",
          sessionId: actor.sessionId,
          ipAddress: observedRemoteAddress
        });

        return {
          accessKey,
          apiKey: toAdminApiKeySummary(apiKey, principal)
        };
      });
    },

    async revokeAdminApiKey(apiKeyId, actor) {
      if (!hasAdminRole(actor, ["admin"])) {
        throw new AdminAuthorizationError();
      }

      return mutateState(async (state) => {
        const principal = findAdminPrincipalById(state, actor.actorId);
        if (!principal || !principal.enabled) {
          throw new AdminAuthorizationError();
        }

        const apiKey = state.adminApiKeys.find((item) => item.id === apiKeyId);
        if (!apiKey) {
          throw new AdminAuthorizationError(`API key not found: ${apiKeyId}`);
        }

        apiKey.revokedAt = apiKey.revokedAt ?? now();
        apiKey.updatedAt = now();
        recordAdminAuditEvent(state, {
          occurredAt: apiKey.updatedAt,
          actorId: principal.id,
          actorName: principal.displayName,
          actorType: actor.actorType,
          action: "admin.api_key.revoke",
          resourceType: "admin_api_key",
          resourceId: apiKey.id,
          outcome: "success",
          severity: "medium",
          details: `Revoked API key ${apiKey.name}.`,
          source: "control-plane",
          sessionId: actor.sessionId
        });

        return toAdminApiKeySummary(apiKey, principal);
      });
    },

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
        defaultPolicy: state.defaultPolicy,
        policies: sortPolicies(state.policies),
        scripts: sortScripts(state.scripts)
      };
    },

    async getDeviceDetail(deviceId: string) {
      const state = await loadState();
      const device = findDeviceOrThrow(state, deviceId);
      return {
        device: toDeviceSummary(state, device),
        posture: state.devicePosture.find((item) => item.deviceId === deviceId) ?? null,
        latestScore: findLatestDeviceScore(state, deviceId),
        scoreHistory: sortDeviceScoreHistory(state.deviceScoreHistory.filter((item) => item.deviceId === deviceId)).slice(0, 30),
        riskTelemetry: buildEffectiveRiskTelemetry(state, device, now()),
        privilegeBaseline: findPrivilegeBaseline(state, deviceId),
        privilegeState: findPrivilegeState(state, deviceId),
        privilegeEvents: sortPrivilegeEvents(state.privilegeEvents.filter((item) => item.deviceId === deviceId)).slice(0, 100),
        alerts: sortAlerts(state.alerts.filter((item) => item.deviceId === deviceId || item.hostname === device.hostname)),
        telemetry: sortTelemetry(state.telemetry.filter((item) => item.deviceId === deviceId)).slice(0, 200),
        commands: sortCommands(state.commands.filter((item) => item.deviceId === deviceId)).slice(0, 200),
        quarantineItems: sortQuarantineItems(state.quarantineItems.filter((item) => item.deviceId === deviceId)).slice(0, 200),
        evidence: sortEvidence(state.evidence.filter((item) => item.deviceId === deviceId)).slice(0, 200),
        scanHistory: sortScanHistory(state.scanHistory.filter((item) => item.deviceId === deviceId)).slice(0, 200),
        installedSoftware: sortInstalledSoftware(device.installedSoftware)
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

    async getAlertDetail(alertId: string) {
      const state = await loadState();
      const alert = findAlertOrThrow(state, alertId);
      const relatedDevice = findRelatedDeviceForAlert(state, alert);
      const normalizedHostname = alert.hostname.toLowerCase();
      const relatedDeviceIds = new Set(
        [alert.deviceId, relatedDevice?.id].filter((value): value is string => Boolean(value))
      );

      const matchesAlertContext = (item: { deviceId?: string; hostname: string }) => {
        if (item.deviceId && relatedDeviceIds.has(item.deviceId)) {
          return true;
        }

        return item.hostname.toLowerCase() === normalizedHostname;
      };

      const telemetry = sortTelemetry(state.telemetry.filter(matchesAlertContext)).slice(0, 200);
      const matchingTelemetry = telemetry
        .filter((record) => generateAlertsFromTelemetry([record]).some((candidate) => matchesGeneratedAlert(alert, candidate)))
        .slice(0, 50);
      const behaviorChain = buildAlertBehaviorChain(
        alert,
        matchingTelemetry,
        telemetry,
        sortCommands(state.commands.filter(matchesAlertContext)).slice(0, 50),
        sortEvidence(state.evidence.filter(matchesAlertContext)).slice(0, 50),
        sortQuarantineItems(state.quarantineItems.filter(matchesAlertContext)).slice(0, 50),
        sortScanHistory(state.scanHistory.filter(matchesAlertContext)).slice(0, 50)
      );
      const commands = sortCommands(state.commands.filter(matchesAlertContext)).slice(0, 50);
      const evidence = sortEvidence(state.evidence.filter(matchesAlertContext)).slice(0, 50);
      const quarantineItems = sortQuarantineItems(state.quarantineItems.filter(matchesAlertContext)).slice(0, 50);
      const scanHistory = sortScanHistory(state.scanHistory.filter(matchesAlertContext)).slice(0, 50);
      const playbook = buildAlertResponsePlaybook(alert, relatedDevice, behaviorChain, matchingTelemetry, evidence, quarantineItems, scanHistory);

      return {
        alert,
        device: relatedDevice ? toDeviceSummary(state, relatedDevice) : null,
        posture: relatedDevice ? state.devicePosture.find((item) => item.deviceId === relatedDevice.id) ?? null : null,
        behaviorChain,
        playbook,
        matchingTelemetry,
        telemetry,
        commands,
        evidence,
        quarantineItems,
        scanHistory,
        relatedAlerts: sortAlerts(state.alerts.filter((item) => item.id !== alert.id && matchesAlertContext(item))).slice(0, 20)
      };
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

    async listPolicies() {
      const state = await loadState();
      return sortPolicies(state.policies);
    },

    async listPolicyExclusionChangeRequests(policyId, status, limit = 50) {
      const state = await loadState();
      const filtered = state.policyExclusionChangeRequests.filter((item) => {
        if (policyId && item.policyId !== policyId) {
          return false;
        }

        if (status && item.status !== status) {
          return false;
        }

        return true;
      });

      return sortPolicyExclusionChangeRequests(filtered).slice(0, limit);
    },

    async createPolicyExclusionChangeRequest(policyId, request, actor) {
      return mutateState(async (state) => {
        if (!actor || !hasAdminRole(actor, ["admin", "operator"])) {
          throw new AdminAuthorizationError();
        }

        const principal = findAdminPrincipalById(state, actor.actorId);
        if (!principal || !principal.enabled) {
          throw new AdminAuthorizationError();
        }

        const policy = findPolicyOrThrow(state, policyId);
        const entries = normalizePolicyExclusionEntries(request.entries);
        if (entries.length === 0) {
          throw new AdminAuthorizationError("At least one valid exclusion change entry is required.");
        }

        const timestamp = now();
        const created: PolicyExclusionChangeRequestSummary = {
          id: randomUUID(),
          policyId: policy.id,
          policyName: policy.name,
          status: "pending",
          reason: request.reason.trim(),
          entries,
          requestedAt: timestamp,
          requestedBy: principal.displayName,
          requestedById: principal.id
        };

        state.policyExclusionChangeRequests.push(created);
        recordAdminAuditEvent(state, {
          occurredAt: timestamp,
          actorId: principal.id,
          actorName: principal.displayName,
          actorType: actor.actorType,
          action: "policy.exclusion.request",
          resourceType: "policy_exclusion_request",
          resourceId: created.id,
          outcome: "success",
          severity: "medium",
          details: `Submitted exclusion request for policy ${policy.name} with ${entries.length} change(s).`,
          source: "control-plane",
          sessionId: actor.sessionId
        });

        return created;
      });
    },

    async reviewPolicyExclusionChangeRequest(requestId, request, actor) {
      return mutateState(async (state) => {
        if (!actor || !hasAdminRole(actor, ["admin"])) {
          throw new AdminAuthorizationError();
        }

        const principal = findAdminPrincipalById(state, actor.actorId);
        if (!principal || !principal.enabled) {
          throw new AdminAuthorizationError();
        }

        const exclusionRequest = findPolicyExclusionChangeRequestOrThrow(state, requestId);
        if (exclusionRequest.status !== "pending") {
          throw new PolicyExclusionChangeRequestStateError(exclusionRequest.id, exclusionRequest.status);
        }

        const timestamp = now();
        const normalizedReviewComment = request.reviewComment?.trim();
        let affectedPolicy: PolicyProfile | null = null;

        if (request.outcome === "approved") {
          const policy = findPolicyOrThrow(state, exclusionRequest.policyId);
          applyPolicyExclusionChanges(policy, exclusionRequest.entries);
          policy.revision = buildPolicyRevision(timestamp);
          policy.updatedAt = timestamp;
          affectedPolicy = policy;

          if (policy.isDefault) {
            state.defaultPolicy = toPolicySummary(policy);
          }

          for (const device of state.devices) {
            if (device.policyId === policy.id) {
              recalculateDeviceScoreSnapshot(state, device, timestamp);
            }
          }
        }

        exclusionRequest.status = request.outcome;
        exclusionRequest.reviewedAt = timestamp;
        exclusionRequest.reviewedBy = principal.displayName;
        exclusionRequest.reviewedById = principal.id;
        exclusionRequest.reviewComment =
          normalizedReviewComment && normalizedReviewComment.length > 0 ? normalizedReviewComment : undefined;

        recordAdminAuditEvent(state, {
          occurredAt: timestamp,
          actorId: principal.id,
          actorName: principal.displayName,
          actorType: actor.actorType,
          action: request.outcome === "approved" ? "policy.exclusion.approve" : "policy.exclusion.reject",
          resourceType: "policy_exclusion_request",
          resourceId: exclusionRequest.id,
          outcome: "success",
          severity: request.outcome === "approved" ? "high" : "medium",
          details:
            request.outcome === "approved"
              ? `Approved exclusion request ${exclusionRequest.id} and applied ${exclusionRequest.entries.length} change(s) to ${exclusionRequest.policyName}.`
              : `Rejected exclusion request ${exclusionRequest.id} for ${exclusionRequest.policyName}.`,
          source: "control-plane",
          sessionId: actor.sessionId
        });

        if (affectedPolicy) {
          recordAdminAuditEvent(state, {
            occurredAt: timestamp,
            actorId: principal.id,
            actorName: principal.displayName,
            actorType: actor.actorType,
            action: "policy.update",
            resourceType: "policy",
            resourceId: affectedPolicy.id,
            outcome: "success",
            severity: "medium",
            details: `Applied approved exclusion changes to policy ${affectedPolicy.name}.`,
            source: "control-plane",
            sessionId: actor.sessionId
          });
        }

        return exclusionRequest;
      });
    },

    async createPolicy(request, actor) {
      return mutateState(async (state) => {
        if (!actor || !hasAdminRole(actor, ["admin"])) {
          throw new AdminAuthorizationError();
        }

        const principal = findAdminPrincipalById(state, actor.actorId);
        if (!principal || !principal.enabled) {
          throw new AdminAuthorizationError();
        }

        const requestedSuppressionPathRoots = normalizePolicyStringArray(request.suppressionPathRoots);
        const requestedSuppressionSha256 = normalizePolicyStringArray(request.suppressionSha256, (item) => item.toLowerCase());
        const requestedSuppressionSignerNames = normalizePolicyStringArray(request.suppressionSignerNames);
        if (
          requestedSuppressionPathRoots.length > 0 ||
          requestedSuppressionSha256.length > 0 ||
          requestedSuppressionSignerNames.length > 0
        ) {
          throw new PolicyExclusionWorkflowRequiredError();
        }

        const timestamp = now();
        const created: PolicyProfile = {
          id: randomUUID(),
          name: request.name,
          description: request.description?.trim() || `${request.name} protection profile`,
          revision: buildPolicyRevision(timestamp),
          realtimeProtection: request.realtimeProtection,
          cloudLookup: request.cloudLookup,
          scriptInspection: request.scriptInspection,
          networkContainment: request.networkContainment,
          quarantineOnMalicious: request.quarantineOnMalicious,
          dnsGuardEnabled: request.dnsGuardEnabled ?? request.networkContainment,
          trafficTelemetryEnabled: request.trafficTelemetryEnabled ?? request.networkContainment,
          integrityWatchEnabled: request.integrityWatchEnabled ?? request.quarantineOnMalicious,
          privilegeHardeningEnabled: request.privilegeHardeningEnabled ?? false,
          pamLiteEnabled: request.pamLiteEnabled ?? false,
          denyHighRiskElevation: request.denyHighRiskElevation ?? request.privilegeHardeningEnabled ?? false,
          denyUnsignedElevation: request.denyUnsignedElevation ?? request.privilegeHardeningEnabled ?? false,
          requireBreakGlassEscrow: request.requireBreakGlassEscrow ?? request.privilegeHardeningEnabled ?? false,
          suppressionPathRoots: [],
          suppressionSha256: [],
          suppressionSignerNames: [],
          isDefault: false,
          assignedDeviceIds: [],
          createdAt: timestamp,
          updatedAt: timestamp
        };
        state.policies.push(created);
        recordAdminAuditEvent(state, {
          occurredAt: timestamp,
          actorId: principal.id,
          actorName: principal.displayName,
          actorType: actor.actorType,
          action: "policy.create",
          resourceType: "policy",
          resourceId: created.id,
          outcome: "success",
          severity: "medium",
          details: `Created policy ${created.name}.`,
          source: "control-plane",
          sessionId: actor.sessionId
        });
        return created;
      });
    },

    async updatePolicy(policyId, request, actor) {
      return mutateState(async (state) => {
        if (!actor || !hasAdminRole(actor, ["admin"])) {
          throw new AdminAuthorizationError();
        }

        const principal = findAdminPrincipalById(state, actor.actorId);
        if (!principal || !principal.enabled) {
          throw new AdminAuthorizationError();
        }

        if (
          request.suppressionPathRoots !== undefined ||
          request.suppressionSha256 !== undefined ||
          request.suppressionSignerNames !== undefined
        ) {
          throw new PolicyExclusionWorkflowRequiredError();
        }

        const policy = findPolicyOrThrow(state, policyId);
        const timestamp = now();
        Object.assign(policy, {
          name: request.name?.trim() || policy.name,
          description: request.description?.trim() || policy.description,
          realtimeProtection: request.realtimeProtection ?? policy.realtimeProtection,
          cloudLookup: request.cloudLookup ?? policy.cloudLookup,
          scriptInspection: request.scriptInspection ?? policy.scriptInspection,
          networkContainment: request.networkContainment ?? policy.networkContainment,
          quarantineOnMalicious: request.quarantineOnMalicious ?? policy.quarantineOnMalicious,
          dnsGuardEnabled: request.dnsGuardEnabled ?? policy.dnsGuardEnabled,
          trafficTelemetryEnabled: request.trafficTelemetryEnabled ?? policy.trafficTelemetryEnabled,
          integrityWatchEnabled: request.integrityWatchEnabled ?? policy.integrityWatchEnabled,
          privilegeHardeningEnabled: request.privilegeHardeningEnabled ?? policy.privilegeHardeningEnabled,
          pamLiteEnabled: request.pamLiteEnabled ?? policy.pamLiteEnabled,
          denyHighRiskElevation: request.denyHighRiskElevation ?? policy.denyHighRiskElevation,
          denyUnsignedElevation: request.denyUnsignedElevation ?? policy.denyUnsignedElevation,
          requireBreakGlassEscrow: request.requireBreakGlassEscrow ?? policy.requireBreakGlassEscrow,
          suppressionPathRoots: policy.suppressionPathRoots,
          suppressionSha256: policy.suppressionSha256,
          suppressionSignerNames: policy.suppressionSignerNames,
          revision: buildPolicyRevision(timestamp),
          updatedAt: timestamp
        });

        for (const device of state.devices) {
          if (device.policyId === policy.id) {
            device.policyName = policy.name;
          }
        }

        if (policy.isDefault) {
          state.defaultPolicy = toPolicySummary(policy);
        }

        for (const device of state.devices) {
          if (device.policyId === policy.id) {
            recalculateDeviceScoreSnapshot(state, device, timestamp);
          }
        }

        recordAdminAuditEvent(state, {
          occurredAt: timestamp,
          actorId: principal.id,
          actorName: principal.displayName,
          actorType: actor.actorType,
          action: "policy.update",
          resourceType: "policy",
          resourceId: policy.id,
          outcome: "success",
          severity: "medium",
          details: `Updated policy ${policy.name}.`,
          source: "control-plane",
          sessionId: actor.sessionId
        });

        return policy;
      });
    },

    async assignPolicy(policyId, request, actor) {
      return mutateState(async (state) => {
        if (!actor || !hasAdminRole(actor, ["admin", "operator"])) {
          throw new AdminAuthorizationError();
        }

        const principal = findAdminPrincipalById(state, actor.actorId);
        if (!principal || !principal.enabled) {
          throw new AdminAuthorizationError();
        }

        const policy = findPolicyOrThrow(state, policyId);
        const timestamp = now();

        for (const deviceId of request.deviceIds) {
          const device = findDeviceOrThrow(state, deviceId);
          device.policyId = policy.id;
          device.policyName = policy.name;
          device.lastPolicySyncAt = timestamp;
          recalculateDeviceScoreSnapshot(state, device, timestamp);
        }

        policy.updatedAt = timestamp;
        syncPolicyAssignments(state);

        recordAdminAuditEvent(state, {
          occurredAt: timestamp,
          actorId: principal.id,
          actorName: principal.displayName,
          actorType: actor.actorType,
          action: "policy.assign",
          resourceType: "policy",
          resourceId: policy.id,
          outcome: "success",
          severity: "medium",
          details: `Assigned policy ${policy.name} to ${request.deviceIds.length} device(s).`,
          source: "control-plane",
          sessionId: actor.sessionId
        });
        return policy;
      });
    },

    async listScripts() {
      const state = await loadState();
      return sortScripts(state.scripts);
    },

    async createScript(request, actor) {
      return mutateState(async (state) => {
        if (!actor || !hasAdminRole(actor, ["admin"])) {
          throw new AdminAuthorizationError();
        }

        const principal = findAdminPrincipalById(state, actor.actorId);
        if (!principal || !principal.enabled) {
          throw new AdminAuthorizationError();
        }

        const timestamp = now();
        const created: ScriptSummary = {
          id: randomUUID(),
          name: request.name,
          description: request.description?.trim() || `${request.name} automation`,
          language: request.language,
          content: request.content,
          createdAt: timestamp,
          updatedAt: timestamp
        };
        state.scripts.push(created);
        recordAdminAuditEvent(state, {
          occurredAt: timestamp,
          actorId: principal.id,
          actorName: principal.displayName,
          actorType: actor.actorType,
          action: "script.create",
          resourceType: "script",
          resourceId: created.id,
          outcome: "success",
          severity: "medium",
          details: `Created script ${created.name}.`,
          source: "control-plane",
          sessionId: actor.sessionId
        });
        return created;
      });
    },

    async updateScript(scriptId, request, actor) {
      return mutateState(async (state) => {
        if (!actor || !hasAdminRole(actor, ["admin"])) {
          throw new AdminAuthorizationError();
        }

        const principal = findAdminPrincipalById(state, actor.actorId);
        if (!principal || !principal.enabled) {
          throw new AdminAuthorizationError();
        }

        const script = findScriptOrThrow(state, scriptId);
        script.name = request.name?.trim() || script.name;
        script.description = request.description?.trim() || script.description;
        script.language = request.language ?? script.language;
        script.content = request.content ?? script.content;
        const timestamp = now();
        script.updatedAt = timestamp;

        recordAdminAuditEvent(state, {
          occurredAt: timestamp,
          actorId: principal.id,
          actorName: principal.displayName,
          actorType: actor.actorType,
          action: "script.update",
          resourceType: "script",
          resourceId: script.id,
          outcome: "success",
          severity: "medium",
          details: `Updated script ${script.name}.`,
          source: "control-plane",
          sessionId: actor.sessionId
        });
        return script;
      });
    },

    async upsertDeviceRiskTelemetry(deviceId, request) {
      return mutateState(async (state) => {
        const device = findDeviceOrThrow(state, deviceId);
        const timestamp = now();
        const existing = findDeviceRiskTelemetry(state, deviceId);
        const next: DeviceRiskTelemetrySnapshot = {
          ...(existing ?? {
            deviceId,
            hostname: device.hostname,
            updatedAt: timestamp,
            source: request.source?.trim() || "manual"
          }),
          ...request,
          deviceId,
          hostname: device.hostname,
          updatedAt: timestamp,
          source: request.source?.trim() || existing?.source || "manual",
          tacticIds: request.tacticIds ?? existing?.tacticIds ?? [],
          techniqueIds: request.techniqueIds ?? existing?.techniqueIds ?? []
        };

        if (existing) {
          Object.assign(existing, next);
        } else {
          state.deviceRiskTelemetry.push(next);
        }

        recalculateDeviceScoreSnapshot(state, device, timestamp);
        return existing ?? next;
      });
    },

    async recalculateDeviceScore(deviceId) {
      return mutateState(async (state) => {
        const device = findDeviceOrThrow(state, deviceId);
        return recalculateDeviceScoreSnapshot(state, device, now());
      });
    },

    async getLatestDeviceScore(deviceId) {
      const state = await loadState();
      findDeviceOrThrow(state, deviceId);
      const score = findLatestDeviceScore(state, deviceId);
      if (!score) {
        throw new DeviceNotFoundError(deviceId);
      }

      return score;
    },

    async listDeviceScoreHistory(deviceId, limit = 30) {
      const state = await loadState();
      findDeviceOrThrow(state, deviceId);
      return sortDeviceScoreHistory(state.deviceScoreHistory.filter((item) => item.deviceId === deviceId)).slice(0, limit);
    },

    async getDeviceRiskSummary(deviceId) {
      const state = await loadState();
      const device = findDeviceOrThrow(state, deviceId);
      const score = findLatestDeviceScore(state, deviceId) ?? recalculateDeviceScoreSnapshot(state, device, now());
      return {
        deviceId,
        summary: summarizeDeviceRisk(score),
        explanation: explainDeviceRisk(score),
        score
      };
    },

    async getDevicePrivilegeBaseline(deviceId) {
      const state = await loadState();
      findDeviceOrThrow(state, deviceId);
      return findPrivilegeBaseline(state, deviceId);
    },

    async getDevicePrivilegeState(deviceId) {
      const state = await loadState();
      findDeviceOrThrow(state, deviceId);
      return findPrivilegeState(state, deviceId);
    },

    async listDevicePrivilegeEvents(deviceId, limit = 50) {
      const state = await loadState();
      findDeviceOrThrow(state, deviceId);
      return sortPrivilegeEvents(state.privilegeEvents.filter((item) => item.deviceId === deviceId)).slice(0, limit);
    },

    async enforceDevicePrivilegeHardening(deviceId, request, actor) {
      return mutateState(async (state) => {
        if (!actor || !hasAdminRole(actor, ["admin", "operator"])) {
          throw new AdminAuthorizationError();
        }

        const principal = findAdminPrincipalById(state, actor.actorId);
        if (!principal || !principal.enabled) {
          throw new AdminAuthorizationError();
        }

        const device = findDeviceOrThrow(state, deviceId);
        const policy = state.policies.find((item) => item.id === device.policyId);
        const timestamp = now();
        const mode: PrivilegeHardeningMode = policy?.pamLiteEnabled ? "restricted" : "enforce";
        return applyPrivilegeHardeningAction(state, device, timestamp, {
          type: "privilege.enforce",
          kind: "hardening.applied",
          issuedBy: request.issuedBy,
          reason: request.reason,
          mode,
          pamEnforcementEnabled: true,
          summary: mode === "restricted"
            ? "PAM-lite hardening applied; standing administrator access is now restricted through the recovery path."
            : "Privilege hardening applied; standing administrator access is being brokered through controlled elevation."
        }, actor);
      });
    },

    async recoverDevicePrivilegeHardening(deviceId, request, actor) {
      return mutateState(async (state) => {
        if (!actor || !hasAdminRole(actor, ["admin", "operator"])) {
          throw new AdminAuthorizationError();
        }

        const principal = findAdminPrincipalById(state, actor.actorId);
        if (!principal || !principal.enabled) {
          throw new AdminAuthorizationError();
        }

        const device = findDeviceOrThrow(state, deviceId);
        const policy = state.policies.find((item) => item.id === device.policyId);
        const timestamp = now();
        const mode: PrivilegeHardeningMode = policy?.privilegeHardeningEnabled
          ? policy.pamLiteEnabled
            ? "restricted"
            : "enforce"
          : "monitor_only";
        return applyPrivilegeHardeningAction(state, device, timestamp, {
          type: "privilege.recover",
          kind: "recovery.applied",
          issuedBy: request.issuedBy,
          reason: request.reason,
          mode,
          pamEnforcementEnabled: policy?.privilegeHardeningEnabled ?? false,
          summary:
            mode === "monitor_only"
              ? "Privilege recovery completed and the endpoint has returned to monitored access with break-glass escrow intact."
              : "Privilege recovery completed and hardening remains in effect with a recoverable administrative path intact."
        }, actor);
      });
    },

    async enrollDevice(request, observedRemoteAddress) {
      return mutateState(async (state) => {
        const issuedAt = now();
        const defaultPolicy = state.policies.find((item) => item.isDefault) ?? state.policies[0];
        const normalizedSerialNumber = normalizeDeviceSerialNumber(request.serialNumber);
        const existingDevice =
          normalizedSerialNumber === null
            ? undefined
            : state.devices.find((item) => normalizeDeviceSerialNumber(item.serialNumber) === normalizedSerialNumber);
        const deviceId = existingDevice?.id ?? randomUUID();

        if (existingDevice) {
          existingDevice.hostname = request.hostname;
          existingDevice.osVersion = request.osVersion;
          existingDevice.lastSeenAt = issuedAt;
          existingDevice.healthState = "healthy";
          existingDevice.isolated = false;
          applyObservedRemoteAddress(existingDevice, observedRemoteAddress);
          recalculateDeviceScoreSnapshot(state, existingDevice, issuedAt);
          return {
            deviceId,
            issuedAt,
            policy: toPolicySummary(defaultPolicy),
            commandChannelUrl
          };
        }

        const device: DeviceRecord = {
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
          policyId: defaultPolicy.id,
          policyName: defaultPolicy.name,
          privateIpAddresses: [],
          publicIpAddress: null,
          lastLoggedOnUser: null,
          installedSoftware: []
        };
        applyObservedRemoteAddress(device, observedRemoteAddress);
        state.devices.push(device);
        recalculateDeviceScoreSnapshot(state, device, issuedAt);

        return {
          deviceId,
          issuedAt,
          policy: toPolicySummary(defaultPolicy),
          commandChannelUrl
        };
      });
    },

    async recordHeartbeat(deviceId, request, observedRemoteAddress) {
      return mutateState(async (state) => {
        const device = findDeviceOrThrow(state, deviceId);
        const receivedAt = now();
        device.agentVersion = request.agentVersion;
        device.platformVersion = request.platformVersion;
        device.healthState = request.healthState;
        device.isolated = request.isolated;
        device.lastSeenAt = receivedAt;
        applyObservedRemoteAddress(device, observedRemoteAddress);

        const posture = getOrCreateDevicePosture(state, device, receivedAt);
        posture.hostname = device.hostname;
        posture.updatedAt = receivedAt;
        posture.isolationState = request.isolated ? "active" : "inactive";
        posture.isolationSummary = request.isolated
          ? "Heartbeat reported that host isolation is active."
          : "Heartbeat reported that host isolation is inactive.";
        recomputePosture(posture);
        recalculateDeviceScoreSnapshot(state, device, receivedAt);

        const effectivePolicy = state.policies.find((item) => item.id === device.policyId) ?? (state.policies[0] as PolicyProfile);
        return {
          deviceId,
          receivedAt,
          effectivePolicyRevision: effectivePolicy.revision,
          commandsPending: state.commands.filter((item) => item.deviceId === deviceId && item.status === "pending").length
        };
      });
    },

    async policyCheckIn(deviceId, request, observedRemoteAddress) {
      return mutateState(async (state) => {
        const device = findDeviceOrThrow(state, deviceId);
        const retrievedAt = now();
        device.lastSeenAt = retrievedAt;
        device.lastPolicySyncAt = retrievedAt;
        applyObservedRemoteAddress(device, observedRemoteAddress);
        if (request.agentVersion) {
          device.agentVersion = request.agentVersion;
        }
        if (request.platformVersion) {
          device.platformVersion = request.platformVersion;
        }

        const effectivePolicy = state.policies.find((item) => item.id === device.policyId) ?? (state.policies[0] as PolicyProfile);
        recalculateDeviceScoreSnapshot(state, device, retrievedAt);
        return {
          deviceId,
          retrievedAt,
          changed: request.currentPolicyRevision !== effectivePolicy.revision,
          policy: toPolicySummary(effectivePolicy)
        };
      });
    },

    async ingestTelemetry(deviceId, request, observedRemoteAddress) {
      return mutateState(async (state) => {
        const device = findDeviceOrThrow(state, deviceId);
        const receivedAt = now();
        applyObservedRemoteAddress(device, observedRemoteAddress);
        const existingIds = new Set(
          state.telemetry.filter((item) => item.deviceId === deviceId).map((item) => item.eventId)
        );

        const acceptedRecords: TelemetryRecord[] = [];
        for (const event of request.events) {
          if (existingIds.has(event.eventId)) {
            continue;
          }

          const record = normalizeTelemetryRecord(
            {
              ...event,
              deviceId,
              hostname: device.hostname,
              ingestedAt: receivedAt
            },
            new Map([[device.id, device.hostname]]),
            receivedAt
          );
          acceptedRecords.push(record);
          state.telemetry.push(record);
          updateQuarantineInventory(state, record);
          updateEvidenceInventory(state, record);
          updateScanHistory(state, record);
          updateDevicePosture(state, device, record);
          updateDeviceInventory(state, device, record);
          updateRiskTelemetryFromTelemetry(state, device, record);
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

        recalculateDeviceScoreSnapshot(state, device, receivedAt);

        return {
          deviceId,
          accepted: acceptedRecords.length,
          receivedAt,
          totalStored: state.telemetry.length
        };
      });
    },

    async queueCommand(deviceId, request, actor) {
      return mutateState(async (state) => {
        if (actor) {
          const principal = findAdminPrincipalById(state, actor.actorId);
          if (!principal || !principal.enabled || !hasAdminRole(actor, ["admin", "operator"])) {
            throw new AdminAuthorizationError();
          }
        }

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
          recordId: request.recordId,
          payloadJson: request.payloadJson
        };
        state.commands.push(command);

        if (actor) {
          const principal = findAdminPrincipalById(state, actor.actorId);
          if (principal) {
            recordAdminAuditEvent(state, {
              occurredAt: createdAt,
              actorId: principal.id,
              actorName: principal.displayName,
              actorType: actor.actorType,
              action: "command.queue",
              resourceType: "device_command",
              resourceId: command.id,
              outcome: "success",
              severity: "medium",
              details: `Queued ${command.type} for ${device.hostname}.`,
              source: "control-plane",
              sessionId: actor.sessionId
            });
          }
        }
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
        recalculateDeviceScoreSnapshot(state, device, completedAt);
        return command;
      });
    }
  };
}
