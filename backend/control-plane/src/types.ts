export type DeviceHealthState = "healthy" | "degraded" | "isolated";
export type AlertSeverity = "low" | "medium" | "high" | "critical";
export type AlertStatus = "new" | "triaged" | "contained";
export type PostureState = "ready" | "degraded" | "failed" | "unknown";
export type IsolationState = "active" | "inactive" | "error" | "unknown";
export type CommandType =
  | "device.isolate"
  | "device.release"
  | "scan.targeted"
  | "quarantine.restore"
  | "quarantine.delete"
  | "update.apply"
  | "update.rollback"
  | "agent.repair"
  | "process.terminate"
  | "process.tree.terminate"
  | "persistence.cleanup"
  | "remediate.path"
  | "script.run"
  | "software.uninstall"
  | "software.update"
  | "software.update.search"
  | "software.block";
export type CommandStatus = "pending" | "in_progress" | "completed" | "failed";
export type QuarantineStatus = "quarantined" | "restored" | "deleted";
export type MailDirection = "inbound" | "outbound";
export type MailDomainHealthStatus = "ready" | "degraded" | "pending";
export type MailVerificationStatus = "verified" | "pending" | "failed";
export type MailVerdict = "clean" | "spam" | "phish" | "malware" | "suspicious";
export type MailDeliveryAction = "delivered" | "quarantined" | "rejected" | "held" | "junked" | "purged";
export type MailQuarantineStatus = "quarantined" | "released" | "purged";
export type MailAuthResult = "pass" | "fail" | "softfail" | "none";
export type MailActionType = "quarantine.release" | "message.purge";
export type MailActionStatus = "completed" | "failed";

export interface PolicySummary {
  id: string;
  name: string;
  revision: string;
  realtimeProtection: boolean;
  cloudLookup: boolean;
  scriptInspection: boolean;
  networkContainment: boolean;
  quarantineOnMalicious: boolean;
}

export interface PolicyProfile extends PolicySummary {
  description: string;
  isDefault: boolean;
  assignedDeviceIds: string[];
  createdAt: string;
  updatedAt: string;
}

export interface ScriptSummary {
  id: string;
  name: string;
  description: string;
  language: "powershell" | "cmd";
  content: string;
  createdAt: string;
  updatedAt: string;
  lastExecutedAt?: string;
}

export type SoftwareUpdateState = "unknown" | "checking" | "available" | "current" | "error";

export interface InstalledSoftwareSummary {
  id: string;
  displayName: string;
  displayVersion: string;
  publisher: string;
  installLocation?: string;
  uninstallCommand?: string;
  quietUninstallCommand?: string;
  installDate?: string;
  displayIconPath?: string;
  executableNames: string[];
  blocked: boolean;
  updateState: SoftwareUpdateState;
  lastUpdateCheckAt?: string;
  updateSummary?: string;
}

export interface DeviceSummary {
  id: string;
  hostname: string;
  osVersion: string;
  agentVersion: string;
  platformVersion: string;
  serialNumber: string;
  enrolledAt: string;
  lastSeenAt: string;
  lastPolicySyncAt: string | null;
  lastTelemetryAt: string | null;
  healthState: DeviceHealthState;
  isolated: boolean;
  policyId: string;
  policyName: string;
  openAlertCount: number;
  quarantinedItemCount: number;
  postureState: PostureState;
  privateIpAddresses: string[];
  publicIpAddress: string | null;
  lastLoggedOnUser: string | null;
}

export interface AlertSummary {
  id: string;
  deviceId?: string;
  title: string;
  severity: AlertSeverity;
  status: AlertStatus;
  hostname: string;
  detectedAt: string;
  technique?: string;
  summary: string;
  fingerprint?: string;
}

export interface DashboardSnapshot {
  generatedAt: string;
  devices: DeviceSummary[];
  alerts: AlertSummary[];
  recentTelemetry: TelemetryRecord[];
  recentCommands: DeviceCommandSummary[];
  quarantineItems: QuarantineItemSummary[];
  recentEvidence: EvidenceSummary[];
  recentScanHistory: ScanHistorySummary[];
  postureOverview: DevicePostureSummary[];
  defaultPolicy: PolicySummary;
  policies: PolicyProfile[];
  scripts: ScriptSummary[];
}

export interface MailPolicySummary {
  id: string;
  name: string;
  revision: string;
  defaultAction: MailDeliveryAction;
  urlRewriteEnabled: boolean;
  attachmentScanningEnabled: boolean;
  impersonationProtectionEnabled: boolean;
  quarantineRetentionDays: number;
}

export interface MailAuthSummary {
  spf: MailAuthResult;
  dkim: MailAuthResult;
  dmarc: MailAuthResult;
  arc: MailAuthResult;
}

export interface MailAttachmentSummary {
  id: string;
  fileName: string;
  sha256: string;
  sizeBytes: number;
  verdict: MailVerdict;
}

export interface MailUrlSummary {
  id: string;
  originalUrl: string;
  verdict: MailVerdict;
  rewriteApplied: boolean;
}

export interface MailDomainSummary {
  id: string;
  domain: string;
  status: MailDomainHealthStatus;
  verificationStatus: MailVerificationStatus;
  mxRecordsConfigured: boolean;
  downstreamRoute: string;
  activeMessageCount: number;
  quarantinedMessageCount: number;
  lastMessageAt: string | null;
}

export interface MailMessageSummary {
  id: string;
  mailDomainId: string;
  domain: string;
  internetMessageId: string;
  direction: MailDirection;
  subject: string;
  sender: string;
  recipients: string[];
  verdict: MailVerdict;
  deliveryAction: MailDeliveryAction;
  receivedAt: string;
  deliveredAt: string | null;
  summary: string;
  auth: MailAuthSummary;
  attachments: MailAttachmentSummary[];
  urls: MailUrlSummary[];
  relatedAlertId?: string;
  relatedDeviceId?: string;
  relatedUser?: string;
}

export interface MailQuarantineItemSummary {
  id: string;
  mailMessageId: string;
  domain: string;
  subject: string;
  sender: string;
  recipientSummary: string;
  reason: string;
  status: MailQuarantineStatus;
  quarantinedAt: string;
  releasedAt: string | null;
}

export interface MailActionRecord {
  id: string;
  mailMessageId: string;
  actionType: MailActionType;
  requestedBy: string;
  requestedAt: string;
  status: MailActionStatus;
  resultSummary: string;
}

export interface MailDashboardSnapshot {
  generatedAt: string;
  domains: MailDomainSummary[];
  recentMessages: MailMessageSummary[];
  quarantineItems: MailQuarantineItemSummary[];
  recentActions: MailActionRecord[];
  defaultPolicy: MailPolicySummary;
}

export interface EnrollmentRequest {
  hostname: string;
  osVersion: string;
  serialNumber: string;
}

export interface EnrollmentResponse {
  deviceId: string;
  deviceApiKey?: string;
  issuedAt: string;
  policy: PolicySummary;
  commandChannelUrl: string;
}

export interface DeviceRecord {
  id: string;
  hostname: string;
  osVersion: string;
  agentVersion: string;
  platformVersion: string;
  serialNumber: string;
  enrolledAt: string;
  lastSeenAt: string;
  lastPolicySyncAt: string | null;
  lastTelemetryAt: string | null;
  healthState: DeviceHealthState;
  isolated: boolean;
  policyId: string;
  policyName: string;
  privateIpAddresses: string[];
  publicIpAddress: string | null;
  lastLoggedOnUser: string | null;
  installedSoftware: InstalledSoftwareSummary[];
}

export interface HeartbeatRequest {
  agentVersion: string;
  platformVersion: string;
  healthState: DeviceHealthState;
  isolated: boolean;
}

export interface HeartbeatResponse {
  deviceId: string;
  receivedAt: string;
  effectivePolicyRevision: string;
  commandsPending: number;
}

export interface PolicyCheckInRequest {
  currentPolicyRevision?: string;
  agentVersion?: string;
  platformVersion?: string;
}

export interface PolicyCheckInResponse {
  deviceId: string;
  retrievedAt: string;
  changed: boolean;
  policy: PolicySummary;
}

export interface ControlPlaneState {
  defaultPolicy: PolicySummary;
  policies: PolicyProfile[];
  scripts: ScriptSummary[];
  devices: DeviceRecord[];
  alerts: AlertSummary[];
  telemetry: TelemetryRecord[];
  commands: DeviceCommandSummary[];
  quarantineItems: QuarantineItemSummary[];
  evidence: EvidenceSummary[];
  scanHistory: ScanHistorySummary[];
  devicePosture: DevicePostureSummary[];
}

export interface MailState {
  defaultPolicy: MailPolicySummary;
  domains: MailDomainSummary[];
  messages: MailMessageSummary[];
  quarantineItems: MailQuarantineItemSummary[];
  actionRecords: MailActionRecord[];
}

export interface DeviceCommandSummary {
  id: string;
  deviceId: string;
  hostname: string;
  type: CommandType;
  status: CommandStatus;
  createdAt: string;
  updatedAt: string;
  issuedBy: string;
  targetPath?: string;
  recordId?: string;
  payloadJson?: string;
  resultJson?: string;
}

export interface QuarantineItemSummary {
  recordId: string;
  deviceId: string;
  hostname: string;
  originalPath: string;
  quarantinedPath: string;
  sha256: string;
  sizeBytes: number;
  capturedAt: string;
  lastUpdatedAt: string;
  evidenceRecordId?: string;
  technique?: string;
  status: QuarantineStatus;
}

export interface TelemetryBatchEvent {
  eventId: string;
  eventType: string;
  source: string;
  summary: string;
  occurredAt: string;
  payloadJson: string;
}

export interface TelemetryBatchRequest {
  events: TelemetryBatchEvent[];
}

export interface TelemetryBatchResponse {
  deviceId: string;
  accepted: number;
  receivedAt: string;
  totalStored: number;
}

export interface TelemetryRecord extends TelemetryBatchEvent {
  deviceId: string;
  hostname: string;
  ingestedAt: string;
}

export interface EvidenceSummary {
  recordId: string;
  deviceId: string;
  hostname: string;
  recordedAt: string;
  source: string;
  subjectPath: string;
  sha256: string;
  disposition: string;
  tacticId?: string;
  techniqueId?: string;
  contentType?: string;
  reputation?: string;
  signer?: string;
  quarantineRecordId?: string;
  summary: string;
}

export interface ScanHistorySummary {
  eventId: string;
  deviceId: string;
  hostname: string;
  scannedAt: string;
  source: string;
  subjectPath: string;
  sha256: string;
  contentType?: string;
  reputation?: string;
  signer?: string;
  heuristicScore?: number;
  archiveEntryCount?: number;
  disposition: string;
  confidence?: number;
  tacticId?: string;
  techniqueId?: string;
  remediationStatus?: string;
  remediationError?: string;
  evidenceRecordId?: string;
  quarantineRecordId?: string;
  summary: string;
}

export interface DevicePostureSummary {
  deviceId: string;
  hostname: string;
  updatedAt: string;
  overallState: PostureState;
  tamperProtectionState: PostureState;
  tamperProtectionSummary?: string;
  wscState: PostureState;
  wscSummary?: string;
  etwState: PostureState;
  etwSummary?: string;
  wfpState: PostureState;
  wfpSummary?: string;
  isolationState: IsolationState;
  isolationSummary?: string;
  registryConfigured?: boolean;
  runtimePathsProtected?: boolean;
  uninstallProtectionEnabled?: boolean;
  elamDriverPresent?: boolean;
  elamCertificateInstalled?: boolean;
  launchProtectedConfigured?: boolean;
  wscAvailable?: boolean;
  providerHealth?: string;
}

export interface DeviceDetail {
  device: DeviceSummary;
  posture: DevicePostureSummary | null;
  alerts: AlertSummary[];
  telemetry: TelemetryRecord[];
  commands: DeviceCommandSummary[];
  quarantineItems: QuarantineItemSummary[];
  evidence: EvidenceSummary[];
  scanHistory: ScanHistorySummary[];
  installedSoftware: InstalledSoftwareSummary[];
}

export interface QueueCommandRequest {
  type: CommandType;
  issuedBy?: string;
  targetPath?: string;
  recordId?: string;
  payloadJson?: string;
}

export interface CreatePolicyRequest {
  name: string;
  description?: string;
  realtimeProtection: boolean;
  cloudLookup: boolean;
  scriptInspection: boolean;
  networkContainment: boolean;
  quarantineOnMalicious: boolean;
}

export interface UpdatePolicyRequest extends Partial<CreatePolicyRequest> {}

export interface PolicyAssignmentRequest {
  deviceIds: string[];
}

export interface CreateScriptRequest {
  name: string;
  description?: string;
  language: "powershell" | "cmd";
  content: string;
}

export interface UpdateScriptRequest extends Partial<CreateScriptRequest> {}

export interface PollCommandsResponse {
  deviceId: string;
  polledAt: string;
  items: DeviceCommandSummary[];
}

export interface CompleteCommandRequest {
  status: Extract<CommandStatus, "completed" | "failed">;
  resultJson?: string;
}

export interface SimulatedMailAttachmentInput {
  fileName: string;
  sha256: string;
  sizeBytes: number;
  verdict: MailVerdict;
}

export interface SimulatedMailUrlInput {
  originalUrl: string;
  verdict: MailVerdict;
  rewriteApplied?: boolean;
}

export interface SimulatedInboundMailRequest {
  mailDomainId?: string;
  sender: string;
  recipients: string[];
  subject: string;
  summary?: string;
  verdict: MailVerdict;
  deliveryAction: MailDeliveryAction;
  relatedAlertId?: string;
  relatedDeviceId?: string;
  relatedUser?: string;
  attachments?: SimulatedMailAttachmentInput[];
  urls?: SimulatedMailUrlInput[];
  auth?: Partial<MailAuthSummary>;
}
