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
  | "privilege.elevation.request"
  | "privilege.enforce"
  | "privilege.recover"
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
export type AdminRole = "admin" | "analyst" | "operator" | "read_only" | "automation";
export type AdminActorType = "user" | "api_key" | "session" | "system" | "anonymous";

export interface AdminPrincipalRecord {
  id: string;
  username: string;
  displayName: string;
  passwordSalt: string;
  passwordHash: string;
  mfaSecret: string;
  roles: AdminRole[];
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
  lastLoginAt?: string;
}

export interface AdminPrincipalSummary {
  id: string;
  username: string;
  displayName: string;
  roles: AdminRole[];
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
  lastLoginAt?: string;
}

export interface AdminSessionRecord {
  id: string;
  principalId: string;
  tokenHash: string;
  createdAt: string;
  expiresAt: string;
  lastSeenAt: string;
  revokedAt?: string;
  sourceIp?: string;
  userAgent?: string;
}

export interface AdminSessionSummary {
  id: string;
  principalId: string;
  principalUsername: string;
  principalDisplayName: string;
  principalRoles: AdminRole[];
  createdAt: string;
  expiresAt: string;
  lastSeenAt: string;
  revokedAt?: string;
  sourceIp?: string;
  userAgent?: string;
}

export interface AdminApiKeyRecord {
  id: string;
  principalId: string;
  name: string;
  scopes: string[];
  tokenHash: string;
  createdAt: string;
  updatedAt: string;
  revokedAt?: string;
  lastUsedAt?: string;
  sourceIp?: string;
}

export interface AdminApiKeySummary {
  id: string;
  principalId: string;
  principalUsername: string;
  principalDisplayName: string;
  name: string;
  scopes: string[];
  createdAt: string;
  updatedAt: string;
  revokedAt?: string;
  lastUsedAt?: string;
  sourceIp?: string;
}

export interface AdminAuditEventSummary {
  id: string;
  occurredAt: string;
  actorId?: string;
  actorName: string;
  actorType: AdminActorType;
  action: string;
  resourceType?: string;
  resourceId?: string;
  outcome: "success" | "failure";
  severity: AlertSeverity;
  details: string;
  source: string;
  sessionId?: string;
  ipAddress?: string;
}

export interface AdminActorContext {
  actorId: string;
  actorName: string;
  actorType: AdminActorType;
  roles: AdminRole[];
  sessionId?: string;
}

export interface AdminLoginRequest {
  username: string;
  password: string;
  mfaCode: string;
  sessionMinutes?: number;
}

export interface AdminLoginResponse {
  accessToken: string;
  principal: AdminPrincipalSummary;
  session: AdminSessionSummary;
}

export interface AdminApiKeyCreateRequest {
  name: string;
  scopes: string[];
  sessionMinutes?: number;
}

export interface AdminApiKeyCreateResponse {
  accessKey: string;
  apiKey: AdminApiKeySummary;
}

export interface PolicySummary {
  id: string;
  name: string;
  revision: string;
  realtimeProtection: boolean;
  cloudLookup: boolean;
  scriptInspection: boolean;
  networkContainment: boolean;
  quarantineOnMalicious: boolean;
  dnsGuardEnabled: boolean;
  trafficTelemetryEnabled: boolean;
  integrityWatchEnabled: boolean;
  privilegeHardeningEnabled: boolean;
  pamLiteEnabled: boolean;
  denyHighRiskElevation: boolean;
  denyUnsignedElevation: boolean;
  requireBreakGlassEscrow: boolean;
  suppressionPathRoots: string[];
  suppressionSha256: string[];
  suppressionSignerNames: string[];
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
export type RiskBand = "low" | "guarded" | "elevated" | "high" | "critical";
export type RiskCategoryKey =
  | "patch_posture"
  | "software_hygiene"
  | "threat_activity"
  | "exposure"
  | "network_behaviour"
  | "control_health"
  | "identity_posture";

export type PrivilegeHardeningMode = "monitor_only" | "enforce" | "restricted" | "recovery";

export interface PrivilegeAccountSummary {
  name: string;
  source: "local" | "domain" | "service";
  enabled: boolean;
  authorized: boolean;
}

export interface PrivilegeBaselineSnapshot {
  deviceId: string;
  hostname: string;
  capturedAt: string;
  localUsers: PrivilegeAccountSummary[];
  localAdministrators: PrivilegeAccountSummary[];
  domainLinkedAdminMemberships: Array<{
    name: string;
    group: string;
    source: "local" | "domain";
  }>;
  breakGlassAccountName: string;
  breakGlassAccountEnabled: boolean;
  recoveryCredentialEscrowed: boolean;
  recoveryCredentialLastRotatedAt?: string;
}

export type PrivilegeEventKind =
  | "baseline.captured"
  | "admin.added"
  | "admin.removed"
  | "admin.reenabled"
  | "elevation.requested"
  | "elevation.approved"
  | "elevation.denied"
  | "breakglass.used"
  | "hardening.applied"
  | "recovery.applied"
  | "hardening.tamper";

export interface PrivilegeEventSummary {
  id: string;
  deviceId: string;
  hostname: string;
  recordedAt: string;
  kind: PrivilegeEventKind;
  subject?: string;
  actor?: string;
  severity: AlertSeverity;
  source: string;
  summary: string;
}

export interface PrivilegeStateSnapshot {
  deviceId: string;
  hostname: string;
  updatedAt: string;
  privilegeHardeningMode: PrivilegeHardeningMode;
  pamEnforcementEnabled: boolean;
  standingAdminPresentFlag: boolean;
  unapprovedAdminAccountCount: number;
  adminGroupTamperIndicator: boolean;
  directAdminLogonAttemptCount_7d: number;
  breakGlassAccountUsageIndicator: boolean;
  unauthorisedAdminReenableIndicator: boolean;
  recoveryPathExists: boolean;
  lastEnforcedAt?: string;
  lastRecoveredAt?: string;
  lastBreakGlassUsedAt?: string;
  summary: string;
  recommendedActions: string[];
}

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

export interface DeviceRiskTelemetrySnapshot {
  deviceId: string;
  hostname: string;
  updatedAt: string;
  source: string;
  os_patch_age_days?: number;
  critical_patches_overdue_count?: number;
  high_patches_overdue_count?: number;
  known_exploited_vuln_count?: number;
  internet_exposed_unpatched_critical_count?: number;
  unsupported_software_count?: number;
  outdated_browser_count?: number;
  outdated_high_risk_app_count?: number;
  untrusted_or_unsigned_software_count?: number;
  active_malware_count?: number;
  quarantined_threat_count_7d?: number;
  persistent_threat_count?: number;
  ransomware_behaviour_flag?: boolean;
  lateral_movement_indicator?: boolean;
  open_port_count?: number;
  risky_open_port_count?: number;
  internet_exposed_admin_service_count?: number;
  smb_exposed_flag?: boolean;
  rdp_exposed_flag?: boolean;
  malicious_domain_contacts_7d?: number;
  suspicious_domain_contacts_7d?: number;
  dns_query_count_7d?: number;
  dns_blocked_count_7d?: number;
  malicious_destination_count_7d?: number;
  suspicious_destination_count_7d?: number;
  c2_beacon_indicator?: boolean;
  data_exfiltration_indicator?: boolean;
  unusual_egress_indicator?: boolean;
  file_integrity_change_count_7d?: number;
  protected_file_change_count_7d?: number;
  edr_enabled?: boolean;
  av_enabled?: boolean;
  firewall_enabled?: boolean;
  disk_encryption_enabled?: boolean;
  tamper_protection_enabled?: boolean;
  local_admin_users_count?: number;
  standing_admin_present_flag?: boolean;
  unapproved_admin_account_count?: number;
  admin_group_tamper_indicator?: boolean;
  direct_admin_logon_attempt_count_7d?: number;
  break_glass_account_usage_indicator?: boolean;
  pam_enforcement_enabled?: boolean;
  privilege_hardening_mode?: PrivilegeHardeningMode;
  unauthorised_admin_reenable_indicator?: boolean;
  recovery_path_exists?: boolean;
  risky_signin_indicator?: boolean;
  stolen_token_indicator?: boolean;
  mfa_gap_indicator?: boolean;
  tacticIds?: string[];
  techniqueIds?: string[];
}

export interface DeviceRiskCategoryScore {
  category: RiskCategoryKey;
  weight: number;
  score: number;
  contribution: number;
}

export interface RiskDriverSummary {
  id: string;
  category: RiskCategoryKey;
  title: string;
  detail: string;
  scoreImpact: number;
  severity: AlertSeverity;
  tacticIds: string[];
  techniqueIds: string[];
}

export interface DeviceScoreSnapshot {
  id: string;
  deviceId: string;
  hostname: string;
  calculatedAt: string;
  telemetryUpdatedAt?: string;
  telemetrySource?: string;
  overallScore: number;
  riskBand: RiskBand;
  confidenceScore: number;
  categoryScores: DeviceRiskCategoryScore[];
  topRiskDrivers: RiskDriverSummary[];
  overrideReasons: string[];
  recommendedActions: string[];
  missingTelemetryFields: string[];
  tacticIds: string[];
  techniqueIds: string[];
  summary: string;
  analystSummary: string;
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
  riskScore: number | null;
  riskBand: RiskBand | null;
  confidenceScore: number | null;
}

export interface AlertSummary {
  id: string;
  deviceId?: string;
  title: string;
  severity: AlertSeverity;
  status: AlertStatus;
  hostname: string;
  detectedAt: string;
  tacticId?: string;
  technique?: string;
  summary: string;
  fingerprint?: string;
}

export interface AlertBehaviorChainStep {
  id: string;
  occurredAt: string;
  category: "alert" | "process" | "module" | "script" | "file" | "network" | "evidence" | "quarantine" | "scan" | "response";
  title: string;
  summary: string;
  source: string;
  severity: AlertSeverity;
  tacticId?: string;
  techniqueId?: string;
  blocked?: boolean;
  atRisk?: string;
  linkedEventIds?: string[];
}

export interface AlertBehaviorChain {
  score: number;
  narrative: string;
  whatHappened: string;
  whySuspicious: string;
  blocked: string;
  atRisk: string;
  tacticIds: string[];
  techniqueIds: string[];
  steps: AlertBehaviorChainStep[];
}

export interface AlertResponsePlaybookAction {
  id: string;
  category: "containment" | "investigation" | "cleanup" | "monitoring";
  title: string;
  detail: string;
  reason: string;
  commandType?: CommandType;
  targetPath?: string;
  automationEligible: boolean;
  approvalRequired: boolean;
  linkedEventIds?: string[];
}

export interface AlertResponsePlaybook {
  mode: "containment" | "investigation" | "cleanup";
  title: string;
  summary: string;
  evidenceToPreserve: string[];
  actions: AlertResponsePlaybookAction[];
}

export interface AlertDetail {
  alert: AlertSummary;
  device: DeviceSummary | null;
  posture: DevicePostureSummary | null;
  behaviorChain: AlertBehaviorChain | null;
  playbook: AlertResponsePlaybook | null;
  matchingTelemetry: TelemetryRecord[];
  telemetry: TelemetryRecord[];
  commands: DeviceCommandSummary[];
  evidence: EvidenceSummary[];
  quarantineItems: QuarantineItemSummary[];
  scanHistory: ScanHistorySummary[];
  relatedAlerts: AlertSummary[];
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
  adminPrincipals: AdminPrincipalRecord[];
  adminSessions: AdminSessionRecord[];
  adminApiKeys: AdminApiKeyRecord[];
  adminAuditEvents: AdminAuditEventSummary[];
  devices: DeviceRecord[];
  alerts: AlertSummary[];
  telemetry: TelemetryRecord[];
  commands: DeviceCommandSummary[];
  quarantineItems: QuarantineItemSummary[];
  evidence: EvidenceSummary[];
  scanHistory: ScanHistorySummary[];
  devicePosture: DevicePostureSummary[];
  deviceRiskTelemetry: DeviceRiskTelemetrySnapshot[];
  deviceScoreHistory: DeviceScoreSnapshot[];
  privilegeBaselines: PrivilegeBaselineSnapshot[];
  privilegeEvents: PrivilegeEventSummary[];
  privilegeStates: PrivilegeStateSnapshot[];
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
  processId?: number;
  parentProcessId?: number;
  processImageName?: string;
  processImagePath?: string;
  parentProcessImageName?: string;
  parentProcessImagePath?: string;
  processCommandLine?: string;
  processUserSid?: string;
  processIntegrityLevel?: string;
  processSessionId?: string;
  processSigner?: string;
  processExitCode?: number;
  moduleImageName?: string;
  moduleImagePath?: string;
  moduleImageBase?: string;
  moduleImageSize?: string;
}

export interface EvidenceSummary {
  recordId: string;
  deviceId: string;
  hostname: string;
  recordedAt: string;
  source: string;
  subjectPath: string;
  appName?: string;
  contentName?: string;
  sourceType?: string;
  sessionId?: number;
  preview?: string;
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
  appName?: string;
  contentName?: string;
  sourceType?: string;
  sessionId?: number;
  preview?: string;
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
  latestScore: DeviceScoreSnapshot | null;
  scoreHistory: DeviceScoreSnapshot[];
  riskTelemetry: DeviceRiskTelemetrySnapshot | null;
  privilegeBaseline: PrivilegeBaselineSnapshot | null;
  privilegeState: PrivilegeStateSnapshot | null;
  privilegeEvents: PrivilegeEventSummary[];
  alerts: AlertSummary[];
  telemetry: TelemetryRecord[];
  commands: DeviceCommandSummary[];
  quarantineItems: QuarantineItemSummary[];
  evidence: EvidenceSummary[];
  scanHistory: ScanHistorySummary[];
  installedSoftware: InstalledSoftwareSummary[];
}

export interface UpsertDeviceRiskTelemetryRequest {
  source?: string;
  os_patch_age_days?: number;
  critical_patches_overdue_count?: number;
  high_patches_overdue_count?: number;
  known_exploited_vuln_count?: number;
  internet_exposed_unpatched_critical_count?: number;
  unsupported_software_count?: number;
  outdated_browser_count?: number;
  outdated_high_risk_app_count?: number;
  untrusted_or_unsigned_software_count?: number;
  active_malware_count?: number;
  quarantined_threat_count_7d?: number;
  persistent_threat_count?: number;
  ransomware_behaviour_flag?: boolean;
  lateral_movement_indicator?: boolean;
  open_port_count?: number;
  risky_open_port_count?: number;
  internet_exposed_admin_service_count?: number;
  smb_exposed_flag?: boolean;
  rdp_exposed_flag?: boolean;
  malicious_domain_contacts_7d?: number;
  suspicious_domain_contacts_7d?: number;
  dns_query_count_7d?: number;
  dns_blocked_count_7d?: number;
  malicious_destination_count_7d?: number;
  suspicious_destination_count_7d?: number;
  c2_beacon_indicator?: boolean;
  data_exfiltration_indicator?: boolean;
  unusual_egress_indicator?: boolean;
  file_integrity_change_count_7d?: number;
  protected_file_change_count_7d?: number;
  edr_enabled?: boolean;
  av_enabled?: boolean;
  firewall_enabled?: boolean;
  disk_encryption_enabled?: boolean;
  tamper_protection_enabled?: boolean;
  local_admin_users_count?: number;
  standing_admin_present_flag?: boolean;
  unapproved_admin_account_count?: number;
  admin_group_tamper_indicator?: boolean;
  direct_admin_logon_attempt_count_7d?: number;
  break_glass_account_usage_indicator?: boolean;
  pam_enforcement_enabled?: boolean;
  privilege_hardening_mode?: PrivilegeHardeningMode;
  unauthorised_admin_reenable_indicator?: boolean;
  recovery_path_exists?: boolean;
  risky_signin_indicator?: boolean;
  stolen_token_indicator?: boolean;
  mfa_gap_indicator?: boolean;
  tacticIds?: string[];
  techniqueIds?: string[];
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
  dnsGuardEnabled?: boolean;
  trafficTelemetryEnabled?: boolean;
  integrityWatchEnabled?: boolean;
  privilegeHardeningEnabled?: boolean;
  pamLiteEnabled?: boolean;
  denyHighRiskElevation?: boolean;
  denyUnsignedElevation?: boolean;
  requireBreakGlassEscrow?: boolean;
  suppressionPathRoots?: string[];
  suppressionSha256?: string[];
  suppressionSignerNames?: string[];
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
