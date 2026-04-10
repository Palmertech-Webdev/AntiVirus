import { emptyMailDashboard, fallbackMailDashboard } from "./mail-mock-data";
import { buildFallbackDeviceDetail, fallbackDashboard } from "./mock-data";
import type {
  AdminApiKeyCreateRequest,
  AdminApiKeyCreateResponse,
  AdminApiKeySummary,
  AdminAuditEventSummary,
  AdminLoginRequest,
  AdminLoginResponse,
  AdminSessionStateResponse,
  CreatePolicyRequest,
  CreateScriptRequest,
  DashboardSnapshot,
  DeviceCommandSummary,
  DeviceDetail,
  PrivilegeBaselineSnapshot,
  PrivilegeEventSummary,
  DeviceRiskTelemetrySnapshot,
  DeviceScoreSnapshot,
  MailDashboardSnapshot,
  MailMessageSummary,
  MailQuarantineItemSummary,
  AdminSessionSummary,
  PolicyAssignmentRequest,
  PolicyProfile,
  QuarantineItemSummary,
  RiskDriverSummary,
  ScriptSummary,
  PrivilegeStateSnapshot,
  UpdatePolicyRequest,
  UpdateScriptRequest
} from "./types";

export type DataSource = "live" | "fallback";

export const apiBaseUrl = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:4000/api/v1";
const adminSessionStorageKey = "fenrir.admin.sessionToken";

class HttpRequestError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly body: string
  ) {
    super(message);
    this.name = "HttpRequestError";
  }
}

interface LoadResult<T> {
  data: T;
  source: DataSource;
}

async function requestJson<T>(path: string): Promise<T> {
  return requestJsonWithBody<T>(path, "GET");
}

async function requestJsonWithBody<T>(path: string, method: "GET" | "POST" | "PATCH", body?: object): Promise<T> {
  let response: Response;

  const headers: Record<string, string> = {};
  if (body) {
    headers["Content-Type"] = "application/json";
  }

  const adminSessionToken = getStoredAdminSessionToken();
  if (adminSessionToken) {
    headers["x-admin-session-token"] = adminSessionToken;
  }

  try {
    response = await fetch(`${apiBaseUrl}${path}`, {
      method,
      cache: "no-store",
      headers: Object.keys(headers).length > 0 ? headers : undefined,
      body: body ? JSON.stringify(body) : undefined
    });
  } catch (error) {
    throw error;
  }

  if (!response.ok) {
    const body = await response.text();
    throw new HttpRequestError(`request failed with status ${response.status}`, response.status, body);
  }

  return (await response.json()) as T;
}

export function getStoredAdminSessionToken() {
  if (typeof window === "undefined") {
    return null;
  }

  try {
    return window.localStorage.getItem(adminSessionStorageKey);
  } catch {
    return null;
  }
}

export function setStoredAdminSessionToken(token: string) {
  if (typeof window === "undefined") {
    return;
  }

  try {
    window.localStorage.setItem(adminSessionStorageKey, token);
  } catch {
    // Ignore storage failures in hardened browser contexts.
  }
}

export function clearStoredAdminSessionToken() {
  if (typeof window === "undefined") {
    return;
  }

  try {
    window.localStorage.removeItem(adminSessionStorageKey);
  } catch {
    // Ignore storage failures in hardened browser contexts.
  }
}

export async function loadDashboard(): Promise<LoadResult<DashboardSnapshot>> {
  try {
    return {
      data: await requestJson<DashboardSnapshot>("/dashboard"),
      source: "live"
    };
  } catch (error) {
    if (error instanceof HttpRequestError) {
      throw error;
    }

    return {
      data: fallbackDashboard,
      source: "fallback"
    };
  }
}

export async function loadDeviceDetail(deviceId: string): Promise<LoadResult<DeviceDetail | null>> {
  try {
    return {
      data: await requestJson<DeviceDetail>(`/devices/${deviceId}`),
      source: "live"
    };
  } catch (error) {
    if (error instanceof HttpRequestError) {
      if (error.status === 404) {
        return {
          data: null,
          source: "live"
        };
      }

      throw error;
    }

    return {
      data: buildFallbackDeviceDetail(deviceId),
      source: "fallback"
    };
  }
}

export async function loadDeviceScore(deviceId: string): Promise<DeviceScoreSnapshot> {
  return requestJson<DeviceScoreSnapshot>(`/devices/${deviceId}/score`);
}

export async function loadDeviceScoreHistory(deviceId: string, limit?: number): Promise<DeviceScoreSnapshot[]> {
  const suffix = typeof limit === "number" ? `?limit=${limit}` : "";
  const response = await requestJson<{ items: DeviceScoreSnapshot[] }>(`/devices/${deviceId}/score-history${suffix}`);
  return response.items;
}

export async function loadDeviceRiskSummary(deviceId: string): Promise<{
  deviceId: string;
  summary: string;
  explanation: string;
  score: DeviceScoreSnapshot;
}> {
  return requestJson<{ deviceId: string; summary: string; explanation: string; score: DeviceScoreSnapshot }>(
    `/devices/${deviceId}/risk-summary`
  );
}

export async function loadDevicePrivilegeBaseline(deviceId: string): Promise<PrivilegeBaselineSnapshot | null> {
  return requestJson<PrivilegeBaselineSnapshot | null>(`/devices/${deviceId}/privilege/baseline`);
}

export async function loadDevicePrivilegeState(deviceId: string): Promise<PrivilegeStateSnapshot | null> {
  return requestJson<PrivilegeStateSnapshot | null>(`/devices/${deviceId}/privilege/state`);
}

export async function loadDevicePrivilegeEvents(
  deviceId: string,
  limit?: number
): Promise<PrivilegeEventSummary[]> {
  const suffix = typeof limit === "number" ? `?limit=${limit}` : "";
  const response = await requestJson<{ items: PrivilegeEventSummary[] }>(`/devices/${deviceId}/privilege/events${suffix}`);
  return response.items;
}

export async function loadDeviceFindings(deviceId: string): Promise<RiskDriverSummary[]> {
  const response = await requestJson<{ items: RiskDriverSummary[] }>(`/devices/${deviceId}/findings`);
  return response.items;
}

export async function recalculateDeviceScore(deviceId: string): Promise<DeviceScoreSnapshot> {
  return requestJsonWithBody<DeviceScoreSnapshot>(`/devices/${deviceId}/score/recalculate`, "POST");
}

export async function upsertDeviceRiskTelemetry(
  deviceId: string,
  request: Partial<DeviceRiskTelemetrySnapshot>
): Promise<DeviceRiskTelemetrySnapshot> {
  return requestJsonWithBody<DeviceRiskTelemetrySnapshot>(`/devices/${deviceId}/risk-telemetry`, "POST", request);
}

export async function loadMailDashboard(): Promise<LoadResult<MailDashboardSnapshot>> {
  try {
    return {
      data: await requestJson<MailDashboardSnapshot>("/mail/dashboard"),
      source: "live"
    };
  } catch (error) {
    if (error instanceof HttpRequestError) {
      throw error;
    }

    return {
      data: fallbackMailDashboard,
      source: "fallback"
    };
  }
}

export async function loginAdmin(request: AdminLoginRequest): Promise<AdminLoginResponse> {
  const response = await requestJsonWithBody<AdminLoginResponse>("/admin/auth/login", "POST", request);
  setStoredAdminSessionToken(response.accessToken);
  return response;
}

export async function loadAdminSession(): Promise<AdminSessionStateResponse> {
  return requestJson<AdminSessionStateResponse>("/admin/auth/me");
}

export async function logoutAdmin(): Promise<{ revoked: boolean }> {
  const response = await requestJsonWithBody<{ revoked: boolean }>("/admin/auth/logout", "POST");
  clearStoredAdminSessionToken();
  return response;
}

export async function listAdminSessions(): Promise<AdminSessionSummary[]> {
  const response = await requestJson<{ items: AdminSessionSummary[] }>("/admin/sessions");
  return response.items;
}

export async function listAdminAuditEvents(limit?: number): Promise<AdminAuditEventSummary[]> {
  const suffix = typeof limit === "number" ? `?limit=${limit}` : "";
  const response = await requestJson<{ items: AdminAuditEventSummary[] }>(`/admin/audit${suffix}`);
  return response.items;
}

export async function listAdminApiKeys(): Promise<AdminApiKeySummary[]> {
  const response = await requestJson<{ items: AdminApiKeySummary[] }>("/admin/api-keys");
  return response.items;
}

export async function createAdminApiKey(request: AdminApiKeyCreateRequest): Promise<AdminApiKeyCreateResponse> {
  return requestJsonWithBody<AdminApiKeyCreateResponse>("/admin/api-keys", "POST", request);
}

export async function revokeAdminApiKey(apiKeyId: string): Promise<AdminApiKeySummary> {
  return requestJsonWithBody<AdminApiKeySummary>(`/admin/api-keys/${apiKeyId}/revoke`, "POST");
}

export async function releaseMailQuarantineItem(
  mailQuarantineItemId: string,
  requestedBy = "console"
): Promise<MailQuarantineItemSummary> {
  return requestJsonWithBody<MailQuarantineItemSummary>(`/mail/quarantine/${mailQuarantineItemId}/release`, "POST", {
    requestedBy
  });
}

export async function purgeMailMessage(mailMessageId: string, requestedBy = "console"): Promise<MailMessageSummary> {
  return requestJsonWithBody<MailMessageSummary>(`/mail/messages/${mailMessageId}/purge`, "POST", {
    requestedBy
  });
}

export async function listPolicies(): Promise<PolicyProfile[]> {
  const response = await requestJson<{ items: PolicyProfile[] }>("/policies");
  return response.items;
}

export async function createPolicy(request: CreatePolicyRequest): Promise<PolicyProfile> {
  return requestJsonWithBody<PolicyProfile>("/policies", "POST", request);
}

export async function updatePolicy(policyId: string, request: UpdatePolicyRequest): Promise<PolicyProfile> {
  return requestJsonWithBody<PolicyProfile>(`/policies/${policyId}`, "PATCH", request);
}

export async function assignPolicy(policyId: string, request: PolicyAssignmentRequest): Promise<PolicyProfile> {
  return requestJsonWithBody<PolicyProfile>(`/policies/${policyId}/assign`, "POST", request);
}

export async function listScripts(): Promise<ScriptSummary[]> {
  const response = await requestJson<{ items: ScriptSummary[] }>("/scripts");
  return response.items;
}

export async function createScript(request: CreateScriptRequest): Promise<ScriptSummary> {
  return requestJsonWithBody<ScriptSummary>("/scripts", "POST", request);
}

export async function updateScript(scriptId: string, request: UpdateScriptRequest): Promise<ScriptSummary> {
  return requestJsonWithBody<ScriptSummary>(`/scripts/${scriptId}`, "PATCH", request);
}

export async function isolateDevice(deviceId: string, issuedBy = "console"): Promise<DeviceCommandSummary> {
  return requestJsonWithBody<DeviceCommandSummary>(`/devices/${deviceId}/isolate`, "POST", { issuedBy });
}

export async function releaseDevice(deviceId: string, issuedBy = "console"): Promise<DeviceCommandSummary> {
  return requestJsonWithBody<DeviceCommandSummary>(`/devices/${deviceId}/release`, "POST", { issuedBy });
}

export async function restoreQuarantineItem(
  deviceId: string,
  recordId: string,
  issuedBy = "console"
): Promise<DeviceCommandSummary> {
  return requestJsonWithBody<DeviceCommandSummary>(`/devices/${deviceId}/quarantine/${recordId}/restore`, "POST", {
    issuedBy
  });
}

export async function deleteQuarantineItem(
  deviceId: string,
  recordId: string,
  issuedBy = "console"
): Promise<DeviceCommandSummary> {
  return requestJsonWithBody<DeviceCommandSummary>(`/devices/${deviceId}/quarantine/${recordId}/delete`, "POST", {
    issuedBy
  });
}

export async function queueRemediatePath(
  deviceId: string,
  targetPath: string,
  issuedBy = "console"
): Promise<DeviceCommandSummary> {
  return requestJsonWithBody<DeviceCommandSummary>(`/devices/${deviceId}/actions/remediate-path`, "POST", {
    targetPath,
    issuedBy
  });
}

export async function queueProcessTreeTerminate(
  deviceId: string,
  targetPath: string,
  issuedBy = "console"
): Promise<DeviceCommandSummary> {
  return requestJsonWithBody<DeviceCommandSummary>(`/devices/${deviceId}/actions/process-tree-terminate`, "POST", {
    targetPath,
    issuedBy
  });
}

export async function queueAgentUpdate(
  deviceId: string,
  targetPath: string,
  issuedBy = "console"
): Promise<DeviceCommandSummary> {
  return requestJsonWithBody<DeviceCommandSummary>(`/devices/${deviceId}/actions/update-agent`, "POST", {
    targetPath,
    issuedBy
  });
}

export async function queueRunScript(
  deviceId: string,
  scriptId: string,
  issuedBy = "console"
): Promise<DeviceCommandSummary> {
  return requestJsonWithBody<DeviceCommandSummary>(`/devices/${deviceId}/actions/run-script`, "POST", {
    scriptId,
    issuedBy
  });
}

export async function queuePrivilegeElevation(
  deviceId: string,
  request: {
    requestedBy?: string;
    applicationName?: string;
    targetPath?: string;
    reason?: string;
    approved?: boolean;
    issuedBy?: string;
  }
): Promise<DeviceCommandSummary> {
  return requestJsonWithBody<DeviceCommandSummary>(`/devices/${deviceId}/commands`, "POST", {
    type: "privilege.elevation.request",
    issuedBy: request.issuedBy ?? "console",
    payloadJson: JSON.stringify({
      requestedBy: request.requestedBy ?? request.issuedBy ?? "console",
      applicationName: request.applicationName,
      targetPath: request.targetPath,
      reason: request.reason,
      approved: request.approved ?? false
    })
  });
}

export async function enforceDevicePrivilegeHardening(
  deviceId: string,
  request: { issuedBy?: string; reason?: string } = {}
): Promise<PrivilegeStateSnapshot> {
  return requestJsonWithBody<PrivilegeStateSnapshot>(`/devices/${deviceId}/privilege/enforce`, "POST", request);
}

export async function recoverDevicePrivilegeHardening(
  deviceId: string,
  request: { issuedBy?: string; reason?: string } = {}
): Promise<PrivilegeStateSnapshot> {
  return requestJsonWithBody<PrivilegeStateSnapshot>(`/devices/${deviceId}/privilege/recover`, "POST", request);
}

export async function queueSoftwareUninstall(
  deviceId: string,
  request: {
    softwareId?: string;
    displayName: string;
    displayVersion?: string;
    publisher?: string;
    installLocation?: string;
    uninstallCommand?: string;
    quietUninstallCommand?: string;
    executableNames?: string[];
    commandLine?: string;
    workingDirectory?: string;
    issuedBy?: string;
  }
): Promise<DeviceCommandSummary> {
  return requestJsonWithBody<DeviceCommandSummary>(`/devices/${deviceId}/actions/software-uninstall`, "POST", request);
}

export async function queueSoftwareUpdate(
  deviceId: string,
  request: {
    softwareId?: string;
    displayName: string;
    displayVersion?: string;
    publisher?: string;
    installLocation?: string;
    executableNames?: string[];
    commandLine?: string;
    workingDirectory?: string;
    issuedBy?: string;
  }
): Promise<DeviceCommandSummary> {
  return requestJsonWithBody<DeviceCommandSummary>(`/devices/${deviceId}/actions/software-update`, "POST", request);
}

export async function queueSoftwareUpdateSearch(
  deviceId: string,
  request: {
    softwareId?: string;
    displayName: string;
    displayVersion?: string;
    publisher?: string;
    installLocation?: string;
    executableNames?: string[];
    issuedBy?: string;
  }
): Promise<DeviceCommandSummary> {
  return requestJsonWithBody<DeviceCommandSummary>(`/devices/${deviceId}/actions/software-search-updates`, "POST", request);
}

export async function queueSoftwareBlock(
  deviceId: string,
  request: {
    softwareId?: string;
    displayName: string;
    displayVersion?: string;
    publisher?: string;
    installLocation?: string;
    executableNames?: string[];
    issuedBy?: string;
  }
): Promise<DeviceCommandSummary> {
  return requestJsonWithBody<DeviceCommandSummary>(`/devices/${deviceId}/actions/software-block`, "POST", request);
}

export { emptyMailDashboard };
