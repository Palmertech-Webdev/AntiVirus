import { emptyMailDashboard, fallbackMailDashboard } from "./mail-mock-data";
import { buildFallbackDeviceDetail, fallbackDashboard } from "./mock-data";
import type {
  CreatePolicyRequest,
  CreateScriptRequest,
  DashboardSnapshot,
  DeviceCommandSummary,
  DeviceDetail,
  MailDashboardSnapshot,
  MailMessageSummary,
  MailQuarantineItemSummary,
  PolicyAssignmentRequest,
  PolicyProfile,
  QuarantineItemSummary,
  ScriptSummary,
  UpdatePolicyRequest,
  UpdateScriptRequest
} from "./types";

export type DataSource = "live" | "fallback";

export const apiBaseUrl = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:4000/api/v1";

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

  try {
    response = await fetch(`${apiBaseUrl}${path}`, {
      method,
      cache: "no-store",
      headers: body ? { "Content-Type": "application/json" } : undefined,
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
