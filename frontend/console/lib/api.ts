import { emptyMailDashboard, fallbackMailDashboard } from "./mail-mock-data";
import { buildFallbackDeviceDetail, fallbackDashboard } from "./mock-data";
import type { DashboardSnapshot, DeviceDetail, MailDashboardSnapshot, MailMessageSummary, MailQuarantineItemSummary } from "./types";

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

async function requestJsonWithBody<T>(path: string, method: "GET" | "POST", body?: object): Promise<T> {
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

export { emptyMailDashboard };
