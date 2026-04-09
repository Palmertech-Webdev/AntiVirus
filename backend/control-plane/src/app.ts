import Fastify from "fastify";
import cors from "@fastify/cors";
import { z } from "zod";
import { randomBytes } from "node:crypto";

import {
  createFileBackedMailStore,
  MailDomainNotFoundError,
  MailMessageNotFoundError,
  MailQuarantineItemNotFoundError,
  type MailStore
} from "./mailStore.ts";
import {
  CommandNotFoundError,
  createFileBackedControlPlaneStore,
  DeviceNotFoundError,
  PolicyNotFoundError,
  ScriptNotFoundError,
  type ControlPlaneStore
} from "./controlPlaneStore.ts";

const enrollmentRequestSchema = z.object({
  hostname: z.string().min(1),
  osVersion: z.string().min(1),
  serialNumber: z.string().min(1)
});

const deviceParamsSchema = z.object({
  deviceId: z.string().min(1)
});

const heartbeatRequestSchema = z.object({
  agentVersion: z.string().min(1),
  platformVersion: z.string().min(1),
  healthState: z.enum(["healthy", "degraded", "isolated"]),
  isolated: z.boolean()
});

const policyCheckInRequestSchema = z.object({
  currentPolicyRevision: z.string().min(1).optional(),
  agentVersion: z.string().min(1).optional(),
  platformVersion: z.string().min(1).optional()
});

const telemetryBatchRequestSchema = z.object({
  events: z.array(
    z.object({
      eventId: z.string().min(1),
      eventType: z.string().min(1),
      source: z.string().min(1),
      summary: z.string().min(1),
      occurredAt: z.string().min(1),
      payloadJson: z.string()
    })
  ).min(1)
});

const telemetryQuerySchema = z.object({
  deviceId: z.string().min(1).optional(),
  limit: z.coerce.number().int().positive().max(200).optional()
});

const limitQuerySchema = z.object({
  limit: z.coerce.number().int().positive().max(200).optional()
});

const upsertDeviceRiskTelemetryRequestSchema = z.object({
  source: z.string().min(1).optional(),
  os_patch_age_days: z.number().int().nonnegative().max(10_000).optional(),
  critical_patches_overdue_count: z.number().int().nonnegative().max(10_000).optional(),
  high_patches_overdue_count: z.number().int().nonnegative().max(10_000).optional(),
  known_exploited_vuln_count: z.number().int().nonnegative().max(10_000).optional(),
  internet_exposed_unpatched_critical_count: z.number().int().nonnegative().max(10_000).optional(),
  unsupported_software_count: z.number().int().nonnegative().max(10_000).optional(),
  outdated_browser_count: z.number().int().nonnegative().max(10_000).optional(),
  outdated_high_risk_app_count: z.number().int().nonnegative().max(10_000).optional(),
  untrusted_or_unsigned_software_count: z.number().int().nonnegative().max(10_000).optional(),
  active_malware_count: z.number().int().nonnegative().max(10_000).optional(),
  quarantined_threat_count_7d: z.number().int().nonnegative().max(10_000).optional(),
  persistent_threat_count: z.number().int().nonnegative().max(10_000).optional(),
  ransomware_behaviour_flag: z.boolean().optional(),
  lateral_movement_indicator: z.boolean().optional(),
  open_port_count: z.number().int().nonnegative().max(10_000).optional(),
  risky_open_port_count: z.number().int().nonnegative().max(10_000).optional(),
  internet_exposed_admin_service_count: z.number().int().nonnegative().max(10_000).optional(),
  smb_exposed_flag: z.boolean().optional(),
  rdp_exposed_flag: z.boolean().optional(),
  malicious_domain_contacts_7d: z.number().int().nonnegative().max(10_000).optional(),
  suspicious_domain_contacts_7d: z.number().int().nonnegative().max(10_000).optional(),
  dns_query_count_7d: z.number().int().nonnegative().max(10_000).optional(),
  dns_blocked_count_7d: z.number().int().nonnegative().max(10_000).optional(),
  malicious_destination_count_7d: z.number().int().nonnegative().max(10_000).optional(),
  suspicious_destination_count_7d: z.number().int().nonnegative().max(10_000).optional(),
  c2_beacon_indicator: z.boolean().optional(),
  data_exfiltration_indicator: z.boolean().optional(),
  unusual_egress_indicator: z.boolean().optional(),
  file_integrity_change_count_7d: z.number().int().nonnegative().max(10_000).optional(),
  protected_file_change_count_7d: z.number().int().nonnegative().max(10_000).optional(),
  edr_enabled: z.boolean().optional(),
  av_enabled: z.boolean().optional(),
  firewall_enabled: z.boolean().optional(),
  disk_encryption_enabled: z.boolean().optional(),
  tamper_protection_enabled: z.boolean().optional(),
  local_admin_users_count: z.number().int().nonnegative().max(10_000).optional(),
  standing_admin_present_flag: z.boolean().optional(),
  unapproved_admin_account_count: z.number().int().nonnegative().max(10_000).optional(),
  admin_group_tamper_indicator: z.boolean().optional(),
  direct_admin_logon_attempt_count_7d: z.number().int().nonnegative().max(10_000).optional(),
  break_glass_account_usage_indicator: z.boolean().optional(),
  pam_enforcement_enabled: z.boolean().optional(),
  privilege_hardening_mode: z.enum(["monitor_only", "enforce", "restricted", "recovery"]).optional(),
  unauthorised_admin_reenable_indicator: z.boolean().optional(),
  recovery_path_exists: z.boolean().optional(),
  risky_signin_indicator: z.boolean().optional(),
  stolen_token_indicator: z.boolean().optional(),
  mfa_gap_indicator: z.boolean().optional(),
  tacticIds: z.array(z.string().min(1)).optional(),
  techniqueIds: z.array(z.string().min(1)).optional()
});

const commandsQuerySchema = z.object({
  deviceId: z.string().min(1).optional(),
  status: z.enum(["pending", "in_progress", "completed", "failed"]).optional(),
  limit: z.coerce.number().int().positive().max(200).optional()
});

const quarantineQuerySchema = z.object({
  deviceId: z.string().min(1).optional(),
  status: z.enum(["quarantined", "restored", "deleted"]).optional(),
  limit: z.coerce.number().int().positive().max(200).optional()
});

const queueCommandRequestSchema = z.object({
  type: z.enum([
    "device.isolate",
    "device.release",
    "scan.targeted",
    "quarantine.restore",
    "quarantine.delete",
    "update.apply",
    "update.rollback",
    "agent.repair",
    "process.terminate",
    "process.tree.terminate",
    "persistence.cleanup",
    "remediate.path",
    "script.run",
    "privilege.elevation.request",
    "privilege.enforce",
    "privilege.recover",
    "software.uninstall",
    "software.update",
    "software.update.search",
    "software.block"
  ]),
  issuedBy: z.string().min(1).optional(),
  targetPath: z.string().min(1).optional(),
  recordId: z.string().min(1).optional(),
  payloadJson: z.string().min(2).optional()
});

const policyParamsSchema = z.object({
  policyId: z.string().min(1)
});

const scriptParamsSchema = z.object({
  scriptId: z.string().min(1)
});

const createPolicyRequestSchema = z.object({
  name: z.string().min(1),
  description: z.string().optional(),
  realtimeProtection: z.boolean(),
  cloudLookup: z.boolean(),
  scriptInspection: z.boolean(),
  networkContainment: z.boolean(),
  quarantineOnMalicious: z.boolean()
  ,dnsGuardEnabled: z.boolean().optional(),
  trafficTelemetryEnabled: z.boolean().optional(),
  integrityWatchEnabled: z.boolean().optional(),
  privilegeHardeningEnabled: z.boolean().optional(),
  pamLiteEnabled: z.boolean().optional(),
  denyHighRiskElevation: z.boolean().optional(),
  denyUnsignedElevation: z.boolean().optional(),
  requireBreakGlassEscrow: z.boolean().optional()
});

const updatePolicyRequestSchema = createPolicyRequestSchema.partial();

const policyAssignmentRequestSchema = z.object({
  deviceIds: z.array(z.string().min(1)).min(1)
});

const createScriptRequestSchema = z.object({
  name: z.string().min(1),
  description: z.string().optional(),
  language: z.enum(["powershell", "cmd"]),
  content: z.string().min(1)
});

const updateScriptRequestSchema = createScriptRequestSchema.partial();

const deviceRecordParamsSchema = z.object({
  deviceId: z.string().min(1),
  recordId: z.string().min(1)
});

const issuedByRequestSchema = z.object({
  issuedBy: z.string().min(1).optional()
});

const privilegeActionRequestSchema = z.object({
  issuedBy: z.string().min(1).optional(),
  reason: z.string().min(1).optional()
});

const targetPathActionRequestSchema = z.object({
  targetPath: z.string().min(1),
  issuedBy: z.string().min(1).optional()
});

const updateApplyRequestSchema = z.object({
  targetPath: z.string().min(1),
  issuedBy: z.string().min(1).optional()
});

const runScriptRequestSchema = z.object({
  scriptId: z.string().min(1),
  issuedBy: z.string().min(1).optional()
});

const softwareCommandRequestSchema = z.object({
  softwareId: z.string().min(1).optional(),
  displayName: z.string().min(1),
  displayVersion: z.string().min(1).optional(),
  publisher: z.string().min(1).optional(),
  installLocation: z.string().min(1).optional(),
  uninstallCommand: z.string().min(1).optional(),
  quietUninstallCommand: z.string().min(1).optional(),
  executableNames: z.array(z.string().min(1)).optional(),
  commandLine: z.string().min(1).optional(),
  workingDirectory: z.string().min(1).optional(),
  issuedBy: z.string().min(1).optional()
});

const pollCommandsQuerySchema = z.object({
  limit: z.coerce.number().int().positive().max(100).optional()
});

const commandParamsSchema = z.object({
  deviceId: z.string().min(1),
  commandId: z.string().min(1)
});

const completeCommandRequestSchema = z.object({
  status: z.enum(["completed", "failed"]),
  resultJson: z.string().optional()
});

const mailMessagesQuerySchema = z.object({
  verdict: z.enum(["clean", "spam", "phish", "malware", "suspicious"]).optional(),
  deliveryAction: z.enum(["delivered", "quarantined", "rejected", "held", "junked", "purged"]).optional(),
  limit: z.coerce.number().int().positive().max(200).optional()
});

const mailQuarantineQuerySchema = z.object({
  status: z.enum(["quarantined", "released", "purged"]).optional(),
  limit: z.coerce.number().int().positive().max(200).optional()
});

const mailMessageParamsSchema = z.object({
  mailMessageId: z.string().min(1)
});

const mailQuarantineParamsSchema = z.object({
  mailQuarantineItemId: z.string().min(1)
});

const mailActionRequestSchema = z.object({
  requestedBy: z.string().min(1).optional()
});

const simulatedInboundMailRequestSchema = z.object({
  mailDomainId: z.string().min(1).optional(),
  sender: z.string().min(1),
  recipients: z.array(z.string().min(1)).min(1),
  subject: z.string().min(1),
  summary: z.string().min(1).optional(),
  verdict: z.enum(["clean", "spam", "phish", "malware", "suspicious"]),
  deliveryAction: z.enum(["delivered", "quarantined", "rejected", "held", "junked", "purged"]),
  relatedAlertId: z.string().min(1).optional(),
  relatedDeviceId: z.string().min(1).optional(),
  relatedUser: z.string().min(1).optional(),
  attachments: z
    .array(
      z.object({
        fileName: z.string().min(1),
        sha256: z.string().min(1),
        sizeBytes: z.number().int().nonnegative(),
        verdict: z.enum(["clean", "spam", "phish", "malware", "suspicious"])
      })
    )
    .optional(),
  urls: z
    .array(
      z.object({
        originalUrl: z.string().min(1),
        verdict: z.enum(["clean", "spam", "phish", "malware", "suspicious"]),
        rewriteApplied: z.boolean().optional()
      })
    )
    .optional(),
  auth: z
    .object({
      spf: z.enum(["pass", "fail", "softfail", "none"]).optional(),
      dkim: z.enum(["pass", "fail", "softfail", "none"]).optional(),
      dmarc: z.enum(["pass", "fail", "softfail", "none"]).optional(),
      arc: z.enum(["pass", "fail", "softfail", "none"]).optional()
    })
    .optional()
});

interface BuildServerOptions {
  store?: ControlPlaneStore;
  mailStore?: MailStore;
}

function sendValidationError(reply: { code: (statusCode: number) => { send: (payload: unknown) => unknown } }, details: unknown) {
  return reply.code(400).send({
    error: "invalid_request",
    details
  });
}

function sendNotFound(reply: { code: (statusCode: number) => { send: (payload: unknown) => unknown } }, deviceId: string) {
  return reply.code(404).send({
    error: "device_not_found",
    deviceId
  });
}

function sendCommandNotFound(reply: { code: (statusCode: number) => { send: (payload: unknown) => unknown } }, commandId: string) {
  return reply.code(404).send({
    error: "command_not_found",
    commandId
  });
}

function sendPolicyNotFound(reply: { code: (statusCode: number) => { send: (payload: unknown) => unknown } }, policyId: string) {
  return reply.code(404).send({
    error: "policy_not_found",
    policyId
  });
}

function sendScriptNotFound(reply: { code: (statusCode: number) => { send: (payload: unknown) => unknown } }, scriptId: string) {
  return reply.code(404).send({
    error: "script_not_found",
    scriptId
  });
}

function sendMailMessageNotFound(
  reply: { code: (statusCode: number) => { send: (payload: unknown) => unknown } },
  mailMessageId: string
) {
  return reply.code(404).send({
    error: "mail_message_not_found",
    mailMessageId
  });
}

function sendMailQuarantineNotFound(
  reply: { code: (statusCode: number) => { send: (payload: unknown) => unknown } },
  mailQuarantineItemId: string
) {
  return reply.code(404).send({
    error: "mail_quarantine_item_not_found",
    mailQuarantineItemId
  });
}

function sendMailDomainNotFound(
  reply: { code: (statusCode: number) => { send: (payload: unknown) => unknown } },
  identifier: string
) {
  return reply.code(404).send({
    error: "mail_domain_not_found",
    identifier
  });
}

function validateQueuedCommand(
  body: z.infer<typeof queueCommandRequestSchema>
): { valid: true } | { valid: false; details: string } {
  if (body.type === "scan.targeted" && !body.targetPath) {
    return {
      valid: false,
      details: "scan.targeted requires targetPath"
    };
  }

  if (
    (body.type === "update.apply" ||
      body.type === "process.terminate" ||
      body.type === "process.tree.terminate" ||
      body.type === "persistence.cleanup" ||
      body.type === "remediate.path") &&
    !body.targetPath
  ) {
    return {
      valid: false,
      details: `${body.type} requires targetPath`
    };
  }

  if (body.type === "update.rollback" && !body.recordId) {
    return {
      valid: false,
      details: "update.rollback requires recordId"
    };
  }

  if ((body.type === "quarantine.restore" || body.type === "quarantine.delete") && !body.recordId) {
    return {
      valid: false,
      details: `${body.type} requires recordId`
    };
  }

  if (body.type === "privilege.elevation.request" && !body.payloadJson) {
    return {
      valid: false,
      details: "privilege.elevation.request requires payloadJson"
    };
  }

  if (
    (body.type === "script.run" ||
      body.type === "software.uninstall" ||
      body.type === "software.update" ||
      body.type === "software.update.search" ||
      body.type === "software.block") &&
    !body.payloadJson
  ) {
    return {
      valid: false,
      details: `${body.type} requires payloadJson`
    };
  }

  return { valid: true };
}

export function buildServer(options: BuildServerOptions = {}) {
  const store = options.store ?? createFileBackedControlPlaneStore();
  const mailStore = options.mailStore ?? createFileBackedMailStore();
  const deviceApiKeys = new Map<string, string>();
  const app = Fastify({
    logger: true
  });

  function issueDeviceApiKey() {
    return `avd_${randomBytes(24).toString("hex")}`;
  }

  function buildCommandChannelUrl(baseUrl: string, deviceId: string, deviceApiKey: string) {
    const separator = baseUrl.includes("?") ? "&" : "?";
    return `${baseUrl}${separator}deviceId=${encodeURIComponent(deviceId)}&deviceApiKey=${encodeURIComponent(deviceApiKey)}`;
  }

  function extractDeviceApiKey(request: { headers: Record<string, unknown>; raw: { url?: string } }) {
    const headerValue = request.headers["x-device-api-key"];
    if (typeof headerValue === "string" && headerValue.length > 0) {
      return headerValue;
    }

    const authHeader = request.headers.authorization;
    if (typeof authHeader === "string" && authHeader.startsWith("Bearer ")) {
      return authHeader.slice("Bearer ".length).trim();
    }

    const rawUrl = request.raw.url;
    if (typeof rawUrl === "string") {
      const queryStart = rawUrl.indexOf("?");
      if (queryStart >= 0) {
        const query = rawUrl.slice(queryStart + 1);
        const params = new URLSearchParams(query);
        const queryKey = params.get("deviceApiKey");
        if (queryKey && queryKey.length > 0) {
          return queryKey;
        }
      }
    }

    return undefined;
  }

  function extractObservedRemoteAddress(request: { ip: string }) {
    return request.ip;
  }

  function requireDeviceAuthentication(
    request: { headers: Record<string, unknown>; raw: { url?: string } },
    reply: { code: (statusCode: number) => { send: (payload: unknown) => unknown } },
    deviceId: string
  ) {
    const presentedKey = extractDeviceApiKey(request);
    const expectedKey = deviceApiKeys.get(deviceId);

    if (!expectedKey && presentedKey) {
      deviceApiKeys.set(deviceId, presentedKey);
      return true;
    }

    if (!expectedKey && !presentedKey) {
      return true;
    }

    if (!expectedKey || !presentedKey || presentedKey !== expectedKey) {
      reply.code(401).send({
        error: "invalid_device_api_key",
        deviceId
      });
      return false;
    }

    return true;
  }

  void app.register(cors, {
    origin: true
  });

  app.get("/health", async () => ({
    service: "control-plane",
    status: "ok",
    timestamp: new Date().toISOString()
  }));

  app.get("/api/v1/dashboard", async () => store.getDashboardSnapshot());

  app.get("/api/v1/mail/dashboard", async () => mailStore.getDashboardSnapshot());

  app.get("/api/v1/mail/domains", async () => ({
    items: await mailStore.listDomains()
  }));

  app.get("/api/v1/mail/messages", async (request, reply) => {
    const parsed = mailMessagesQuerySchema.safeParse(request.query);

    if (!parsed.success) {
      return sendValidationError(reply, parsed.error.flatten());
    }

    return {
      items: await mailStore.listMessages(parsed.data.limit, parsed.data.verdict, parsed.data.deliveryAction)
    };
  });

  app.get("/api/v1/mail/messages/:mailMessageId", async (request, reply) => {
    const params = mailMessageParamsSchema.safeParse(request.params);

    if (!params.success) {
      return sendValidationError(reply, params.error.flatten());
    }

    try {
      return await mailStore.getMessage(params.data.mailMessageId);
    } catch (error) {
      if (error instanceof MailMessageNotFoundError) {
        return sendMailMessageNotFound(reply, params.data.mailMessageId);
      }

      throw error;
    }
  });

  app.get("/api/v1/mail/quarantine", async (request, reply) => {
    const parsed = mailQuarantineQuerySchema.safeParse(request.query);

    if (!parsed.success) {
      return sendValidationError(reply, parsed.error.flatten());
    }

    return {
      items: await mailStore.listQuarantineItems(parsed.data.status, parsed.data.limit)
    };
  });

  app.get("/api/v1/mail/policies/default", async () => mailStore.getDefaultPolicy());

  app.post("/api/v1/mail/simulate", async (request, reply) => {
    const parsed = simulatedInboundMailRequestSchema.safeParse(request.body);

    if (!parsed.success) {
      return sendValidationError(reply, parsed.error.flatten());
    }

    try {
      return reply.code(201).send(await mailStore.simulateInboundMessage(parsed.data));
    } catch (error) {
      if (error instanceof MailDomainNotFoundError) {
        return sendMailDomainNotFound(reply, parsed.data.mailDomainId ?? "recipient-domain");
      }

      throw error;
    }
  });

  app.post("/api/v1/mail/quarantine/:mailQuarantineItemId/release", async (request, reply) => {
    const params = mailQuarantineParamsSchema.safeParse(request.params);
    const body = mailActionRequestSchema.safeParse(request.body ?? {});

    if (!params.success) {
      return sendValidationError(reply, params.error.flatten());
    }

    if (!body.success) {
      return sendValidationError(reply, body.error.flatten());
    }

    try {
      return await mailStore.releaseQuarantineItem(params.data.mailQuarantineItemId, body.data.requestedBy);
    } catch (error) {
      if (error instanceof MailQuarantineItemNotFoundError) {
        return sendMailQuarantineNotFound(reply, params.data.mailQuarantineItemId);
      }

      if (error instanceof MailMessageNotFoundError) {
        return sendMailMessageNotFound(reply, params.data.mailQuarantineItemId);
      }

      throw error;
    }
  });

  app.post("/api/v1/mail/messages/:mailMessageId/purge", async (request, reply) => {
    const params = mailMessageParamsSchema.safeParse(request.params);
    const body = mailActionRequestSchema.safeParse(request.body ?? {});

    if (!params.success) {
      return sendValidationError(reply, params.error.flatten());
    }

    if (!body.success) {
      return sendValidationError(reply, body.error.flatten());
    }

    try {
      return await mailStore.purgeMessage(params.data.mailMessageId, body.data.requestedBy);
    } catch (error) {
      if (error instanceof MailMessageNotFoundError) {
        return sendMailMessageNotFound(reply, params.data.mailMessageId);
      }

      throw error;
    }
  });

  app.get("/api/v1/devices", async () => ({
    items: await store.listDevices()
  }));

  app.get("/api/v1/devices/:deviceId", async (request, reply) => {
    const params = deviceParamsSchema.safeParse(request.params);

    if (!params.success) {
      return sendValidationError(reply, params.error.flatten());
    }

    try {
      return await store.getDeviceDetail(params.data.deviceId);
    } catch (error) {
      if (error instanceof DeviceNotFoundError) {
        return sendNotFound(reply, params.data.deviceId);
      }

      throw error;
    }
  });

  app.get("/api/v1/devices/:deviceId/score", async (request, reply) => {
    const params = deviceParamsSchema.safeParse(request.params);

    if (!params.success) {
      return sendValidationError(reply, params.error.flatten());
    }

    try {
      return await store.getLatestDeviceScore(params.data.deviceId);
    } catch (error) {
      if (error instanceof DeviceNotFoundError) {
        return sendNotFound(reply, params.data.deviceId);
      }

      throw error;
    }
  });

  app.get("/api/v1/devices/:deviceId/score-history", async (request, reply) => {
    const params = deviceParamsSchema.safeParse(request.params);
    const query = limitQuerySchema.safeParse(request.query);

    if (!params.success) {
      return sendValidationError(reply, params.error.flatten());
    }

    if (!query.success) {
      return sendValidationError(reply, query.error.flatten());
    }

    try {
      return {
        items: await store.listDeviceScoreHistory(params.data.deviceId, query.data.limit)
      };
    } catch (error) {
      if (error instanceof DeviceNotFoundError) {
        return sendNotFound(reply, params.data.deviceId);
      }

      throw error;
    }
  });

  app.get("/api/v1/devices/:deviceId/findings", async (request, reply) => {
    const params = deviceParamsSchema.safeParse(request.params);

    if (!params.success) {
      return sendValidationError(reply, params.error.flatten());
    }

    try {
      const score = await store.getLatestDeviceScore(params.data.deviceId);
      return {
        items: score.topRiskDrivers
      };
    } catch (error) {
      if (error instanceof DeviceNotFoundError) {
        return sendNotFound(reply, params.data.deviceId);
      }

      throw error;
    }
  });

  app.get("/api/v1/devices/:deviceId/risk-summary", async (request, reply) => {
    const params = deviceParamsSchema.safeParse(request.params);

    if (!params.success) {
      return sendValidationError(reply, params.error.flatten());
    }

    try {
      return await store.getDeviceRiskSummary(params.data.deviceId);
    } catch (error) {
      if (error instanceof DeviceNotFoundError) {
        return sendNotFound(reply, params.data.deviceId);
      }

      throw error;
    }
  });

  app.post("/api/v1/devices/:deviceId/score/recalculate", async (request, reply) => {
    const params = deviceParamsSchema.safeParse(request.params);

    if (!params.success) {
      return sendValidationError(reply, params.error.flatten());
    }

    try {
      return await store.recalculateDeviceScore(params.data.deviceId);
    } catch (error) {
      if (error instanceof DeviceNotFoundError) {
        return sendNotFound(reply, params.data.deviceId);
      }

      throw error;
    }
  });

  app.get("/api/v1/devices/:deviceId/privilege/baseline", async (request, reply) => {
    const params = deviceParamsSchema.safeParse(request.params);

    if (!params.success) {
      return sendValidationError(reply, params.error.flatten());
    }

    try {
      return await store.getDevicePrivilegeBaseline(params.data.deviceId);
    } catch (error) {
      if (error instanceof DeviceNotFoundError) {
        return sendNotFound(reply, params.data.deviceId);
      }

      throw error;
    }
  });

  app.get("/api/v1/devices/:deviceId/privilege/state", async (request, reply) => {
    const params = deviceParamsSchema.safeParse(request.params);

    if (!params.success) {
      return sendValidationError(reply, params.error.flatten());
    }

    try {
      return await store.getDevicePrivilegeState(params.data.deviceId);
    } catch (error) {
      if (error instanceof DeviceNotFoundError) {
        return sendNotFound(reply, params.data.deviceId);
      }

      throw error;
    }
  });

  app.get("/api/v1/devices/:deviceId/privilege/events", async (request, reply) => {
    const params = deviceParamsSchema.safeParse(request.params);
    const query = limitQuerySchema.safeParse(request.query);

    if (!params.success) {
      return sendValidationError(reply, params.error.flatten());
    }

    if (!query.success) {
      return sendValidationError(reply, query.error.flatten());
    }

    try {
      return { items: await store.listDevicePrivilegeEvents(params.data.deviceId, query.data.limit) };
    } catch (error) {
      if (error instanceof DeviceNotFoundError) {
        return sendNotFound(reply, params.data.deviceId);
      }

      throw error;
    }
  });

  app.post("/api/v1/devices/:deviceId/privilege/enforce", async (request, reply) => {
    const params = deviceParamsSchema.safeParse(request.params);
    const body = privilegeActionRequestSchema.safeParse(request.body ?? {});

    if (!params.success) {
      return sendValidationError(reply, params.error.flatten());
    }

    if (!body.success) {
      return sendValidationError(reply, body.error.flatten());
    }

    try {
      return reply.code(201).send(await store.enforceDevicePrivilegeHardening(params.data.deviceId, body.data));
    } catch (error) {
      if (error instanceof DeviceNotFoundError) {
        return sendNotFound(reply, params.data.deviceId);
      }

      throw error;
    }
  });

  app.post("/api/v1/devices/:deviceId/privilege/recover", async (request, reply) => {
    const params = deviceParamsSchema.safeParse(request.params);
    const body = privilegeActionRequestSchema.safeParse(request.body ?? {});

    if (!params.success) {
      return sendValidationError(reply, params.error.flatten());
    }

    if (!body.success) {
      return sendValidationError(reply, body.error.flatten());
    }

    try {
      return reply.code(201).send(await store.recoverDevicePrivilegeHardening(params.data.deviceId, body.data));
    } catch (error) {
      if (error instanceof DeviceNotFoundError) {
        return sendNotFound(reply, params.data.deviceId);
      }

      throw error;
    }
  });

  app.get("/api/v1/alerts", async () => ({
    items: await store.listAlerts()
  }));

  app.get("/api/v1/commands", async (request, reply) => {
    const parsed = commandsQuerySchema.safeParse(request.query);

    if (!parsed.success) {
      return sendValidationError(reply, parsed.error.flatten());
    }

    return {
      items: await store.listCommands(parsed.data.deviceId, parsed.data.status, parsed.data.limit)
    };
  });

  app.get("/api/v1/quarantine", async (request, reply) => {
    const parsed = quarantineQuerySchema.safeParse(request.query);

    if (!parsed.success) {
      return sendValidationError(reply, parsed.error.flatten());
    }

    return {
      items: await store.listQuarantineItems(parsed.data.deviceId, parsed.data.status, parsed.data.limit)
    };
  });

  app.get("/api/v1/telemetry", async (request, reply) => {
    const parsed = telemetryQuerySchema.safeParse(request.query);

    if (!parsed.success) {
      return sendValidationError(reply, parsed.error.flatten());
    }

    return {
      items: await store.listTelemetry(parsed.data.deviceId, parsed.data.limit)
    };
  });

  app.get("/api/v1/evidence", async (request, reply) => {
    const parsed = telemetryQuerySchema.safeParse(request.query);

    if (!parsed.success) {
      return sendValidationError(reply, parsed.error.flatten());
    }

    return {
      items: await store.listEvidence(parsed.data.deviceId, parsed.data.limit)
    };
  });

  app.get("/api/v1/scan-history", async (request, reply) => {
    const parsed = telemetryQuerySchema.safeParse(request.query);

    if (!parsed.success) {
      return sendValidationError(reply, parsed.error.flatten());
    }

    return {
      items: await store.listScanHistory(parsed.data.deviceId, parsed.data.limit)
    };
  });

  app.get("/api/v1/policies/default", async () => store.getDefaultPolicy());

  app.get("/api/v1/policies", async () => ({
    items: await store.listPolicies()
  }));

  app.post("/api/v1/policies", async (request, reply) => {
    const body = createPolicyRequestSchema.safeParse(request.body);

    if (!body.success) {
      return sendValidationError(reply, body.error.flatten());
    }

    return reply.code(201).send(await store.createPolicy(body.data));
  });

  app.patch("/api/v1/policies/:policyId", async (request, reply) => {
    const params = policyParamsSchema.safeParse(request.params);
    const body = updatePolicyRequestSchema.safeParse(request.body);

    if (!params.success) {
      return sendValidationError(reply, params.error.flatten());
    }

    if (!body.success) {
      return sendValidationError(reply, body.error.flatten());
    }

    try {
      return await store.updatePolicy(params.data.policyId, body.data);
    } catch (error) {
      if (error instanceof PolicyNotFoundError) {
        return sendPolicyNotFound(reply, params.data.policyId);
      }

      throw error;
    }
  });

  app.post("/api/v1/policies/:policyId/assign", async (request, reply) => {
    const params = policyParamsSchema.safeParse(request.params);
    const body = policyAssignmentRequestSchema.safeParse(request.body);

    if (!params.success) {
      return sendValidationError(reply, params.error.flatten());
    }

    if (!body.success) {
      return sendValidationError(reply, body.error.flatten());
    }

    try {
      return await store.assignPolicy(params.data.policyId, body.data);
    } catch (error) {
      if (error instanceof PolicyNotFoundError) {
        return sendPolicyNotFound(reply, params.data.policyId);
      }

      if (error instanceof DeviceNotFoundError) {
        return sendNotFound(reply, error.message.replace("Device not found: ", ""));
      }

      throw error;
    }
  });

  app.get("/api/v1/scripts", async () => ({
    items: await store.listScripts()
  }));

  app.post("/api/v1/scripts", async (request, reply) => {
    const body = createScriptRequestSchema.safeParse(request.body);

    if (!body.success) {
      return sendValidationError(reply, body.error.flatten());
    }

    return reply.code(201).send(await store.createScript(body.data));
  });

  app.patch("/api/v1/scripts/:scriptId", async (request, reply) => {
    const params = scriptParamsSchema.safeParse(request.params);
    const body = updateScriptRequestSchema.safeParse(request.body);

    if (!params.success) {
      return sendValidationError(reply, params.error.flatten());
    }

    if (!body.success) {
      return sendValidationError(reply, body.error.flatten());
    }

    try {
      return await store.updateScript(params.data.scriptId, body.data);
    } catch (error) {
      if (error instanceof ScriptNotFoundError) {
        return sendScriptNotFound(reply, params.data.scriptId);
      }

      throw error;
    }
  });

  app.post("/api/v1/enroll", async (request, reply) => {
    const finalizeEnrollment = (enrollment: { deviceId: string; commandChannelUrl: string }) => {
      const deviceApiKey = issueDeviceApiKey();
      deviceApiKeys.set(enrollment.deviceId, deviceApiKey);

      return {
        ...enrollment,
        deviceApiKey,
        commandChannelUrl: buildCommandChannelUrl(enrollment.commandChannelUrl, enrollment.deviceId, deviceApiKey)
      };
    };
    const parsed = enrollmentRequestSchema.safeParse(request.body);

    if (!parsed.success) {
      return sendValidationError(reply, parsed.error.flatten());
    }

    return reply.code(201).send(
      finalizeEnrollment(await store.enrollDevice(parsed.data, extractObservedRemoteAddress(request)))
    );
  });

  app.post("/api/v1/devices/:deviceId/heartbeat", async (request, reply) => {
    const params = deviceParamsSchema.safeParse(request.params);
    const body = heartbeatRequestSchema.safeParse(request.body);

    if (!params.success) {
      return sendValidationError(reply, params.error.flatten());
    }

    if (!requireDeviceAuthentication(request, reply, params.data.deviceId)) {
      return;
    }

    if (!body.success) {
      return sendValidationError(reply, body.error.flatten());
    }

    try {
      return await store.recordHeartbeat(params.data.deviceId, body.data, extractObservedRemoteAddress(request));
    } catch (error) {
      if (error instanceof DeviceNotFoundError) {
        return sendNotFound(reply, params.data.deviceId);
      }

      throw error;
    }
  });

  app.post("/api/v1/devices/:deviceId/policy-check-in", async (request, reply) => {
    const params = deviceParamsSchema.safeParse(request.params);
    const body = policyCheckInRequestSchema.safeParse(request.body);

    if (!params.success) {
      return sendValidationError(reply, params.error.flatten());
    }

    if (!requireDeviceAuthentication(request, reply, params.data.deviceId)) {
      return;
    }

    if (!body.success) {
      return sendValidationError(reply, body.error.flatten());
    }

    try {
      return await store.policyCheckIn(params.data.deviceId, body.data, extractObservedRemoteAddress(request));
    } catch (error) {
      if (error instanceof DeviceNotFoundError) {
        return sendNotFound(reply, params.data.deviceId);
      }

      throw error;
    }
  });

  app.post("/api/v1/devices/:deviceId/commands", async (request, reply) => {
    const params = deviceParamsSchema.safeParse(request.params);
    const body = queueCommandRequestSchema.safeParse(request.body);

    if (!params.success) {
      return sendValidationError(reply, params.error.flatten());
    }

    if (!body.success) {
      return sendValidationError(reply, body.error.flatten());
    }

    const validation = validateQueuedCommand(body.data);
    if (!validation.valid) {
      return sendValidationError(reply, validation.details);
    }

    try {
      return reply.code(201).send(await store.queueCommand(params.data.deviceId, body.data));
    } catch (error) {
      if (error instanceof DeviceNotFoundError) {
        return sendNotFound(reply, params.data.deviceId);
      }

      throw error;
    }
  });

  app.post("/api/v1/devices/:deviceId/isolate", async (request, reply) => {
    const params = deviceParamsSchema.safeParse(request.params);
    const body = issuedByRequestSchema.safeParse(request.body ?? {});

    if (!params.success) {
      return sendValidationError(reply, params.error.flatten());
    }

    if (!body.success) {
      return sendValidationError(reply, body.error.flatten());
    }

    try {
      return reply.code(201).send(
        await store.queueCommand(params.data.deviceId, {
          type: "device.isolate",
          issuedBy: body.data.issuedBy ?? "console"
        })
      );
    } catch (error) {
      if (error instanceof DeviceNotFoundError) {
        return sendNotFound(reply, params.data.deviceId);
      }

      throw error;
    }
  });

  app.post("/api/v1/devices/:deviceId/release", async (request, reply) => {
    const params = deviceParamsSchema.safeParse(request.params);
    const body = issuedByRequestSchema.safeParse(request.body ?? {});

    if (!params.success) {
      return sendValidationError(reply, params.error.flatten());
    }

    if (!body.success) {
      return sendValidationError(reply, body.error.flatten());
    }

    try {
      return reply.code(201).send(
        await store.queueCommand(params.data.deviceId, {
          type: "device.release",
          issuedBy: body.data.issuedBy ?? "console"
        })
      );
    } catch (error) {
      if (error instanceof DeviceNotFoundError) {
        return sendNotFound(reply, params.data.deviceId);
      }

      throw error;
    }
  });

  app.post("/api/v1/devices/:deviceId/quarantine/:recordId/restore", async (request, reply) => {
    const params = deviceRecordParamsSchema.safeParse(request.params);
    const body = issuedByRequestSchema.safeParse(request.body ?? {});

    if (!params.success) {
      return sendValidationError(reply, params.error.flatten());
    }

    if (!body.success) {
      return sendValidationError(reply, body.error.flatten());
    }

    try {
      return reply.code(201).send(
        await store.queueCommand(params.data.deviceId, {
          type: "quarantine.restore",
          recordId: params.data.recordId,
          issuedBy: body.data.issuedBy ?? "console"
        })
      );
    } catch (error) {
      if (error instanceof DeviceNotFoundError) {
        return sendNotFound(reply, params.data.deviceId);
      }

      throw error;
    }
  });

  app.post("/api/v1/devices/:deviceId/quarantine/:recordId/delete", async (request, reply) => {
    const params = deviceRecordParamsSchema.safeParse(request.params);
    const body = issuedByRequestSchema.safeParse(request.body ?? {});

    if (!params.success) {
      return sendValidationError(reply, params.error.flatten());
    }

    if (!body.success) {
      return sendValidationError(reply, body.error.flatten());
    }

    try {
      return reply.code(201).send(
        await store.queueCommand(params.data.deviceId, {
          type: "quarantine.delete",
          recordId: params.data.recordId,
          issuedBy: body.data.issuedBy ?? "console"
        })
      );
    } catch (error) {
      if (error instanceof DeviceNotFoundError) {
        return sendNotFound(reply, params.data.deviceId);
      }

      throw error;
    }
  });

  app.post("/api/v1/devices/:deviceId/actions/remediate-path", async (request, reply) => {
    const params = deviceParamsSchema.safeParse(request.params);
    const body = targetPathActionRequestSchema.safeParse(request.body);

    if (!params.success) {
      return sendValidationError(reply, params.error.flatten());
    }

    if (!body.success) {
      return sendValidationError(reply, body.error.flatten());
    }

    try {
      return reply.code(201).send(
        await store.queueCommand(params.data.deviceId, {
          type: "remediate.path",
          targetPath: body.data.targetPath,
          issuedBy: body.data.issuedBy ?? "console"
        })
      );
    } catch (error) {
      if (error instanceof DeviceNotFoundError) {
        return sendNotFound(reply, params.data.deviceId);
      }

      throw error;
    }
  });

  app.post("/api/v1/devices/:deviceId/actions/process-tree-terminate", async (request, reply) => {
    const params = deviceParamsSchema.safeParse(request.params);
    const body = targetPathActionRequestSchema.safeParse(request.body);

    if (!params.success) {
      return sendValidationError(reply, params.error.flatten());
    }

    if (!body.success) {
      return sendValidationError(reply, body.error.flatten());
    }

    try {
      return reply.code(201).send(
        await store.queueCommand(params.data.deviceId, {
          type: "process.tree.terminate",
          targetPath: body.data.targetPath,
          issuedBy: body.data.issuedBy ?? "console"
        })
      );
    } catch (error) {
      if (error instanceof DeviceNotFoundError) {
        return sendNotFound(reply, params.data.deviceId);
      }

      throw error;
    }
  });

  app.post("/api/v1/devices/:deviceId/actions/update-agent", async (request, reply) => {
    const params = deviceParamsSchema.safeParse(request.params);
    const body = updateApplyRequestSchema.safeParse(request.body);

    if (!params.success) {
      return sendValidationError(reply, params.error.flatten());
    }

    if (!body.success) {
      return sendValidationError(reply, body.error.flatten());
    }

    try {
      return reply.code(201).send(
        await store.queueCommand(params.data.deviceId, {
          type: "update.apply",
          targetPath: body.data.targetPath,
          issuedBy: body.data.issuedBy ?? "console"
        })
      );
    } catch (error) {
      if (error instanceof DeviceNotFoundError) {
        return sendNotFound(reply, params.data.deviceId);
      }

      throw error;
    }
  });

  app.post("/api/v1/devices/:deviceId/actions/run-script", async (request, reply) => {
    const params = deviceParamsSchema.safeParse(request.params);
    const body = runScriptRequestSchema.safeParse(request.body);

    if (!params.success) {
      return sendValidationError(reply, params.error.flatten());
    }

    if (!body.success) {
      return sendValidationError(reply, body.error.flatten());
    }

    try {
      const scripts = await store.listScripts();
      const script = scripts.find((item) => item.id === body.data.scriptId);
      if (!script) {
        return sendScriptNotFound(reply, body.data.scriptId);
      }

      return reply.code(201).send(
        await store.queueCommand(params.data.deviceId, {
          type: "script.run",
          issuedBy: body.data.issuedBy ?? "console",
          payloadJson: JSON.stringify({
            scriptId: script.id,
            scriptName: script.name,
            language: script.language,
            content: script.content
          })
        })
      );
    } catch (error) {
      if (error instanceof DeviceNotFoundError) {
        return sendNotFound(reply, params.data.deviceId);
      }

      throw error;
    }
  });

  app.post("/api/v1/devices/:deviceId/actions/software-uninstall", async (request, reply) => {
    const params = deviceParamsSchema.safeParse(request.params);
    const body = softwareCommandRequestSchema.safeParse(request.body);

    if (!params.success) {
      return sendValidationError(reply, params.error.flatten());
    }

    if (!body.success) {
      return sendValidationError(reply, body.error.flatten());
    }

    try {
      return reply.code(201).send(
        await store.queueCommand(params.data.deviceId, {
          type: "software.uninstall",
          issuedBy: body.data.issuedBy ?? "console",
          payloadJson: JSON.stringify({
            softwareId: body.data.softwareId,
            displayName: body.data.displayName,
            displayVersion: body.data.displayVersion,
            publisher: body.data.publisher,
            installLocation: body.data.installLocation,
            uninstallCommand: body.data.uninstallCommand,
            quietUninstallCommand: body.data.quietUninstallCommand,
            executableNames: body.data.executableNames,
            commandLine: body.data.commandLine,
            workingDirectory: body.data.workingDirectory ?? body.data.installLocation
          })
        })
      );
    } catch (error) {
      if (error instanceof DeviceNotFoundError) {
        return sendNotFound(reply, params.data.deviceId);
      }

      throw error;
    }
  });

  app.post("/api/v1/devices/:deviceId/actions/software-update", async (request, reply) => {
    const params = deviceParamsSchema.safeParse(request.params);
    const body = softwareCommandRequestSchema.safeParse(request.body);

    if (!params.success) {
      return sendValidationError(reply, params.error.flatten());
    }

    if (!body.success) {
      return sendValidationError(reply, body.error.flatten());
    }

    try {
      return reply.code(201).send(
        await store.queueCommand(params.data.deviceId, {
          type: "software.update",
          issuedBy: body.data.issuedBy ?? "console",
          payloadJson: JSON.stringify({
            softwareId: body.data.softwareId,
            displayName: body.data.displayName,
            displayVersion: body.data.displayVersion,
            publisher: body.data.publisher,
            installLocation: body.data.installLocation,
            executableNames: body.data.executableNames,
            commandLine: body.data.commandLine,
            workingDirectory: body.data.workingDirectory ?? body.data.installLocation
          })
        })
      );
    } catch (error) {
      if (error instanceof DeviceNotFoundError) {
        return sendNotFound(reply, params.data.deviceId);
      }

      throw error;
    }
  });

  app.post("/api/v1/devices/:deviceId/actions/software-search-updates", async (request, reply) => {
    const params = deviceParamsSchema.safeParse(request.params);
    const body = softwareCommandRequestSchema.safeParse(request.body);

    if (!params.success) {
      return sendValidationError(reply, params.error.flatten());
    }

    if (!body.success) {
      return sendValidationError(reply, body.error.flatten());
    }

    try {
      return reply.code(201).send(
        await store.queueCommand(params.data.deviceId, {
          type: "software.update.search",
          issuedBy: body.data.issuedBy ?? "console",
          payloadJson: JSON.stringify({
            softwareId: body.data.softwareId,
            displayName: body.data.displayName,
            displayVersion: body.data.displayVersion,
            publisher: body.data.publisher,
            installLocation: body.data.installLocation,
            executableNames: body.data.executableNames
          })
        })
      );
    } catch (error) {
      if (error instanceof DeviceNotFoundError) {
        return sendNotFound(reply, params.data.deviceId);
      }

      throw error;
    }
  });

  app.post("/api/v1/devices/:deviceId/actions/software-block", async (request, reply) => {
    const params = deviceParamsSchema.safeParse(request.params);
    const body = softwareCommandRequestSchema.safeParse(request.body);

    if (!params.success) {
      return sendValidationError(reply, params.error.flatten());
    }

    if (!body.success) {
      return sendValidationError(reply, body.error.flatten());
    }

    try {
      return reply.code(201).send(
        await store.queueCommand(params.data.deviceId, {
          type: "software.block",
          issuedBy: body.data.issuedBy ?? "console",
          payloadJson: JSON.stringify({
            softwareId: body.data.softwareId,
            displayName: body.data.displayName,
            displayVersion: body.data.displayVersion,
            publisher: body.data.publisher,
            installLocation: body.data.installLocation,
            executableNames: body.data.executableNames
          })
        })
      );
    } catch (error) {
      if (error instanceof DeviceNotFoundError) {
        return sendNotFound(reply, params.data.deviceId);
      }

      throw error;
    }
  });

  app.get("/api/v1/devices/:deviceId/commands/pending", async (request, reply) => {
    const params = deviceParamsSchema.safeParse(request.params);
    const query = pollCommandsQuerySchema.safeParse(request.query);

    if (!params.success) {
      return sendValidationError(reply, params.error.flatten());
    }

    if (!requireDeviceAuthentication(request, reply, params.data.deviceId)) {
      return;
    }

    if (!query.success) {
      return sendValidationError(reply, query.error.flatten());
    }

    try {
      return await store.pollPendingCommands(params.data.deviceId, query.data.limit);
    } catch (error) {
      if (error instanceof DeviceNotFoundError) {
        return sendNotFound(reply, params.data.deviceId);
      }

      throw error;
    }
  });

  app.post("/api/v1/devices/:deviceId/commands/:commandId/complete", async (request, reply) => {
    const params = commandParamsSchema.safeParse(request.params);
    const body = completeCommandRequestSchema.safeParse(request.body);

    if (!params.success) {
      return sendValidationError(reply, params.error.flatten());
    }

    if (!requireDeviceAuthentication(request, reply, params.data.deviceId)) {
      return;
    }

    if (!body.success) {
      return sendValidationError(reply, body.error.flatten());
    }

    try {
      return await store.completeCommand(params.data.deviceId, params.data.commandId, body.data);
    } catch (error) {
      if (error instanceof DeviceNotFoundError) {
        return sendNotFound(reply, params.data.deviceId);
      }

      if (error instanceof CommandNotFoundError) {
        return sendCommandNotFound(reply, params.data.commandId);
      }

      throw error;
    }
  });

  app.post("/api/v1/devices/:deviceId/telemetry", async (request, reply) => {
    const params = deviceParamsSchema.safeParse(request.params);
    const body = telemetryBatchRequestSchema.safeParse(request.body);

    if (!params.success) {
      return sendValidationError(reply, params.error.flatten());
    }

    if (!requireDeviceAuthentication(request, reply, params.data.deviceId)) {
      return;
    }

    if (!body.success) {
      return sendValidationError(reply, body.error.flatten());
    }

    try {
      return await store.ingestTelemetry(params.data.deviceId, body.data, extractObservedRemoteAddress(request));
    } catch (error) {
      if (error instanceof DeviceNotFoundError) {
        return sendNotFound(reply, params.data.deviceId);
      }

      throw error;
    }
  });

  app.post("/api/v1/devices/:deviceId/risk-telemetry", async (request, reply) => {
    const params = deviceParamsSchema.safeParse(request.params);
    const body = upsertDeviceRiskTelemetryRequestSchema.safeParse(request.body ?? {});

    if (!params.success) {
      return sendValidationError(reply, params.error.flatten());
    }

    if (!requireDeviceAuthentication(request, reply, params.data.deviceId)) {
      return;
    }

    if (!body.success) {
      return sendValidationError(reply, body.error.flatten());
    }

    try {
      return await store.upsertDeviceRiskTelemetry(params.data.deviceId, body.data);
    } catch (error) {
      if (error instanceof DeviceNotFoundError) {
        return sendNotFound(reply, params.data.deviceId);
      }

      throw error;
    }
  });

  return app;
}
