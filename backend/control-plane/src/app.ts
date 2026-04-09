import Fastify from "fastify";
import cors from "@fastify/cors";
import { z } from "zod";

import {
  createFileBackedMailStore,
  MailDomainNotFoundError,
  MailMessageNotFoundError,
  MailQuarantineItemNotFoundError,
  type MailStore
} from "./mailStore.js";
import {
  CommandNotFoundError,
  createFileBackedControlPlaneStore,
  DeviceNotFoundError,
  type ControlPlaneStore
} from "./controlPlaneStore.js";

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
    "remediate.path"
  ]),
  issuedBy: z.string().min(1).optional(),
  targetPath: z.string().min(1).optional(),
  recordId: z.string().min(1).optional()
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

  return { valid: true };
}

export function buildServer(options: BuildServerOptions = {}) {
  const store = options.store ?? createFileBackedControlPlaneStore();
  const mailStore = options.mailStore ?? createFileBackedMailStore();
  const app = Fastify({
    logger: true
  });

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

  app.post("/api/v1/enroll", async (request, reply) => {
    const parsed = enrollmentRequestSchema.safeParse(request.body);

    if (!parsed.success) {
      return sendValidationError(reply, parsed.error.flatten());
    }

    return reply.code(201).send(await store.enrollDevice(parsed.data));
  });

  app.post("/api/v1/devices/:deviceId/heartbeat", async (request, reply) => {
    const params = deviceParamsSchema.safeParse(request.params);
    const body = heartbeatRequestSchema.safeParse(request.body);

    if (!params.success) {
      return sendValidationError(reply, params.error.flatten());
    }

    if (!body.success) {
      return sendValidationError(reply, body.error.flatten());
    }

    try {
      return await store.recordHeartbeat(params.data.deviceId, body.data);
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

    if (!body.success) {
      return sendValidationError(reply, body.error.flatten());
    }

    try {
      return await store.policyCheckIn(params.data.deviceId, body.data);
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

  app.get("/api/v1/devices/:deviceId/commands/pending", async (request, reply) => {
    const params = deviceParamsSchema.safeParse(request.params);
    const query = pollCommandsQuerySchema.safeParse(request.query);

    if (!params.success) {
      return sendValidationError(reply, params.error.flatten());
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

    if (!body.success) {
      return sendValidationError(reply, body.error.flatten());
    }

    try {
      return await store.ingestTelemetry(params.data.deviceId, body.data);
    } catch (error) {
      if (error instanceof DeviceNotFoundError) {
        return sendNotFound(reply, params.data.deviceId);
      }

      throw error;
    }
  });

  return app;
}
