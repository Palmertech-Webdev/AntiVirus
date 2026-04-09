import { randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import { createEmptyMailState, createSeedMailState } from "./mailSeedState.ts";
import type {
  MailActionRecord,
  MailAuthResult,
  MailAuthSummary,
  MailDashboardSnapshot,
  MailDeliveryAction,
  MailDomainHealthStatus,
  MailDomainSummary,
  MailMessageSummary,
  MailPolicySummary,
  MailQuarantineItemSummary,
  MailQuarantineStatus,
  MailState,
  MailVerdict,
  MailVerificationStatus,
  SimulatedInboundMailRequest
} from "./types.ts";

const DEFAULT_STATE_FILE_PATH = join(process.cwd(), ".data", "mail-state.json");
const MAX_MESSAGES = 2_000;
const MAX_QUARANTINE_ITEMS = 2_000;
const MAX_ACTION_RECORDS = 2_000;

interface CreateFileBackedMailStoreOptions {
  stateFilePath?: string;
  now?: () => string;
  seedDemoData?: boolean;
}

export interface MailStore {
  getDashboardSnapshot(): Promise<MailDashboardSnapshot>;
  listDomains(): Promise<MailDomainSummary[]>;
  listMessages(limit?: number, verdict?: MailVerdict, deliveryAction?: MailDeliveryAction): Promise<MailMessageSummary[]>;
  getMessage(mailMessageId: string): Promise<MailMessageSummary>;
  listQuarantineItems(status?: MailQuarantineStatus, limit?: number): Promise<MailQuarantineItemSummary[]>;
  getDefaultPolicy(): Promise<MailPolicySummary>;
  simulateInboundMessage(request: SimulatedInboundMailRequest): Promise<MailMessageSummary>;
  releaseQuarantineItem(quarantineItemId: string, requestedBy?: string): Promise<MailQuarantineItemSummary>;
  purgeMessage(mailMessageId: string, requestedBy?: string): Promise<MailMessageSummary>;
}

export class MailMessageNotFoundError extends Error {
  constructor(mailMessageId: string) {
    super(`Mail message not found: ${mailMessageId}`);
    this.name = "MailMessageNotFoundError";
  }
}

export class MailQuarantineItemNotFoundError extends Error {
  constructor(quarantineItemId: string) {
    super(`Mail quarantine item not found: ${quarantineItemId}`);
    this.name = "MailQuarantineItemNotFoundError";
  }
}

export class MailDomainNotFoundError extends Error {
  constructor(identifier: string) {
    super(`Mail domain not found: ${identifier}`);
    this.name = "MailDomainNotFoundError";
  }
}

function readOptionalString(value: unknown, fallback = "") {
  return typeof value === "string" ? value : fallback;
}

function readNullableString(value: unknown) {
  return typeof value === "string" ? value : null;
}

function clampMailDomainHealthStatus(value: unknown): MailDomainHealthStatus {
  return value === "ready" || value === "degraded" ? value : "pending";
}

function clampMailVerificationStatus(value: unknown): MailVerificationStatus {
  return value === "verified" || value === "failed" ? value : "pending";
}

function clampMailVerdict(value: unknown): MailVerdict {
  switch (value) {
    case "spam":
    case "phish":
    case "malware":
    case "suspicious":
      return value;
    default:
      return "clean";
  }
}

function clampMailDeliveryAction(value: unknown): MailDeliveryAction {
  switch (value) {
    case "quarantined":
    case "rejected":
    case "held":
    case "junked":
    case "purged":
      return value;
    default:
      return "delivered";
  }
}

function clampMailQuarantineStatus(value: unknown): MailQuarantineStatus {
  return value === "released" || value === "purged" ? value : "quarantined";
}

function clampMailAuthResult(value: unknown): MailAuthResult {
  return value === "pass" || value === "fail" || value === "softfail" ? value : "none";
}

function normalizeMailAuthSummary(raw: unknown): MailAuthSummary {
  const summary = (raw ?? {}) as Partial<MailAuthSummary>;
  return {
    spf: clampMailAuthResult(summary.spf),
    dkim: clampMailAuthResult(summary.dkim),
    dmarc: clampMailAuthResult(summary.dmarc),
    arc: clampMailAuthResult(summary.arc)
  };
}

function normalizeMailPolicySummary(raw: unknown): MailPolicySummary {
  const policy = (raw ?? {}) as Partial<MailPolicySummary>;
  return {
    id: readOptionalString(policy.id, "mail-policy-default"),
    name: readOptionalString(policy.name, "Inbound Mail Baseline"),
    revision: readOptionalString(policy.revision, "unknown"),
    defaultAction: clampMailDeliveryAction(policy.defaultAction),
    urlRewriteEnabled: policy.urlRewriteEnabled !== false,
    attachmentScanningEnabled: policy.attachmentScanningEnabled !== false,
    impersonationProtectionEnabled: policy.impersonationProtectionEnabled !== false,
    quarantineRetentionDays:
      typeof policy.quarantineRetentionDays === "number" && Number.isFinite(policy.quarantineRetentionDays)
        ? policy.quarantineRetentionDays
        : 30
  };
}

function normalizeMailDomainSummary(raw: unknown): MailDomainSummary {
  const domain = (raw ?? {}) as Partial<MailDomainSummary>;
  return {
    id: readOptionalString(domain.id, randomUUID()),
    domain: readOptionalString(domain.domain, "example.invalid"),
    status: clampMailDomainHealthStatus(domain.status),
    verificationStatus: clampMailVerificationStatus(domain.verificationStatus),
    mxRecordsConfigured: domain.mxRecordsConfigured === true,
    downstreamRoute: readOptionalString(domain.downstreamRoute, "unassigned"),
    activeMessageCount:
      typeof domain.activeMessageCount === "number" && Number.isFinite(domain.activeMessageCount)
        ? domain.activeMessageCount
        : 0,
    quarantinedMessageCount:
      typeof domain.quarantinedMessageCount === "number" && Number.isFinite(domain.quarantinedMessageCount)
        ? domain.quarantinedMessageCount
        : 0,
    lastMessageAt: readNullableString(domain.lastMessageAt)
  };
}

function normalizeMailMessageSummary(raw: unknown, nowIso: string): MailMessageSummary {
  const message = (raw ?? {}) as Partial<MailMessageSummary>;
  return {
    id: readOptionalString(message.id, randomUUID()),
    mailDomainId: readOptionalString(message.mailDomainId),
    domain: readOptionalString(message.domain, "example.invalid"),
    internetMessageId: readOptionalString(message.internetMessageId, `<${randomUUID()}@example.invalid>`),
    direction: message.direction === "outbound" ? "outbound" : "inbound",
    subject: readOptionalString(message.subject, "Untitled message"),
    sender: readOptionalString(message.sender, "unknown@example.invalid"),
    recipients: Array.isArray(message.recipients)
      ? message.recipients.filter((item): item is string => typeof item === "string" && item.length > 0)
      : [],
    verdict: clampMailVerdict(message.verdict),
    deliveryAction: clampMailDeliveryAction(message.deliveryAction),
    receivedAt: readOptionalString(message.receivedAt, nowIso),
    deliveredAt: readNullableString(message.deliveredAt),
    summary: readOptionalString(message.summary, "No message summary available."),
    auth: normalizeMailAuthSummary(message.auth),
    attachments: Array.isArray(message.attachments)
      ? message.attachments.map((item) => {
          const attachment = (item ?? {}) as Partial<MailMessageSummary["attachments"][number]>;
          return {
            id: readOptionalString(attachment.id, randomUUID()),
            fileName: readOptionalString(attachment.fileName, "attachment.bin"),
            sha256: readOptionalString(attachment.sha256, "unknown"),
            sizeBytes:
              typeof attachment.sizeBytes === "number" && Number.isFinite(attachment.sizeBytes) ? attachment.sizeBytes : 0,
            verdict: clampMailVerdict(attachment.verdict)
          };
        })
      : [],
    urls: Array.isArray(message.urls)
      ? message.urls.map((item) => {
          const url = (item ?? {}) as Partial<MailMessageSummary["urls"][number]>;
          return {
            id: readOptionalString(url.id, randomUUID()),
            originalUrl: readOptionalString(url.originalUrl, "https://example.invalid"),
            verdict: clampMailVerdict(url.verdict),
            rewriteApplied: url.rewriteApplied === true
          };
        })
      : [],
    relatedAlertId: typeof message.relatedAlertId === "string" ? message.relatedAlertId : undefined,
    relatedDeviceId: typeof message.relatedDeviceId === "string" ? message.relatedDeviceId : undefined,
    relatedUser: typeof message.relatedUser === "string" ? message.relatedUser : undefined
  };
}

function normalizeMailQuarantineItemSummary(raw: unknown, nowIso: string): MailQuarantineItemSummary {
  const item = (raw ?? {}) as Partial<MailQuarantineItemSummary>;
  return {
    id: readOptionalString(item.id, randomUUID()),
    mailMessageId: readOptionalString(item.mailMessageId),
    domain: readOptionalString(item.domain, "example.invalid"),
    subject: readOptionalString(item.subject, "Untitled message"),
    sender: readOptionalString(item.sender, "unknown@example.invalid"),
    recipientSummary: readOptionalString(item.recipientSummary, "unknown recipient"),
    reason: readOptionalString(item.reason, "Policy action"),
    status: clampMailQuarantineStatus(item.status),
    quarantinedAt: readOptionalString(item.quarantinedAt, nowIso),
    releasedAt: readNullableString(item.releasedAt)
  };
}

function normalizeMailActionRecord(raw: unknown, nowIso: string): MailActionRecord {
  const record = (raw ?? {}) as Partial<MailActionRecord>;
  return {
    id: readOptionalString(record.id, randomUUID()),
    mailMessageId: readOptionalString(record.mailMessageId),
    actionType: record.actionType === "quarantine.release" ? "quarantine.release" : "message.purge",
    requestedBy: readOptionalString(record.requestedBy, "system"),
    requestedAt: readOptionalString(record.requestedAt, nowIso),
    status: record.status === "failed" ? "failed" : "completed",
    resultSummary: readOptionalString(record.resultSummary, "Action completed.")
  };
}

function normalizeState(rawState: unknown, nowIso: string): MailState {
  const raw = (rawState ?? {}) as Partial<MailState>;
  const defaults = createEmptyMailState(nowIso);
  const state: MailState = {
    defaultPolicy: raw.defaultPolicy ? normalizeMailPolicySummary(raw.defaultPolicy) : defaults.defaultPolicy,
    domains: Array.isArray(raw.domains) ? raw.domains.map((item) => normalizeMailDomainSummary(item)) : [],
    messages: Array.isArray(raw.messages) ? raw.messages.map((item) => normalizeMailMessageSummary(item, nowIso)) : [],
    quarantineItems: Array.isArray(raw.quarantineItems)
      ? raw.quarantineItems.map((item) => normalizeMailQuarantineItemSummary(item, nowIso))
      : [],
    actionRecords: Array.isArray(raw.actionRecords)
      ? raw.actionRecords.map((item) => normalizeMailActionRecord(item, nowIso))
      : []
  };
  recomputeDomainStats(state);
  return state;
}

function sortByIsoDescending<T>(items: T[], getIso: (item: T) => string | null) {
  return [...items].sort((left, right) => {
    const rightIso = getIso(right) ?? "";
    const leftIso = getIso(left) ?? "";
    return rightIso.localeCompare(leftIso);
  });
}

function sortDomains(items: MailDomainSummary[]) {
  return [...items].sort((left, right) => left.domain.localeCompare(right.domain));
}

function sortMessages(items: MailMessageSummary[]) {
  return sortByIsoDescending(items, (item) => item.receivedAt);
}

function sortQuarantine(items: MailQuarantineItemSummary[]) {
  return sortByIsoDescending(items, (item) => item.quarantinedAt);
}

function sortActions(items: MailActionRecord[]) {
  return sortByIsoDescending(items, (item) => item.requestedAt);
}

function trimState(state: MailState) {
  state.messages = sortMessages(state.messages).slice(0, MAX_MESSAGES);
  state.quarantineItems = sortQuarantine(state.quarantineItems).slice(0, MAX_QUARANTINE_ITEMS);
  state.actionRecords = sortActions(state.actionRecords).slice(0, MAX_ACTION_RECORDS);
}

function recomputeDomainStats(state: MailState) {
  for (const domain of state.domains) {
    const messages = state.messages.filter((item) => item.mailDomainId === domain.id);
    domain.activeMessageCount = messages.length;
    domain.quarantinedMessageCount = state.quarantineItems.filter(
      (item) => item.domain === domain.domain && item.status === "quarantined"
    ).length;
    domain.lastMessageAt = messages.reduce<string | null>(
      (latest, item) => (latest === null || item.receivedAt > latest ? item.receivedAt : latest),
      null
    );
  }
}

function findMessageOrThrow(state: MailState, mailMessageId: string) {
  const message = state.messages.find((item) => item.id === mailMessageId);
  if (!message) {
    throw new MailMessageNotFoundError(mailMessageId);
  }

  return message;
}

function findQuarantineItemOrThrow(state: MailState, quarantineItemId: string) {
  const item = state.quarantineItems.find((entry) => entry.id === quarantineItemId);
  if (!item) {
    throw new MailQuarantineItemNotFoundError(quarantineItemId);
  }

  return item;
}

function selectDomainForInboundMessage(state: MailState, request: SimulatedInboundMailRequest) {
  if (request.mailDomainId) {
    const matched = state.domains.find((item) => item.id === request.mailDomainId);
    if (!matched) {
      throw new MailDomainNotFoundError(request.mailDomainId);
    }

    return matched;
  }

  const recipientDomain = request.recipients[0]?.split("@").at(-1)?.toLowerCase();
  if (!recipientDomain) {
    throw new MailDomainNotFoundError("recipient-domain");
  }

  const matched = state.domains.find((item) => item.domain.toLowerCase() === recipientDomain);
  if (!matched) {
    throw new MailDomainNotFoundError(recipientDomain);
  }

  return matched;
}

function createQuarantineReason(message: MailMessageSummary) {
  if (message.verdict === "malware") {
    return "Malicious attachment or embedded payload detected during content inspection.";
  }

  if (message.verdict === "phish") {
    return "Credential-phishing indicators and sender-anomaly checks triggered quarantine.";
  }

  if (message.verdict === "spam") {
    return "Bulk-mail or sender-reputation controls routed the message into quarantine.";
  }

  return "Suspicious content requires analyst review.";
}

export function createFileBackedMailStore(options: CreateFileBackedMailStoreOptions = {}): MailStore {
  const stateFilePath = options.stateFilePath ?? DEFAULT_STATE_FILE_PATH;
  const now = options.now ?? (() => new Date().toISOString());
  const seedDemoData = options.seedDemoData ?? false;

  let cachedState: MailState | null = null;

  async function persistState(state: MailState) {
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
    } catch (error) {
      const maybeNodeError = error as NodeJS.ErrnoException;
      if (maybeNodeError.code !== "ENOENT") {
        throw error;
      }

      cachedState = seedDemoData ? createSeedMailState(now()) : createEmptyMailState(now());
    }

    trimState(cachedState);
    recomputeDomainStats(cachedState);
    await persistState(cachedState);
    return cachedState;
  }

  async function mutateState<T>(mutator: (state: MailState) => T | Promise<T>) {
    const state = await loadState();
    const result = await mutator(state);
    trimState(state);
    recomputeDomainStats(state);
    await persistState(state);
    return result;
  }

  function appendActionRecord(state: MailState, record: Omit<MailActionRecord, "id">) {
    state.actionRecords.push({
      id: randomUUID(),
      ...record
    });
  }

  return {
    async getDashboardSnapshot() {
      const state = await loadState();
      return {
        generatedAt: now(),
        domains: sortDomains(state.domains),
        recentMessages: sortMessages(state.messages).slice(0, 50),
        quarantineItems: sortQuarantine(state.quarantineItems).slice(0, 50),
        recentActions: sortActions(state.actionRecords).slice(0, 20),
        defaultPolicy: state.defaultPolicy
      };
    },

    async listDomains() {
      const state = await loadState();
      return sortDomains(state.domains);
    },

    async listMessages(limit = 50, verdict, deliveryAction) {
      const state = await loadState();
      return sortMessages(
        state.messages.filter((item) => {
          if (verdict && item.verdict !== verdict) {
            return false;
          }

          if (deliveryAction && item.deliveryAction !== deliveryAction) {
            return false;
          }

          return true;
        })
      ).slice(0, limit);
    },

    async getMessage(mailMessageId) {
      const state = await loadState();
      return findMessageOrThrow(state, mailMessageId);
    },

    async listQuarantineItems(status, limit = 50) {
      const state = await loadState();
      return sortQuarantine(
        state.quarantineItems.filter((item) => {
          if (status && item.status !== status) {
            return false;
          }

          return true;
        })
      ).slice(0, limit);
    },

    async getDefaultPolicy() {
      const state = await loadState();
      return state.defaultPolicy;
    },

    async simulateInboundMessage(request) {
      return mutateState(async (state) => {
        const domain = selectDomainForInboundMessage(state, request);
        const receivedAt = now();
        const messageId = randomUUID();

        const message: MailMessageSummary = {
          id: messageId,
          mailDomainId: domain.id,
          domain: domain.domain,
          internetMessageId: `<${messageId}@${domain.domain}>`,
          direction: "inbound",
          subject: request.subject,
          sender: request.sender,
          recipients: request.recipients,
          verdict: request.verdict,
          deliveryAction: request.deliveryAction,
          receivedAt,
          deliveredAt:
            request.deliveryAction === "delivered" || request.deliveryAction === "junked" ? receivedAt : null,
          summary: request.summary ?? "Simulated inbound message was staged for Phase A validation.",
          auth: {
            spf: clampMailAuthResult(request.auth?.spf),
            dkim: clampMailAuthResult(request.auth?.dkim),
            dmarc: clampMailAuthResult(request.auth?.dmarc),
            arc: clampMailAuthResult(request.auth?.arc)
          },
          attachments: (request.attachments ?? []).map((item) => ({
            id: randomUUID(),
            fileName: item.fileName,
            sha256: item.sha256,
            sizeBytes: item.sizeBytes,
            verdict: item.verdict
          })),
          urls: (request.urls ?? []).map((item) => ({
            id: randomUUID(),
            originalUrl: item.originalUrl,
            verdict: item.verdict,
            rewriteApplied: item.rewriteApplied === true
          })),
          relatedAlertId: request.relatedAlertId,
          relatedDeviceId: request.relatedDeviceId,
          relatedUser: request.relatedUser
        };

        state.messages.push(message);

        if (message.deliveryAction === "quarantined") {
          state.quarantineItems.push({
            id: randomUUID(),
            mailMessageId: message.id,
            domain: message.domain,
            subject: message.subject,
            sender: message.sender,
            recipientSummary: message.recipients.join(", "),
            reason: createQuarantineReason(message),
            status: "quarantined",
            quarantinedAt: receivedAt,
            releasedAt: null
          });
        }

        return message;
      });
    },

    async releaseQuarantineItem(quarantineItemId, requestedBy = "console") {
      return mutateState(async (state) => {
        const item = findQuarantineItemOrThrow(state, quarantineItemId);
        const message = findMessageOrThrow(state, item.mailMessageId);
        const releasedAt = now();

        item.status = "released";
        item.releasedAt = releasedAt;
        message.deliveryAction = "delivered";
        message.deliveredAt = releasedAt;

        appendActionRecord(state, {
          mailMessageId: message.id,
          actionType: "quarantine.release",
          requestedBy,
          requestedAt: releasedAt,
          status: "completed",
          resultSummary: `Released "${message.subject}" for downstream delivery.`
        });

        return item;
      });
    },

    async purgeMessage(mailMessageId, requestedBy = "console") {
      return mutateState(async (state) => {
        const message = findMessageOrThrow(state, mailMessageId);
        const requestedAt = now();
        message.deliveryAction = "purged";
        message.deliveredAt = null;

        const quarantineItem = state.quarantineItems.find((item) => item.mailMessageId === mailMessageId);
        if (quarantineItem) {
          quarantineItem.status = "purged";
          quarantineItem.releasedAt = requestedAt;
        }

        appendActionRecord(state, {
          mailMessageId,
          actionType: "message.purge",
          requestedBy,
          requestedAt,
          status: "completed",
          resultSummary: `Marked "${message.subject}" for purge and downstream removal follow-up.`
        });

        return message;
      });
    }
  };
}
