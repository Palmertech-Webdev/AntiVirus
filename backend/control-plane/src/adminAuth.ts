import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

import type {
  AdminActorContext,
  AdminApiKeyCreateRequest,
  AdminApiKeyRecord,
  AdminApiKeySummary,
  AdminAuditEventSummary,
  AdminPrincipalRecord,
  AdminPrincipalSummary,
  AdminRole,
  AdminSessionRecord,
  AdminSessionSummary,
  AdminLoginRequest,
  AdminLoginResponse
} from "./types.ts";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export const DEFAULT_ADMIN_USERNAME = process.env.FENRIR_ADMIN_USERNAME?.trim() || "admin@fenrir.local";
export const DEFAULT_ADMIN_DISPLAY_NAME = process.env.FENRIR_ADMIN_DISPLAY_NAME?.trim() || "Fenrir Platform Admin";
export const DEFAULT_ADMIN_PASSWORD = process.env.FENRIR_ADMIN_PASSWORD ?? "Fenrir!Admin123";
export const DEFAULT_ADMIN_MFA_SECRET = process.env.FENRIR_ADMIN_MFA_SECRET?.trim() || "JBSWY3DPEHPK3PXP";
export const DEFAULT_ADMIN_ROLES: AdminRole[] = ["admin"];

export function createPasswordSalt() {
  return randomBytes(16).toString("hex");
}

export function hashPassword(password: string, salt: string) {
  return createHash("sha256").update(`${salt}:${password}`).digest("hex");
}

export function verifyPassword(password: string, salt: string, expectedHash: string) {
  const candidate = Buffer.from(hashPassword(password, salt), "hex");
  const expected = Buffer.from(expectedHash, "hex");

  if (candidate.length !== expected.length) {
    return false;
  }

  return timingSafeEqual(candidate, expected);
}

export function createSessionToken() {
  return randomBytes(32).toString("hex");
}

export function hashSessionToken(token: string) {
  return createHash("sha256").update(token).digest("hex");
}

function decodeBase32(secret: string) {
  const normalized = secret.replace(/\s+/g, "").toUpperCase();
  const bits: number[] = [];

  for (const char of normalized) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index < 0) {
      continue;
    }

    bits.push((index >>> 4) & 1, (index >>> 3) & 1, (index >>> 2) & 1, (index >>> 1) & 1, index & 1);
  }

  const bytes: number[] = [];
  for (let offset = 0; offset + 8 <= bits.length; offset += 8) {
    let value = 0;
    for (let bitIndex = 0; bitIndex < 8; bitIndex += 1) {
      value = (value << 1) | bits[offset + bitIndex];
    }
    bytes.push(value);
  }

  return Buffer.from(bytes);
}

export function generateTotpCode(secret: string, timestamp = Date.now(), stepSeconds = 30, digits = 6) {
  const counter = Math.floor(timestamp / 1000 / stepSeconds);
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));

  const hmac = createHmac("sha1", decodeBase32(secret)).update(counterBuffer).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    (hmac[offset + 1] << 16) |
    (hmac[offset + 2] << 8) |
    hmac[offset + 3];
  const code = binary % 10 ** digits;
  return code.toString().padStart(digits, "0");
}

export function verifyTotpCode(secret: string, code: string, timestamp = Date.now(), window = 1) {
  const normalizedCode = code.trim();
  if (!/^\d{6}$/.test(normalizedCode)) {
    return false;
  }

  for (let offset = -window; offset <= window; offset += 1) {
    const candidate = generateTotpCode(secret, timestamp + offset * 30_000);
    if (candidate === normalizedCode) {
      return true;
    }
  }

  return false;
}

export function createBootstrapAdminPrincipal(nowIso: string): AdminPrincipalRecord {
  const passwordSalt = createPasswordSalt();

  return {
    id: "admin-bootstrap",
    username: DEFAULT_ADMIN_USERNAME,
    displayName: DEFAULT_ADMIN_DISPLAY_NAME,
    passwordSalt,
    passwordHash: hashPassword(DEFAULT_ADMIN_PASSWORD, passwordSalt),
    mfaSecret: DEFAULT_ADMIN_MFA_SECRET,
    roles: [...DEFAULT_ADMIN_ROLES],
    enabled: true,
    createdAt: nowIso,
    updatedAt: nowIso
  };
}

export function createBootstrapAdminState(nowIso: string) {
  const principal = createBootstrapAdminPrincipal(nowIso);

  return {
    adminPrincipals: [principal],
    adminSessions: [] as AdminSessionRecord[],
    adminApiKeys: [] as AdminApiKeyRecord[],
    adminAuditEvents: [
      {
        id: randomBytes(16).toString("hex"),
        occurredAt: nowIso,
        actorName: "system",
        actorType: "system" as const,
        action: "admin.bootstrap",
        resourceType: "admin_principal",
        resourceId: principal.id,
        outcome: "success" as const,
        severity: "medium" as const,
        details: `Bootstrap admin principal ${principal.username} seeded.`,
        source: "control-plane"
      } satisfies AdminAuditEventSummary
    ]
  };
}

export function toAdminPrincipalSummary(principal: AdminPrincipalRecord): AdminPrincipalSummary {
  return {
    id: principal.id,
    username: principal.username,
    displayName: principal.displayName,
    roles: [...principal.roles],
    enabled: principal.enabled,
    createdAt: principal.createdAt,
    updatedAt: principal.updatedAt,
    lastLoginAt: principal.lastLoginAt
  };
}

export function toAdminSessionSummary(session: AdminSessionRecord, principal: AdminPrincipalRecord): AdminSessionSummary {
  return {
    id: session.id,
    principalId: session.principalId,
    principalUsername: principal.username,
    principalDisplayName: principal.displayName,
    principalRoles: [...principal.roles],
    createdAt: session.createdAt,
    expiresAt: session.expiresAt,
    lastSeenAt: session.lastSeenAt,
    revokedAt: session.revokedAt,
    sourceIp: session.sourceIp,
    userAgent: session.userAgent
  };
}

export function toAdminApiKeySummary(apiKey: AdminApiKeyRecord, principal: AdminPrincipalRecord): AdminApiKeySummary {
  return {
    id: apiKey.id,
    principalId: apiKey.principalId,
    principalUsername: principal.username,
    principalDisplayName: principal.displayName,
    name: apiKey.name,
    scopes: [...apiKey.scopes],
    createdAt: apiKey.createdAt,
    updatedAt: apiKey.updatedAt,
    revokedAt: apiKey.revokedAt,
    lastUsedAt: apiKey.lastUsedAt,
    sourceIp: apiKey.sourceIp
  };
}

export function buildAdminActorContext(principal: AdminPrincipalRecord, sessionId?: string): AdminActorContext {
  return {
    actorId: principal.id,
    actorName: principal.displayName,
    actorType: "user",
    roles: [...principal.roles],
    sessionId
  };
}

export function createAdminLoginResponse(sessionToken: string, principal: AdminPrincipalRecord, session: AdminSessionRecord): AdminLoginResponse {
  return {
    accessToken: sessionToken,
    principal: toAdminPrincipalSummary(principal),
    session: toAdminSessionSummary(session, principal)
  };
}

export function hasAdminRole(actor: AdminActorContext, allowedRoles: AdminRole[]) {
  if (actor.roles.includes("admin")) {
    return true;
  }

  return allowedRoles.some((role) => actor.roles.includes(role));
}
