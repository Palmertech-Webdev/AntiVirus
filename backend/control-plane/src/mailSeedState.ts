import type { MailState } from "./types.ts";

function minusMinutes(baseIso: string, minutes: number) {
  return new Date(Date.parse(baseIso) - minutes * 60_000).toISOString();
}

function createDefaultMailPolicy() {
  return {
    id: "mail-policy-default",
    name: "Inbound Mail Baseline",
    revision: "2026.04.08.1",
    defaultAction: "quarantined" as const,
    urlRewriteEnabled: true,
    attachmentScanningEnabled: true,
    impersonationProtectionEnabled: true,
    quarantineRetentionDays: 30
  };
}

export function createEmptyMailState(baseIso: string = new Date().toISOString()): MailState {
  void baseIso;
  return {
    defaultPolicy: createDefaultMailPolicy(),
    domains: [],
    messages: [],
    quarantineItems: [],
    actionRecords: []
  };
}

export function createSeedMailState(baseIso: string = new Date().toISOString()): MailState {
  return {
    defaultPolicy: createDefaultMailPolicy(),
    domains: [
      {
        id: "mail-domain-001",
        domain: "contoso-internal.test",
        status: "ready",
        verificationStatus: "verified",
        mxRecordsConfigured: true,
        downstreamRoute: "m365-eu-west",
        activeMessageCount: 0,
        quarantinedMessageCount: 0,
        lastMessageAt: minusMinutes(baseIso, 18)
      },
      {
        id: "mail-domain-002",
        domain: "fabrikam-ops.test",
        status: "degraded",
        verificationStatus: "pending",
        mxRecordsConfigured: false,
        downstreamRoute: "m365-uk-south",
        activeMessageCount: 0,
        quarantinedMessageCount: 0,
        lastMessageAt: minusMinutes(baseIso, 42)
      }
    ],
    messages: [
      {
        id: "mail-msg-001",
        mailDomainId: "mail-domain-001",
        domain: "contoso-internal.test",
        internetMessageId: "<mail-msg-001@contoso-internal.test>",
        direction: "inbound",
        subject: "Updated payroll portal instructions",
        sender: "payroll-notify@microsofft-support.com",
        recipients: ["finance@contoso-internal.test", "ops@contoso-internal.test"],
        verdict: "phish",
        deliveryAction: "quarantined",
        receivedAt: minusMinutes(baseIso, 18),
        deliveredAt: null,
        summary: "Lookalike-domain and credential-harvest indicators caused the message to be quarantined.",
        auth: {
          spf: "fail",
          dkim: "none",
          dmarc: "fail",
          arc: "none"
        },
        attachments: [],
        urls: [
          {
            id: "mail-url-001",
            originalUrl: "https://contoso-payroll-login.example/login",
            verdict: "phish",
            rewriteApplied: true
          }
        ],
        relatedAlertId: "alert-001",
        relatedDeviceId: "dev-lon-002",
        relatedUser: "finance@contoso-internal.test"
      },
      {
        id: "mail-msg-002",
        mailDomainId: "mail-domain-001",
        domain: "contoso-internal.test",
        internetMessageId: "<mail-msg-002@contoso-internal.test>",
        direction: "inbound",
        subject: "Q2 vendor maintenance schedule",
        sender: "noreply@trustedvendor.example",
        recipients: ["ops@contoso-internal.test"],
        verdict: "clean",
        deliveryAction: "delivered",
        receivedAt: minusMinutes(baseIso, 27),
        deliveredAt: minusMinutes(baseIso, 26),
        summary: "Authenticated vendor communication was relayed to Microsoft 365.",
        auth: {
          spf: "pass",
          dkim: "pass",
          dmarc: "pass",
          arc: "none"
        },
        attachments: [
          {
            id: "mail-attachment-001",
            fileName: "maintenance-window.ics",
            sha256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            sizeBytes: 1904,
            verdict: "clean"
          }
        ],
        urls: [],
        relatedUser: "ops@contoso-internal.test"
      },
      {
        id: "mail-msg-003",
        mailDomainId: "mail-domain-001",
        domain: "contoso-internal.test",
        internetMessageId: "<mail-msg-003@contoso-internal.test>",
        direction: "inbound",
        subject: "Invoice archive for immediate review",
        sender: "accounts@settlement-updates.example",
        recipients: ["finance@contoso-internal.test"],
        verdict: "malware",
        deliveryAction: "quarantined",
        receivedAt: minusMinutes(baseIso, 41),
        deliveredAt: null,
        summary: "Attachment scanning detected a malicious loader inside a password-themed archive.",
        auth: {
          spf: "softfail",
          dkim: "none",
          dmarc: "fail",
          arc: "none"
        },
        attachments: [
          {
            id: "mail-attachment-002",
            fileName: "invoice-package.zip",
            sha256: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            sizeBytes: 48256,
            verdict: "malware"
          }
        ],
        urls: [
          {
            id: "mail-url-002",
            originalUrl: "https://settlement-updates.example/review",
            verdict: "suspicious",
            rewriteApplied: true
          }
        ],
        relatedAlertId: "alert-002",
        relatedDeviceId: "dev-lon-001",
        relatedUser: "finance@contoso-internal.test"
      }
    ],
    quarantineItems: [
      {
        id: "mail-quarantine-001",
        mailMessageId: "mail-msg-001",
        domain: "contoso-internal.test",
        subject: "Updated payroll portal instructions",
        sender: "payroll-notify@microsofft-support.com",
        recipientSummary: "finance@contoso-internal.test, ops@contoso-internal.test",
        reason: "Credential-phishing indicators and sender-authentication failure.",
        status: "quarantined",
        quarantinedAt: minusMinutes(baseIso, 18),
        releasedAt: null
      },
      {
        id: "mail-quarantine-002",
        mailMessageId: "mail-msg-003",
        domain: "contoso-internal.test",
        subject: "Invoice archive for immediate review",
        sender: "accounts@settlement-updates.example",
        recipientSummary: "finance@contoso-internal.test",
        reason: "Malicious attachment detected during archive inspection.",
        status: "quarantined",
        quarantinedAt: minusMinutes(baseIso, 41),
        releasedAt: null
      }
    ],
    actionRecords: [
      {
        id: "mail-action-001",
        mailMessageId: "mail-msg-003",
        actionType: "message.purge",
        requestedBy: "soc-tier2",
        requestedAt: minusMinutes(baseIso, 39),
        status: "completed",
        resultSummary: "Similar recipients were not found in this pilot dataset, so only the original quarantined message was marked for purge review."
      }
    ]
  };
}
