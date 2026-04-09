import type { ControlPlaneState } from "./types.js";

export const DEMO_DEVICE_IDS = ["dev-lon-001", "dev-lon-002", "dev-lon-003"] as const;
export const DEMO_HOSTNAMES = ["FINANCE-LAPTOP-07", "OPS-DESKTOP-03", "HR-LAPTOP-12"] as const;

function minusMinutes(baseIso: string, minutes: number) {
  return new Date(Date.parse(baseIso) - minutes * 60_000).toISOString();
}

function createDefaultPolicy() {
  return {
    id: "policy-default",
    name: "Business Baseline",
    revision: "2026.04.08.1",
    realtimeProtection: true,
    cloudLookup: true,
    scriptInspection: true,
    networkContainment: false
  };
}

export function createEmptyState(baseIso: string = new Date().toISOString()): ControlPlaneState {
  return {
    defaultPolicy: createDefaultPolicy(),
    devices: [],
    alerts: [],
    telemetry: [],
    commands: [],
    quarantineItems: [],
    evidence: [],
    scanHistory: [],
    devicePosture: []
  };
}

export function createSeedState(baseIso: string = new Date().toISOString()): ControlPlaneState {
  return {
    defaultPolicy: createDefaultPolicy(),
    devices: [
      {
        id: "dev-lon-001",
        hostname: "FINANCE-LAPTOP-07",
        osVersion: "Windows 11 24H2",
        agentVersion: "0.1.0-alpha",
        platformVersion: "platform-0.1.0",
        serialNumber: "FIN-0007",
        enrolledAt: minusMinutes(baseIso, 24),
        lastSeenAt: minusMinutes(baseIso, 3),
        lastPolicySyncAt: minusMinutes(baseIso, 4),
        lastTelemetryAt: null,
        healthState: "healthy",
        isolated: false,
        policyName: "Business Baseline"
      },
      {
        id: "dev-lon-002",
        hostname: "OPS-DESKTOP-03",
        osVersion: "Windows 11 24H2",
        agentVersion: "0.1.0-alpha",
        platformVersion: "platform-0.1.0",
        serialNumber: "OPS-0003",
        enrolledAt: minusMinutes(baseIso, 42),
        lastSeenAt: minusMinutes(baseIso, 6),
        lastPolicySyncAt: minusMinutes(baseIso, 10),
        lastTelemetryAt: null,
        healthState: "degraded",
        isolated: false,
        policyName: "Business Baseline"
      },
      {
        id: "dev-lon-003",
        hostname: "HR-LAPTOP-12",
        osVersion: "Windows 10 22H2",
        agentVersion: "0.1.0-alpha",
        platformVersion: "platform-0.1.0",
        serialNumber: "HR-0012",
        enrolledAt: minusMinutes(baseIso, 61),
        lastSeenAt: minusMinutes(baseIso, 12),
        lastPolicySyncAt: minusMinutes(baseIso, 27),
        lastTelemetryAt: null,
        healthState: "isolated",
        isolated: true,
        policyName: "Business Baseline"
      }
    ],
    alerts: [
      {
        id: "alert-001",
        deviceId: "dev-lon-002",
        title: "Obfuscated PowerShell launcher blocked",
        severity: "critical",
        status: "new",
        hostname: "OPS-DESKTOP-03",
        detectedAt: minusMinutes(baseIso, 7),
        technique: "T1059.001",
        summary: "AMSI and behavior scoring identified a staged PowerShell launcher attempting to fetch a payload."
      },
      {
        id: "alert-002",
        deviceId: "dev-lon-001",
        title: "Unsigned archive dropper quarantined",
        severity: "high",
        status: "triaged",
        hostname: "FINANCE-LAPTOP-07",
        detectedAt: minusMinutes(baseIso, 19),
        technique: "T1204.002",
        summary: "Real-time protection quarantined a recently downloaded executable extracted from a ZIP archive."
      },
      {
        id: "alert-003",
        deviceId: "dev-lon-003",
        title: "Host isolation manually applied",
        severity: "medium",
        status: "contained",
        hostname: "HR-LAPTOP-12",
        detectedAt: minusMinutes(baseIso, 55),
        technique: "T1071",
        summary: "The device remains isolated while the investigation bundle is collected."
      }
    ],
    telemetry: [],
    commands: [
      {
        id: "cmd-001",
        deviceId: "dev-lon-003",
        hostname: "HR-LAPTOP-12",
        type: "device.isolate",
        status: "completed",
        createdAt: minusMinutes(baseIso, 56),
        updatedAt: minusMinutes(baseIso, 55),
        issuedBy: "soc-tier2"
      },
      {
        id: "cmd-002",
        deviceId: "dev-lon-002",
        hostname: "OPS-DESKTOP-03",
        type: "scan.targeted",
        status: "pending",
        createdAt: minusMinutes(baseIso, 5),
        updatedAt: minusMinutes(baseIso, 5),
        issuedBy: "automated-triage",
        targetPath: "C:\\Users\\ops\\Downloads"
      }
    ],
    quarantineItems: [
      {
        recordId: "qr-001",
        deviceId: "dev-lon-001",
        hostname: "FINANCE-LAPTOP-07",
        originalPath: "C:\\Users\\finance\\Downloads\\invoice-dropper.exe",
        quarantinedPath: "C:\\ProgramData\\AntiVirus\\quarantine\\files\\qr-001.exe.quarantine",
        sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        sizeBytes: 48256,
        capturedAt: minusMinutes(baseIso, 19),
        lastUpdatedAt: minusMinutes(baseIso, 19),
        evidenceRecordId: "ev-001",
        technique: "T1204.002",
        status: "quarantined"
      }
    ],
    evidence: [
      {
        recordId: "ev-001",
        deviceId: "dev-lon-001",
        hostname: "FINANCE-LAPTOP-07",
        recordedAt: minusMinutes(baseIso, 19),
        source: "scannercli",
        subjectPath: "C:\\Users\\finance\\Downloads\\invoice-dropper.exe",
        sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        disposition: "quarantine",
        tacticId: "TA0002",
        techniqueId: "T1204.002",
        contentType: "portable-executable",
        reputation: "user-writable-unsigned",
        quarantineRecordId: "qr-001",
        summary: "Evidence captured for a quarantined download-folder executable."
      }
    ],
    scanHistory: [
      {
        eventId: "scan-seed-001",
        deviceId: "dev-lon-001",
        hostname: "FINANCE-LAPTOP-07",
        scannedAt: minusMinutes(baseIso, 19),
        source: "scannercli",
        subjectPath: "C:\\Users\\finance\\Downloads\\invoice-dropper.exe",
        sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        contentType: "portable-executable",
        reputation: "user-writable-unsigned",
        disposition: "quarantine",
        confidence: 98,
        tacticId: "TA0002",
        techniqueId: "T1204.002",
        remediationStatus: "quarantined",
        evidenceRecordId: "ev-001",
        quarantineRecordId: "qr-001",
        summary: "On-demand scan quarantined invoice-dropper.exe."
      }
    ],
    devicePosture: [
      {
        deviceId: "dev-lon-001",
        hostname: "FINANCE-LAPTOP-07",
        updatedAt: minusMinutes(baseIso, 5),
        overallState: "ready",
        tamperProtectionState: "ready",
        tamperProtectionSummary: "Protected runtime paths and service hardening are configured.",
        wscState: "ready",
        wscSummary: "Windows Security Center coexistence data was collected.",
        etwState: "ready",
        etwSummary: "The ETW process sensor started a real-time kernel event session.",
        wfpState: "ready",
        wfpSummary: "The WFP isolation manager opened the filtering engine and subscribed to net events.",
        isolationState: "inactive",
        isolationSummary: "Host isolation is not currently active.",
        registryConfigured: true,
        runtimePathsProtected: true,
        uninstallProtectionEnabled: true,
        wscAvailable: true,
        providerHealth: "security_center_running"
      }
    ]
  };
}
