import type { ControlPlaneState } from "./types.ts";

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
    networkContainment: false,
    quarantineOnMalicious: true
  };
}

function createDefaultPolicyProfile(baseIso: string) {
  return {
    ...createDefaultPolicy(),
    description: "Balanced endpoint baseline for always-on protection, script inspection, and analyst-led containment.",
    isDefault: true,
    assignedDeviceIds: [],
    createdAt: baseIso,
    updatedAt: baseIso
  };
}

export function createEmptyState(baseIso: string = new Date().toISOString()): ControlPlaneState {
  return {
    defaultPolicy: createDefaultPolicy(),
    policies: [createDefaultPolicyProfile(baseIso)],
    scripts: [],
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
  const defaultPolicy = createDefaultPolicy();
  const financeSoftware = [
    {
      id: "sw-fin-vpn",
      displayName: "Contoso VPN",
      displayVersion: "5.4.2",
      publisher: "Contoso",
      installLocation: "C:\\Program Files\\Contoso\\VPN",
      uninstallCommand: "MsiExec.exe /x {CONTOSO-VPN-001} /qn",
      quietUninstallCommand: "MsiExec.exe /x {CONTOSO-VPN-001} /qn",
      installDate: "2026-03-12",
      displayIconPath: "C:\\Program Files\\Contoso\\VPN\\vpn.exe",
      executableNames: ["vpn.exe"],
      blocked: false,
      updateState: "available" as const,
      lastUpdateCheckAt: minusMinutes(baseIso, 11),
      updateSummary: "Version 5.5.0 is available from the configured software catalog."
    },
    {
      id: "sw-fin-reader",
      displayName: "Adobe Acrobat Reader",
      displayVersion: "24.001.1000",
      publisher: "Adobe",
      installLocation: "C:\\Program Files\\Adobe\\Acrobat Reader",
      uninstallCommand: "\"C:\\Program Files\\Adobe\\Acrobat Reader\\Setup.exe\" /remove /quiet",
      executableNames: ["acrord32.exe"],
      blocked: false,
      updateState: "current" as const,
      lastUpdateCheckAt: minusMinutes(baseIso, 32),
      updateSummary: "No newer package was reported during the last update check."
    }
  ];

  return {
    defaultPolicy,
    policies: [
      {
        ...defaultPolicy,
        description: "Balanced endpoint baseline for everyday protected workstations.",
        isDefault: true,
        assignedDeviceIds: [...DEMO_DEVICE_IDS],
        createdAt: minusMinutes(baseIso, 120),
        updatedAt: minusMinutes(baseIso, 15)
      },
      {
        id: "policy-containment",
        name: "High Containment",
        revision: "2026.04.08.2",
        realtimeProtection: true,
        cloudLookup: true,
        scriptInspection: true,
        networkContainment: true,
        quarantineOnMalicious: true,
        description: "Tighter network containment and aggressive quarantine for high-risk devices.",
        isDefault: false,
        assignedDeviceIds: ["dev-lon-003"],
        createdAt: minusMinutes(baseIso, 75),
        updatedAt: minusMinutes(baseIso, 20)
      }
    ],
    scripts: [
      {
        id: "script-001",
        name: "Collect triage bundle",
        description: "Collect a quick triage package from common staging locations.",
        language: "powershell",
        content: "Get-ChildItem $env:TEMP -Force | Select-Object -First 25 | Out-String",
        createdAt: minusMinutes(baseIso, 65),
        updatedAt: minusMinutes(baseIso, 65)
      }
    ],
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
        policyId: "policy-default",
        policyName: "Business Baseline",
        privateIpAddresses: ["10.44.7.23"],
        publicIpAddress: "203.0.113.19",
        lastLoggedOnUser: "CORP\\finance.user",
        installedSoftware: financeSoftware
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
        policyId: "policy-default",
        policyName: "Business Baseline",
        privateIpAddresses: ["10.44.7.38", "192.168.56.1"],
        publicIpAddress: "203.0.113.44",
        lastLoggedOnUser: "CORP\\ops.user",
        installedSoftware: [
          {
            id: "sw-ops-remote",
            displayName: "RustDesk",
            displayVersion: "1.3.8",
            publisher: "RustDesk",
            installLocation: "C:\\Program Files\\RustDesk",
            uninstallCommand: "\"C:\\Program Files\\RustDesk\\uninstall.exe\" /S",
            executableNames: ["rustdesk.exe"],
            blocked: false,
            updateState: "unknown",
            updateSummary: "No update check has been issued yet."
          }
        ]
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
        policyId: "policy-containment",
        policyName: "High Containment",
        privateIpAddresses: ["10.44.8.16"],
        publicIpAddress: "198.51.100.17",
        lastLoggedOnUser: "CORP\\hr.user",
        installedSoftware: [
          {
            id: "sw-hr-chat",
            displayName: "Northwind Chat",
            displayVersion: "2.1.0",
            publisher: "Northwind",
            installLocation: "C:\\Program Files\\Northwind\\Chat",
            uninstallCommand: "\"C:\\Program Files\\Northwind\\Chat\\uninstall.exe\" /quiet",
            executableNames: ["northwind-chat.exe"],
            blocked: true,
            updateState: "error",
            lastUpdateCheckAt: minusMinutes(baseIso, 5),
            updateSummary: "Software is blocked pending review."
          }
        ]
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
        targetPath: "C:\\Users\\ops\\Downloads",
        payloadJson: "{\"reason\":\"triage\"}"
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
