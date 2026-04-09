import type { DeviceDetail, DevicePostureSummary, DashboardSnapshot } from "./types";

export const emptyDashboard: DashboardSnapshot = {
  generatedAt: "2026-04-08T00:00:00Z",
  devices: [],
  alerts: [],
  recentTelemetry: [],
  recentCommands: [],
  quarantineItems: [],
  recentEvidence: [],
  recentScanHistory: [],
  postureOverview: [],
  defaultPolicy: {
    id: "policy-default",
    name: "Business Baseline",
    revision: "unknown",
    realtimeProtection: false,
    cloudLookup: false,
    scriptInspection: false,
    networkContainment: false,
    quarantineOnMalicious: false
  },
  policies: [],
  scripts: []
};

export const fallbackDashboard: DashboardSnapshot = {
  generatedAt: "2026-04-07T21:50:00Z",
  devices: [
    {
      id: "dev-lon-001",
      hostname: "FINANCE-LAPTOP-07",
      osVersion: "Windows 11 24H2",
      agentVersion: "0.1.0-alpha",
      platformVersion: "platform-0.1.0",
      serialNumber: "FIN-0007",
      enrolledAt: "2026-04-07T21:26:00Z",
      lastSeenAt: "2026-04-07T21:47:00Z",
      lastPolicySyncAt: "2026-04-07T21:46:00Z",
      lastTelemetryAt: "2026-04-07T21:45:00Z",
      healthState: "healthy",
      isolated: false,
      policyId: "policy-default",
      policyName: "Business Baseline",
      openAlertCount: 1,
      quarantinedItemCount: 1,
      postureState: "ready",
      privateIpAddresses: ["10.44.7.23"],
      publicIpAddress: "203.0.113.19",
      lastLoggedOnUser: "CORP\\finance.user"
    },
    {
      id: "dev-lon-002",
      hostname: "OPS-DESKTOP-03",
      osVersion: "Windows 11 24H2",
      agentVersion: "0.1.0-alpha",
      platformVersion: "platform-0.1.0",
      serialNumber: "OPS-0003",
      enrolledAt: "2026-04-07T21:08:00Z",
      lastSeenAt: "2026-04-07T21:44:00Z",
      lastPolicySyncAt: "2026-04-07T21:40:00Z",
      lastTelemetryAt: "2026-04-07T21:42:18Z",
      healthState: "degraded",
      isolated: false,
      policyId: "policy-default",
      policyName: "Business Baseline",
      openAlertCount: 1,
      quarantinedItemCount: 0,
      postureState: "degraded",
      privateIpAddresses: ["10.44.7.38", "192.168.56.1"],
      publicIpAddress: "203.0.113.44",
      lastLoggedOnUser: "CORP\\ops.user"
    },
    {
      id: "dev-lon-003",
      hostname: "HR-LAPTOP-12",
      osVersion: "Windows 10 22H2",
      agentVersion: "0.1.0-alpha",
      platformVersion: "platform-0.1.0",
      serialNumber: "HR-0012",
      enrolledAt: "2026-04-07T20:49:00Z",
      lastSeenAt: "2026-04-07T21:41:00Z",
      lastPolicySyncAt: "2026-04-07T21:30:00Z",
      lastTelemetryAt: "2026-04-07T21:41:00Z",
      healthState: "isolated",
      isolated: true,
      policyId: "policy-containment",
      policyName: "Business Baseline",
      openAlertCount: 0,
      quarantinedItemCount: 0,
      postureState: "degraded",
      privateIpAddresses: ["10.44.8.16"],
      publicIpAddress: "198.51.100.17",
      lastLoggedOnUser: "CORP\\hr.user"
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
      detectedAt: "2026-04-07T21:42:18Z",
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
      detectedAt: "2026-04-07T20:58:51Z",
      technique: "T1204.002",
      summary: "Real-time protection quarantined a recently downloaded executable extracted from a ZIP archive."
    }
  ],
  recentTelemetry: [
    {
      eventId: "evt-001",
      deviceId: "dev-lon-002",
      hostname: "OPS-DESKTOP-03",
      eventType: "process.synthetic",
      source: "telemetry-spool",
      summary: "Synthetic process telemetry was queued for backend validation.",
      occurredAt: "2026-04-08T09:00:11Z",
      ingestedAt: "2026-04-08T09:00:13Z",
      payloadJson: "{\"imagePath\":\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\"}"
    },
    {
      eventId: "evt-002",
      deviceId: "dev-lon-001",
      hostname: "FINANCE-LAPTOP-07",
      eventType: "device.heartbeat",
      source: "control-plane-client",
      summary: "The endpoint heartbeat was acknowledged by the control plane.",
      occurredAt: "2026-04-08T08:59:57Z",
      ingestedAt: "2026-04-08T08:59:57Z",
      payloadJson: "{\"commandsPending\":0}"
    }
  ],
  recentCommands: [
    {
      id: "cmd-001",
      deviceId: "dev-lon-002",
      hostname: "OPS-DESKTOP-03",
      type: "scan.targeted",
      status: "pending",
      createdAt: "2026-04-08T08:58:00Z",
      updatedAt: "2026-04-08T08:58:00Z",
      issuedBy: "automated-triage",
      targetPath: "C:\\Users\\ops\\Downloads",
      payloadJson: "{\"reason\":\"triage\"}"
    },
    {
      id: "cmd-002",
      deviceId: "dev-lon-003",
      hostname: "HR-LAPTOP-12",
      type: "device.isolate",
      status: "completed",
      createdAt: "2026-04-08T08:01:00Z",
      updatedAt: "2026-04-08T08:02:00Z",
      issuedBy: "soc-tier2"
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
      capturedAt: "2026-04-08T08:40:00Z",
      lastUpdatedAt: "2026-04-08T08:40:00Z",
      evidenceRecordId: "ev-001",
      technique: "T1204.002",
      status: "quarantined"
    }
  ],
  recentEvidence: [
    {
      recordId: "ev-001",
      deviceId: "dev-lon-001",
      hostname: "FINANCE-LAPTOP-07",
      recordedAt: "2026-04-08T08:40:00Z",
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
  recentScanHistory: [
    {
      eventId: "scan-001",
      deviceId: "dev-lon-001",
      hostname: "FINANCE-LAPTOP-07",
      scannedAt: "2026-04-08T08:40:00Z",
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
  postureOverview: [
    {
      deviceId: "dev-lon-001",
      hostname: "FINANCE-LAPTOP-07",
      updatedAt: "2026-04-08T08:45:00Z",
      overallState: "ready",
      tamperProtectionState: "ready",
      wscState: "ready",
      etwState: "ready",
      wfpState: "ready",
      isolationState: "inactive",
      runtimePathsProtected: true,
      uninstallProtectionEnabled: true,
      wscAvailable: true,
      providerHealth: "security_center_running"
    }
  ],
  defaultPolicy: {
    id: "policy-default",
    name: "Business Baseline",
    revision: "2026.04.07.1",
    realtimeProtection: true,
    cloudLookup: true,
    scriptInspection: true,
    networkContainment: false,
    quarantineOnMalicious: true
  },
  policies: [
    {
      id: "policy-default",
      name: "Business Baseline",
      revision: "2026.04.07.1",
      realtimeProtection: true,
      cloudLookup: true,
      scriptInspection: true,
      networkContainment: false,
      quarantineOnMalicious: true,
      description: "Balanced endpoint baseline for everyday protected workstations.",
      isDefault: true,
      assignedDeviceIds: ["dev-lon-001", "dev-lon-002"],
      createdAt: "2026-04-07T20:00:00Z",
      updatedAt: "2026-04-07T21:46:00Z"
    },
    {
      id: "policy-containment",
      name: "High Containment",
      revision: "2026.04.07.2",
      realtimeProtection: true,
      cloudLookup: true,
      scriptInspection: true,
      networkContainment: true,
      quarantineOnMalicious: true,
      description: "Tighter network containment and aggressive quarantine for high-risk devices.",
      isDefault: false,
      assignedDeviceIds: ["dev-lon-003"],
      createdAt: "2026-04-07T20:30:00Z",
      updatedAt: "2026-04-07T21:41:00Z"
    }
  ],
  scripts: [
    {
      id: "script-001",
      name: "Collect triage bundle",
      description: "Collect a quick triage package from common staging locations.",
      language: "powershell",
      content: "Get-ChildItem $env:TEMP -Force | Select-Object -First 25 | Out-String",
      createdAt: "2026-04-07T20:45:00Z",
      updatedAt: "2026-04-07T20:45:00Z"
    }
  ]
};

function buildFallbackPosture(deviceId: string, hostname: string): DevicePostureSummary {
  const existing = fallbackDashboard.postureOverview.find((item) => item.deviceId === deviceId);
  if (existing) {
    return existing;
  }

  return {
    deviceId,
    hostname,
    updatedAt: fallbackDashboard.generatedAt,
    overallState: "unknown",
    tamperProtectionState: "unknown",
    wscState: "unknown",
    etwState: "unknown",
    wfpState: "unknown",
    isolationState: "unknown"
  };
}

export function buildFallbackDeviceDetail(deviceId: string): DeviceDetail | null {
  const device = fallbackDashboard.devices.find((item) => item.id === deviceId);
  if (!device) {
    return null;
  }

  return {
    device,
    posture: buildFallbackPosture(deviceId, device.hostname),
    alerts: fallbackDashboard.alerts.filter((item) => item.deviceId === deviceId || item.hostname === device.hostname),
    telemetry: fallbackDashboard.recentTelemetry.filter((item) => item.deviceId === deviceId),
    commands: fallbackDashboard.recentCommands.filter((item) => item.deviceId === deviceId),
    quarantineItems: fallbackDashboard.quarantineItems.filter((item) => item.deviceId === deviceId),
    evidence: fallbackDashboard.recentEvidence.filter((item) => item.deviceId === deviceId),
    scanHistory: fallbackDashboard.recentScanHistory.filter((item) => item.deviceId === deviceId),
    installedSoftware:
      deviceId === "dev-lon-001"
        ? [
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
              updateState: "available",
              lastUpdateCheckAt: "2026-04-08T08:49:00Z",
              updateSummary: "Version 5.5.0 is available from the configured catalog."
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
              updateState: "current",
              lastUpdateCheckAt: "2026-04-08T08:20:00Z",
              updateSummary: "No update is currently available."
            }
          ]
        : deviceId === "dev-lon-002"
          ? [
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
                updateSummary: "No update check has been run yet."
              }
            ]
          : [
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
                lastUpdateCheckAt: "2026-04-08T08:45:00Z",
                updateSummary: "Execution is blocked while the investigation remains open."
              }
            ]
  };
}
