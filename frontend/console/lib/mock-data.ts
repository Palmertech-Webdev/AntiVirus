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
    networkContainment: false
  }
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
      policyName: "Business Baseline",
      openAlertCount: 1,
      quarantinedItemCount: 1,
      postureState: "ready"
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
      policyName: "Business Baseline",
      openAlertCount: 1,
      quarantinedItemCount: 0,
      postureState: "degraded"
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
      policyName: "Business Baseline",
      openAlertCount: 0,
      quarantinedItemCount: 0,
      postureState: "degraded"
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
      targetPath: "C:\\Users\\ops\\Downloads"
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
    networkContainment: false
  }
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
    scanHistory: fallbackDashboard.recentScanHistory.filter((item) => item.deviceId === deviceId)
  };
}
