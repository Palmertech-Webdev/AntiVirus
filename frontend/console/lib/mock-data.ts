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
    quarantineOnMalicious: false,
    dnsGuardEnabled: false,
    trafficTelemetryEnabled: false,
    integrityWatchEnabled: false,
    privilegeHardeningEnabled: false,
    pamLiteEnabled: false,
    denyHighRiskElevation: false,
    denyUnsignedElevation: false,
    requireBreakGlassEscrow: false
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
      lastLoggedOnUser: "CORP\\finance.user",
      riskScore: 18,
      riskBand: "low",
      confidenceScore: 94
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
      lastLoggedOnUser: "CORP\\ops.user",
      riskScore: 78,
      riskBand: "high",
      confidenceScore: 92
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
      lastLoggedOnUser: "CORP\\hr.user",
      riskScore: 86,
      riskBand: "critical",
      confidenceScore: 74
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
    quarantineOnMalicious: true,
    dnsGuardEnabled: false,
    trafficTelemetryEnabled: true,
    integrityWatchEnabled: true,
    privilegeHardeningEnabled: true,
    pamLiteEnabled: true,
    denyHighRiskElevation: true,
    denyUnsignedElevation: true,
    requireBreakGlassEscrow: true
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
      dnsGuardEnabled: false,
      trafficTelemetryEnabled: true,
      integrityWatchEnabled: true,
      privilegeHardeningEnabled: true,
      pamLiteEnabled: true,
      denyHighRiskElevation: true,
      denyUnsignedElevation: true,
      requireBreakGlassEscrow: true,
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
      dnsGuardEnabled: true,
      trafficTelemetryEnabled: true,
      integrityWatchEnabled: true,
      privilegeHardeningEnabled: true,
      pamLiteEnabled: true,
      denyHighRiskElevation: true,
      denyUnsignedElevation: true,
      requireBreakGlassEscrow: true,
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

function buildFallbackLatestScore(deviceId: string, hostname: string) {
  if (deviceId === "dev-lon-001") {
    return {
      id: "score-001",
      deviceId,
      hostname,
      calculatedAt: "2026-04-08T08:46:00Z",
      telemetryUpdatedAt: "2026-04-08T08:45:00Z",
      telemetrySource: "fallback",
      overallScore: 18,
      riskBand: "low" as const,
      confidenceScore: 94,
      categoryScores: [
        { category: "patch_posture" as const, weight: 25, score: 18, contribution: 5 },
        { category: "software_hygiene" as const, weight: 10, score: 20, contribution: 2 },
        { category: "threat_activity" as const, weight: 20, score: 12, contribution: 2 },
        { category: "exposure" as const, weight: 15, score: 10, contribution: 2 },
        { category: "network_behaviour" as const, weight: 15, score: 8, contribution: 1 },
        { category: "control_health" as const, weight: 10, score: 10, contribution: 1 },
        { category: "identity_posture" as const, weight: 5, score: 18, contribution: 1 }
      ],
      topRiskDrivers: [
        {
          id: "driver-001",
          category: "software_hygiene" as const,
          title: "A browser update is still pending",
          detail: "One user-facing browser package is behind the configured update baseline.",
          scoreImpact: 8,
          severity: "low" as const,
          tacticIds: [],
          techniqueIds: []
        }
      ],
      overrideReasons: [],
      recommendedActions: ["Apply the pending browser update during the next maintenance window."],
      missingTelemetryFields: [],
      tacticIds: [],
      techniqueIds: [],
      summary: "FINANCE-LAPTOP-07 is low risk with only light software hygiene drift.",
      analystSummary: "Risk is low. A pending browser update is the main issue and no override conditions were triggered."
    };
  }

  if (deviceId === "dev-lon-002") {
    return {
      id: "score-002",
      deviceId,
      hostname,
      calculatedAt: "2026-04-08T08:46:00Z",
      telemetryUpdatedAt: "2026-04-08T08:42:18Z",
      telemetrySource: "fallback",
      overallScore: 78,
      riskBand: "high" as const,
      confidenceScore: 92,
      categoryScores: [
        { category: "patch_posture" as const, weight: 25, score: 58, contribution: 15 },
        { category: "software_hygiene" as const, weight: 10, score: 74, contribution: 7 },
        { category: "threat_activity" as const, weight: 20, score: 82, contribution: 16 },
        { category: "exposure" as const, weight: 15, score: 28, contribution: 4 },
        { category: "network_behaviour" as const, weight: 15, score: 34, contribution: 5 },
        { category: "control_health" as const, weight: 10, score: 46, contribution: 5 },
        { category: "identity_posture" as const, weight: 5, score: 40, contribution: 2 }
      ],
      topRiskDrivers: [
        {
          id: "driver-002",
          category: "threat_activity" as const,
          title: "Active malware remains unresolved",
          detail: "An unresolved PowerShell launcher detection is still associated with this endpoint.",
          scoreImpact: 32,
          severity: "high" as const,
          tacticIds: ["TA0002"],
          techniqueIds: ["T1059.001"]
        },
        {
          id: "driver-003",
          category: "software_hygiene" as const,
          title: "Untrusted remote software is installed",
          detail: "Remote access tooling with weak publisher trust is still installed.",
          scoreImpact: 18,
          severity: "medium" as const,
          tacticIds: [],
          techniqueIds: []
        }
      ],
      overrideReasons: [],
      recommendedActions: [
        "Investigate and remediate the unresolved malware finding.",
        "Remove or restrict untrusted remote administration software.",
        "Re-enable tamper protection after confirming sensor integrity."
      ],
      missingTelemetryFields: [],
      tacticIds: ["TA0002"],
      techniqueIds: ["T1059.001"],
      summary: "OPS-DESKTOP-03 is high risk because threat activity and software hygiene are both degraded.",
      analystSummary:
        "Risk is high. The device still carries an unresolved malware signal and untrusted remote tooling, even though protection controls remain partially available."
    };
  }

  return {
    id: "score-003",
    deviceId,
    hostname,
    calculatedAt: "2026-04-08T08:46:00Z",
    telemetryUpdatedAt: "2026-04-08T08:41:00Z",
    telemetrySource: "fallback",
    overallScore: 86,
    riskBand: "critical" as const,
    confidenceScore: 74,
    categoryScores: [
      { category: "patch_posture" as const, weight: 25, score: 72, contribution: 18 },
      { category: "software_hygiene" as const, weight: 10, score: 35, contribution: 4 },
      { category: "threat_activity" as const, weight: 20, score: 88, contribution: 18 },
      { category: "exposure" as const, weight: 15, score: 40, contribution: 6 },
      { category: "network_behaviour" as const, weight: 15, score: 55, contribution: 8 },
      { category: "control_health" as const, weight: 10, score: 90, contribution: 9 },
      { category: "identity_posture" as const, weight: 5, score: 62, contribution: 3 }
    ],
    topRiskDrivers: [
      {
        id: "driver-004",
        category: "control_health" as const,
        title: "EDR is disabled while malware remains active",
        detail: "Protection controls are degraded at the same time active malware remains on the endpoint.",
        scoreImpact: 34,
        severity: "critical" as const,
        tacticIds: [],
        techniqueIds: []
      },
      {
        id: "driver-005",
        category: "identity_posture" as const,
        title: "Risky identity signals are present",
        detail: "Recent sign-in risk and MFA gaps increase the chance of follow-on compromise.",
        scoreImpact: 18,
        severity: "high" as const,
        tacticIds: ["TA0001"],
        techniqueIds: ["T1078"]
      }
    ],
    overrideReasons: ["Active malware is present while endpoint protection controls are disabled."],
    recommendedActions: [
      "Re-enable EDR immediately and validate the sensor stack.",
      "Contain the endpoint until the active malware signal is resolved.",
      "Review risky sign-ins and close the MFA gap for the affected user."
    ],
    missingTelemetryFields: ["internet_exposed_admin_service_count", "data_exfiltration_indicator"],
    tacticIds: ["TA0001"],
    techniqueIds: ["T1078"],
    summary: "HR-LAPTOP-12 is critical risk because active malware is paired with weakened protection controls.",
    analystSummary:
      "Risk is critical. Active malware remains unresolved while EDR is disabled, which triggers an override and sharply raises urgency."
  };
}

function buildFallbackRiskTelemetry(deviceId: string, hostname: string) {
  if (deviceId === "dev-lon-001") {
    return {
      deviceId,
      hostname,
      updatedAt: "2026-04-08T08:45:00Z",
      source: "fallback",
      os_patch_age_days: 8,
      outdated_browser_count: 1,
      active_malware_count: 0,
      quarantined_threat_count_7d: 1,
      edr_enabled: true,
      av_enabled: true,
      firewall_enabled: true,
      disk_encryption_enabled: true,
      tamper_protection_enabled: true,
      local_admin_users_count: 1,
      tacticIds: [],
      techniqueIds: []
    };
  }

  if (deviceId === "dev-lon-002") {
    return {
      deviceId,
      hostname,
      updatedAt: "2026-04-08T08:42:18Z",
      source: "fallback",
      os_patch_age_days: 24,
      outdated_high_risk_app_count: 2,
      untrusted_or_unsigned_software_count: 1,
      active_malware_count: 1,
      suspicious_domain_contacts_7d: 2,
      unusual_egress_indicator: true,
      edr_enabled: true,
      av_enabled: true,
      firewall_enabled: true,
      disk_encryption_enabled: true,
      tamper_protection_enabled: false,
      local_admin_users_count: 2,
      tacticIds: ["TA0002"],
      techniqueIds: ["T1059.001"]
    };
  }

  return {
    deviceId,
    hostname,
    updatedAt: "2026-04-08T08:41:00Z",
    source: "fallback",
    os_patch_age_days: 46,
    critical_patches_overdue_count: 2,
    known_exploited_vuln_count: 1,
    active_malware_count: 1,
    persistent_threat_count: 1,
    risky_signin_indicator: true,
    mfa_gap_indicator: true,
    edr_enabled: false,
    av_enabled: true,
    firewall_enabled: true,
    disk_encryption_enabled: false,
    tamper_protection_enabled: false,
    tacticIds: ["TA0001"],
    techniqueIds: ["T1078"]
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
    latestScore: buildFallbackLatestScore(deviceId, device.hostname),
    scoreHistory: [buildFallbackLatestScore(deviceId, device.hostname)],
    riskTelemetry: buildFallbackRiskTelemetry(deviceId, device.hostname),
    privilegeBaseline:
      deviceId === "dev-lon-001"
        ? {
            deviceId,
            hostname: device.hostname,
            capturedAt: "2026-04-08T08:45:00Z",
            localUsers: [
              { name: "CORP\\finance.user", source: "domain", enabled: true, authorized: true },
              { name: "FINANCE-LAPTOP-07-breakglass", source: "local", enabled: true, authorized: true }
            ],
            localAdministrators: [
              { name: "CORP\\IT Admins", source: "domain", enabled: true, authorized: true },
              { name: "FINANCE-LAPTOP-07-breakglass", source: "local", enabled: true, authorized: true }
            ],
            domainLinkedAdminMemberships: [
              { name: "CORP\\finance.user", group: "Local Administrators", source: "domain" }
            ],
            breakGlassAccountName: "FINANCE-LAPTOP-07-breakglass",
            breakGlassAccountEnabled: true,
            recoveryCredentialEscrowed: true,
            recoveryCredentialLastRotatedAt: "2026-04-08T08:45:00Z"
          }
        : null,
    privilegeState:
      deviceId === "dev-lon-002"
        ? {
            deviceId,
            hostname: device.hostname,
            updatedAt: "2026-04-08T08:42:18Z",
            privilegeHardeningMode: "restricted",
            pamEnforcementEnabled: true,
            standingAdminPresentFlag: true,
            unapprovedAdminAccountCount: 0,
            adminGroupTamperIndicator: false,
            directAdminLogonAttemptCount_7d: 1,
            breakGlassAccountUsageIndicator: false,
            unauthorisedAdminReenableIndicator: false,
            recoveryPathExists: true,
            lastEnforcedAt: "2026-04-08T08:41:00Z",
            summary: "Privilege hardening is active and standing admin access remains present.",
            recommendedActions: [
              "Replace standing local admin access with just-in-time elevation.",
              "Review recent direct administrator logons and elevation requests."
            ]
          }
        : null,
    privilegeEvents:
      deviceId === "dev-lon-002"
        ? [
            {
              id: "pe-fallback-001",
              deviceId,
              hostname: device.hostname,
              recordedAt: "2026-04-08T08:41:00Z",
              kind: "hardening.applied",
              actor: "console",
              severity: "high",
              source: "fallback",
              summary: "Privilege hardening applied; standing administrator access is being brokered through controlled elevation."
            }
          ]
        : [],
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
