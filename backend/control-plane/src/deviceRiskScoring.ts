import { randomUUID } from "node:crypto";

import type {
  AlertSeverity,
  DeviceRiskCategoryScore,
  DeviceRiskTelemetrySnapshot,
  DeviceScoreSnapshot,
  RiskBand,
  RiskCategoryKey,
  RiskDriverSummary
} from "./types.ts";

const RISK_CATEGORY_WEIGHTS: Record<RiskCategoryKey, number> = {
  patch_posture: 25,
  software_hygiene: 10,
  threat_activity: 20,
  exposure: 15,
  network_behaviour: 15,
  control_health: 10,
  identity_posture: 5
};

type RiskTelemetryField = Exclude<
  keyof DeviceRiskTelemetrySnapshot,
  "deviceId" | "hostname" | "updatedAt" | "source" | "tacticIds" | "techniqueIds"
>;

const CATEGORY_FIELDS: Record<RiskCategoryKey, RiskTelemetryField[]> = {
  patch_posture: [
    "os_patch_age_days",
    "critical_patches_overdue_count",
    "high_patches_overdue_count",
    "known_exploited_vuln_count",
    "internet_exposed_unpatched_critical_count"
  ],
  software_hygiene: [
    "unsupported_software_count",
    "outdated_browser_count",
    "outdated_high_risk_app_count",
    "untrusted_or_unsigned_software_count"
  ],
  threat_activity: [
    "active_malware_count",
    "quarantined_threat_count_7d",
    "persistent_threat_count",
    "ransomware_behaviour_flag",
    "lateral_movement_indicator"
  ],
  exposure: [
    "open_port_count",
    "risky_open_port_count",
    "internet_exposed_admin_service_count",
    "smb_exposed_flag",
    "rdp_exposed_flag"
  ],
  network_behaviour: [
    "malicious_domain_contacts_7d",
    "suspicious_domain_contacts_7d",
    "c2_beacon_indicator",
    "data_exfiltration_indicator",
    "unusual_egress_indicator"
  ],
  control_health: [
    "edr_enabled",
    "av_enabled",
    "firewall_enabled",
    "disk_encryption_enabled",
    "tamper_protection_enabled"
  ],
  identity_posture: [
    "local_admin_users_count",
    "risky_signin_indicator",
    "stolen_token_indicator",
    "mfa_gap_indicator"
  ]
};

const CRITICAL_FIELDS: Record<RiskCategoryKey, RiskTelemetryField[]> = {
  patch_posture: [
    "critical_patches_overdue_count",
    "known_exploited_vuln_count",
    "internet_exposed_unpatched_critical_count"
  ],
  software_hygiene: ["unsupported_software_count", "untrusted_or_unsigned_software_count"],
  threat_activity: ["active_malware_count", "ransomware_behaviour_flag", "lateral_movement_indicator"],
  exposure: ["risky_open_port_count", "internet_exposed_admin_service_count", "rdp_exposed_flag", "smb_exposed_flag"],
  network_behaviour: ["malicious_domain_contacts_7d", "c2_beacon_indicator", "data_exfiltration_indicator"],
  control_health: ["edr_enabled", "av_enabled", "firewall_enabled", "tamper_protection_enabled"],
  identity_posture: ["risky_signin_indicator", "stolen_token_indicator", "mfa_gap_indicator"]
};

const CATEGORY_ORDER: RiskCategoryKey[] = [
  "patch_posture",
  "software_hygiene",
  "threat_activity",
  "exposure",
  "network_behaviour",
  "control_health",
  "identity_posture"
];

interface DeviceRiskEvaluationInput {
  deviceId: string;
  hostname: string;
  telemetry: DeviceRiskTelemetrySnapshot;
  now: string;
  inheritedTacticIds?: string[];
  inheritedTechniqueIds?: string[];
}

interface ConfidenceResult {
  confidenceScore: number;
  missingTelemetryFields: string[];
}

function clamp(value: number, min: number, max: number) {
  return Math.min(max, Math.max(min, value));
}

function roundScore(value: number) {
  return Math.round(clamp(value, 0, 100));
}

function riskBandFromScore(score: number): RiskBand {
  if (score <= 19) {
    return "low";
  }

  if (score <= 39) {
    return "guarded";
  }

  if (score <= 59) {
    return "elevated";
  }

  if (score <= 79) {
    return "high";
  }

  return "critical";
}

function isFieldPresent(value: unknown) {
  return value !== undefined && value !== null;
}

function formatCountLabel(value: number, singular: string, plural: string) {
  return `${value} ${value === 1 ? singular : plural}`;
}

function addUniqueAction(target: string[], value: string) {
  if (!target.includes(value)) {
    target.push(value);
  }
}

function severityForImpact(scoreImpact: number): AlertSeverity {
  if (scoreImpact >= 35) {
    return "critical";
  }

  if (scoreImpact >= 20) {
    return "high";
  }

  if (scoreImpact >= 10) {
    return "medium";
  }

  return "low";
}

function driver(
  category: RiskCategoryKey,
  title: string,
  detail: string,
  scoreImpact: number,
  tacticIds: string[] = [],
  techniqueIds: string[] = []
): RiskDriverSummary {
  return {
    id: randomUUID(),
    category,
    title,
    detail,
    scoreImpact,
    severity: severityForImpact(scoreImpact),
    tacticIds,
    techniqueIds
  };
}

function calculatePatchPosture(telemetry: DeviceRiskTelemetrySnapshot, drivers: RiskDriverSummary[]) {
  let score = 0;

  const patchAge = telemetry.os_patch_age_days ?? 0;
  if (patchAge >= 90) {
    score += 85;
    drivers.push(driver("patch_posture", "Operating system patching is badly stale", `The OS patch age is ${patchAge} days, which materially increases exploit exposure.`, 26));
  } else if (patchAge >= 60) {
    score += 65;
    drivers.push(driver("patch_posture", "Operating system patching is behind", `The OS patch age is ${patchAge} days.`, 18));
  } else if (patchAge >= 30) {
    score += 45;
    drivers.push(driver("patch_posture", "Operating system patching is delayed", `The OS patch age is ${patchAge} days.`, 12));
  } else if (patchAge >= 14) {
    score += 20;
  } else if (patchAge >= 7) {
    score += 8;
  }

  const overdueCritical = telemetry.critical_patches_overdue_count ?? 0;
  if (overdueCritical > 0) {
    score += Math.min(48, overdueCritical * 14);
    drivers.push(
      driver(
        "patch_posture",
        "Critical security patches are overdue",
        `${formatCountLabel(overdueCritical, "critical patch is", "critical patches are")} overdue on this device.`,
        Math.min(34, 10 + overdueCritical * 4)
      )
    );
  }

  const overdueHigh = telemetry.high_patches_overdue_count ?? 0;
  if (overdueHigh > 0) {
    score += Math.min(20, overdueHigh * 4);
  }

  const kevCount = telemetry.known_exploited_vuln_count ?? 0;
  if (kevCount > 0) {
    score += Math.min(54, kevCount * 18);
    drivers.push(
      driver(
        "patch_posture",
        "Known exploited vulnerabilities remain exposed",
        `${formatCountLabel(kevCount, "known exploited vulnerability remains", "known exploited vulnerabilities remain")} unremediated.`,
        Math.min(40, 18 + kevCount * 6)
      )
    );
  }

  const exposedUnpatchedCriticals = telemetry.internet_exposed_unpatched_critical_count ?? 0;
  if (exposedUnpatchedCriticals > 0) {
    score += Math.min(60, exposedUnpatchedCriticals * 25);
    drivers.push(
      driver(
        "patch_posture",
        "Internet-exposed critical vulnerabilities are unpatched",
        `${formatCountLabel(exposedUnpatchedCriticals, "internet-exposed critical issue is", "internet-exposed critical issues are")} still unpatched.`,
        Math.min(42, 20 + exposedUnpatchedCriticals * 8)
      )
    );
  }

  return roundScore(score);
}

function calculateSoftwareHygiene(telemetry: DeviceRiskTelemetrySnapshot, drivers: RiskDriverSummary[]) {
  let score = 0;

  const unsupported = telemetry.unsupported_software_count ?? 0;
  if (unsupported > 0) {
    score += Math.min(70, unsupported * 22);
    drivers.push(
      driver(
        "software_hygiene",
        "Unsupported software is installed",
        `${formatCountLabel(unsupported, "unsupported application is", "unsupported applications are")} present on the device.`,
        Math.min(26, 10 + unsupported * 4)
      )
    );
  }

  const outdatedBrowsers = telemetry.outdated_browser_count ?? 0;
  if (outdatedBrowsers > 0) {
    score += Math.min(24, outdatedBrowsers * 10);
  }

  const outdatedHighRiskApps = telemetry.outdated_high_risk_app_count ?? 0;
  if (outdatedHighRiskApps > 0) {
    score += Math.min(30, outdatedHighRiskApps * 8);
  }

  const untrusted = telemetry.untrusted_or_unsigned_software_count ?? 0;
  if (untrusted > 0) {
    score += Math.min(55, untrusted * 16);
    drivers.push(
      driver(
        "software_hygiene",
        "Untrusted or unsigned software is present",
        `${formatCountLabel(untrusted, "untrusted or unsigned application is", "untrusted or unsigned applications are")} installed.`,
        Math.min(28, 12 + untrusted * 5)
      )
    );
  }

  return roundScore(score);
}

function calculateThreatActivity(telemetry: DeviceRiskTelemetrySnapshot, drivers: RiskDriverSummary[]) {
  let score = 0;

  const activeMalware = telemetry.active_malware_count ?? 0;
  if (activeMalware > 0) {
    score += Math.min(70, activeMalware * 30);
    drivers.push(
      driver(
        "threat_activity",
        "Active malware is present",
        `${formatCountLabel(activeMalware, "active malware finding remains", "active malware findings remain")} unresolved on the device.`,
        Math.min(36, 18 + activeMalware * 6)
      )
    );
  }

  const quarantinedThreats = telemetry.quarantined_threat_count_7d ?? 0;
  if (quarantinedThreats > 0) {
    score += Math.min(18, quarantinedThreats * 4);
  }

  const persistentThreats = telemetry.persistent_threat_count ?? 0;
  if (persistentThreats > 0) {
    score += Math.min(45, persistentThreats * 18);
    drivers.push(
      driver(
        "threat_activity",
        "Persistent threat indicators are present",
        `${formatCountLabel(persistentThreats, "persistent threat indicator is", "persistent threat indicators are")} still active after initial response.`,
        Math.min(30, 14 + persistentThreats * 6)
      )
    );
  }

  if (telemetry.ransomware_behaviour_flag) {
    score += 45;
    drivers.push(
      driver(
        "threat_activity",
        "Ransomware behaviour was observed",
        "Fenrir observed behaviour consistent with encryption impact or ransomware staging.",
        45,
        ["TA0040"],
        ["T1486"]
      )
    );
  }

  if (telemetry.lateral_movement_indicator) {
    score += 30;
    drivers.push(
      driver(
        "threat_activity",
        "Lateral movement behaviour is suspected",
        "The endpoint shows indicators of remote execution or lateral movement activity.",
        28,
        ["TA0008"],
        ["T1021"]
      )
    );
  }

  return roundScore(score);
}

function calculateExposure(telemetry: DeviceRiskTelemetrySnapshot, drivers: RiskDriverSummary[]) {
  let score = 0;

  const openPorts = telemetry.open_port_count ?? 0;
  if (openPorts > 0) {
    score += Math.min(20, openPorts * 2);
  }

  const riskyPorts = telemetry.risky_open_port_count ?? 0;
  if (riskyPorts > 0) {
    score += Math.min(45, riskyPorts * 10);
    drivers.push(
      driver(
        "exposure",
        "Risky ports are exposed",
        `${formatCountLabel(riskyPorts, "high-risk service port is", "high-risk service ports are")} exposed on the device.`,
        Math.min(24, 10 + riskyPorts * 4)
      )
    );
  }

  const adminServices = telemetry.internet_exposed_admin_service_count ?? 0;
  if (adminServices > 0) {
    score += Math.min(70, adminServices * 24);
    drivers.push(
      driver(
        "exposure",
        "Internet-exposed admin services were identified",
        `${formatCountLabel(adminServices, "internet-exposed admin service is", "internet-exposed admin services are")} reachable and should be restricted.`,
        Math.min(34, 18 + adminServices * 6)
      )
    );
  }

  if (telemetry.smb_exposed_flag) {
    score += 18;
    drivers.push(driver("exposure", "SMB is exposed", "SMB exposure increases the attack surface for lateral movement and wormable activity.", 16));
  }

  if (telemetry.rdp_exposed_flag) {
    score += 24;
    drivers.push(driver("exposure", "RDP is exposed", "RDP exposure materially raises credential attack and remote-access risk.", 20));
  }

  return roundScore(score);
}

function calculateNetworkBehaviour(telemetry: DeviceRiskTelemetrySnapshot, drivers: RiskDriverSummary[]) {
  let score = 0;

  const maliciousContacts = telemetry.malicious_domain_contacts_7d ?? 0;
  if (maliciousContacts > 0) {
    score += Math.min(60, maliciousContacts * 18);
    drivers.push(
      driver(
        "network_behaviour",
        "The device contacted malicious domains",
        `${formatCountLabel(maliciousContacts, "contact with a malicious domain was", "contacts with malicious domains were")} observed recently.`,
        Math.min(34, 18 + maliciousContacts * 4),
        ["TA0011"],
        ["T1071"]
      )
    );
  }

  const suspiciousContacts = telemetry.suspicious_domain_contacts_7d ?? 0;
  if (suspiciousContacts > 0) {
    score += Math.min(24, suspiciousContacts * 5);
  }

  if (telemetry.c2_beacon_indicator) {
    score += 40;
    drivers.push(
      driver(
        "network_behaviour",
        "Command-and-control beaconing is suspected",
        "Network behaviour indicates a likely command-and-control beacon pattern.",
        38,
        ["TA0011"],
        ["T1071"]
      )
    );
  }

  if (telemetry.data_exfiltration_indicator) {
    score += 45;
    drivers.push(
      driver(
        "network_behaviour",
        "Potential data exfiltration was detected",
        "Outbound behaviour indicates possible staged or active data exfiltration.",
        42,
        ["TA0010"],
        ["T1041"]
      )
    );
  }

  if (telemetry.unusual_egress_indicator) {
    score += 20;
    drivers.push(driver("network_behaviour", "Unusual outbound behaviour was observed", "The endpoint shows unusual egress behaviour that warrants investigation.", 18));
  }

  return roundScore(score);
}

function calculateControlHealth(telemetry: DeviceRiskTelemetrySnapshot, drivers: RiskDriverSummary[]) {
  let score = 0;

  if (telemetry.edr_enabled === false) {
    score += 35;
    drivers.push(driver("control_health", "EDR visibility is disabled", "EDR coverage is missing or not functioning on the endpoint.", 28));
  }

  if (telemetry.av_enabled === false) {
    score += 30;
    drivers.push(driver("control_health", "Antivirus protection is disabled", "Core antivirus protection is not currently enabled.", 26));
  }

  if (telemetry.firewall_enabled === false) {
    score += 20;
    drivers.push(driver("control_health", "Host firewall protection is disabled", "The local firewall is disabled or unavailable.", 18));
  }

  if (telemetry.disk_encryption_enabled === false) {
    score += 12;
  }

  if (telemetry.tamper_protection_enabled === false) {
    score += 16;
    drivers.push(driver("control_health", "Tamper protection is not enabled", "Endpoint hardening is weakened because tamper protection is off or degraded.", 16));
  }

  return roundScore(score);
}

function calculateIdentityPosture(telemetry: DeviceRiskTelemetrySnapshot, drivers: RiskDriverSummary[]) {
  let score = 0;

  const localAdmins = telemetry.local_admin_users_count ?? 0;
  if (localAdmins > 1) {
    score += Math.min(30, (localAdmins - 1) * 8);
    drivers.push(
      driver(
        "identity_posture",
        "Local administrator membership is broad",
        `${localAdmins} local administrator accounts are present, increasing abuse potential.`,
        Math.min(16, 8 + (localAdmins - 1) * 2)
      )
    );
  }

  if (telemetry.risky_signin_indicator) {
    score += 28;
    drivers.push(driver("identity_posture", "Risky sign-in activity is linked to this device", "Fenrir has evidence of risky sign-in behaviour associated with this endpoint.", 20));
  }

  if (telemetry.stolen_token_indicator) {
    score += 42;
    drivers.push(
      driver(
        "identity_posture",
        "A stolen-token indicator is present",
        "Identity telemetry indicates possible token theft or reuse on this device.",
        34,
        ["TA0006"],
        ["T1528"]
      )
    );
  }

  if (telemetry.mfa_gap_indicator) {
    score += 18;
    drivers.push(driver("identity_posture", "An MFA gap was identified", "Accounts associated with this device do not appear to be protected by strong MFA enforcement.", 14));
  }

  return roundScore(score);
}

function calculateConfidence(telemetry: DeviceRiskTelemetrySnapshot): ConfidenceResult {
  let confidenceScore = 100;
  const missingTelemetryFields: string[] = [];

  for (const category of CATEGORY_ORDER) {
    const fields = CATEGORY_FIELDS[category];
    const presentCount = fields.filter((field) => isFieldPresent(telemetry[field])).length;

    if (presentCount === 0) {
      confidenceScore -= 14;
    }

    for (const field of fields) {
      const value = telemetry[field];
      if (isFieldPresent(value)) {
        continue;
      }

      missingTelemetryFields.push(field);
      confidenceScore -= CRITICAL_FIELDS[category].includes(field) ? 5 : 2;
    }
  }

  return {
    confidenceScore: clamp(confidenceScore, 0, 100),
    missingTelemetryFields: [...new Set(missingTelemetryFields)]
  };
}

function buildRecommendedActions(
  telemetry: DeviceRiskTelemetrySnapshot,
  overrideReasons: string[],
  drivers: RiskDriverSummary[]
) {
  const actions: string[] = [];

  if (telemetry.ransomware_behaviour_flag || telemetry.c2_beacon_indicator || telemetry.data_exfiltration_indicator) {
    addUniqueAction(actions, "Isolate the device immediately while preserving the Fenrir control-plane channel.");
  }

  if ((telemetry.known_exploited_vuln_count ?? 0) > 0) {
    addUniqueAction(actions, "Remediate known exploited vulnerabilities as the highest patching priority.");
  }

  if ((telemetry.os_patch_age_days ?? 0) >= 30 || (telemetry.critical_patches_overdue_count ?? 0) > 0) {
    addUniqueAction(actions, "Patch the operating system immediately and clear overdue critical updates.");
  }

  if ((telemetry.internet_exposed_admin_service_count ?? 0) > 0 || telemetry.rdp_exposed_flag || telemetry.smb_exposed_flag) {
    addUniqueAction(actions, "Remove or restrict exposed RDP, SMB, and administrative services.");
  }

  if ((telemetry.malicious_domain_contacts_7d ?? 0) > 0 || telemetry.unusual_egress_indicator) {
    addUniqueAction(actions, "Investigate malicious or suspicious outbound traffic from the device.");
  }

  if (telemetry.edr_enabled === false || telemetry.av_enabled === false || telemetry.tamper_protection_enabled === false) {
    addUniqueAction(actions, "Re-enable EDR, antivirus, and tamper protection controls.");
  }

  if ((telemetry.unsupported_software_count ?? 0) > 0 || (telemetry.untrusted_or_unsigned_software_count ?? 0) > 0) {
    addUniqueAction(actions, "Remove unsupported or untrusted software and review application allow-listing.");
  }

  if (telemetry.stolen_token_indicator || telemetry.risky_signin_indicator || telemetry.mfa_gap_indicator) {
    addUniqueAction(actions, "Review identity exposure, revoke risky sessions, and enforce MFA.");
  }

  if ((telemetry.local_admin_users_count ?? 0) > 1) {
    addUniqueAction(actions, "Reduce unnecessary local administrator memberships on the device.");
  }

  if ((telemetry.active_malware_count ?? 0) > 0 || (telemetry.persistent_threat_count ?? 0) > 0) {
    addUniqueAction(actions, "Investigate and remediate active or persistent malware on the endpoint.");
  }

  if (actions.length === 0 && drivers.length > 0) {
    addUniqueAction(actions, "Review the highest-impact risk drivers and validate that the device posture is expected.");
  }

  if (overrideReasons.length > 0 && !actions.some((item) => item.toLowerCase().includes("isolate"))) {
    addUniqueAction(actions, "Consider isolating the device if investigation confirms active compromise.");
  }

  return actions.slice(0, 6);
}

function buildOverrideReasons(telemetry: DeviceRiskTelemetrySnapshot) {
  const reasons: string[] = [];

  if (telemetry.ransomware_behaviour_flag) {
    reasons.push("Ransomware behaviour triggered a critical-risk floor of 90.");
  }

  if ((telemetry.active_malware_count ?? 0) > 0 && (telemetry.edr_enabled === false || telemetry.av_enabled === false)) {
    reasons.push("Active malware with missing EDR or antivirus coverage triggered a risk floor of 80.");
  }

  if (
    (telemetry.internet_exposed_admin_service_count ?? 0) > 0 &&
    (telemetry.internet_exposed_unpatched_critical_count ?? 0) > 0
  ) {
    reasons.push("Internet-exposed admin services combined with unpatched critical exposure triggered a risk floor of 75.");
  }

  if (telemetry.c2_beacon_indicator) {
    reasons.push("Command-and-control beaconing triggered a risk floor of 80.");
  }

  if (telemetry.data_exfiltration_indicator) {
    reasons.push("Potential data exfiltration triggered a risk floor of 85.");
  }

  return reasons;
}

function applyOverrides(baseScore: number, telemetry: DeviceRiskTelemetrySnapshot) {
  let score = baseScore;

  if (telemetry.ransomware_behaviour_flag) {
    score = Math.max(score, 90);
  }

  if ((telemetry.active_malware_count ?? 0) > 0 && (telemetry.edr_enabled === false || telemetry.av_enabled === false)) {
    score = Math.max(score, 80);
  }

  if (
    (telemetry.internet_exposed_admin_service_count ?? 0) > 0 &&
    (telemetry.internet_exposed_unpatched_critical_count ?? 0) > 0
  ) {
    score = Math.max(score, 75);
  }

  if (telemetry.c2_beacon_indicator) {
    score = Math.max(score, 80);
  }

  if (telemetry.data_exfiltration_indicator) {
    score = Math.max(score, 85);
  }

  return roundScore(score);
}

export function summarizeDeviceRisk(score: DeviceScoreSnapshot) {
  const primaryDrivers = score.topRiskDrivers.slice(0, 3).map((item) => item.title.toLowerCase());
  const driverPhrase = primaryDrivers.length > 0 ? ` Primary drivers: ${primaryDrivers.join("; ")}.` : "";
  return `${score.hostname} is ${score.riskBand} risk at ${score.overallScore}/100 with telemetry confidence ${score.confidenceScore}%.${driverPhrase}`;
}

export function explainDeviceRisk(score: DeviceScoreSnapshot) {
  const driverList = score.topRiskDrivers.length > 0
    ? score.topRiskDrivers.map((item) => `${item.title}: ${item.detail}`).join(" ")
    : "No strong risk drivers were identified from the available telemetry.";
  const overrideList =
    score.overrideReasons.length > 0 ? ` Overrides applied: ${score.overrideReasons.join(" ")}` : "";
  const actionList =
    score.recommendedActions.length > 0 ? ` Recommended actions: ${score.recommendedActions.join(" ")}` : "";
  return `${score.hostname} is ${score.riskBand} risk with an overall score of ${score.overallScore} and confidence ${score.confidenceScore}. ${driverList}${overrideList}${actionList}`;
}

export function scoreDeviceRisk(input: DeviceRiskEvaluationInput): DeviceScoreSnapshot {
  const drivers: RiskDriverSummary[] = [];

  const categoryScores: DeviceRiskCategoryScore[] = [
    {
      category: "patch_posture",
      weight: RISK_CATEGORY_WEIGHTS.patch_posture,
      score: calculatePatchPosture(input.telemetry, drivers),
      contribution: 0
    },
    {
      category: "software_hygiene",
      weight: RISK_CATEGORY_WEIGHTS.software_hygiene,
      score: calculateSoftwareHygiene(input.telemetry, drivers),
      contribution: 0
    },
    {
      category: "threat_activity",
      weight: RISK_CATEGORY_WEIGHTS.threat_activity,
      score: calculateThreatActivity(input.telemetry, drivers),
      contribution: 0
    },
    {
      category: "exposure",
      weight: RISK_CATEGORY_WEIGHTS.exposure,
      score: calculateExposure(input.telemetry, drivers),
      contribution: 0
    },
    {
      category: "network_behaviour",
      weight: RISK_CATEGORY_WEIGHTS.network_behaviour,
      score: calculateNetworkBehaviour(input.telemetry, drivers),
      contribution: 0
    },
    {
      category: "control_health",
      weight: RISK_CATEGORY_WEIGHTS.control_health,
      score: calculateControlHealth(input.telemetry, drivers),
      contribution: 0
    },
    {
      category: "identity_posture",
      weight: RISK_CATEGORY_WEIGHTS.identity_posture,
      score: calculateIdentityPosture(input.telemetry, drivers),
      contribution: 0
    }
  ].map((item): DeviceRiskCategoryScore => ({
    category: item.category as RiskCategoryKey,
    weight: item.weight,
    score: item.score,
    contribution: roundScore((item.score * item.weight) / 100)
  }));

  const weightedScore = categoryScores.reduce((total, item) => total + (item.score * item.weight) / 100, 0);
  const overrideReasons = buildOverrideReasons(input.telemetry);
  const overallScore = applyOverrides(roundScore(weightedScore), input.telemetry);
  const confidence = calculateConfidence(input.telemetry);
  const topRiskDrivers = [...drivers].sort((left, right) => right.scoreImpact - left.scoreImpact).slice(0, 5);
  const recommendedActions = buildRecommendedActions(input.telemetry, overrideReasons, topRiskDrivers);
  const inheritedTacticIds = input.inheritedTacticIds ?? [];
  const inheritedTechniqueIds = input.inheritedTechniqueIds ?? [];
  const tacticIds = [
    ...new Set([...(input.telemetry.tacticIds ?? []), ...inheritedTacticIds, ...topRiskDrivers.flatMap((item) => item.tacticIds)])
  ];
  const techniqueIds = [
    ...new Set([
      ...(input.telemetry.techniqueIds ?? []),
      ...inheritedTechniqueIds,
      ...topRiskDrivers.flatMap((item) => item.techniqueIds)
    ])
  ];

  const score: DeviceScoreSnapshot = {
    id: randomUUID(),
    deviceId: input.deviceId,
    hostname: input.hostname,
    calculatedAt: input.now,
    telemetryUpdatedAt: input.telemetry.updatedAt,
    telemetrySource: input.telemetry.source,
    overallScore,
    riskBand: riskBandFromScore(overallScore),
    confidenceScore: confidence.confidenceScore,
    categoryScores,
    topRiskDrivers,
    overrideReasons,
    recommendedActions,
    missingTelemetryFields: confidence.missingTelemetryFields,
    tacticIds,
    techniqueIds,
    summary: "",
    analystSummary: ""
  };

  score.summary = summarizeDeviceRisk(score);
  score.analystSummary = explainDeviceRisk(score);
  return score;
}

export const deviceRiskTelemetryFieldsByCategory = CATEGORY_FIELDS;
