import { randomUUID } from "node:crypto";
import { win32 } from "node:path";

import type { AlertSeverity, AlertSummary, ControlPlaneState, TelemetryRecord } from "./types.ts";

interface GeneratedAlertCandidate extends AlertSummary {
  fingerprint: string;
}

type ParsedPayload = Record<string, unknown>;

interface SuspiciousProcessRule {
  imageName: string;
  severity: AlertSeverity;
  technique: string;
  title: string;
  detail: string;
}

interface RiskyFileRule {
  severity: AlertSeverity;
  technique: string;
  title: string;
  detail: string;
}

const suspiciousProcessRules = new Map<string, SuspiciousProcessRule>([
  [
    "powershell.exe",
    {
      imageName: "powershell.exe",
      severity: "high",
      technique: "T1059.001",
      title: "PowerShell execution observed",
      detail: "Command-and-scripting execution should be reviewed for staging or post-exploitation behavior."
    }
  ],
  [
    "pwsh.exe",
    {
      imageName: "pwsh.exe",
      severity: "high",
      technique: "T1059.001",
      title: "PowerShell execution observed",
      detail: "Command-and-scripting execution should be reviewed for staging or post-exploitation behavior."
    }
  ],
  [
    "wscript.exe",
    {
      imageName: "wscript.exe",
      severity: "high",
      technique: "T1059",
      title: "Windows Script Host execution observed",
      detail: "Script host launches in user space are often associated with phishing or living-off-the-land execution."
    }
  ],
  [
    "cscript.exe",
    {
      imageName: "cscript.exe",
      severity: "high",
      technique: "T1059",
      title: "Windows Script Host execution observed",
      detail: "Script host launches in user space are often associated with phishing or living-off-the-land execution."
    }
  ],
  [
    "mshta.exe",
    {
      imageName: "mshta.exe",
      severity: "critical",
      technique: "T1218.005",
      title: "MSHTA execution observed",
      detail: "MSHTA is a high-risk signed proxy execution binary and should be triaged immediately."
    }
  ],
  [
    "rundll32.exe",
    {
      imageName: "rundll32.exe",
      severity: "high",
      technique: "T1218.011",
      title: "Rundll32 execution observed",
      detail: "Signed proxy execution through Rundll32 can indicate DLL side-loading or LOLBin abuse."
    }
  ],
  [
    "regsvr32.exe",
    {
      imageName: "regsvr32.exe",
      severity: "high",
      technique: "T1218.010",
      title: "Regsvr32 execution observed",
      detail: "Regsvr32 execution should be reviewed for remote scriptlet or COM registration abuse."
    }
  ]
]);

const riskyFileRules = new Map<string, RiskyFileRule>([
  [
    ".exe",
    {
      severity: "high",
      technique: "T1204.002",
      title: "Executable dropped in monitored folder",
      detail: "Fresh executables in user-accessible folders are a common precursor to user-execution malware chains."
    }
  ],
  [
    ".dll",
    {
      severity: "high",
      technique: "T1204.002",
      title: "Executable dropped in monitored folder",
      detail: "Fresh binaries in user-accessible folders are a common precursor to side-loading and user-execution chains."
    }
  ],
  [
    ".scr",
    {
      severity: "high",
      technique: "T1204.002",
      title: "Executable dropped in monitored folder",
      detail: "Screen saver executables in user folders should be treated like regular portable executables."
    }
  ],
  [
    ".msi",
    {
      severity: "high",
      technique: "T1204.002",
      title: "Installer package dropped in monitored folder",
      detail: "Installer packages in user-accessible folders can be used to deliver staged malware."
    }
  ],
  [
    ".ps1",
    {
      severity: "high",
      technique: "T1059.001",
      title: "Script dropped in monitored folder",
      detail: "PowerShell scripts in monitored folders deserve review before execution."
    }
  ],
  [
    ".bat",
    {
      severity: "high",
      technique: "T1059.003",
      title: "Script dropped in monitored folder",
      detail: "Batch script drops in monitored folders can kick off chained payload execution."
    }
  ],
  [
    ".cmd",
    {
      severity: "high",
      technique: "T1059.003",
      title: "Script dropped in monitored folder",
      detail: "Command script drops in monitored folders can kick off chained payload execution."
    }
  ],
  [
    ".js",
    {
      severity: "high",
      technique: "T1059",
      title: "Script dropped in monitored folder",
      detail: "JavaScript drops in monitored folders are a common lure and execution vector."
    }
  ],
  [
    ".jse",
    {
      severity: "high",
      technique: "T1059",
      title: "Script dropped in monitored folder",
      detail: "Encoded script drops in monitored folders are a common lure and execution vector."
    }
  ],
  [
    ".vbs",
    {
      severity: "high",
      technique: "T1059",
      title: "Script dropped in monitored folder",
      detail: "VBScript drops in monitored folders are a common lure and execution vector."
    }
  ],
  [
    ".vbe",
    {
      severity: "high",
      technique: "T1059",
      title: "Script dropped in monitored folder",
      detail: "Encoded VBScript drops in monitored folders are a common lure and execution vector."
    }
  ],
  [
    ".hta",
    {
      severity: "critical",
      technique: "T1218.005",
      title: "HTA content dropped in monitored folder",
      detail: "HTA payloads combine script and proxy execution risk, especially when paired with MSHTA."
    }
  ],
  [
    ".lnk",
    {
      severity: "medium",
      technique: "T1204.001",
      title: "Shortcut dropped in monitored folder",
      detail: "Shortcut files in monitored folders can be used as user-execution lures."
    }
  ],
  [
    ".zip",
    {
      severity: "medium",
      technique: "T1204.002",
      title: "Archive dropped in monitored folder",
      detail: "Archives in monitored folders often precede payload extraction and execution."
    }
  ],
  [
    ".iso",
    {
      severity: "medium",
      technique: "T1204.002",
      title: "Disk image dropped in monitored folder",
      detail: "Disk image files in monitored folders can be used to package lure content and malware."
    }
  ]
]);

function tacticIdForTechnique(technique: string | undefined) {
  switch (technique) {
    case "T1059.001":
    case "T1059.003":
    case "T1059":
    case "T1218.005":
    case "T1218.010":
    case "T1218.011":
    case "T1204.001":
    case "T1204.002":
      return "TA0002";
    case "T1490":
    case "T1486":
      return "TA0040";
    case "T1021.001":
      return "TA0008";
    case "T1071":
    case "T1041":
      return "TA0011";
    default:
      return undefined;
  }
}


function readStringValue(payload: ParsedPayload | null, key: string) {
  const value = payload?.[key];
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : undefined;
}

function truncateText(value: string, maxLength: number) {
  if (value.length <= maxLength) {
    return value;
  }

  return `${value.slice(0, Math.max(0, maxLength - 3)).trimEnd()}...`;
}

function buildProcessContextSummary(record: TelemetryRecord) {
  const parts: string[] = [];

  if (record.processCommandLine) {
    parts.push(`Command line: ${truncateText(record.processCommandLine, 120)}`);
  }

  if (record.processImagePath) {
    parts.push(`Image path: ${record.processImagePath}`);
  }

  if (record.parentProcessImageName || record.parentProcessImagePath) {
    parts.push(`Parent: ${record.parentProcessImageName ?? record.parentProcessImagePath}`);
  }

  if (record.processIntegrityLevel) {
    parts.push(`Integrity: ${record.processIntegrityLevel}`);
  }

  if (record.processSigner) {
    parts.push(`Signer: ${record.processSigner}`);
  }

  return parts.join(". ");
}

function classifyAmsiSubject(appName: string | undefined, contentName: string | undefined) {
  const haystack = `${appName ?? ""} ${contentName ?? ""}`.toLowerCase();
  if (haystack.includes("powershell") || haystack.includes("pwsh") || haystack.includes(".ps1")) {
    return "PowerShell";
  }

  if (haystack.includes("wscript") || haystack.includes("cscript") || haystack.includes(".vbs") ||
      haystack.includes(".vbe") || haystack.includes(".js") || haystack.includes(".jse")) {
    return "WSH";
  }

  if (haystack.includes("winword") || haystack.includes("excel") || haystack.includes("powerpoint") ||
      haystack.includes(".docm") || haystack.includes(".xlsm") || haystack.includes(".pptm")) {
    return "Office";
  }

  if (haystack.includes("mshta") || haystack.includes(".hta")) {
    return "HTA";
  }

  if (haystack.includes("cmd.exe") || haystack.includes(".bat") || haystack.includes(".cmd")) {
    return "Command shell";
  }

  return appName?.trim() || contentName?.trim() || "";
}

function buildAmsiContextSummary(appName: string | undefined, contentName: string | undefined,
                                 sourceType: string | undefined, preview: string | undefined) {
  const parts: string[] = [];
  if (appName) {
    parts.push(`AMSI app: ${appName}`);
  }
  if (contentName) {
    parts.push(`Content: ${contentName}`);
  }
  if (sourceType) {
    parts.push(`Source type: ${sourceType}`);
  }
  if (preview) {
    parts.push(`Preview: ${truncateText(preview, 120)}`);
  }

  return parts.join(". ");
}
const severityWeight: Record<AlertSeverity, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
};

function parsePayload(payloadJson: string): ParsedPayload | null {
  try {
    const parsed = JSON.parse(payloadJson) as unknown;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as ParsedPayload;
    }
  } catch {
    return null;
  }

  return null;
}

function readString(payload: ParsedPayload | null, key: string) {
  const value = payload?.[key];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function normalizeWindowsPath(path: string) {
  return path.replaceAll("/", "\\").toLowerCase();
}

function buildProcessAlert(record: TelemetryRecord): GeneratedAlertCandidate | null {
  if (record.eventType !== "process.started") {
    return null;
  }

  const payload = parsePayload(record.payloadJson);
  const imageName = readString(payload, "imageName")?.toLowerCase();

  if (!imageName) {
    return null;
  }

  const rule = suspiciousProcessRules.get(imageName);
  if (!rule) {
    return null;
  }

  const contextSummary = buildProcessContextSummary(record);

  return {
    id: randomUUID(),
    deviceId: record.deviceId,
    fingerprint: `process:${record.deviceId}:${rule.imageName}`,
    title: rule.title,
    severity: rule.severity,
    status: "new",
    hostname: record.hostname,
    detectedAt: record.occurredAt,
    tacticId: tacticIdForTechnique(rule.technique),
    technique: rule.technique,
    summary: contextSummary ? `${record.summary} ${rule.detail} ${contextSummary}` : `${record.summary} ${rule.detail}`
  };
}

function buildFileAlert(record: TelemetryRecord): GeneratedAlertCandidate | null {
  if (record.eventType !== "file.created" && record.eventType !== "file.modified") {
    return null;
  }

  const payload = parsePayload(record.payloadJson);
  const rawPath = readString(payload, "path");

  if (!rawPath) {
    return null;
  }

  const normalizedPath = normalizeWindowsPath(rawPath);
  const extension = win32.extname(normalizedPath);
  const rule = riskyFileRules.get(extension);

  if (!rule) {
    return null;
  }

  const fileName = win32.basename(rawPath);

  return {
    id: randomUUID(),
    deviceId: record.deviceId,
    fingerprint: `file:${record.deviceId}:${normalizedPath}`,
    title: rule.title,
    severity: rule.severity,
    status: "new",
    hostname: record.hostname,
    detectedAt: record.occurredAt,
    tacticId: tacticIdForTechnique(rule.technique),
    technique: rule.technique,
    summary: `${record.summary} ${fileName} has a monitored ${extension} extension. ${rule.detail}`
  };
}

function buildScanFindingAlert(record: TelemetryRecord): GeneratedAlertCandidate | null {
  if (record.eventType !== "scan.finding") {
    return null;
  }

  const payload = parsePayload(record.payloadJson);
  const rawPath = readString(payload, "path");
  const appName = readStringValue(payload, "appName");
  const contentName = readStringValue(payload, "contentName");
  const sourceType = readStringValue(payload, "source");
  const preview = readStringValue(payload, "preview");
  const disposition = readString(payload, "disposition")?.toLowerCase();
  const remediationStatus = readString(payload, "remediationStatus")?.toLowerCase();
  const techniqueId = readString(payload, "techniqueId");
  const sha256 = readString(payload, "sha256")?.toLowerCase();
  const remediationError = readString(payload, "remediationError");

  if (!rawPath) {
    return null;
  }

  const fingerprintBasis = sha256 && sha256.length > 0 ? sha256 : normalizeWindowsPath(rawPath);
  const amsiSubject = record.source === "amsi-provider" ? classifyAmsiSubject(appName, contentName) : "";
  const fileName = record.source === "amsi-provider"
    ? (contentName && !contentName.toLowerCase().startsWith("memory://")
        ? win32.basename(contentName)
        : amsiSubject || win32.basename(rawPath))
    : win32.basename(rawPath);

  let severity: AlertSeverity = "high";
  let title = "Suspicious file detected by on-demand scan";

  if (record.source === "amsi-provider") {
    title = `Suspicious ${amsiSubject || "script"} content detected after AMSI inspection`;
  }

  if (techniqueId === "T1490") {
    severity = "critical";
    title = "Ransomware recovery-inhibition activity detected";
  } else if (techniqueId === "T1486") {
    severity = "critical";
    title = remediationStatus === "quarantined" || disposition === "quarantine"
      ? "Possible ransomware artifact quarantined"
      : "Possible ransomware artifact detected";
  }

  if (remediationStatus === "failed") {
    severity = "critical";
    title = techniqueId === "T1490"
      ? "Ransomware recovery-inhibition detected but remediation failed"
      : techniqueId === "T1486"
        ? "Possible ransomware artifact detected but quarantine failed"
        : record.source === "amsi-provider"
          ? `Suspicious ${amsiSubject || "script"} content detected but AMSI remediation failed`
          : "Suspicious file detected but quarantine failed";
  } else if ((remediationStatus === "quarantined" || disposition === "quarantine") &&
             techniqueId !== "T1490" &&
             techniqueId !== "T1486") {
    severity = "high";
    title = record.source === "amsi-provider"
      ? `Suspicious ${amsiSubject || "script"} content quarantined after AMSI inspection`
      : techniqueId === "T1486"
        ? "Possible ransomware artifact quarantined"
        : "Suspicious file quarantined after on-demand scan";
  } else if (disposition === "block" && techniqueId !== "T1490" && techniqueId !== "T1486") {
    severity = "high";
    title = record.source === "amsi-provider"
      ? `Suspicious ${amsiSubject || "script"} content blocked after AMSI inspection`
      : "Suspicious file blocked by on-demand scan policy";
  }

  let summary = `${record.summary} ${record.source === "amsi-provider" ? "Subject" : "File"}: ${fileName}.`;
  if (sha256) {
    summary += ` SHA-256: ${sha256}.`;
  }
  if (record.source === "amsi-provider") {
    const amsiSummary = buildAmsiContextSummary(appName, contentName, sourceType, preview);
    if (amsiSummary) {
      summary += ` ${amsiSummary}.`;
    }
  }
  if (remediationStatus === "quarantined") {
    summary += " Local quarantine completed successfully.";
  } else if (remediationStatus === "failed") {
    summary += remediationError ? ` Local quarantine failed: ${remediationError}.` : " Local quarantine failed.";
  }
  if (techniqueId === "T1490") {
    summary += " The finding maps to ATT&CK T1490 (Inhibit System Recovery), a common ransomware precursor.";
  } else if (techniqueId === "T1486") {
    summary += " The finding maps to ATT&CK T1486 (Data Encrypted for Impact), which should be triaged as potential ransomware.";
  }

  return {
    id: randomUUID(),
    deviceId: record.deviceId,
    fingerprint: `scan:${record.deviceId}:${fingerprintBasis}`,
    title,
    severity,
    status: "new",
    hostname: record.hostname,
    detectedAt: record.occurredAt,
    tacticId: techniqueId ? tacticIdForTechnique(techniqueId) : undefined,
    technique: techniqueId && techniqueId !== "unknown" ? techniqueId : undefined,
    summary
  };
}

export function generateAlertsFromTelemetry(records: TelemetryRecord[]) {
  return records.flatMap((record) => {
    const matches = [buildProcessAlert(record), buildFileAlert(record), buildScanFindingAlert(record)].filter(
      (candidate): candidate is GeneratedAlertCandidate => candidate !== null
    );

    return matches;
  });
}

export function mergeGeneratedAlerts(loadedState: ControlPlaneState, candidates: GeneratedAlertCandidate[]) {
  for (const candidate of candidates) {
    const existing = loadedState.alerts.find((alert) => {
      if (alert.status === "contained") {
        return false;
      }

      if (alert.fingerprint) {
        return alert.fingerprint === candidate.fingerprint;
      }

      return alert.hostname === candidate.hostname &&
        alert.title === candidate.title &&
        alert.technique === candidate.technique;
    });

    if (existing) {
      existing.detectedAt = candidate.detectedAt;
      existing.summary = candidate.summary;
      existing.fingerprint = existing.fingerprint ?? candidate.fingerprint;

      if (severityWeight[candidate.severity] > severityWeight[existing.severity]) {
        existing.severity = candidate.severity;
      }

      continue;
    }

    loadedState.alerts.push(candidate);
  }
}
