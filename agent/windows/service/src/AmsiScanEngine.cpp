#include "AmsiScanEngine.h"

#include <algorithm>
#include <cwctype>
#include <filesystem>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "AmsiEvidenceRecorder.h"
#include "CryptoUtils.h"
#include "ReputationLookup.h"
#include "QuarantineStore.h"
#include "StringUtils.h"

namespace antivirus::agent {
namespace {

struct IndicatorHit {
  std::wstring code;
  std::wstring message;
  std::wstring tacticId;
  std::wstring techniqueId;
  int score{0};
};

struct IndicatorRule {
  std::wstring code;
  std::wstring message;
  std::wstring tacticId;
  std::wstring techniqueId;
  int score{0};
  std::vector<std::wstring> patterns;
};

constexpr std::size_t kPreviewCharacters = 220;

std::wstring ToLowerCopy(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return value;
}

std::wstring SanitizePreview(const std::wstring& text) {
  std::wstring preview;
  preview.reserve(std::min<std::size_t>(text.size(), kPreviewCharacters));

  for (const auto ch : text) {
    auto out = ch;
    if (out == L'\r' || out == L'\n' || out == L'\t') {
      out = L' ';
    }

    preview.push_back(out);
    if (preview.size() >= kPreviewCharacters) {
      break;
    }
  }

  return preview;
}

std::wstring DecodeScriptText(const std::vector<unsigned char>& content) {
  if (content.empty()) {
    return {};
  }

  if (content.size() >= 4 && content[1] == 0x00) {
    std::wstring text;
    for (std::size_t index = 0; index + 1 < content.size(); index += 2) {
      const auto ch = static_cast<wchar_t>(content[index] | (content[index + 1] << 8));
      if (ch != L'\0') {
        text.push_back(ch);
      }
    }
    return text;
  }

  if (content.size() >= 2 && content[0] == 0xFF && content[1] == 0xFE) {
    std::wstring text;
    for (std::size_t index = 2; index + 1 < content.size(); index += 2) {
      const auto ch = static_cast<wchar_t>(content[index] | (content[index + 1] << 8));
      if (ch != L'\0') {
        text.push_back(ch);
      }
    }
    return text;
  }

  if (content.size() >= 2 && content[0] == 0xFE && content[1] == 0xFF) {
    std::wstring text;
    for (std::size_t index = 2; index + 1 < content.size(); index += 2) {
      const auto ch = static_cast<wchar_t>((content[index] << 8) | content[index + 1]);
      if (ch != L'\0') {
        text.push_back(ch);
      }
    }
    return text;
  }

  const auto utf8 = std::string(reinterpret_cast<const char*>(content.data()), content.size());
  const auto utf8Wide = Utf8ToWide(utf8);
  if (!utf8Wide.empty()) {
    return utf8Wide;
  }

  std::wstring fallback;
  fallback.reserve(content.size());
  for (const auto byte : content) {
    fallback.push_back(byte >= 0x20 && byte <= 0x7E ? static_cast<wchar_t>(byte) : L'.');
  }

  return fallback;
}

bool Contains(std::wstring_view haystack, std::wstring_view needle) {
  return haystack.find(needle) != std::wstring_view::npos;
}

bool ContainsAny(std::wstring_view haystack, std::initializer_list<std::wstring_view> needles) {
  return std::any_of(needles.begin(), needles.end(),
                     [haystack](const auto needle) { return Contains(haystack, needle); });
}

bool ContainsLongBase64Blob(std::wstring_view text) {
  std::size_t currentRun = 0;
  for (const auto ch : text) {
    const auto isBase64 = (ch >= L'A' && ch <= L'Z') || (ch >= L'a' && ch <= L'z') || (ch >= L'0' && ch <= L'9') ||
                          ch == L'+' || ch == L'/' || ch == L'=';
    currentRun = isBase64 ? currentRun + 1 : 0;
    if (currentRun >= 96) {
      return true;
    }
  }

  return false;
}

bool ContainsRecoveryInhibitionCommands(std::wstring_view scriptLower) {
  return ContainsAny(scriptLower, {L"vssadmin delete shadows", L"wmic shadowcopy delete", L"wbadmin delete catalog",
                                   L"wbadmin delete backup", L"bcdedit /set {default} recoveryenabled no",
                                   L"bcdedit /set {current} recoveryenabled no",
                                   L"bcdedit /set {default} bootstatuspolicy ignoreallfailures",
                                   L"bcdedit /set {current} bootstatuspolicy ignoreallfailures", L"reagentc /disable"});
}

bool ContainsSuspiciousNetworkDestinations(std::wstring_view scriptLower) {
  return ContainsAny(scriptLower, {L".onion", L"pastebin.com", L"anonfiles", L"transfer.sh", L"ngrok",
                                   L"telegram.me", L"discordapp.com/api/webhooks", L":4444", L":8080", L":8443"});
}

bool ContainsMassEncryptionScriptBehavior(std::wstring_view scriptLower) {
  const auto enumeratesFiles =
      ContainsAny(scriptLower, {L"get-childitem", L"enumeratefiles", L"directory.getfiles", L"findfirstfile",
                                L"forfiles", L"dir /s", L"walk("});
  const auto usesCrypto =
      ContainsAny(scriptLower, {L"aesmanaged", L"rijndaelmanaged", L"cryptostream", L"createencryptor",
                                L"transformfinalblock", L"encryptor", L"cryptoapi"});
  const auto rewritesContent =
      ContainsAny(scriptLower, {L"writeallbytes", L"set-content", L"writealltext", L"move-item", L"rename-item",
                                L"copyto(", L"filesystem::rename"});

  return enumeratesFiles && usesCrypto && rewritesContent;
}

bool ContainsReflectiveLoaderBehavior(std::wstring_view scriptLower) {
  const auto hasReflectiveLoad =
      ContainsAny(scriptLower, {L"reflection.assembly", L"assembly.load(", L"definedynamicassembly",
                                L"getdelegateforfunctionpointer", L"marshal.copy", L"unsafe native methods"});
  const auto hasMemoryWrite =
      ContainsAny(scriptLower, {L"virtualalloc", L"virtualprotect", L"rtlmovememory", L"writeprocessmemory",
                                L"createthread", L"create remote thread"});
  return hasReflectiveLoad || hasMemoryWrite;
}

bool ContainsLateralLolbinProxyChain(std::wstring_view scriptLower) {
  return ContainsAny(scriptLower, {L"mshta ", L"regsvr32 ", L"rundll32 ", L"wmic process call create",
                                   L"installutil ", L"msbuild ", L"control.exe ", L"forfiles /c"});
}

bool LooksLikeRansomNoteContent(std::wstring_view scriptLower, std::wstring_view contentNameLower) {
  const auto suspiciousName =
      ContainsAny(contentNameLower, {L"readme", L"decrypt", L"recover", L"restore", L"how_to", L"ransom"});
  const auto mentionsEncryption =
      ContainsAny(scriptLower, {L"your files have been encrypted", L"all your files have been encrypted",
                                L"data encrypted", L"files are encrypted", L"encrypted with"});
  const auto mentionsRecovery =
      ContainsAny(scriptLower, {L"how to decrypt", L"recover your files", L"restore your files",
                                L"private key", L"decryptor", L"decryption key"});
  const auto mentionsPayment =
      ContainsAny(scriptLower, {L"bitcoin", L"monero", L"onion", L"tor browser", L"contact us", L"pay"});

  return suspiciousName && ((mentionsEncryption && mentionsRecovery) || (mentionsEncryption && mentionsPayment));
}

std::wstring BuildContentLabel(const AmsiContentRequest& request) {
  if (!request.contentName.empty()) {
    return request.contentName;
  }

  std::wstring label = L"memory://";
  label += request.appName.empty() ? L"unknown" : request.appName;
  label += L"/";
  label += std::to_wstring(request.sessionId);
  return label;
}

std::optional<std::filesystem::path> ResolveQuarantineCandidate(const std::wstring& contentName) {
  if (contentName.empty()) {
    return std::nullopt;
  }

  const std::filesystem::path path(contentName);
  std::error_code error;
  if (std::filesystem::exists(path, error) && std::filesystem::is_regular_file(path, error)) {
    return path;
  }

  return std::nullopt;
}

std::wstring GuessDefaultTechnique(const std::wstring& appNameLower, const std::wstring& contentNameLower) {
  if (Contains(appNameLower, L"powershell") || Contains(contentNameLower, L".ps1")) {
    return L"T1059.001";
  }
  if (Contains(contentNameLower, L".bat") || Contains(contentNameLower, L".cmd")) {
    return L"T1059.003";
  }
  if (Contains(contentNameLower, L".js") || Contains(contentNameLower, L".jse")) {
    return L"T1059.007";
  }
  if (Contains(contentNameLower, L".vbs") || Contains(contentNameLower, L".vbe") || Contains(appNameLower, L"winword") ||
      Contains(appNameLower, L"excel") || Contains(contentNameLower, L".docm") || Contains(contentNameLower, L".xlsm")) {
    return L"T1059.005";
  }
  if (Contains(contentNameLower, L".hta")) {
    return L"T1218.005";
  }

  return L"T1059";
}

std::wstring MakePattern(std::initializer_list<const wchar_t*> fragments) {
  std::wstring value;
  for (const auto* fragment : fragments) {
    value += fragment;
  }
  return value;
}

std::vector<IndicatorHit> CollectIndicatorHits(const std::wstring& appNameLower, const std::wstring& contentNameLower,
                                               const std::wstring& scriptLower) {
  const std::vector<IndicatorRule> rules = {
      {L"DEFENSE_EVASION_AMSI", L"Script content contains defense-evasion indicators for the script-scanning path.",
       L"TA0005", L"T1562.001", 55,
       {MakePattern({L"am", L"si", L"ut", L"ils"}), MakePattern({L"amsiinit", L"failed"}),
        MakePattern({L"system.management.automation.", L"amsi"}), MakePattern({L"virtual", L"protect"})}},
      {L"ENCODED_PAYLOAD", L"Script content contains encoded payload or decode routines.", L"TA0005", L"T1027", 35,
       {MakePattern({L"from", L"base64", L"string"}), MakePattern({L"encoded", L"command"}), L"-enc "}},
      {L"DOWNLOAD_CRADLE", L"Script content contains network download cradle behavior.", L"TA0011", L"T1105", 35,
       {MakePattern({L"download", L"string"}), MakePattern({L"download", L"file"}),
        MakePattern({L"invoke-", L"webrequest"}), MakePattern({L"start-bit", L"stransfer"}),
        MakePattern({L"net.", L"webclient"})}},
      {L"DYNAMIC_EXECUTION", L"Script content uses dynamic execution primitives.", L"TA0002", L"T1059.001", 30,
       {MakePattern({L"invoke-", L"expression"}), MakePattern({L"ie", L"x("}), L"iex "}},
      {L"OFFICE_MACRO_LAUNCH", L"Macro auto-run and shell execution patterns were found.", L"TA0002", L"T1059.005", 40,
       {MakePattern({L"auto", L"open"}), MakePattern({L"document_", L"open"}), MakePattern({L"workbook_", L"open"}),
        MakePattern({L"createobject(\"", L"wscript.shell", L"\")"}), MakePattern({L"shell", L"("})}},
      {L"HTA_PROXY_EXECUTION", L"Script content references HTA or proxy execution patterns.", L"TA0005", L"T1218.005",
       40, {MakePattern({L"ms", L"hta"}), L".hta", MakePattern({L"vbscript:", L"execute"}),
            MakePattern({L"java", L"script:eval"})}},
      {L"PROCESS_INJECTION_API", L"Script content references in-memory injection APIs.", L"TA0005", L"T1055", 45,
       {MakePattern({L"virtual", L"alloc"}), MakePattern({L"write", L"process", L"memory"}),
        MakePattern({L"create", L"remote", L"thread"}), MakePattern({L"queue", L"user", L"apc"})}},
      {L"SCRIPT_HOST_ABUSE", L"Script host abuse patterns were detected.", L"TA0002", L"T1059", 30,
       {MakePattern({L"wscript", L".shell"}), MakePattern({L"shell.", L"application"}),
        MakePattern({L"run", L"dll32"}), MakePattern({L"reg", L"svr32"}), MakePattern({L"ms", L"build"})}},
      {L"AMSI_PATCH_BYPASS", L"Script content includes AMSI bypass or in-memory patching primitives.", L"TA0005",
       L"T1562.001", 62,
       {MakePattern({L"amsi", L"scan", L"buffer"}), MakePattern({L"getproc", L"address"}),
        MakePattern({L"load", L"library"}), MakePattern({L"patch", L"amsi"}),
        MakePattern({L"amsi", L"init", L"failed"})}},
      {L"REFLECTIVE_MEMORY_LOADER", L"Script content includes reflective or memory-loader behavior.", L"TA0002",
       L"T1620", 54,
       {MakePattern({L"reflection.", L"assembly"}), MakePattern({L"assembly.", L"load("}),
        MakePattern({L"get", L"delegate", L"for", L"function", L"pointer"}),
        MakePattern({L"marshal.", L"copy"}), MakePattern({L"virtual", L"alloc"})}},
      {L"LOLBIN_PROXY_CHAIN", L"Script content drives LOLBins for proxy execution or staging.", L"TA0005", L"T1218",
       48,
       {MakePattern({L"ms", L"hta "}), MakePattern({L"reg", L"svr32 "}), MakePattern({L"run", L"dll32 "}),
        MakePattern({L"wmic ", L"process", L" call ", L"create"}), MakePattern({L"install", L"util "})}},
      {L"SUSPICIOUS_C2_DESTINATION", L"Script content references suspicious external destinations often used for staging or control.",
       L"TA0011", L"T1071", 42,
       {L".onion", L"pastebin.com", L"discordapp.com/api/webhooks", L":4444", L":8443"}}};

  std::vector<IndicatorHit> hits;
  for (const auto& rule : rules) {
    for (const auto& pattern : rule.patterns) {
      if (Contains(scriptLower, pattern) || Contains(appNameLower, pattern) || Contains(contentNameLower, pattern)) {
        hits.push_back(IndicatorHit{
            .code = rule.code,
            .message = rule.message,
            .tacticId = rule.tacticId,
            .techniqueId = rule.techniqueId,
            .score = rule.score});
        break;
      }
    }
  }

  if (ContainsLongBase64Blob(scriptLower)) {
    hits.push_back(IndicatorHit{
        .code = L"LONG_BASE64_BLOB",
        .message = L"Script content contains a long encoded payload blob.",
        .tacticId = L"TA0005",
        .techniqueId = L"T1027",
        .score = 30});
  }

  if (ContainsRecoveryInhibitionCommands(scriptLower)) {
    hits.push_back(IndicatorHit{
        .code = L"RECOVERY_INHIBITION",
        .message = L"Script content attempts to delete shadow copies, backups, or recovery settings commonly targeted by ransomware.",
        .tacticId = L"TA0040",
        .techniqueId = L"T1490",
        .score = 72});
  }

  if (ContainsSuspiciousNetworkDestinations(scriptLower)) {
    hits.push_back(IndicatorHit{
        .code = L"SUSPICIOUS_C2_DESTINATION",
        .message = L"Script content references suspicious network destinations commonly used for staging or command-and-control.",
        .tacticId = L"TA0011",
        .techniqueId = L"T1071",
        .score = 42});
  }

  if (ContainsReflectiveLoaderBehavior(scriptLower)) {
    hits.push_back(IndicatorHit{
        .code = L"REFLECTIVE_MEMORY_LOADER",
        .message = L"Script content includes reflective loading or in-memory execution primitives.",
        .tacticId = L"TA0002",
        .techniqueId = L"T1620",
        .score = 54});
  }

  if (ContainsLateralLolbinProxyChain(scriptLower)) {
    hits.push_back(IndicatorHit{
        .code = L"LOLBIN_PROXY_CHAIN",
        .message = L"Script content chains LOLBins for proxy execution or payload staging.",
        .tacticId = L"TA0005",
        .techniqueId = L"T1218",
        .score = 48});
  }

  if (ContainsMassEncryptionScriptBehavior(scriptLower)) {
    hits.push_back(IndicatorHit{
        .code = L"MASS_ENCRYPTION_SCRIPT",
        .message = L"Script content combines file enumeration, cryptography, and rewrite operations consistent with ransomware.",
        .tacticId = L"TA0040",
        .techniqueId = L"T1486",
        .score = 70});
  }

  if (LooksLikeRansomNoteContent(scriptLower, contentNameLower)) {
    hits.push_back(IndicatorHit{
        .code = L"RANSOM_NOTE_CONTENT",
        .message = L"Script content resembles a ransom note with file-recovery and payment instructions.",
        .tacticId = L"TA0040",
        .techniqueId = L"T1486",
        .score = 68});
  }

  return hits;
}

TelemetryRecord BuildAmsiDecisionTelemetry(const AmsiInspectionOutcome& outcome, const std::wstring& source,
                                           const std::wstring& deviceId) {
  std::wstring summary;
  if (outcome.finding.verdict.disposition == VerdictDisposition::Allow) {
    summary = L"AMSI allowed content for ";
  } else if (outcome.finding.verdict.disposition == VerdictDisposition::Quarantine) {
    summary = L"AMSI quarantined suspicious content for ";
  } else {
    summary = L"AMSI blocked suspicious content for ";
  }
  summary += outcome.appName.empty() ? L"an unknown host" : outcome.appName;
  summary += L".";

  std::wstring payload = L"{\"deviceId\":\"";
  payload += Utf8ToWide(EscapeJsonString(deviceId));
  payload += L"\",\"appName\":\"";
  payload += Utf8ToWide(EscapeJsonString(outcome.appName));
  payload += L"\",\"contentName\":\"";
  payload += Utf8ToWide(EscapeJsonString(outcome.contentName));
  payload += L"\",\"sessionId\":";
  payload += std::to_wstring(outcome.sessionId);
  payload += L",\"source\":\"";
  payload += outcome.source == AmsiContentSource::Notify ? L"notify" : L"stream";
  payload += L"\",\"blocked\":";
  payload += outcome.blocked ? L"true" : L"false";
  payload += L",\"disposition\":\"";
  payload += VerdictDispositionToString(outcome.finding.verdict.disposition);
  payload += L"\",\"preview\":\"";
  payload += Utf8ToWide(EscapeJsonString(outcome.preview));
  payload += L"\",\"reasonCount\":";
  payload += std::to_wstring(outcome.finding.verdict.reasons.size());
  payload += L"}";

  return TelemetryRecord{
      .eventId = GenerateGuidString(),
      .eventType = L"amsi.scan",
      .source = source,
      .summary = summary,
      .occurredAt = CurrentUtcTimestamp(),
      .payloadJson = payload};
}

TelemetryRecord BuildAmsiFindingTelemetry(const AmsiInspectionOutcome& outcome, const std::wstring& source,
                                          const std::wstring& deviceId) {
  auto subject = std::filesystem::path(outcome.contentName).filename().wstring();
  if (subject.empty()) {
    subject = outcome.contentName.empty() ? L"in-memory content" : outcome.contentName;
  }

  std::wstring summary;
  if (outcome.finding.verdict.disposition == VerdictDisposition::Allow) {
    summary = L"AMSI provider allowed ";
  } else if (outcome.finding.verdict.disposition == VerdictDisposition::Quarantine) {
    summary = L"AMSI provider quarantined ";
  } else {
    summary = L"AMSI provider blocked ";
  }
  summary += subject;
  summary += L" for ";
  summary += outcome.appName.empty() ? L"an unknown host." : outcome.appName + L".";

  std::wstring payload = L"{\"deviceId\":\"";
  payload += Utf8ToWide(EscapeJsonString(deviceId));
  payload += L"\",\"path\":\"";
  payload += Utf8ToWide(EscapeJsonString(outcome.finding.path.wstring()));
  payload += L"\",\"sizeBytes\":";
  payload += std::to_wstring(outcome.finding.sizeBytes);
  payload += L",\"sha256\":\"";
  payload += outcome.finding.sha256;
  payload += L"\",\"remediationStatus\":\"";
  payload += RemediationStatusToString(outcome.finding.remediationStatus);
  payload += L"\",\"disposition\":\"";
  payload += VerdictDispositionToString(outcome.finding.verdict.disposition);
  payload += L"\",\"tacticId\":\"";
  payload += outcome.finding.verdict.tacticId;
  payload += L"\",\"techniqueId\":\"";
  payload += outcome.finding.verdict.techniqueId;
  payload += L"\",\"quarantineRecordId\":\"";
  payload += outcome.finding.quarantineRecordId;
  payload += L"\",\"evidenceRecordId\":\"";
  payload += outcome.finding.evidenceRecordId;
  payload += L"\",\"quarantinedPath\":\"";
  payload += Utf8ToWide(EscapeJsonString(outcome.finding.quarantinedPath.wstring()));
  payload += L"\",\"remediationError\":\"";
  payload += Utf8ToWide(EscapeJsonString(outcome.finding.remediationError));
  payload += L"\",\"appName\":\"";
  payload += Utf8ToWide(EscapeJsonString(outcome.appName));
  payload += L"\",\"contentName\":\"";
  payload += Utf8ToWide(EscapeJsonString(outcome.contentName));
  payload += L"\",\"sessionId\":";
  payload += std::to_wstring(outcome.sessionId);
  payload += L",\"preview\":\"";
  payload += Utf8ToWide(EscapeJsonString(outcome.preview));
  payload += L"\",\"reasons\":[";
  for (std::size_t index = 0; index < outcome.finding.verdict.reasons.size(); ++index) {
    const auto& reason = outcome.finding.verdict.reasons[index];
    if (index != 0) {
      payload += L",";
    }
    payload += L"{\"code\":\"";
    payload += Utf8ToWide(EscapeJsonString(reason.code));
    payload += L"\",\"message\":\"";
    payload += Utf8ToWide(EscapeJsonString(reason.message));
    payload += L"\"}";
  }
  payload += L"]}";

  return TelemetryRecord{
      .eventId = GenerateGuidString(),
      .eventType = L"scan.finding",
      .source = source,
      .summary = summary,
      .occurredAt = CurrentUtcTimestamp(),
      .payloadJson = payload};
}

}  // namespace

AmsiInspectionOutcome InspectAmsiContent(const AmsiContentRequest& request, const PolicySnapshot& policy,
                                         const AgentConfig& config) {
  AmsiInspectionOutcome outcome{
      .detection = false,
      .blocked = false,
      .finding = {},
      .appName = request.appName,
      .contentName = BuildContentLabel(request),
      .preview = {},
      .sessionId = request.sessionId,
      .source = request.source,
      .telemetry = {}};

  outcome.finding.path = std::filesystem::path(outcome.contentName);
  outcome.finding.sizeBytes = request.content.size();
  outcome.finding.sha256 = ComputeBufferSha256(request.content);

  if (!policy.scriptInspectionEnabled) {
    outcome.finding.verdict = ScanVerdict{
        .disposition = VerdictDisposition::Allow,
        .confidence = 0,
        .tacticId = L"",
        .techniqueId = L"",
        .reasons = {{L"AMSI_DISABLED", L"Script inspection is disabled by policy."}}};
    outcome.telemetry.push_back(BuildAmsiDecisionTelemetry(outcome, L"amsi-provider", request.deviceId));
    return outcome;
  }

  const auto decoded = DecodeScriptText(request.content);
  const auto scriptLower = ToLowerCopy(decoded);
  const auto appNameLower = ToLowerCopy(request.appName);
  const auto contentNameLower = ToLowerCopy(outcome.contentName);
  outcome.preview = SanitizePreview(decoded);

  const auto hits = CollectIndicatorHits(appNameLower, contentNameLower, scriptLower);
  int score = 0;
  for (const auto& hit : hits) {
    score += hit.score;
    outcome.finding.verdict.reasons.push_back({hit.code, hit.message});
  }

  if (score < 55) {
    outcome.finding.verdict.disposition = VerdictDisposition::Allow;
    outcome.finding.verdict.confidence = static_cast<std::uint32_t>(std::max(score, 0));
    outcome.finding.verdict.tacticId = L"";
    outcome.finding.verdict.techniqueId = GuessDefaultTechnique(appNameLower, contentNameLower);
    if (outcome.finding.verdict.reasons.empty()) {
      outcome.finding.verdict.reasons.push_back(
          {L"AMSI_ALLOW", L"No malicious script or fileless execution indicators were matched."});
    }
    outcome.telemetry.push_back(BuildAmsiDecisionTelemetry(outcome, L"amsi-provider", request.deviceId));
    return outcome;
  }

  const auto topHit =
      std::max_element(hits.begin(), hits.end(),
                       [](const IndicatorHit& left, const IndicatorHit& right) { return left.score < right.score; });
  if (topHit != hits.end()) {
    outcome.finding.verdict.tacticId = topHit->tacticId;
    outcome.finding.verdict.techniqueId = topHit->techniqueId;
  } else {
    outcome.finding.verdict.tacticId = L"TA0002";
    outcome.finding.verdict.techniqueId = GuessDefaultTechnique(appNameLower, contentNameLower);
  }

  outcome.detection = true;

  ReputationLookupResult reputationLookup{};
  if (policy.cloudLookupEnabled && !outcome.finding.sha256.empty()) {
    reputationLookup = LookupPublicFileReputation(outcome.finding.sha256);
    outcome.finding.reputation = DescribeReputationLookup(reputationLookup);
    outcome.finding.verdict.reasons.push_back(
        {reputationLookup.knownGood ? L"REPUTATION_VERIFIED" : L"REPUTATION_LOOKUP", reputationLookup.summary});
  } else {
    outcome.finding.reputation = L"hashlookup-skipped";
  }

  const auto reputationAllows = reputationLookup.attempted && reputationLookup.knownGood && score < 70;
  if (reputationAllows) {
    outcome.blocked = false;
    outcome.finding.verdict.disposition = VerdictDisposition::Allow;
    outcome.finding.verdict.confidence = static_cast<std::uint32_t>(std::min(score, 54));
  } else {
    outcome.blocked = true;
    outcome.finding.verdict.disposition = VerdictDisposition::Block;
    outcome.finding.verdict.confidence = static_cast<std::uint32_t>(std::min(score, 99));

    if (const auto quarantineCandidate = ResolveQuarantineCandidate(outcome.contentName);
        quarantineCandidate.has_value() && policy.quarantineOnMalicious) {
      outcome.finding.path = *quarantineCandidate;
      outcome.finding.verdict.disposition = VerdictDisposition::Quarantine;
      QuarantineStore quarantineStore(config.quarantineRootPath, config.runtimeDatabasePath);
      const auto quarantineResult = quarantineStore.QuarantineFile(outcome.finding);
      if (quarantineResult.success) {
        outcome.finding.remediationStatus = RemediationStatus::Quarantined;
        outcome.finding.quarantineRecordId = quarantineResult.recordId;
        outcome.finding.quarantinedPath = quarantineResult.quarantinedPath;
        outcome.finding.verdict.reasons.push_back(
            {L"QUARANTINE_APPLIED", L"Fenrir moved the backing artifact into local quarantine."});
        if (!quarantineResult.localStatus.empty()) {
          outcome.finding.verdict.reasons.push_back(
              {L"QUARANTINE_STATUS", L"Quarantine status: " + quarantineResult.localStatus + L"."});
        }
        if (!quarantineResult.verificationDetail.empty()) {
          outcome.finding.verdict.reasons.push_back({L"QUARANTINE_VERIFIED", quarantineResult.verificationDetail});
        }
      } else {
        if (!quarantineResult.recordId.empty()) {
          outcome.finding.quarantineRecordId = quarantineResult.recordId;
        }
        if (!quarantineResult.quarantinedPath.empty()) {
          outcome.finding.quarantinedPath = quarantineResult.quarantinedPath;
        }
        outcome.finding.remediationStatus = RemediationStatus::Failed;
        outcome.finding.remediationError =
            quarantineResult.errorMessage.empty() ? L"AMSI quarantine failed for the backing file."
                                                  : quarantineResult.errorMessage;
        if (!quarantineResult.localStatus.empty()) {
          outcome.finding.verdict.reasons.push_back(
              {L"QUARANTINE_STATUS", L"Quarantine status: " + quarantineResult.localStatus + L"."});
        }
        if (!quarantineResult.verificationDetail.empty()) {
          outcome.finding.verdict.reasons.push_back(
              {L"QUARANTINE_VERIFICATION_FAILED", quarantineResult.verificationDetail});
        }
        outcome.finding.verdict.reasons.push_back({L"QUARANTINE_FAILED", outcome.finding.remediationError});
        outcome.finding.verdict.disposition = VerdictDisposition::Block;
      }
    }
  }

  AmsiEvidenceRecorder evidenceRecorder(config.evidenceRootPath, config.runtimeDatabasePath);
  const auto evidence = evidenceRecorder.RecordInspection(request, outcome, policy, L"amsi-provider");
  outcome.finding.evidenceRecordId = evidence.recordId;

  outcome.telemetry.push_back(BuildAmsiDecisionTelemetry(outcome, L"amsi-provider", request.deviceId));
  outcome.telemetry.push_back(BuildAmsiFindingTelemetry(outcome, L"amsi-provider", request.deviceId));
  return outcome;
}

}  // namespace antivirus::agent
