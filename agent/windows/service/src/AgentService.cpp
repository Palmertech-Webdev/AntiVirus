#include "AgentService.h"

#include <WtsApi32.h>
#include <lm.h>
#include <sddl.h>
#include <userenv.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <vector>

#include "EvidenceRecorder.h"
#include "CryptoUtils.h"
#include "DestinationEventRecorder.h"
#include "DestinationRuntimeStore.h"
#include "DestinationVerdictEngine.h"
#include "DeviceInventoryCollector.h"
#include "FileInventory.h"
#include "FileSnapshotCollector.h"
#include "HardeningManager.h"
#include "LocalSecurity.h"
#include "ProcessInventory.h"
#include "ProcessSnapshotCollector.h"
#include "ServiceSnapshotCollector.h"
#include "QuarantineStore.h"
#include "ReputationLookup.h"
#include "RemediationEngine.h"
#include "RuntimeDatabase.h"
#include "RuntimeTrustValidator.h"
#include "ScanEngine.h"
#include "StringUtils.h"
#include "UpdaterService.h"
#include "WscCoexistenceManager.h"

namespace antivirus::agent {

namespace {

struct ProcessExecutionResult {
  DWORD exitCode{0};
  std::wstring output;
};

constexpr wchar_t kPamRequestEventName[] = L"Global\\FenrirPamRequestReady";
constexpr wchar_t kPamRequestFileName[] = L"pam-request.json";
constexpr wchar_t kPamAuditFileName[] = L"privilege-requests.jsonl";
constexpr wchar_t kPamPolicyFileName[] = L"pam-policy.json";
constexpr wchar_t kPamPolicyDigestFileName[] = L"pam-policy.sha256";
constexpr wchar_t kPamPolicyBackupFileName[] = L"pam-policy.backup.json";
constexpr wchar_t kLocalApprovalQueueFileName[] = L"local-approval-requests.jsonl";
constexpr wchar_t kLocalApprovalLedgerFileName[] = L"local-approval-ledger.jsonl";
constexpr wchar_t kLocalAdminBaselineFileName[] = L"local-admin-baseline.jsonl";
constexpr std::size_t kMaxCommandPayloadChars = 64 * 1024;

struct PamRequestPayload {
  std::wstring requestedAt;
  std::wstring requester;
  std::wstring action;
  std::wstring targetPath;
  std::wstring arguments;
  std::wstring reason;
};

struct PamLaunchPlan {
  std::wstring executablePath;
  std::wstring arguments;
  std::wstring targetPath;
  std::optional<std::uint32_t> maxRuntimeSeconds;
};

struct PamPolicySnapshot {
  bool enabled{true};
  bool requireReason{true};
  bool allowBuiltInAdminTools{true};
  bool allowArbitraryApplications{true};
  std::uint32_t maxTimedRuntimeSeconds{120};
  std::vector<std::wstring> allowedActions;
  std::vector<std::wstring> allowedRequesters;
  std::vector<std::wstring> blockedPathPrefixes;
  std::vector<std::wstring> allowedPathPrefixes;
};

struct QueuedLocalApprovalRequest {
  std::wstring requestId;
  std::wstring createdAt;
  std::wstring type;
  std::wstring requester;
  std::wstring callerSid;
  std::wstring role;
  std::wstring reason;
  std::wstring recordId;
  std::wstring targetPath;
  std::wstring payloadJson;
};

struct LocalAdminMember {
  std::wstring accountName;
  std::wstring sid;
};

struct ClassifiedLocalAdminMember {
  LocalAdminMember member;
  std::wstring memberClass;
  bool protectedMember{false};
  bool managedCandidate{false};
};

struct LoadedLocalAdminBaseline {
  std::wstring baselineId;
  std::wstring capturedAt;
  std::vector<LocalAdminMember> members;
  std::wstring source{L"journal"};
};

std::wstring GetSystemBinaryPath(const wchar_t* relativePath);
bool QueuePamRequestPayload(const std::filesystem::path& requestPath, const PamRequestPayload& request,
                            std::wstring* errorMessage);

std::string EscapeRegex(const std::string& value) {
  std::string escaped;
  escaped.reserve(value.size() * 2);

  for (const auto ch : value) {
    switch (ch) {
      case '\\':
      case '^':
      case '$':
      case '.':
      case '|':
      case '?':
      case '*':
      case '+':
      case '(':
      case ')':
      case '[':
      case ']':
      case '{':
      case '}':
        escaped.push_back('\\');
        break;
      default:
        break;
    }

    escaped.push_back(ch);
  }

  return escaped;
}

std::string UnescapeJsonString(const std::string& value) {
  std::string result;
  result.reserve(value.size());

  bool escaping = false;
  for (const auto ch : value) {
    if (!escaping) {
      if (ch == '\\') {
        escaping = true;
      } else {
        result.push_back(ch);
      }
      continue;
    }

    switch (ch) {
      case '\\':
        result.push_back('\\');
        break;
      case '"':
        result.push_back('"');
        break;
      case 'n':
        result.push_back('\n');
        break;
      case 'r':
        result.push_back('\r');
        break;
      case 't':
        result.push_back('\t');
        break;
      default:
        result.push_back(ch);
        break;
    }

    escaping = false;
  }

  if (escaping) {
    result.push_back('\\');
  }

  return result;
}

std::optional<std::wstring> ExtractPayloadString(const std::wstring& json, const std::string& key) {
  if (json.size() > kMaxCommandPayloadChars) {
    return std::nullopt;
  }

  const auto utf8Json = WideToUtf8(json);
  const std::regex pattern("\\\"" + EscapeRegex(key) + "\\\"\\s*:\\s*\\\"((?:\\\\\\\\.|[^\\\"])*)\\\"");
  std::smatch match;
  if (std::regex_search(utf8Json, match, pattern)) {
    return Utf8ToWide(UnescapeJsonString(match[1].str()));
  }

  return std::nullopt;
}

std::optional<std::uint32_t> ExtractPayloadUInt32(const std::wstring& json, const std::string& key) {
  if (json.size() > kMaxCommandPayloadChars) {
    return std::nullopt;
  }

  const auto utf8Json = WideToUtf8(json);
  const std::regex pattern("\\\"" + EscapeRegex(key) + "\\\"\\s*:\\s*(\\d+)");
  std::smatch match;
  if (std::regex_search(utf8Json, match, pattern)) {
    try {
      return static_cast<std::uint32_t>(std::stoul(match[1].str()));
    } catch (...) {
      return std::nullopt;
    }
  }

  return std::nullopt;
}

std::optional<bool> ExtractPayloadBool(const std::wstring& json, const std::string& key) {
  if (json.size() > kMaxCommandPayloadChars) {
    return std::nullopt;
  }

  const auto utf8Json = WideToUtf8(json);
  const std::regex pattern("\\\"" + EscapeRegex(key) + "\\\"\\s*:\\s*(true|false|1|0)");
  std::smatch match;
  if (!std::regex_search(utf8Json, match, pattern)) {
    return std::nullopt;
  }

  const auto token = match[1].str();
  return token == "true" || token == "1";
}

std::vector<std::wstring> ExtractPayloadStringArray(const std::wstring& json, const std::string& key) {
  std::vector<std::wstring> values;
  if (json.size() > kMaxCommandPayloadChars) {
    return values;
  }

  const auto utf8Json = WideToUtf8(json);
  const std::regex arrayPattern("\\\"" + EscapeRegex(key) + "\\\"\\s*:\\s*\\[(.*?)\\]");
  std::smatch arrayMatch;
  if (!std::regex_search(utf8Json, arrayMatch, arrayPattern)) {
    return values;
  }

  const std::regex itemPattern("\\\"((?:\\\\\\\\.|[^\\\"])*)\\\"");
  auto begin = std::sregex_iterator(arrayMatch[1].first, arrayMatch[1].second, itemPattern);
  const auto end = std::sregex_iterator();
  for (auto iterator = begin; iterator != end; ++iterator) {
    values.push_back(Utf8ToWide(UnescapeJsonString((*iterator)[1].str())));
  }

  return values;
}

bool PayloadContainsKey(const std::wstring& json, const std::string& key) {
  if (json.size() > kMaxCommandPayloadChars) {
    return false;
  }

  const auto utf8Json = WideToUtf8(json);
  const std::regex pattern("\\\"" + EscapeRegex(key) + "\\\"\\s*:");
  return std::regex_search(utf8Json, pattern);
}

std::wstring ToLowerCopy(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return value;
}

bool PathStartsWith(std::wstring path, std::wstring prefix) {
  if (path.empty() || prefix.empty()) {
    return false;
  }

  path = ToLowerCopy(path);
  prefix = ToLowerCopy(prefix);
  if (!prefix.empty() && prefix.back() != L'\\') {
    prefix += L'\\';
  }

  return path == prefix.substr(0, prefix.size() - 1) || path.starts_with(prefix);
}

std::filesystem::path ResolveRuntimeRoot(const AgentConfig& config) {
  auto runtimeRoot = config.runtimeDatabasePath.parent_path();
  if (runtimeRoot.empty()) {
    runtimeRoot = config.runtimeDatabasePath;
  }
  return runtimeRoot;
}

std::filesystem::path ResolveInstallRootForConfig(const AgentConfig& config) {
  if (!config.installRootPath.empty()) {
    return config.installRootPath;
  }

  const auto runtimeRoot = ResolveRuntimeRoot(config);
  return runtimeRoot.has_parent_path() ? runtimeRoot.parent_path() : std::filesystem::current_path();
}

std::filesystem::path ResolveLocalApprovalRuntimeRoot() {
  const auto programData = ReadEnvironmentVariable(L"PROGRAMDATA");
  if (!programData.empty()) {
    return std::filesystem::path(programData) / L"FenrirAgent" / L"runtime";
  }

  return std::filesystem::current_path() / L"runtime";
}

std::filesystem::path ResolveLocalApprovalQueuePath() {
  return ResolveLocalApprovalRuntimeRoot() / kLocalApprovalQueueFileName;
}

std::filesystem::path ResolveLocalApprovalLedgerPath() {
  return ResolveLocalApprovalRuntimeRoot() / kLocalApprovalLedgerFileName;
}

std::filesystem::path ResolveLocalAdminBaselinePath(const AgentConfig& config) {
  return ResolveRuntimeRoot(config) / kLocalAdminBaselineFileName;
}

std::wstring BuildJsonStringArray(const std::vector<std::wstring>& values) {
  std::wstring result = L"[";
  for (std::size_t index = 0; index < values.size(); ++index) {
    if (index != 0) {
      result += L",";
    }
    result += L"\\\"" + Utf8ToWide(EscapeJsonString(values[index])) + L"\\\"";
  }
  result += L"]";
  return result;
}

std::wstring BuildLocalAdminMembersJson(const std::vector<LocalAdminMember>& members) {
  std::wstring result = L"[";
  for (std::size_t index = 0; index < members.size(); ++index) {
    if (index != 0) {
      result += L",";
    }

    result += L"{\\\"accountName\\\":\\\"" + Utf8ToWide(EscapeJsonString(members[index].accountName)) +
              L"\\\",\\\"sid\\\":\\\"" + Utf8ToWide(EscapeJsonString(members[index].sid)) + L"\\\"}";
  }
  result += L"]";
  return result;
}

std::wstring BuildClassifiedLocalAdminMembersJson(const std::vector<ClassifiedLocalAdminMember>& members) {
  std::wstring result = L"[";
  for (std::size_t index = 0; index < members.size(); ++index) {
    if (index != 0) {
      result += L",";
    }

    const auto& item = members[index];
    result += L"{\\\"accountName\\\":\\\"" + Utf8ToWide(EscapeJsonString(item.member.accountName)) +
              L"\\\",\\\"sid\\\":\\\"" + Utf8ToWide(EscapeJsonString(item.member.sid)) + L"\\\",\\\"memberClass\\\":\\\"" +
              Utf8ToWide(EscapeJsonString(item.memberClass)) + L"\\\",\\\"protected\\\":" +
              (item.protectedMember ? std::wstring(L"true") : std::wstring(L"false")) + L",\\\"managedCandidate\\\":" +
              (item.managedCandidate ? std::wstring(L"true") : std::wstring(L"false")) + L"}";
  }
  result += L"]";
  return result;
}

/* ... existing unchanged content omitted here intentionally in this generated replacement ... */

void AgentService::DrainNetworkTelemetry() {
  if (!networkIsolationManager_) {
    return;
  }

  const auto telemetry = networkIsolationManager_->DrainTelemetry();
  if (telemetry.empty()) {
    return;
  }

  RuntimeDatabase runtimeDatabase(config_.runtimeDatabasePath);
  DestinationRuntimeStore destinationStore(config_.runtimeDatabasePath);
  destinationStore.SavePolicy(policy_);
  const auto destinationPolicy = ProjectDestinationPolicy(policy_);
  DestinationVerdictEngine verdictEngine(config_.runtimeDatabasePath);

  bool isolationAttempted = false;

  for (const auto& record : telemetry) {
    if (realtimeProtectionBroker_) {
      if (const auto behaviorEvent = BuildBehaviorEventFromNetworkTelemetry(record, state_.deviceId);
          behaviorEvent.has_value()) {
        realtimeProtectionBroker_->ObserveBehaviorEvent(*behaviorEvent);
      }
    }

    const auto remoteAddress = ExtractPayloadString(record.payloadJson, "remoteAddress").value_or(L"");
    if (remoteAddress.empty()) {
      continue;
    }

    auto processImagePath = ExtractPayloadString(record.payloadJson, "processImagePath").value_or(L"");
    if (processImagePath.empty()) {
      processImagePath = ExtractPayloadString(record.payloadJson, "appId").value_or(L"");
    }

    const auto processImageLower = ToLowerCopy(processImagePath);

    DestinationContext context{};
    context.indicatorType = ThreatIndicatorType::Ip;
    context.originalIndicator = remoteAddress;
    context.normalizedIndicator = NormalizeDestinationIndicator(ThreatIndicatorType::Ip, remoteAddress);
    context.host = ExtractPayloadString(record.payloadJson, "remoteHost").value_or(L"");
    if (context.host.empty()) {
      context.host = remoteAddress;
    }
    context.source = record.source.empty() ? L"network-wfp" : record.source;
    context.sourceApplication = processImagePath;
    context.parentApplication = ExtractPayloadString(record.payloadJson, "parentProcessImagePath").value_or(L"");
    context.userName = ExtractPayloadString(record.payloadJson, "userSid").value_or(L"");
    context.browserFamily = processImageLower.find(L"chrome.exe") != std::wstring::npos
                                ? L"chrome"
                                : (processImageLower.find(L"msedge.exe") != std::wstring::npos
                                       ? L"edge"
                                       : (processImageLower.find(L"firefox.exe") != std::wstring::npos ? L"firefox" : L""));
    context.deliveryVector = record.eventType;
    context.observedAt = record.occurredAt;
    context.browserInitiated = !context.browserFamily.empty();
    context.emailOriginated = processImageLower.find(L"outlook.exe") != std::wstring::npos ||
                              processImageLower.find(L"thunderbird.exe") != std::wstring::npos;
    context.attachmentOriginated = false;
    context.offlineMode = lastControlPlaneSyncFailed_;

    const auto verdict = verdictEngine.Evaluate(context, destinationPolicy);
    const auto evidence = verdictEngine.BuildEvidenceRecord(context, destinationPolicy, verdict, policy_.policyId,
                                                            policy_.revision);
    const auto intelRecord = BuildDestinationIntelligenceRecord(context, verdict, evidence,
                                                                destinationPolicy.destinationCacheTtlMinutes);
    destinationStore.UpsertIntelligenceRecord(intelRecord);

    QueueTelemetryEvent(BuildDestinationEventType(verdict), L"destination-protection",
                        BuildDestinationEventSummary(verdict),
                        BuildDestinationTelemetryPayload(context, verdict, evidence));

    if (verdict.action == DestinationAction::Warn || verdict.action == DestinationAction::Block ||
        verdict.action == DestinationAction::DegradedAllow) {
      runtimeDatabase.RecordScanHistory(BuildDestinationScanHistoryRecord(context, verdict, evidence));
    }

    if (verdict.action == DestinationAction::Block) {
      if (!policy_.networkObserveOnly && !isolationAttempted) {
        isolationAttempted = true;
        std::wstring isolationError;
        const auto enforced = networkIsolationManager_->IsolationActive() ||
                              networkIsolationManager_->ApplyIsolation(true, &isolationError);
        QueueTelemetryEvent(enforced ? L"network.destination.reputation.enforced"
                                     : L"network.destination.reputation.enforcement_failed",
                            L"network-wfp",
                            enforced ? L"Fenrir enforced host isolation after a blocked destination verdict."
                                     : L"Fenrir attempted destination-based isolation enforcement but the WFP action failed.",
                            std::wstring(L"{\"remoteAddress\":\"") + Utf8ToWide(EscapeJsonString(remoteAddress)) +
                                L"\",\"action\":\"" + DestinationActionToString(verdict.action) +
                                L"\",\"category\":\"" + DestinationThreatCategoryToString(verdict.category) +
                                L"\",\"confidence\":" + std::to_wstring(verdict.confidence) +
                                L",\"error\":\"" + Utf8ToWide(EscapeJsonString(isolationError)) + L"\"}");
      } else if (policy_.networkObserveOnly) {
        QueueTelemetryEvent(L"network.destination.reputation.observe_only", L"network-wfp",
                            L"Fenrir observed a blocked destination verdict but skipped isolation because policy is observe-only.",
                            std::wstring(L"{\"remoteAddress\":\"") + Utf8ToWide(EscapeJsonString(remoteAddress)) +
                                L"\",\"action\":\"" + DestinationActionToString(verdict.action) +
                                L"\",\"category\":\"" + DestinationThreatCategoryToString(verdict.category) +
                                L"\",\"confidence\":" + std::to_wstring(verdict.confidence) + L"}");
      }
    }
  }

  QueueTelemetryRecords(telemetry);
}

void AgentService::QueueCycleTelemetry(const int cycle) {
  QueueTelemetryEvent(L"service.sync.cycle", L"agent-service",
                      L"The endpoint is starting a scheduled sync cycle.",
                      BuildCyclePayload(cycle, std::wstring(L"\\\"hostname\\\":\\\"") + state_.hostname + L"\\\""));

  DrainProcessTelemetry();
  DrainNetworkTelemetry();
  if (!processEtwSensor_ || !processEtwSensor_->IsActive()) {
    const auto processInventory = CollectProcessInventory();
    const auto processSnapshotRecords = BuildProcessSnapshotTelemetry(processInventory, 4);
    if (processSnapshotRecords.empty()) {
      QueueTelemetryEvent(L"process.snapshot.empty", L"process-snapshot",
                          L"No process snapshot records were collected during this cycle.", BuildCyclePayload(cycle));
    } else {
      QueueTelemetryRecords(processSnapshotRecords);
    }
    QueueTelemetryRecords(processDeltaTracker_.CollectDeltaTelemetry(processInventory));
  }

  const auto serviceSnapshotRecords = CollectServiceSnapshotTelemetry(4);
  if (serviceSnapshotRecords.empty()) {
    QueueTelemetryEvent(L"service.snapshot.empty", L"service-snapshot",
                        L"No service snapshot records were collected during this cycle.", BuildCyclePayload(cycle));
  } else {
    QueueTelemetryRecords(serviceSnapshotRecords);
  }

  const auto fileInventory = CollectFileInventory(BuildMonitoredRoots());
  const auto fileSnapshotRecords = BuildRecentFileTelemetry(fileInventory, 4);
  if (fileSnapshotRecords.empty()) {
    QueueTelemetryEvent(L"file.snapshot.empty", L"file-snapshot",
                        L"No recent files were found in the monitored folders during this cycle.",
                        BuildCyclePayload(cycle));
  } else {
    QueueTelemetryRecords(fileSnapshotRecords);
  }
  QueueTelemetryRecords(fileDeltaTracker_.CollectDeltaTelemetry(fileInventory));

  if (networkIsolationManager_ && networkIsolationManager_->EngineReady()) {
    QueueTelemetryRecords(networkIsolationManager_->CollectConnectionSnapshotTelemetry(6));
  }

  QueuePatchTelemetry(cycle);
}

void AgentService::QueueTelemetryEvent(const std::wstring& eventType, const std::wstring& source,
                                       const std::wstring& summary, const std::wstring& payloadJson) {
  pendingTelemetry_.push_back(TelemetryRecord{
      .eventId = GenerateGuidString(),
      .eventType = eventType,
      .source = source,
      .summary = summary,
      .occurredAt = CurrentUtcTimestamp(),
      .payloadJson = payloadJson});

  EnforceTelemetryQueueBudget(&pendingTelemetry_);
  telemetryQueueStore_->SavePending(pendingTelemetry_);
}

void AgentService::QueueTelemetryRecords(const std::vector<TelemetryRecord>& records) {
  pendingTelemetry_.insert(pendingTelemetry_.end(), records.begin(), records.end());
  EnforceTelemetryQueueBudget(&pendingTelemetry_);
  telemetryQueueStore_->SavePending(pendingTelemetry_);
}

void AgentService::FlushTelemetryQueue() {
  if (state_.deviceId.empty() || pendingTelemetry_.empty()) {
    lastTelemetryFlushFailed_ = false;
    return;
  }

  lastTelemetryFlushFailed_ = false;
  bool attemptedRecovery = false;
  while (!pendingTelemetry_.empty() && !ShouldStop()) {
    const auto batchSize =
        std::min<std::size_t>(pendingTelemetry_.size(), static_cast<std::size_t>(config_.telemetryBatchSize));
    const std::vector<TelemetryRecord> batch(pendingTelemetry_.begin(), pendingTelemetry_.begin() + batchSize);

    try {
      const auto result = controlPlaneClient_->SendTelemetryBatch(state_, batch);
      pendingTelemetry_.erase(pendingTelemetry_.begin(), pendingTelemetry_.begin() + batchSize);
      telemetryQueueStore_->SavePending(pendingTelemetry_);
      std::wcout << L"Uploaded " << result.accepted << L" telemetry event(s) at " << result.receivedAt
                 << L". Backend now stores " << result.totalStored << L" event(s)." << std::endl;
    } catch (const std::exception& error) {
      if (!attemptedRecovery && RecoverDeviceIdentity(error, L"telemetry upload")) {
        attemptedRecovery = true;
        continue;
      }

      lastTelemetryFlushFailed_ = true;
      std::wcerr << L"Telemetry upload failed, leaving " << pendingTelemetry_.size()
                 << L" event(s) queued locally: " << Utf8ToWide(error.what()) << std::endl;
      break;
    }
  }
}

ScanVerdict AgentService::EvaluateEvent(const EventEnvelope& event) const {
  if (realtimeProtectionBroker_) {
    return realtimeProtectionBroker_->EvaluateEvent(event);
  }

  return ScanVerdict{};
}

}  // namespace antivirus::agent
