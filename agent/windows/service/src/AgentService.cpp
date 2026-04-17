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
#include "ContextAwareness.h"
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

void EnforceTelemetryQueueBudget(std::vector<TelemetryRecord>* pendingTelemetry) {
  if (pendingTelemetry == nullptr) {
    return;
  }

  constexpr std::size_t kMaxQueuedTelemetry = 5000;
  if (pendingTelemetry->size() <= kMaxQueuedTelemetry) {
    return;
  }

  pendingTelemetry->erase(pendingTelemetry->begin(),
                          pendingTelemetry->begin() + (pendingTelemetry->size() - kMaxQueuedTelemetry));
}

std::optional<EventEnvelope> BuildBehaviorEventFromNetworkTelemetry(const TelemetryRecord& record,
                                                                    const std::wstring& deviceId) {
  const auto targetPath = ExtractPayloadString(record.payloadJson, "path").value_or(L"");
  const auto processImagePath = ExtractPayloadString(record.payloadJson, "processImagePath").value_or(L"");
  const auto remoteAddress = ExtractPayloadString(record.payloadJson, "remoteAddress").value_or(L"");
  if (remoteAddress.empty() && processImagePath.empty() && targetPath.empty()) {
    return std::nullopt;
  }

  return EventEnvelope{
      .kind = EventKind::NetworkConnect,
      .deviceId = deviceId,
      .correlationId = GenerateGuidString(),
      .targetPath = remoteAddress,
      .sha256 = {},
      .process = ProcessContext{
          .imagePath = processImagePath,
          .commandLine = ExtractPayloadString(record.payloadJson, "commandLine").value_or(L""),
          .parentImagePath = ExtractPayloadString(record.payloadJson, "parentProcessImagePath").value_or(L""),
          .userSid = ExtractPayloadString(record.payloadJson, "userSid").value_or(L""),
          .signer = {}},
      .occurredAt = std::chrono::system_clock::now()};
}

}  // namespace

AgentService::AgentService() = default;

AgentService::~AgentService() {
  if (localControlChannel_) {
    localControlChannel_->Stop();
    localControlChannel_.reset();
  }
  if (pamRequestEvent_ != nullptr) {
    CloseHandle(pamRequestEvent_);
    pamRequestEvent_ = nullptr;
  }
  if (stopEvent_ != nullptr) {
    CloseHandle(stopEvent_);
    stopEvent_ = nullptr;
  }
}

int AgentService::Run(const AgentRunMode mode) {
  try {
    if (stopEvent_ == nullptr) {
      stopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
      if (stopEvent_ == nullptr) {
        throw std::runtime_error("Unable to create the agent stop event");
      }
    }

    if (pamRequestEvent_ == nullptr) {
      pamRequestEvent_ = CreateEventW(nullptr, TRUE, FALSE, kPamRequestEventName);
    }

    config_ = LoadAgentConfig();
    stateStore_ = std::make_unique<LocalStateStore>(config_.runtimeDatabasePath, config_.stateFilePath);
    controlPlaneClient_ = std::make_unique<ControlPlaneClient>(config_.controlPlaneBaseUrl);
    commandJournalStore_ = std::make_unique<CommandJournalStore>(config_.runtimeDatabasePath);
    telemetryQueueStore_ = std::make_unique<TelemetryQueueStore>(config_.runtimeDatabasePath, config_.telemetryQueuePath);
    realtimeProtectionBroker_ = std::make_unique<RealtimeProtectionBroker>(config_);
    processEtwSensor_ = std::make_unique<ProcessEtwSensor>(config_);
    networkIsolationManager_ = std::make_unique<NetworkIsolationManager>(config_);

    LoadLocalPolicyCache();
    realtimeProtectionBroker_->SetPolicy(policy_);
    realtimeProtectionBroker_->SetDeviceId(state_.deviceId);
    processEtwSensor_->SetDeviceId(state_.deviceId);
    networkIsolationManager_->SetDeviceId(state_.deviceId);

    realtimeProtectionBroker_->Start();
    processEtwSensor_->Start();
    networkIsolationManager_->Start();

    QueueEndpointStatusTelemetry();
    if (state_.isolated) {
      std::wstring isolationError;
      if (!networkIsolationManager_->ApplyIsolation(true, &isolationError)) {
        state_.isolated = false;
        QueueTelemetryEvent(L"network.isolation.resume.failed", L"network-wfp",
                            L"The endpoint could not restore WFP-backed isolation during startup.",
                            std::wstring(L"{\"errorMessage\":\"") +
                                Utf8ToWide(EscapeJsonString(isolationError.empty() ? L"Unknown startup isolation failure"
                                                                                  : isolationError)) +
                                L"\"}");
      }
    }

    StartTelemetrySpool();
    StartCommandLoop();
    QueueTelemetryEvent(L"service.started", L"agent-service", L"The endpoint agent boot sequence started.",
                        L"{\"phase\":\"bootstrap\"}");

    RunSyncLoop(mode);
    DrainProcessTelemetry();
    DrainRealtimeProtectionTelemetry();
    DrainNetworkTelemetry();

    if (networkIsolationManager_) {
      networkIsolationManager_->Stop();
    }
    if (processEtwSensor_) {
      processEtwSensor_->Stop();
    }
    if (realtimeProtectionBroker_) {
      realtimeProtectionBroker_->Stop();
    }

    PersistState();

    if (mode == AgentRunMode::Console) {
      std::wcout << L"Agent service is running." << std::endl;
      PrintStatus();
    }
    return 0;
  } catch (const std::exception& error) {
    std::wcerr << L"Agent service failed to initialize: " << Utf8ToWide(error.what()) << std::endl;
    return 1;
  }
}

void AgentService::RequestStop() {
  if (stopEvent_ != nullptr) {
    SetEvent(stopEvent_);
  }
  if (localControlChannel_) {
    localControlChannel_->Stop();
  }
}

std::wstring AgentService::BuildCyclePayload(const int cycle, const std::wstring& extraFields) {
  std::wstring payload = L"{\"cycle\":";
  payload += std::to_wstring(cycle);
  if (!extraFields.empty()) {
    payload += L",";
    payload += extraFields;
  }
  payload += L"}";
  return payload;
}

std::vector<std::filesystem::path> AgentService::BuildMonitoredRoots() const {
  std::vector<std::filesystem::path> roots;

  const auto userProfile = ReadEnvironmentVariable(L"USERPROFILE");
  if (!userProfile.empty()) {
    roots.emplace_back(std::filesystem::path(userProfile) / L"Downloads");
    roots.emplace_back(std::filesystem::path(userProfile) / L"Desktop");
    roots.emplace_back(std::filesystem::path(userProfile) / L"Documents");
  }

  roots.emplace_back(LR"(C:\Users\Public\Downloads)");
  return roots;
}

void AgentService::RunSyncLoop(const AgentRunMode mode) {
  const auto configuredIterations = std::max(config_.syncIterations, 1);
  int cycle = 1;

  while (!ShouldStop()) {
    ProcessPamRequests();
    QueueCycleTelemetry(cycle);
    DrainProcessTelemetry();
    DrainRealtimeProtectionTelemetry();
    DrainNetworkTelemetry();
    SyncWithControlPlane(cycle);
    DrainProcessTelemetry();
    DrainRealtimeProtectionTelemetry();
    DrainNetworkTelemetry();
    PollAndExecuteCommands(cycle);
    DrainProcessTelemetry();
    DrainRealtimeProtectionTelemetry();
    DrainNetworkTelemetry();
    FlushTelemetryQueue();
    PublishHeartbeat(cycle);
    DrainProcessTelemetry();
    DrainRealtimeProtectionTelemetry();
    DrainNetworkTelemetry();
    FlushTelemetryQueue();
    PersistState();

    if (mode == AgentRunMode::Console && cycle >= configuredIterations) {
      break;
    }

    ++cycle;
    if (!WaitForNextCycle(mode, cycle)) {
      break;
    }
  }
}

bool AgentService::WaitForNextCycle(const AgentRunMode mode, const int nextCycle) {
  if (ShouldStop()) {
    return false;
  }

  if (mode == AgentRunMode::Console) {
    std::wcout << L"Sleeping " << config_.syncIntervalSeconds << L" seconds before sync cycle " << nextCycle
               << std::endl;
  }

  const auto waitMilliseconds = static_cast<DWORD>(std::max(config_.syncIntervalSeconds, 1) * 1000);
  return WaitForSingleObject(stopEvent_, waitMilliseconds) != WAIT_OBJECT_0;
}

bool AgentService::ShouldStop() const {
  return stopEvent_ != nullptr && WaitForSingleObject(stopEvent_, 0) == WAIT_OBJECT_0;
}

void AgentService::ProcessPamRequests() {
  if (pamRequestEvent_ == nullptr || WaitForSingleObject(pamRequestEvent_, 0) != WAIT_OBJECT_0) {
    return;
  }

  ResetEvent(pamRequestEvent_);
  QueueTelemetryEvent(L"pam.request.observed", L"local-control",
                      L"A privileged access request was observed and queued for later handling.",
                      std::wstring(L"{\"requestPath\":\"") +
                          Utf8ToWide(EscapeJsonString(GetPamRequestPath().wstring())) + L"\"}");
}

std::filesystem::path AgentService::GetPamRequestPath() const {
  return ResolveRuntimeRoot(config_) / kPamRequestFileName;
}

std::vector<std::filesystem::path> AgentService::GetPamRequestPaths() const {
  return {GetPamRequestPath()};
}

std::filesystem::path AgentService::GetPamAuditJournalPath() const {
  return ResolveRuntimeRoot(config_) / kPamAuditFileName;
}

void AgentService::SyncWithControlPlane(const int cycle) {
  bool attemptedRecovery = false;

  for (;;) {
    try {
      EnsureEnrollment();
      RefreshPolicy(cycle);
      lastControlPlaneSyncFailed_ = false;
      return;
    } catch (const std::exception& error) {
      if (!attemptedRecovery && RecoverDeviceIdentity(error, L"control-plane sync")) {
        attemptedRecovery = true;
        continue;
      }

      lastControlPlaneSyncFailed_ = true;
      QueueTelemetryEvent(L"control-plane.sync.failed", L"control-plane-client",
                          L"The agent could not complete a control-plane sync and is using cached state.",
                          BuildCyclePayload(cycle));
      std::wcerr << L"Control-plane sync failed, continuing with cached state: " << Utf8ToWide(error.what())
                 << std::endl;
      return;
    }
  }
}

void AgentService::EnsureEnrollment() {
  if (!state_.deviceId.empty()) {
    return;
  }

  const auto enrollment = controlPlaneClient_->Enroll(state_);
  state_.deviceId = enrollment.deviceId;
  state_.commandChannelUrl = enrollment.commandChannelUrl;
  state_.lastEnrollmentAt = enrollment.issuedAt;
  state_.policy = enrollment.policy;
  policy_ = enrollment.policy;

  if (realtimeProtectionBroker_) {
    realtimeProtectionBroker_->SetDeviceId(state_.deviceId);
    realtimeProtectionBroker_->SetPolicy(policy_);
  }
  if (processEtwSensor_) {
    processEtwSensor_->SetDeviceId(state_.deviceId);
  }
  if (networkIsolationManager_) {
    networkIsolationManager_->SetDeviceId(state_.deviceId);
  }

  QueueTelemetryEvent(L"device.enrolled", L"control-plane-client",
                      L"The endpoint enrolled with the control plane.",
                      std::wstring(L"{\"deviceId\":\"") + state_.deviceId + L"\"}");
}

void AgentService::ResetEnrollmentState() {
  state_.deviceId.clear();
  state_.commandChannelUrl.clear();
  state_.lastEnrollmentAt.clear();
  state_.lastHeartbeatAt.clear();
  state_.lastPolicySyncAt.clear();
  if (realtimeProtectionBroker_) {
    realtimeProtectionBroker_->SetDeviceId(L"");
  }
  if (processEtwSensor_) {
    processEtwSensor_->SetDeviceId(L"");
  }
  if (networkIsolationManager_) {
    networkIsolationManager_->SetDeviceId(L"");
  }
}

bool AgentService::RecoverDeviceIdentity(const std::exception& error, const std::wstring& operationName) {
  const auto* rejectedError = dynamic_cast<const DeviceIdentityRejectedError*>(&error);
  if (rejectedError == nullptr) {
    return false;
  }

  const auto previousDeviceId = state_.deviceId;
  QueueTelemetryEvent(L"device.identity.rejected", L"control-plane-client",
                      L"The control plane rejected the cached device identity and the agent is re-enrolling.",
                      std::wstring(L"{\"previousDeviceId\":\"") + previousDeviceId + L"\",\"operation\":\"" +
                          Utf8ToWide(EscapeJsonString(operationName)) + L"\"}");

  ResetEnrollmentState();

  try {
    EnsureEnrollment();
    PersistState();
    return true;
  } catch (const std::exception& recoveryError) {
    std::wcerr << L"Re-enrollment after identity rejection failed: " << Utf8ToWide(recoveryError.what()) << std::endl;
    return false;
  }
}

void AgentService::RefreshPolicy(const int cycle) {
  if (state_.deviceId.empty()) {
    return;
  }

  const auto policyCheckIn = controlPlaneClient_->CheckInPolicy(state_);
  state_.lastPolicySyncAt = policyCheckIn.retrievedAt;
  state_.policy = policyCheckIn.policy;
  policy_ = policyCheckIn.policy;
  if (realtimeProtectionBroker_) {
    realtimeProtectionBroker_->SetPolicy(policy_);
  }

  QueueTelemetryEvent(L"policy.checked-in", L"control-plane-client",
                      policyCheckIn.changed ? L"The endpoint retrieved a newer effective policy."
                                            : L"The endpoint confirmed that policy is already current.",
                      BuildCyclePayload(cycle, std::wstring(L"\"revision\":\"") + policy_.revision + L"\""));
}

void AgentService::PollAndExecuteCommands(const int cycle) {
  if (state_.deviceId.empty()) {
    return;
  }

  bool attemptedRecovery = false;

  for (;;) {
    try {
      const auto pollResult = controlPlaneClient_->PollPendingCommands(state_);
      if (pollResult.items.empty()) {
        return;
      }

      QueueTelemetryEvent(L"commands.polled", L"command-executor",
                          L"The endpoint pulled pending response actions from the control plane.",
                          BuildCyclePayload(cycle, std::wstring(L"\"count\":") + std::to_wstring(pollResult.items.size())));

      for (const auto& command : pollResult.items) {
        if (commandJournalStore_) {
          commandJournalStore_->RecordPolled(command);
        }

        try {
          const auto resultJson = ExecuteCommand(command);
          controlPlaneClient_->CompleteCommand(state_, command.commandId, L"completed", resultJson);
          if (commandJournalStore_) {
            commandJournalStore_->RecordCompleted(command, resultJson);
          }
        } catch (const std::exception& error) {
          const auto errorMessage = Utf8ToWide(error.what());
          const auto failureJson = std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"error\":\"" +
                                   Utf8ToWide(EscapeJsonString(errorMessage)) + L"\"}";
          try {
            controlPlaneClient_->CompleteCommand(state_, command.commandId, L"failed", failureJson);
          } catch (...) {
          }
          if (commandJournalStore_) {
            commandJournalStore_->RecordFailed(command, failureJson, errorMessage);
          }
          QueueTelemetryEvent(L"command.failed", L"command-executor",
                              std::wstring(L"Remote command failed: ") + command.type + L".", failureJson);
        }
      }

      return;
    } catch (const std::exception& error) {
      if (!attemptedRecovery && RecoverDeviceIdentity(error, L"command polling")) {
        attemptedRecovery = true;
        continue;
      }

      QueueTelemetryEvent(L"command.poll.failed", L"command-executor",
                          L"The endpoint could not retrieve pending commands from the control plane.",
                          BuildCyclePayload(cycle));
      std::wcerr << L"Command polling failed: " << Utf8ToWide(error.what()) << std::endl;
      return;
    }
  }
}

std::wstring AgentService::ExecuteCommand(const RemoteCommand& command) {
  if (command.type == L"device.isolate") {
    return ExecuteIsolationCommand(command, true);
  }
  if (command.type == L"device.release") {
    return ExecuteIsolationCommand(command, false);
  }
  if (command.type == L"scan.targeted") {
    return ExecuteTargetedScan(command);
  }
  if (command.type == L"quarantine.restore") {
    return ExecuteQuarantineMutation(command, true);
  }
  if (command.type == L"quarantine.delete") {
    return ExecuteQuarantineMutation(command, false);
  }
  if (command.type == L"update.apply") {
    return ExecuteUpdateCommand(command, false);
  }
  if (command.type == L"update.rollback") {
    return ExecuteUpdateCommand(command, true);
  }
  if (command.type == L"agent.repair") {
    return ExecuteRepairCommand(command);
  }
  if (command.type == L"patch.windows.security") {
    return ExecutePatchCommand(command, true, false, false);
  }
  if (command.type == L"patch.software") {
    return ExecutePatchCommand(command, false, true, false);
  }
  if (command.type == L"patch.cycle") {
    return ExecutePatchCommand(command, true, true, true);
  }
  if (command.type == L"support.bundle") {
    return ExecuteSupportBundleCommand(command, false);
  }
  if (command.type == L"support.bundle.sanitized") {
    return ExecuteSupportBundleCommand(command, true);
  }
  if (command.type == L"storage.maintenance") {
    return ExecuteStorageMaintenanceCommand(command);
  }
  if (command.type == L"threatintel.lookup") {
    return ExecuteThreatIntelLookupCommand(command);
  }
  if (command.type == L"threatintel.pack.ingest") {
    return ExecuteThreatIntelPackIngestCommand(command);
  }
  if (command.type == L"breakglass.enable") {
    return ExecuteBreakGlassCommand(command, true);
  }
  if (command.type == L"breakglass.disable") {
    return ExecuteBreakGlassCommand(command, false);
  }
  if (command.type == L"local.approval.request") {
    return ExecuteLocalApprovalCommand(command);
  }
  if (command.type == L"local.approval.list") {
    return ExecuteLocalApprovalListCommand(command);
  }
  if (command.type == L"localadmin.audit") {
    return ExecuteLocalAdminAuditCommand(command);
  }
  if (command.type == L"localadmin.reduce") {
    return ExecuteLocalAdminReductionCommand(command, true);
  }
  if (command.type == L"localadmin.rollback") {
    return ExecuteLocalAdminRollbackCommand(command);
  }
  if (command.type == L"householdrole.audit") {
    return ExecuteHouseholdRoleAuditCommand(command);
  }
  if (command.type == L"householdrole.propagate") {
    return ExecuteHouseholdRolePropagationCommand(command, true);
  }
  if (command.type == L"process.terminate") {
    return ExecuteProcessTerminationCommand(command, false);
  }
  if (command.type == L"process.tree.terminate") {
    return ExecuteProcessTerminationCommand(command, true);
  }
  if (command.type == L"persistence.cleanup") {
    return ExecutePersistenceCleanupCommand(command);
  }
  if (command.type == L"remediate.path") {
    return ExecutePathRemediationCommand(command);
  }
  if (command.type == L"script.run") {
    return ExecuteScriptCommand(command);
  }
  if (command.type == L"software.search") {
    return ExecuteSoftwareCommand(command, false, true);
  }
  if (command.type == L"software.update") {
    return ExecuteSoftwareCommand(command, false, false);
  }
  if (command.type == L"software.uninstall") {
    return ExecuteSoftwareCommand(command, true, false);
  }
  if (command.type == L"software.block") {
    return ExecuteSoftwareBlockCommand(command);
  }

  throw std::runtime_error("Unsupported remote command type");
}

std::wstring AgentService::ExecuteTargetedScan(const RemoteCommand& command) {
  if (command.targetPath.empty()) {
    throw std::runtime_error("scan.targeted command is missing targetPath");
  }

  const std::filesystem::path targetPath(command.targetPath);
  std::error_code error;
  if (!std::filesystem::exists(targetPath, error)) {
    throw std::runtime_error("Targeted scan path does not exist");
  }

  auto findings = ScanTargets({targetPath}, policy_);
  QuarantineStore quarantineStore(config_.quarantineRootPath, config_.runtimeDatabasePath);
  EvidenceRecorder evidenceRecorder(config_.evidenceRootPath, config_.runtimeDatabasePath);

  for (auto& finding : findings) {
    if (finding.verdict.disposition == VerdictDisposition::Quarantine) {
      const auto quarantineResult = quarantineStore.QuarantineFile(finding);
      if (quarantineResult.success) {
        finding.remediationStatus = RemediationStatus::Quarantined;
        finding.quarantineRecordId = quarantineResult.recordId;
        finding.quarantinedPath = quarantineResult.quarantinedPath;
      } else {
        finding.remediationStatus = RemediationStatus::Failed;
        finding.remediationError =
            quarantineResult.errorMessage.empty() ? L"Unable to move the file into quarantine" : quarantineResult.errorMessage;
      }
    }

    const auto evidenceResult = evidenceRecorder.RecordScanFinding(finding, policy_, L"agent-service");
    finding.evidenceRecordId = evidenceResult.recordId;
  }

  const auto summaryTelemetry = BuildScanSummaryTelemetry(1, findings.size(), policy_, L"agent-service");
  QueueTelemetryEvent(summaryTelemetry.eventType, summaryTelemetry.source, summaryTelemetry.summary,
                      summaryTelemetry.payloadJson);
  for (const auto& finding : findings) {
    const auto record = BuildScanFindingTelemetry(finding, L"agent-service");
    QueueTelemetryEvent(record.eventType, record.source, record.summary, record.payloadJson);
  }

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"targetPath\":\"" +
         Utf8ToWide(EscapeJsonString(command.targetPath)) + L"\",\"findingCount\":" + std::to_wstring(findings.size()) +
         L"}";
}

std::wstring AgentService::ExecuteIsolationCommand(const RemoteCommand& command, const bool isolate) {
  if (!networkIsolationManager_) {
    throw std::runtime_error("The WFP isolation manager is not available");
  }

  std::wstring errorMessage;
  if (!networkIsolationManager_->ApplyIsolation(isolate, &errorMessage)) {
    throw std::runtime_error(WideToUtf8(errorMessage.empty() ? L"The WFP isolation manager rejected the requested state"
                                                            : errorMessage));
  }

  state_.isolated = networkIsolationManager_->IsolationActive();

  QueueTelemetryEvent(isolate ? L"device.isolated" : L"device.released", L"command-executor",
                      isolate ? L"The endpoint entered WFP-backed host isolation after a remote action."
                              : L"The endpoint left WFP-backed host isolation after a remote action.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"wfpApplied\":true}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"isolated\":" +
         (state_.isolated ? L"true" : L"false") + L",\"wfpApplied\":true}";
}

std::wstring AgentService::ExecuteQuarantineMutation(const RemoteCommand& command, const bool restore) {
  if (command.recordId.empty()) {
    throw std::runtime_error("Quarantine command is missing recordId");
  }

  QuarantineStore quarantineStore(config_.quarantineRootPath, config_.runtimeDatabasePath);
  const auto result = restore ? quarantineStore.RestoreFile(command.recordId) : quarantineStore.DeleteRecord(command.recordId);
  if (!result.success) {
    throw std::runtime_error(WideToUtf8(result.errorMessage.empty() ? L"Quarantine operation failed" : result.errorMessage));
  }

  QueueTelemetryEvent(restore ? L"quarantine.restored" : L"quarantine.deleted", L"command-executor",
                      restore ? L"A quarantined item was restored after a remote action."
                              : L"A quarantined item was deleted after a remote action.",
                      std::wstring(L"{\"recordId\":\"") + result.recordId + L"\"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"recordId\":\"" + result.recordId +
         L"\",\"action\":\"" + (restore ? std::wstring(L"restore") : std::wstring(L"delete")) + L"\"}";
}

std::wstring AgentService::ExecuteUpdateCommand(const RemoteCommand& command, const bool rollback) {
  const auto installRoot = ResolveInstallRootForConfig(config_);
  UpdaterService updater(config_, installRoot);
  const auto result = rollback ? updater.RollbackTransaction(command.recordId)
                               : updater.ApplyPackage(command.targetPath, UpdateApplyMode::InService);
  if (!result.success) {
    throw std::runtime_error(WideToUtf8(result.errorMessage.empty() ? L"Update operation failed" : result.errorMessage));
  }

  QueueTelemetryEvent(rollback ? L"update.rolled_back" : L"update.applied", L"command-executor",
                      rollback ? L"The endpoint rolled back a staged platform update."
                               : L"The endpoint applied a staged platform or engine update.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"transactionId\":\"" +
                          result.transactionId + L"\",\"restartRequired\":" +
                          (result.restartRequired ? std::wstring(L"true") : std::wstring(L"false")) + L"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"transactionId\":\"" + result.transactionId +
         L"\",\"packageId\":\"" + result.packageId + L"\",\"status\":\"" + result.status + L"\"}";
}

std::wstring AgentService::ExecuteRepairCommand(const RemoteCommand& command) {
  const auto installRoot = ResolveInstallRootForConfig(config_);
  HardeningManager hardeningManager(config_, installRoot);
  std::wstring errorMessage;
  const auto applied = hardeningManager.ApplyPostInstallHardening(ReadEnvironmentVariable(L"ANTIVIRUS_UNINSTALL_TOKEN"),
                                                                  &errorMessage);
  lastHardeningCheckFailed_ = !applied;

  QueueTelemetryEvent(applied ? L"agent.repaired" : L"agent.repair.failed", L"command-executor",
                      applied ? L"The endpoint reapplied service hardening and coexistence checks."
                              : L"The endpoint could not fully reapply service hardening.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"hardeningApplied\":" +
                          (applied ? std::wstring(L"true") : std::wstring(L"false")) + L"}");

  if (!applied) {
    throw std::runtime_error(WideToUtf8(errorMessage.empty() ? L"Endpoint repair failed" : errorMessage));
  }

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"hardeningApplied\":true}";
}

std::wstring AgentService::ExecutePatchCommand(const RemoteCommand& command, const bool installWindows,
                                               const bool installSoftware, const bool runCycle) {
  PatchOrchestrator orchestrator(config_);
  PatchExecutionResult result{};

  if (runCycle) {
    result = orchestrator.RunPatchCycle();
  } else if (installWindows) {
    result = orchestrator.InstallWindowsUpdates(true);
  } else if (installSoftware) {
    const auto softwareId = command.recordId.empty() ? command.targetPath : command.recordId;
    result = orchestrator.UpdateSoftware(softwareId, false);
  } else {
    throw std::runtime_error("Patch command did not specify a supported action");
  }

  QueueTelemetryEvent(result.success ? L"patch.executed" : L"patch.failed", L"patch-orchestrator",
                      result.success ? L"The endpoint completed a patch orchestration action."
                                     : L"The endpoint patch orchestration action failed.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"status\":\"" + result.status +
                          L"\",\"targetId\":\"" + result.targetId + L"\",\"provider\":\"" + result.provider + L"\"}");

  if (!result.success) {
    throw std::runtime_error(WideToUtf8(result.detailJson.empty() ? L"Patch orchestration failed" : result.detailJson));
  }

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"status\":\"" + result.status +
         L"\",\"targetId\":\"" + result.targetId + L"\"}";
}

std::wstring AgentService::ExecuteSupportBundleCommand(const RemoteCommand& command, const bool sanitized) {
  const auto result = ExportSupportBundle(config_, state_, policy_, sanitized);
  if (!result.success) {
    throw std::runtime_error(WideToUtf8(result.errorMessage.empty() ? L"Support bundle export failed" : result.errorMessage));
  }

  QueueTelemetryEvent(L"support.bundle.exported", L"support-bundle",
                      sanitized ? L"The endpoint exported a sanitized support bundle."
                                : L"The endpoint exported a full support bundle.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"manifestPath\":\"" +
                          Utf8ToWide(EscapeJsonString(result.manifestPath.wstring())) + L"\"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"manifestPath\":\"" +
         Utf8ToWide(EscapeJsonString(result.manifestPath.wstring())) + L"\",\"copiedFileCount\":" +
         std::to_wstring(result.copiedFileCount) + L"}";
}

std::wstring AgentService::ExecuteStorageMaintenanceCommand(const RemoteCommand& command) {
  const auto result = RunStorageMaintenance(config_);
  if (!result.success) {
    throw std::runtime_error(WideToUtf8(result.errorMessage.empty() ? L"Storage maintenance failed" : result.errorMessage));
  }

  QueueTelemetryEvent(L"storage.maintenance.completed", L"storage-maintenance",
                      L"The endpoint completed local protection storage maintenance.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"deletedEntries\":" +
                          std::to_wstring(result.deletedEntries) + L",\"reclaimedBytes\":" +
                          std::to_wstring(result.reclaimedBytes) + L"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"deletedEntries\":" +
         std::to_wstring(result.deletedEntries) + L",\"reclaimedBytes\":" + std::to_wstring(result.reclaimedBytes) + L"}";
}

std::wstring AgentService::ExecuteThreatIntelLookupCommand(const RemoteCommand& command) {
  const auto indicator =
      !command.targetPath.empty() ? command.targetPath : ExtractPayloadString(command.payloadJson, "indicator").value_or(L"");
  if (indicator.empty()) {
    throw std::runtime_error("Threat intelligence lookup is missing an indicator");
  }

  const auto result = LookupDestinationReputation(indicator, config_.runtimeDatabasePath);
  QueueTelemetryEvent(L"threatintel.lookup.completed", L"threat-intelligence",
                      L"The endpoint completed a local threat intelligence lookup.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"indicator\":\"" +
                          Utf8ToWide(EscapeJsonString(indicator)) + L"\",\"lookupSucceeded\":" +
                          (result.lookupSucceeded ? std::wstring(L"true") : std::wstring(L"false")) + L"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"indicator\":\"" +
         Utf8ToWide(EscapeJsonString(indicator)) + L"\",\"summary\":\"" +
         Utf8ToWide(EscapeJsonString(DescribeReputationLookup(result))) + L"\"}";
}

std::wstring AgentService::ExecuteThreatIntelPackIngestCommand(const RemoteCommand& command) {
  const auto packPath = std::filesystem::path(command.targetPath);
  if (packPath.empty()) {
    throw std::runtime_error("Threat intelligence pack ingest is missing targetPath");
  }

  const auto result = IngestSignedThreatIntelPack(packPath, config_.runtimeDatabasePath);
  if (!result.success) {
    throw std::runtime_error(WideToUtf8(result.errorMessage.empty() ? L"Threat intelligence ingest failed"
                                                                   : result.errorMessage));
  }

  QueueTelemetryEvent(L"threatintel.pack.ingested", L"threat-intelligence",
                      L"The endpoint ingested a signed threat intelligence pack.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"recordsLoaded\":" +
                          std::to_wstring(result.recordsLoaded) + L"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"recordsLoaded\":" +
         std::to_wstring(result.recordsLoaded) + L",\"recordsRejected\":" + std::to_wstring(result.recordsRejected) + L"}";
}

std::wstring AgentService::ExecuteBreakGlassCommand(const RemoteCommand& command, const bool enable) {
  QueueTelemetryEvent(enable ? L"breakglass.enabled" : L"breakglass.disabled", L"local-security",
                      enable ? L"The endpoint recorded a temporary break-glass enable request."
                             : L"The endpoint recorded a break-glass disable request.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\"}");
  throw std::runtime_error("Break-glass execution is not wired into the current service build");
}

std::wstring AgentService::ExecuteLocalApprovalCommand(const RemoteCommand&) {
  throw std::runtime_error("Local approval execution is not wired into the current service build");
}

std::wstring AgentService::ExecuteLocalApprovalListCommand(const RemoteCommand&) {
  throw std::runtime_error("Local approval listing is not wired into the current service build");
}

std::wstring AgentService::ExecuteLocalAdminAuditCommand(const RemoteCommand&) {
  throw std::runtime_error("Local admin audit execution is not wired into the current service build");
}

std::wstring AgentService::ExecuteLocalAdminReductionCommand(const RemoteCommand&, const bool) {
  throw std::runtime_error("Local admin reduction execution is not wired into the current service build");
}

std::wstring AgentService::ExecuteLocalAdminRollbackCommand(const RemoteCommand&) {
  throw std::runtime_error("Local admin rollback execution is not wired into the current service build");
}

std::wstring AgentService::ExecuteHouseholdRoleAuditCommand(const RemoteCommand&) {
  throw std::runtime_error("Household role audit execution is not wired into the current service build");
}

std::wstring AgentService::ExecuteHouseholdRolePropagationCommand(const RemoteCommand&, const bool) {
  throw std::runtime_error("Household role propagation execution is not wired into the current service build");
}

std::wstring AgentService::ExecuteProcessTerminationCommand(const RemoteCommand& command, const bool includeChildren) {
  if (command.targetPath.empty()) {
    throw std::runtime_error("Process termination command is missing targetPath");
  }

  RemediationEngine remediationEngine(config_);
  const auto result = remediationEngine.TerminateProcessesForPath(command.targetPath, includeChildren);
  QueueTelemetryEvent(includeChildren ? L"process.tree.terminated" : L"process.terminated", L"command-executor",
                      includeChildren ? L"The endpoint terminated a malicious process tree."
                                      : L"The endpoint terminated a malicious process.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"targetPath\":\"" +
                          Utf8ToWide(EscapeJsonString(command.targetPath)) + L"\",\"terminatedCount\":" +
                          std::to_wstring(result.processesTerminated) + L"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"terminatedCount\":" +
         std::to_wstring(result.processesTerminated) + L"}";
}

std::wstring AgentService::ExecutePersistenceCleanupCommand(const RemoteCommand& command) {
  if (command.targetPath.empty()) {
    throw std::runtime_error("Persistence cleanup command is missing targetPath");
  }

  RemediationEngine remediationEngine(config_);
  const auto result = remediationEngine.CleanupPersistenceForPath(command.targetPath);
  QueueTelemetryEvent(L"persistence.cleaned", L"command-executor",
                      L"The endpoint removed startup persistence tied to a malicious artifact.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"registryValuesRemoved\":" +
                          std::to_wstring(result.registryValuesRemoved) + L"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"registryValuesRemoved\":" +
         std::to_wstring(result.registryValuesRemoved) + L",\"startupArtifactsRemoved\":" +
         std::to_wstring(result.startupArtifactsRemoved) + L"}";
}

std::wstring AgentService::ExecutePathRemediationCommand(const RemoteCommand& command) {
  if (command.targetPath.empty()) {
    throw std::runtime_error("remediate.path command is missing targetPath");
  }

  RemediationEngine remediationEngine(config_);
  const auto result = remediationEngine.RemediatePath(command.targetPath, policy_);
  QueueTelemetryEvent(L"remediation.completed", L"command-executor",
                      L"The endpoint executed a full remediation workflow for a malicious artifact.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"quarantineApplied\":" +
                          (result.quarantineApplied ? std::wstring(L"true") : std::wstring(L"false")) + L"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"quarantineApplied\":" +
         (result.quarantineApplied ? std::wstring(L"true") : std::wstring(L"false")) + L",\"quarantineRecordId\":\"" +
         result.quarantineRecordId + L"\",\"evidenceRecordId\":\"" + result.evidenceRecordId + L"\"}";
}

std::wstring AgentService::ExecuteScriptCommand(const RemoteCommand&) {
  throw std::runtime_error("Script execution is not enabled in the current service build");
}

void AgentService::PublishHeartbeat(const int cycle) {
  if (state_.deviceId.empty()) {
    return;
  }

  const auto wfpIsolationActive = networkIsolationManager_ && networkIsolationManager_->IsolationActive();
  const auto wfpUnavailable =
      policy_.networkContainmentEnabled && (!networkIsolationManager_ || !networkIsolationManager_->EngineReady());

  state_.isolated = wfpIsolationActive;
  state_.healthState = wfpIsolationActive
                           ? L"isolated"
                           : ((wfpUnavailable || lastControlPlaneSyncFailed_ || lastTelemetryFlushFailed_ ||
                               lastHardeningCheckFailed_)
                                  ? L"degraded"
                                  : L"healthy");

  bool attemptedRecovery = false;
  for (;;) {
    try {
      const auto heartbeat = controlPlaneClient_->SendHeartbeat(state_);
      state_.lastHeartbeatAt = heartbeat.receivedAt;
      lastControlPlaneSyncFailed_ = false;
      QueueTelemetryEvent(L"device.heartbeat", L"control-plane-client",
                          L"The endpoint heartbeat was acknowledged by the control plane.",
                          BuildCyclePayload(cycle, std::wstring(L"\"commandsPending\":") +
                                                       std::to_wstring(heartbeat.commandsPending)));
      return;
    } catch (const std::exception& error) {
      if (!attemptedRecovery && RecoverDeviceIdentity(error, L"heartbeat")) {
        attemptedRecovery = true;
        continue;
      }

      lastControlPlaneSyncFailed_ = true;
      QueueTelemetryEvent(L"device.heartbeat.failed", L"control-plane-client",
                          L"The endpoint heartbeat could not be delivered to the control plane.",
                          BuildCyclePayload(cycle));
      std::wcerr << L"Heartbeat failed, keeping the previous health state cached: " << Utf8ToWide(error.what())
                 << std::endl;
      return;
    }
  }
}

void AgentService::PersistState() {
  if (!stateStore_ || !telemetryQueueStore_) {
    return;
  }

  stateStore_->Save(state_);
  telemetryQueueStore_->SavePending(pendingTelemetry_);
}

void AgentService::LoadLocalPolicyCache() {
  state_ = stateStore_ ? stateStore_->LoadOrCreate() : AgentState{};
  state_.agentVersion = config_.agentVersion;
  state_.platformVersion = config_.platformVersion;
  if (state_.policy.policyId.empty()) {
    state_.policy = CreateDefaultPolicySnapshot();
  }
  policy_ = state_.policy;
  pendingTelemetry_ = telemetryQueueStore_ ? telemetryQueueStore_->LoadPending() : std::vector<TelemetryRecord>{};
}

void AgentService::StartTelemetrySpool() const {
  const auto deviceLabel = state_.deviceId.empty() ? std::wstring(L"(not yet enrolled)") : state_.deviceId;
  std::wcout << L"Telemetry spool ready for device " << deviceLabel << L" with " << pendingTelemetry_.size()
             << L" queued event(s)." << std::endl;
}

void AgentService::StartCommandLoop() const {
  if (!state_.commandChannelUrl.empty()) {
    std::wcout << L"Command polling configured at " << state_.commandChannelUrl << std::endl;
  } else {
    std::wcout << L"Command polling has not been assigned yet." << std::endl;
  }

  std::wcout << L"Real-time protection broker targeting port " << config_.realtimeProtectionPortName << std::endl;
  std::wcout << L"ETW process telemetry sensor " << (processEtwSensor_ && processEtwSensor_->IsActive() ? L"active"
                                                                                                          : L"fallback")
             << std::endl;
  std::wcout << L"WFP isolation manager "
             << (networkIsolationManager_ ? (networkIsolationManager_->EngineReady() ? L"ready" : L"unavailable")
                                          : L"not configured")
             << std::endl;
}

void AgentService::PrintStatus() const {
  const auto deviceLabel = state_.deviceId.empty() ? std::wstring(L"(pending)") : state_.deviceId;
  const auto lastPolicySync = state_.lastPolicySyncAt.empty() ? std::wstring(L"(never)") : state_.lastPolicySyncAt;
  const auto lastHeartbeat = state_.lastHeartbeatAt.empty() ? std::wstring(L"(never)") : state_.lastHeartbeatAt;

  std::wcout << L"Hostname: " << state_.hostname << std::endl;
  std::wcout << L"Device ID: " << deviceLabel << std::endl;
  std::wcout << L"Policy: " << policy_.policyName << L" (" << policy_.revision << L")" << std::endl;
  std::wcout << L"Health state: " << state_.healthState << std::endl;
  std::wcout << L"Last policy sync: " << lastPolicySync << std::endl;
  std::wcout << L"Last heartbeat: " << lastHeartbeat << std::endl;
  std::wcout << L"Pending telemetry events: " << pendingTelemetry_.size() << std::endl;
}

void AgentService::QueueEndpointStatusTelemetry() {
  const auto installRoot = ResolveInstallRootForConfig(config_);
  HardeningManager hardeningManager(config_, installRoot);
  const auto hardeningStatus = hardeningManager.QueryStatus();
  const auto protectedServiceExpected = hardeningStatus.elamDriverPresent || !config_.elamDriverPath.empty();
  lastHardeningCheckFailed_ =
      !(hardeningStatus.registryConfigured && hardeningStatus.runtimePathsProtected &&
        (!protectedServiceExpected || hardeningStatus.launchProtectedConfigured));

  QueueTelemetryEvent(lastHardeningCheckFailed_ ? L"tamper.protection.degraded" : L"tamper.protection.ready",
                      L"hardening-manager", hardeningStatus.statusMessage,
                      std::wstring(L"{\"registryConfigured\":") +
                          (hardeningStatus.registryConfigured ? std::wstring(L"true") : std::wstring(L"false")) +
                          L",\"runtimePathsProtected\":" +
                          (hardeningStatus.runtimePathsProtected ? std::wstring(L"true") : std::wstring(L"false")) +
                          L"}");

  const WscCoexistenceManager wscManager;
  QueueTelemetryEvent(L"wsc.coexistence.state", L"wsc-coexistence",
                      L"Windows Security Center coexistence data was collected.",
                      WscCoexistenceManager::ToJson(wscManager.CaptureSnapshot()));
}

void AgentService::QueueDeviceInventoryTelemetry(const int cycle) {
  const auto snapshot = CollectDeviceInventorySnapshot();
  QueueTelemetryEvent(L"device.inventory.snapshot", L"device-inventory",
                      L"The endpoint collected a local device inventory snapshot.",
                      BuildCyclePayload(cycle, std::wstring(L"\"inventory\":") + BuildDeviceInventoryPayload(snapshot)));
}

void AgentService::QueuePatchTelemetry(const int cycle) {
  PatchOrchestrator orchestrator(config_);
  const auto snapshot = orchestrator.LoadSnapshot(20, 50, 20, 50);
  QueueTelemetryEvent(L"patch.snapshot", L"patch-orchestrator",
                      L"The endpoint collected a local patch posture snapshot.",
                      BuildCyclePayload(cycle, std::wstring(L"\"windowsUpdates\":") +
                                                   std::to_wstring(snapshot.windowsUpdates.size()) +
                                                   L",\"software\":" + std::to_wstring(snapshot.software.size()) +
                                                   L",\"history\":" + std::to_wstring(snapshot.history.size())));
}

void AgentService::DrainProcessTelemetry() {
  if (!processEtwSensor_) {
    return;
  }

  const auto telemetry = processEtwSensor_->DrainTelemetry();
  if (!telemetry.empty()) {
    QueueTelemetryRecords(telemetry);
  }
}

void AgentService::DrainRealtimeProtectionTelemetry() {
  if (!realtimeProtectionBroker_) {
    return;
  }

  const auto telemetry = realtimeProtectionBroker_->DrainTelemetry();
  if (!telemetry.empty()) {
    QueueTelemetryRecords(telemetry);
  }
}

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

    const auto parentImagePath = ExtractPayloadString(record.payloadJson, "parentProcessImagePath").value_or(L"");
    const auto browserOrigin =
        BuildContentOriginContext(std::filesystem::path(remoteAddress), processImagePath, parentImagePath,
                                  ExtractPayloadString(record.payloadJson, "commandLine").value_or(L""),
                                  record.occurredAt);

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
    context.parentApplication = parentImagePath;
    context.userName = ExtractPayloadString(record.payloadJson, "userSid").value_or(L"");
    context.browserFamily = browserOrigin.browserFamily;
    context.deliveryVector = record.eventType;
    context.navigationType = browserOrigin.navigationType;
    context.sourceDomain = browserOrigin.sourceDomain;
    context.sourceUrl = browserOrigin.sourceUrl;
    context.observedAt = record.occurredAt;
    context.browserInitiated = browserOrigin.browserOriginated;
    context.emailOriginated = browserOrigin.emailOriginated;
    context.attachmentOriginated = browserOrigin.attachmentOriginated;
    context.redirectNavigation = browserOrigin.navigationType == L"redirect_navigation";
    context.downloadInitiated = browserOrigin.downloadOriginated;
    context.browserLaunchedFile = browserOrigin.browserLaunchedFile;
    context.browserExtensionHost = browserOrigin.browserExtensionHost;
    context.abusivePermissionPrompt = browserOrigin.abusivePermissionPrompt;
    context.suspiciousBrowserChildProcess = browserOrigin.suspiciousChildProcess;
    context.fakeUpdatePattern = browserOrigin.fakeUpdatePattern;
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

  if (cycle == 1 || cycle % 10 == 0) {
    QueueDeviceInventoryTelemetry(cycle);
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

std::wstring AgentService::ExecuteSoftwareCommand(const RemoteCommand& command, const bool uninstall,
                                                  const bool searchOnly) {
  if (uninstall) {
    throw std::runtime_error("Software uninstall is not wired into the current service build");
  }

  const auto softwareId =
      !command.recordId.empty() ? command.recordId : ExtractPayloadString(command.payloadJson, "softwareId").value_or(command.targetPath);
  if (softwareId.empty()) {
    throw std::runtime_error("Software command is missing a software identifier");
  }

  PatchOrchestrator orchestrator(config_);
  const auto result = orchestrator.UpdateSoftware(softwareId, searchOnly);
  QueueTelemetryEvent(searchOnly ? L"software.search.completed" : L"software.update.completed", L"patch-orchestrator",
                      searchOnly ? L"The endpoint refreshed software update metadata for a managed application."
                                 : L"The endpoint executed a software update action for a managed application.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"softwareId\":\"" +
                          Utf8ToWide(EscapeJsonString(softwareId)) + L"\",\"status\":\"" + result.status + L"\"}");

  if (!result.success && !searchOnly) {
    throw std::runtime_error(WideToUtf8(result.detailJson.empty() ? L"Software update failed" : result.detailJson));
  }

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"softwareId\":\"" +
         Utf8ToWide(EscapeJsonString(softwareId)) + L"\",\"status\":\"" + result.status + L"\"}";
}

std::wstring AgentService::ExecuteSoftwareBlockCommand(const RemoteCommand& command) {
  const auto softwareId =
      !command.recordId.empty() ? command.recordId : ExtractPayloadString(command.payloadJson, "softwareId").value_or(L"");
  if (softwareId.empty()) {
    throw std::runtime_error("Software block command is missing a software identifier");
  }

  RuntimeDatabase runtimeDatabase(config_.runtimeDatabasePath);
  runtimeDatabase.UpsertBlockedSoftwareRule(BlockedSoftwareRule{
      .softwareId = softwareId,
      .displayName = ExtractPayloadString(command.payloadJson, "displayName").value_or(L""),
      .installLocation = command.targetPath,
      .executableNames = ExtractPayloadStringArray(command.payloadJson, "executableNames"),
      .blockedAt = CurrentUtcTimestamp()});

  EnforceBlockedSoftware();

  QueueTelemetryEvent(L"software.blocked", L"policy-enforcement",
                      L"The endpoint recorded a blocked software rule.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"softwareId\":\"" +
                          Utf8ToWide(EscapeJsonString(softwareId)) + L"\"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"softwareId\":\"" +
         Utf8ToWide(EscapeJsonString(softwareId)) + L"\"}";
}

void AgentService::EnforceBlockedSoftware() {
  RuntimeDatabase runtimeDatabase(config_.runtimeDatabasePath);
  const auto rules = runtimeDatabase.ListBlockedSoftwareRules(200);
  if (rules.empty()) {
    return;
  }

  const auto processInventory = CollectProcessInventory();
  for (const auto& process : processInventory) {
    const auto processName = ToLowerCopy(process.imageName);
    for (const auto& rule : rules) {
      bool matched = false;
      for (const auto& executableName : rule.executableNames) {
        if (!executableName.empty() && processName == ToLowerCopy(executableName)) {
          matched = true;
          break;
        }
      }

      if (!matched) {
        continue;
      }

      RemediationEngine remediationEngine(config_);
      const auto result = remediationEngine.TerminateProcessByPid(process.processId, true);
      QueueTelemetryEvent(L"software.block.enforced", L"policy-enforcement",
                          L"The endpoint terminated a running process due to a blocked software rule.",
                          std::wstring(L"{\"softwareId\":\"") + Utf8ToWide(EscapeJsonString(rule.softwareId)) +
                              L"\",\"processId\":" + std::to_wstring(process.processId) + L",\"terminatedCount\":" +
                              std::to_wstring(result.processesTerminated) + L"}");
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
