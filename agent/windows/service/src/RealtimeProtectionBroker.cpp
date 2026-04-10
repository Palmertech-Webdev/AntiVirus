#include "RealtimeProtectionBroker.h"

#include <Windows.h>

#include <algorithm>
#include <cwctype>
#include <filesystem>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include "CryptoUtils.h"
#include "EvidenceRecorder.h"
#include "QuarantineStore.h"
#include "StringUtils.h"

namespace antivirus::agent {
namespace {

struct FilterMessageHeader {
  ULONG replyLength;
  ULONGLONG messageId;
};

struct FilterReplyHeader {
  LONG status;
  ULONGLONG messageId;
};

using FilterConnectCommunicationPortFn =
    HRESULT(WINAPI*)(LPCWSTR, DWORD, LPVOID, WORD, LPSECURITY_ATTRIBUTES, HANDLE*);
using FilterGetMessageFn = HRESULT(WINAPI*)(HANDLE, FilterMessageHeader*, DWORD, LPOVERLAPPED);
using FilterReplyMessageFn = HRESULT(WINAPI*)(HANDLE, FilterReplyHeader*, DWORD);

struct FilterApi {
  HMODULE module{nullptr};
  FilterConnectCommunicationPortFn connect{nullptr};
  FilterGetMessageFn getMessage{nullptr};
  FilterReplyMessageFn replyMessage{nullptr};

  bool Load() {
    module = LoadLibraryW(L"fltlib.dll");
    if (module == nullptr) {
      return false;
    }

    connect = reinterpret_cast<FilterConnectCommunicationPortFn>(
        GetProcAddress(module, "FilterConnectCommunicationPort"));
    getMessage = reinterpret_cast<FilterGetMessageFn>(GetProcAddress(module, "FilterGetMessage"));
    replyMessage = reinterpret_cast<FilterReplyMessageFn>(GetProcAddress(module, "FilterReplyMessage"));
    if (connect == nullptr || getMessage == nullptr || replyMessage == nullptr) {
      FreeLibrary(module);
      module = nullptr;
      connect = nullptr;
      getMessage = nullptr;
      replyMessage = nullptr;
      return false;
    }

    return true;
  }

  ~FilterApi() {
    if (module != nullptr) {
      FreeLibrary(module);
      module = nullptr;
    }
  }
};

#pragma pack(push, 8)
struct BrokerPortMessage {
  FilterMessageHeader header;
  RealtimeFileScanRequest request;
};

struct BrokerPortReply {
  FilterReplyHeader header;
  RealtimeFileScanReply reply;
};
#pragma pack(pop)

constexpr DWORD kBrokerMessageWaitMilliseconds = 1'000;

std::wstring ToLowerCopy(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return value;
}

std::wstring SafeCopy(const wchar_t* value) {
  if (value == nullptr) {
    return {};
  }

  return std::wstring(value);
}

template <std::size_t N>
void CopyWideField(wchar_t (&destination)[N], const std::wstring& source) {
  std::fill(std::begin(destination), std::end(destination), L'\0');
  if constexpr (N == 0) {
    return;
  }

  wcsncpy_s(destination, N, source.c_str(), _TRUNCATE);
}

std::wstring OperationToString(const RealtimeFileOperation operation) {
  switch (operation) {
    case ANTIVIRUS_REALTIME_FILE_OPERATION_CREATE:
      return L"create";
    case ANTIVIRUS_REALTIME_FILE_OPERATION_OPEN:
      return L"open";
    case ANTIVIRUS_REALTIME_FILE_OPERATION_WRITE:
      return L"write";
    case ANTIVIRUS_REALTIME_FILE_OPERATION_EXECUTE:
      return L"execute";
    default:
      return L"unknown";
  }
}

EventKind OperationToEventKind(const RealtimeFileOperation operation) {
  switch (operation) {
    case ANTIVIRUS_REALTIME_FILE_OPERATION_CREATE:
      return EventKind::FileCreate;
    case ANTIVIRUS_REALTIME_FILE_OPERATION_OPEN:
      return EventKind::FileOpen;
    case ANTIVIRUS_REALTIME_FILE_OPERATION_WRITE:
      return EventKind::FileWrite;
    case ANTIVIRUS_REALTIME_FILE_OPERATION_EXECUTE:
    default:
      return EventKind::FileExecute;
  }
}

bool PathContains(const std::wstring& path, const std::wstring& pattern) {
  return path.find(pattern) != std::wstring::npos;
}

bool IsUserControlledPath(const std::filesystem::path& path) {
  const auto lower = ToLowerCopy(path.wstring());
  return PathContains(lower, L"\\users\\") || PathContains(lower, L"\\programdata\\") ||
         PathContains(lower, L"\\temp\\") || PathContains(lower, L"\\downloads\\") ||
         PathContains(lower, L"\\desktop\\") || PathContains(lower, L"\\appdata\\local\\temp\\") ||
         PathContains(lower, L"\\start menu\\programs\\startup\\");
}

bool IsExecutableExtension(const std::wstring& extension) {
  return extension == L".exe" || extension == L".dll" || extension == L".scr" || extension == L".msi";
}

bool IsScriptExtension(const std::wstring& extension) {
  return extension == L".ps1" || extension == L".bat" || extension == L".cmd" || extension == L".js" ||
         extension == L".jse" || extension == L".vbs" || extension == L".vbe" || extension == L".hta";
}

bool IsContainerExtension(const std::wstring& extension) {
  return extension == L".lnk" || extension == L".iso" || extension == L".zip";
}

ScanFinding BuildRealtimeFinding(const std::filesystem::path& path, const RealtimeFileOperation operation,
                                 const PolicySnapshot& policy,
                                 const std::vector<std::filesystem::path>& excludedPaths) {
  const auto extension = ToLowerCopy(path.extension().wstring());
  const auto userControlledPath = IsUserControlledPath(path);

  ScanFinding finding{
      .path = path,
      .sizeBytes = 0,
      .sha256 = {},
      .verdict = {},
      .remediationStatus = RemediationStatus::None,
      .quarantinedPath = {},
      .quarantineRecordId = {},
      .evidenceRecordId = {},
      .remediationError = {}};

  std::error_code error;
  if (std::filesystem::exists(path, error)) {
    error.clear();
    if (std::filesystem::is_regular_file(path, error)) {
      finding.sizeBytes = std::filesystem::file_size(path, error);
      try {
        finding.sha256 = ComputeFileSha256(path);
      } catch (...) {
        finding.verdict.reasons.push_back(
            {L"HASH_UNAVAILABLE", L"SHA-256 computation failed during real-time evaluation."});
      }

      if (const auto analyzedFinding = ScanFile(path, policy, excludedPaths); analyzedFinding.has_value()) {
        auto promoted = *analyzedFinding;
        if (promoted.verdict.disposition == VerdictDisposition::Block &&
            operation == ANTIVIRUS_REALTIME_FILE_OPERATION_EXECUTE) {
          promoted.verdict.confidence = std::min<std::uint32_t>(99, promoted.verdict.confidence + 5);
        }
        return promoted;
      }
    }
  }

  if (IsExecutableExtension(extension) && userControlledPath) {
    finding.verdict.disposition = policy.quarantineOnMalicious ? VerdictDisposition::Quarantine : VerdictDisposition::Block;
    finding.verdict.confidence = operation == ANTIVIRUS_REALTIME_FILE_OPERATION_EXECUTE ? 96 : 92;
    finding.verdict.tacticId = L"TA0002";
    finding.verdict.techniqueId = L"T1204.002";
    finding.verdict.reasons.push_back(
        {L"REALTIME_EXECUTABLE_DROP", L"Executable content in a user-controlled path was intercepted by real-time protection."});
    return finding;
  }

  if (extension == L".hta") {
    finding.verdict.disposition = policy.quarantineOnMalicious ? VerdictDisposition::Quarantine : VerdictDisposition::Block;
    finding.verdict.confidence = 95;
    finding.verdict.tacticId = L"TA0005";
    finding.verdict.techniqueId = L"T1218.005";
    finding.verdict.reasons.push_back(
        {L"REALTIME_HTA_CONTENT", L"HTA content was intercepted before it could be proxied through MSHTA."});
    return finding;
  }

  if (IsScriptExtension(extension)) {
    finding.verdict.disposition = VerdictDisposition::Block;
    finding.verdict.confidence = operation == ANTIVIRUS_REALTIME_FILE_OPERATION_EXECUTE ? 93 : 86;
    finding.verdict.tacticId = L"TA0002";
    finding.verdict.techniqueId = extension == L".ps1" ? L"T1059.001" : L"T1059";
    finding.verdict.reasons.push_back(
        {L"REALTIME_SCRIPT_INTERCEPT", L"Script content was intercepted by real-time protection."});
    return finding;
  }

  if (IsContainerExtension(extension) && userControlledPath &&
      (operation == ANTIVIRUS_REALTIME_FILE_OPERATION_OPEN || operation == ANTIVIRUS_REALTIME_FILE_OPERATION_EXECUTE ||
       operation == ANTIVIRUS_REALTIME_FILE_OPERATION_CREATE)) {
    finding.verdict.disposition = VerdictDisposition::Block;
    finding.verdict.confidence = 74;
    finding.verdict.tacticId = L"TA0002";
    finding.verdict.techniqueId = extension == L".lnk" ? L"T1204.001" : L"T1204.002";
    finding.verdict.reasons.push_back(
        {L"REALTIME_CONTAINER_LURE", L"User-writable lure or archive content was intercepted before staging could continue."});
    return finding;
  }

  finding.verdict.disposition = VerdictDisposition::Allow;
  finding.verdict.confidence = 5;
  finding.verdict.reasons.push_back({L"REALTIME_ALLOW", L"No blocking rule matched the intercepted file event."});
  return finding;
}

TelemetryRecord BuildRealtimeProtectionTelemetry(const ScanFinding& finding, const std::wstring& source,
                                                 const std::wstring& deviceId, const std::wstring& correlationId,
                                                 const RealtimeFileOperation operation,
                                                 const RealtimeResponseAction action) {
  const auto actionValue = action == ANTIVIRUS_REALTIME_RESPONSE_ACTION_BLOCK ? L"block" : L"allow";
  const auto dispositionValue = VerdictDispositionToString(finding.verdict.disposition);
  const auto techniqueId = finding.verdict.techniqueId.empty() ? L"unknown" : finding.verdict.techniqueId;
  auto subject = finding.path.filename().wstring();
  if (subject.empty()) {
    subject = finding.path.wstring();
  }

  std::wstring summary = L"Real-time protection ";
  summary += actionValue;
  summary += L"ed ";
  summary += subject;
  summary += L" during ";
  summary += OperationToString(operation);
  summary += L".";

  std::wstring payload = L"{\"deviceId\":\"";
  payload += Utf8ToWide(EscapeJsonString(deviceId));
  payload += L"\",\"correlationId\":\"";
  payload += Utf8ToWide(EscapeJsonString(correlationId));
  payload += L"\",\"path\":\"";
  payload += Utf8ToWide(EscapeJsonString(finding.path.wstring()));
  payload += L"\",\"operation\":\"";
  payload += OperationToString(operation);
  payload += L"\",\"action\":\"";
  payload += actionValue;
  payload += L"\",\"disposition\":\"";
  payload += dispositionValue;
  payload += L"\",\"tacticId\":\"";
  payload += finding.verdict.tacticId;
  payload += L"\",\"techniqueId\":\"";
  payload += techniqueId;
  payload += L"\",\"sha256\":\"";
  payload += finding.sha256;
  payload += L"\",\"quarantineRecordId\":\"";
  payload += finding.quarantineRecordId;
  payload += L"\",\"evidenceRecordId\":\"";
  payload += finding.evidenceRecordId;
  payload += L"\",\"remediationStatus\":\"";
  payload += RemediationStatusToString(finding.remediationStatus);
  payload += L"\"}";

  return TelemetryRecord{
      .eventId = GenerateGuidString(),
      .eventType = L"realtime.protection.action",
      .source = source,
      .summary = summary,
      .occurredAt = CurrentUtcTimestamp(),
      .payloadJson = payload};
}

}  // namespace

RealtimeProtectionBroker::RealtimeProtectionBroker(AgentConfig config) : config_(std::move(config)) {
  stopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
}

RealtimeProtectionBroker::~RealtimeProtectionBroker() {
  Stop();
  if (stopEvent_ != nullptr) {
    CloseHandle(stopEvent_);
    stopEvent_ = nullptr;
  }
}

void RealtimeProtectionBroker::Start() {
  if (workerThread_ != nullptr || stopEvent_ == nullptr) {
    return;
  }

  ResetEvent(stopEvent_);
  workerThread_ = CreateThread(nullptr, 0, ThreadEntry, this, 0, nullptr);
  if (workerThread_ == nullptr) {
    QueueBrokerStateEvent(L"realtime.broker.failed",
                          L"The real-time protection broker could not start its communication worker.",
                          std::wstring(L"{\"portName\":\"") +
                              Utf8ToWide(EscapeJsonString(config_.realtimeProtectionPortName)) + L"\"}");
  }
}

void RealtimeProtectionBroker::Stop() {
  if (stopEvent_ != nullptr) {
    SetEvent(stopEvent_);
  }

  if (workerThread_ != nullptr) {
    WaitForSingleObject(workerThread_, 5'000);
    CloseHandle(workerThread_);
    workerThread_ = nullptr;
  }
}

void RealtimeProtectionBroker::SetPolicy(const PolicySnapshot& policy) {
  const std::scoped_lock lock(stateMutex_);
  policy_ = policy;
}

void RealtimeProtectionBroker::SetDeviceId(std::wstring deviceId) {
  const std::scoped_lock lock(stateMutex_);
  deviceId_ = std::move(deviceId);
}

RealtimeInspectionOutcome RealtimeProtectionBroker::InspectFile(const RealtimeFileScanRequest& request) {
  PolicySnapshot policy;
  std::wstring deviceId;
  {
    const std::scoped_lock lock(stateMutex_);
    policy = policy_;
    deviceId = deviceId_;
  }

  const auto operation = static_cast<RealtimeFileOperation>(request.operation);
  const std::filesystem::path targetPath(SafeCopy(request.path));

  if (!policy.realtimeProtectionEnabled) {
    return RealtimeInspectionOutcome{
        .action = ANTIVIRUS_REALTIME_RESPONSE_ACTION_ALLOW,
        .detection = false,
        .finding =
            ScanFinding{
                .path = targetPath,
                .verdict =
                    ScanVerdict{
                        .disposition = VerdictDisposition::Allow,
                        .confidence = 0,
                        .tacticId = L"",
                        .techniqueId = L"",
                        .reasons = {{L"REALTIME_DISABLED", L"Real-time protection is disabled by policy."}}}}};
  }

  auto finding = BuildRealtimeFinding(targetPath, operation, policy, config_.scanExcludedPaths);
  if (finding.verdict.disposition == VerdictDisposition::Allow) {
    return RealtimeInspectionOutcome{
        .action = ANTIVIRUS_REALTIME_RESPONSE_ACTION_ALLOW,
        .detection = false,
        .finding = std::move(finding)};
  }

  if (policy.quarantineOnMalicious && !finding.path.empty()) {
    QuarantineStore quarantineStore(config_.quarantineRootPath, config_.runtimeDatabasePath);
    const auto quarantineResult = quarantineStore.QuarantineFile(finding);
    if (quarantineResult.success) {
      finding.remediationStatus = RemediationStatus::Quarantined;
      finding.quarantineRecordId = quarantineResult.recordId;
      finding.quarantinedPath = quarantineResult.quarantinedPath;
    } else {
      finding.remediationStatus = RemediationStatus::Failed;
      finding.remediationError =
          quarantineResult.errorMessage.empty() ? L"Real-time quarantine failed during interception."
                                                : quarantineResult.errorMessage;
      finding.verdict.reasons.push_back({L"QUARANTINE_FAILED", finding.remediationError});
    }
  }

  EvidenceRecorder evidenceRecorder(config_.evidenceRootPath, config_.runtimeDatabasePath);
  const auto evidence = evidenceRecorder.RecordScanFinding(finding, policy, L"realtime-protection");
  finding.evidenceRecordId = evidence.recordId;

  QueueTelemetry(BuildScanFindingTelemetry(finding, L"realtime-protection"));
  QueueTelemetry(BuildRealtimeProtectionTelemetry(finding, L"realtime-protection", deviceId,
                                                 SafeCopy(request.correlationId), operation,
                                                 ANTIVIRUS_REALTIME_RESPONSE_ACTION_BLOCK));

  return RealtimeInspectionOutcome{
      .action = ANTIVIRUS_REALTIME_RESPONSE_ACTION_BLOCK,
      .detection = true,
      .finding = std::move(finding)};
}

ScanVerdict RealtimeProtectionBroker::EvaluateEvent(const EventEnvelope& event) {
  RealtimeFileScanRequest request{};
  request.protocolVersion = ANTIVIRUS_REALTIME_PROTOCOL_VERSION;
  request.requestSize = sizeof(request);
  request.requestId = 0;
  request.operation = [&event]() -> uint32_t {
    switch (event.kind) {
      case EventKind::FileCreate:
        return ANTIVIRUS_REALTIME_FILE_OPERATION_CREATE;
      case EventKind::FileOpen:
        return ANTIVIRUS_REALTIME_FILE_OPERATION_OPEN;
      case EventKind::FileWrite:
        return ANTIVIRUS_REALTIME_FILE_OPERATION_WRITE;
      case EventKind::FileExecute:
      default:
        return ANTIVIRUS_REALTIME_FILE_OPERATION_EXECUTE;
    }
  }();

  CopyWideField(request.correlationId, event.correlationId);
  CopyWideField(request.path, event.targetPath);
  CopyWideField(request.processImage, event.process.imagePath);
  CopyWideField(request.commandLine, event.process.commandLine);
  CopyWideField(request.parentImage, event.process.parentImagePath);
  CopyWideField(request.userSid, event.process.userSid);

  const auto outcome = InspectFile(request);
  return outcome.finding.verdict;
}

std::vector<TelemetryRecord> RealtimeProtectionBroker::DrainTelemetry() {
  const std::scoped_lock lock(telemetryMutex_);
  auto telemetry = pendingTelemetry_;
  pendingTelemetry_.clear();
  return telemetry;
}

DWORD WINAPI RealtimeProtectionBroker::ThreadEntry(LPVOID context) {
  auto* broker = reinterpret_cast<RealtimeProtectionBroker*>(context);
  broker->PumpLoop();
  return 0;
}

void RealtimeProtectionBroker::PumpLoop() {
  FilterApi api;
  if (!api.Load()) {
    QueueBrokerStateEvent(L"realtime.broker.unavailable",
                          L"The real-time protection broker could not load Filter Manager user-mode APIs.",
                          std::wstring(L"{\"portName\":\"") +
                              Utf8ToWide(EscapeJsonString(config_.realtimeProtectionPortName)) + L"\"}");
    return;
  }

  while (WaitForSingleObject(stopEvent_, 0) != WAIT_OBJECT_0) {
    HANDLE port = nullptr;
    const auto connectResult =
        api.connect(config_.realtimeProtectionPortName.c_str(), 0, nullptr, 0, nullptr, &port);
    if (FAILED(connectResult) || port == nullptr) {
      QueueBrokerStateEvent(L"realtime.broker.waiting",
                            L"The real-time protection broker is waiting for the minifilter communication port.",
                            std::wstring(L"{\"portName\":\"") +
                                Utf8ToWide(EscapeJsonString(config_.realtimeProtectionPortName)) + L"\"}");
      const auto retryMilliseconds =
          static_cast<DWORD>(std::max(config_.realtimeBrokerRetrySeconds, 1) * 1000);
      if (WaitForSingleObject(stopEvent_, retryMilliseconds) == WAIT_OBJECT_0) {
        return;
      }
      continue;
    }

    QueueBrokerStateEvent(L"realtime.broker.connected",
                          L"The real-time protection broker connected to the minifilter communication port.",
                          std::wstring(L"{\"portName\":\"") +
                              Utf8ToWide(EscapeJsonString(config_.realtimeProtectionPortName)) + L"\"}");

    while (WaitForSingleObject(stopEvent_, 0) != WAIT_OBJECT_0) {
      BrokerPortMessage message{};
      OVERLAPPED overlapped{};
      overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
      if (overlapped.hEvent == nullptr) {
        break;
      }

      const auto getMessageResult =
          api.getMessage(port, &message.header, static_cast<DWORD>(sizeof(message)), &overlapped);
      bool messageReady = SUCCEEDED(getMessageResult);

      if (!messageReady && getMessageResult == HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {
        const auto waitResult = WaitForSingleObject(overlapped.hEvent, kBrokerMessageWaitMilliseconds);
        if (waitResult == WAIT_OBJECT_0) {
          DWORD transferred = 0;
          messageReady = GetOverlappedResult(port, &overlapped, &transferred, FALSE) != FALSE;
        } else if (waitResult == WAIT_TIMEOUT) {
          CloseHandle(overlapped.hEvent);
          continue;
        }
      }

      if (!messageReady) {
        CancelIoEx(port, &overlapped);
        CloseHandle(overlapped.hEvent);
        break;
      }

      CloseHandle(overlapped.hEvent);

      const auto outcome = InspectFile(message.request);
      BrokerPortReply reply{};
      reply.header.status = 0;
      reply.header.messageId = message.header.messageId;
      reply.reply.protocolVersion = ANTIVIRUS_REALTIME_PROTOCOL_VERSION;
      reply.reply.replySize = sizeof(reply.reply);
      reply.reply.requestId = message.request.requestId;
      reply.reply.action = outcome.action;
      reply.reply.disposition = outcome.detection ? ANTIVIRUS_REALTIME_RESPONSE_DISPOSITION_MALICIOUS
                                                  : ANTIVIRUS_REALTIME_RESPONSE_DISPOSITION_CLEAN;
      reply.reply.confidence = outcome.finding.verdict.confidence;

      if (!outcome.finding.verdict.reasons.empty()) {
        CopyWideField(reply.reply.reasonCode, outcome.finding.verdict.reasons.front().code);
        CopyWideField(reply.reply.reasonMessage, outcome.finding.verdict.reasons.front().message);
      }

      CopyWideField(reply.reply.tacticId, outcome.finding.verdict.tacticId);
      CopyWideField(reply.reply.techniqueId, outcome.finding.verdict.techniqueId);
      CopyWideField(reply.reply.quarantineRecordId, outcome.finding.quarantineRecordId);
      CopyWideField(reply.reply.evidenceRecordId, outcome.finding.evidenceRecordId);

      api.replyMessage(port, &reply.header, static_cast<DWORD>(sizeof(reply)));
    }

    CloseHandle(port);
    QueueBrokerStateEvent(L"realtime.broker.disconnected",
                          L"The real-time protection broker lost its connection to the minifilter communication port.",
                          std::wstring(L"{\"portName\":\"") +
                              Utf8ToWide(EscapeJsonString(config_.realtimeProtectionPortName)) + L"\"}");
  }
}

void RealtimeProtectionBroker::QueueTelemetry(const TelemetryRecord& record) {
  const std::scoped_lock lock(telemetryMutex_);
  pendingTelemetry_.push_back(record);
}

void RealtimeProtectionBroker::QueueBrokerStateEvent(const std::wstring& eventType, const std::wstring& summary,
                                                     const std::wstring& payloadJson) {
  QueueTelemetry(TelemetryRecord{
      .eventId = GenerateGuidString(),
      .eventType = eventType,
      .source = L"realtime-protection",
      .summary = summary,
      .occurredAt = CurrentUtcTimestamp(),
      .payloadJson = payloadJson});
}

}  // namespace antivirus::agent
