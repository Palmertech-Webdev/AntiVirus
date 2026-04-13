#include "EndpointClient.h"

#include <Windows.h>
#include <lm.h>

#include <algorithm>
#include <fstream>
#include <memory>
#include <set>
#include <string>

#include "LocalStateStore.h"
#include "QuarantineStore.h"

namespace antivirus::agent {
namespace {

constexpr wchar_t kAgentServiceName[] = L"FenrirAgent";
constexpr wchar_t kPamRequestFileName[] = L"pam-request.json";
constexpr wchar_t kPamAuditFileName[] = L"privilege-requests.jsonl";

struct PamPostureSummary {
  std::size_t pendingRequestCount{0};
  std::size_t approvedCount{0};
  std::size_t deniedCount{0};
  std::wstring healthState{L"unknown"};
};

struct LocalAdminExposureSummary {
  bool known{false};
  std::size_t memberCount{0};
  bool exposed{false};
};

struct ServiceHandleCloser {
  void operator()(SC_HANDLE handle) const noexcept {
    if (handle != nullptr) {
      CloseServiceHandle(handle);
    }
  }
};

using ServiceHandle = std::unique_ptr<std::remove_pointer_t<SC_HANDLE>, ServiceHandleCloser>;

bool IsThreatDisposition(const std::wstring& disposition) {
  return _wcsicmp(disposition.c_str(), L"allow") != 0;
}

bool IsScanSessionRecord(const ScanHistoryRecord& record) {
  return _wcsicmp(record.contentType.c_str(), L"scan-session") == 0;
}

std::filesystem::path ResolveRuntimeRoot(const AgentConfig& config) {
  auto runtimeRoot = config.runtimeDatabasePath.parent_path();
  if (runtimeRoot.empty()) {
    runtimeRoot = config.runtimeDatabasePath;
  }

  if (!runtimeRoot.empty()) {
    return runtimeRoot;
  }

  return std::filesystem::current_path() / L"runtime";
}

std::filesystem::path ResolvePamRequestPath(const AgentConfig& config) {
  return ResolveRuntimeRoot(config) / kPamRequestFileName;
}

std::filesystem::path ResolvePamAuditPath(const AgentConfig& config) {
  auto journalRoot = config.journalRootPath;
  if (journalRoot.empty()) {
    journalRoot = ResolveRuntimeRoot(config);
  }

  return journalRoot / kPamAuditFileName;
}

std::size_t CountToken(const std::string& value, const std::string& token) {
  if (token.empty() || value.empty()) {
    return 0;
  }

  std::size_t count = 0;
  std::size_t position = 0;
  while ((position = value.find(token, position)) != std::string::npos) {
    ++count;
    position += token.size();
  }

  return count;
}

PamPostureSummary QueryPamPosture(const AgentConfig& config) {
  PamPostureSummary summary;

  const auto requestPath = ResolvePamRequestPath(config);
  const auto auditPath = ResolvePamAuditPath(config);

  std::error_code error;
  const auto requestRootReady = std::filesystem::exists(requestPath.parent_path(), error) && !error;
  error.clear();
  const auto auditRootReady = std::filesystem::exists(auditPath.parent_path(), error) && !error;
  summary.healthState = (requestRootReady && auditRootReady) ? L"healthy" : L"degraded";

  error.clear();
  if (std::filesystem::exists(requestPath, error) && !error) {
    summary.pendingRequestCount = 1;
  }

  error.clear();
  if (std::filesystem::exists(auditPath, error) && !error) {
    std::ifstream input(auditPath, std::ios::binary);
    if (input.is_open()) {
      const std::string content((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
      summary.approvedCount = CountToken(content, "\"decision\":\"approved\"");
      summary.deniedCount = CountToken(content, "\"decision\":\"denied\"");
    }
  }

  return summary;
}

LocalAdminExposureSummary QueryLocalAdminExposure() {
  LocalAdminExposureSummary summary;

  std::set<std::wstring> members;
  DWORD_PTR resumeHandle = 0;
  NET_API_STATUS status = NERR_Success;

  do {
    LPLOCALGROUP_MEMBERS_INFO_2 records = nullptr;
    DWORD entriesRead = 0;
    DWORD totalEntries = 0;
    status = NetLocalGroupGetMembers(nullptr, L"Administrators", 2, reinterpret_cast<LPBYTE*>(&records),
                                     MAX_PREFERRED_LENGTH, &entriesRead, &totalEntries, &resumeHandle);
    if (status != NERR_Success && status != ERROR_MORE_DATA) {
      if (records != nullptr) {
        NetApiBufferFree(records);
      }
      return summary;
    }

    for (DWORD index = 0; index < entriesRead; ++index) {
      if (records[index].lgrmi2_domainandname != nullptr) {
        members.insert(records[index].lgrmi2_domainandname);
      }
    }

    if (records != nullptr) {
      NetApiBufferFree(records);
    }
  } while (status == ERROR_MORE_DATA);

  summary.known = true;
  summary.memberCount = members.size();
  summary.exposed = summary.memberCount > 1;
  return summary;
}

}  // namespace

LocalServiceState QueryAgentServiceState() {
  ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
  if (!manager) {
    return LocalServiceState::Unknown;
  }

  ServiceHandle service(OpenServiceW(manager.get(), kAgentServiceName, SERVICE_QUERY_STATUS));
  if (!service) {
    return GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST ? LocalServiceState::NotInstalled : LocalServiceState::Unknown;
  }

  SERVICE_STATUS_PROCESS status{};
  DWORD bytesNeeded = 0;
  if (!QueryServiceStatusEx(service.get(), SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status),
                            &bytesNeeded)) {
    return LocalServiceState::Unknown;
  }

  switch (status.dwCurrentState) {
    case SERVICE_RUNNING:
      return LocalServiceState::Running;
    case SERVICE_STOPPED:
      return LocalServiceState::Stopped;
    case SERVICE_START_PENDING:
      return LocalServiceState::StartPending;
    case SERVICE_STOP_PENDING:
      return LocalServiceState::StopPending;
    case SERVICE_PAUSED:
      return LocalServiceState::Paused;
    default:
      return LocalServiceState::Unknown;
  }
}

std::wstring LocalServiceStateToString(const LocalServiceState state) {
  switch (state) {
    case LocalServiceState::NotInstalled:
      return L"not installed";
    case LocalServiceState::Running:
      return L"running";
    case LocalServiceState::Stopped:
      return L"stopped";
    case LocalServiceState::StartPending:
      return L"starting";
    case LocalServiceState::StopPending:
      return L"stopping";
    case LocalServiceState::Paused:
      return L"paused";
    default:
      return L"unknown";
  }
}

bool StartAgentService() {
  ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
  if (!manager) {
    return false;
  }

  ServiceHandle service(OpenServiceW(manager.get(), kAgentServiceName, SERVICE_START | SERVICE_QUERY_STATUS));
  if (!service) {
    return false;
  }

  if (StartServiceW(service.get(), 0, nullptr)) {
    return true;
  }

  return GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
}

bool StopAgentService() {
  ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
  if (!manager) {
    return false;
  }

  ServiceHandle service(OpenServiceW(manager.get(), kAgentServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS));
  if (!service) {
    return false;
  }

  SERVICE_STATUS status{};
  if (!ControlService(service.get(), SERVICE_CONTROL_STOP, &status)) {
    const auto error = GetLastError();
    if (error != ERROR_SERVICE_NOT_ACTIVE) {
      return false;
    }
  }

  for (int attempt = 0; attempt < 30; ++attempt) {
    SERVICE_STATUS_PROCESS current{};
    DWORD bytesNeeded = 0;
    if (!QueryServiceStatusEx(service.get(), SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&current),
                              sizeof(current), &bytesNeeded)) {
      return false;
    }

    if (current.dwCurrentState == SERVICE_STOPPED) {
      return true;
    }

    Sleep(250);
  }

  return false;
}

bool RestartAgentService() {
  const auto currentState = QueryAgentServiceState();
  if (currentState == LocalServiceState::Running || currentState == LocalServiceState::StopPending ||
      currentState == LocalServiceState::StartPending || currentState == LocalServiceState::Paused) {
    if (!StopAgentService()) {
      return false;
    }
  }

  return StartAgentService();
}

EndpointClientSnapshot LoadEndpointClientSnapshot(const AgentConfig& config, const std::size_t threatLimit,
                                                  const std::size_t quarantineLimit, const std::size_t findingLimit,
                                                  const std::size_t updateLimit) {
  LocalStateStore stateStore(config.runtimeDatabasePath, config.stateFilePath);
  const auto state = stateStore.LoadOrCreate();
  auto serviceState = QueryAgentServiceState();
  if (serviceState == LocalServiceState::Stopped || serviceState == LocalServiceState::Paused) {
    if (StartAgentService()) {
      serviceState = QueryAgentServiceState();
    }
  }

  RuntimeDatabase database(config.runtimeDatabasePath);
  const auto findings = database.ListScanHistory(std::max<std::size_t>({threatLimit, findingLimit, 200}));
  const auto quarantineItems = database.ListQuarantineRecords(quarantineLimit);

  EndpointClientSnapshot snapshot{
      .agentState = state,
      .serviceState = serviceState,
      .queuedTelemetryCount = database.CountTelemetryQueue(),
      .quarantineItems = quarantineItems,
      .updateJournal = database.ListUpdateJournal(updateLimit),
      .windowsUpdates = database.ListWindowsUpdateRecords(50),
      .softwarePatches = database.ListSoftwarePatchRecords(100),
      .patchHistory = database.ListPatchHistoryRecords(50)};

  database.LoadRebootCoordinator(snapshot.rebootCoordinator);

  const auto pamPosture = QueryPamPosture(config);
  snapshot.pendingPamRequestCount = pamPosture.pendingRequestCount;
  snapshot.pamApprovedCount = pamPosture.approvedCount;
  snapshot.pamDeniedCount = pamPosture.deniedCount;
  snapshot.pamHealthState = pamPosture.healthState;

  const auto localAdminExposure = QueryLocalAdminExposure();
  snapshot.localAdminExposureKnown = localAdminExposure.known;
  snapshot.localAdminMemberCount = localAdminExposure.memberCount;
  snapshot.localAdminExposure = localAdminExposure.exposed;

  snapshot.activeQuarantineCount = std::count_if(
      quarantineItems.begin(), quarantineItems.end(),
      [](const QuarantineIndexRecord& record) { return record.localStatus.rfind(L"quarantined", 0) == 0; });

  for (const auto& finding : findings) {
    if (snapshot.recentFindings.size() < findingLimit) {
      snapshot.recentFindings.push_back(finding);
    }

    if (IsScanSessionRecord(finding)) {
      continue;
    }

    if (!IsThreatDisposition(finding.disposition)) {
      continue;
    }

    if (snapshot.recentThreats.size() < threatLimit) {
      snapshot.recentThreats.push_back(finding);
    }

    const auto remediated = _wcsicmp(finding.remediationStatus.c_str(), L"quarantined") == 0;
    if (!remediated) {
      ++snapshot.openThreatCount;
    }
  }

  return snapshot;
}

QuarantineActionResult RestoreQuarantinedItem(const AgentConfig& config, const std::wstring& recordId) {
  QuarantineStore store(config.quarantineRootPath, config.runtimeDatabasePath);
  return store.RestoreFile(recordId);
}

QuarantineActionResult DeleteQuarantinedItem(const AgentConfig& config, const std::wstring& recordId) {
  QuarantineStore store(config.quarantineRootPath, config.runtimeDatabasePath);
  return store.DeleteRecord(recordId);
}

}  // namespace antivirus::agent
