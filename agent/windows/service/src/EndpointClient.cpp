#include "EndpointClient.h"

#include <Windows.h>

#include <algorithm>
#include <memory>

#include "LocalStateStore.h"
#include "QuarantineStore.h"

namespace antivirus::agent {
namespace {

constexpr wchar_t kAgentServiceName[] = L"FenrirAgent";

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
      .updateJournal = database.ListUpdateJournal(updateLimit)};

  snapshot.activeQuarantineCount = std::count_if(
      quarantineItems.begin(), quarantineItems.end(),
      [](const QuarantineIndexRecord& record) { return _wcsicmp(record.localStatus.c_str(), L"quarantined") == 0; });

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
