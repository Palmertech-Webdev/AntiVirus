#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "AgentConfig.h"
#include "AgentState.h"
#include "QuarantineStore.h"
#include "RuntimeDatabase.h"

namespace antivirus::agent {

enum class LocalServiceState {
  NotInstalled,
  Running,
  Stopped,
  StartPending,
  StopPending,
  Paused,
  Unknown
};

struct EndpointClientSnapshot {
  AgentState agentState;
  LocalServiceState serviceState{LocalServiceState::Unknown};
  std::size_t queuedTelemetryCount{0};
  std::size_t activeQuarantineCount{0};
  std::size_t openThreatCount{0};
  std::size_t pendingPamRequestCount{0};
  std::size_t pamApprovedCount{0};
  std::size_t pamDeniedCount{0};
  std::wstring pamHealthState{L"unknown"};
  bool localAdminExposureKnown{false};
  std::size_t localAdminMemberCount{0};
  bool localAdminExposure{false};
  std::vector<ScanHistoryRecord> recentThreats;
  std::vector<ScanHistoryRecord> recentFindings;
  std::vector<QuarantineIndexRecord> quarantineItems;
  std::vector<UpdateJournalRecord> updateJournal;
  RebootCoordinatorRecord rebootCoordinator;
  std::vector<WindowsUpdateRecord> windowsUpdates;
  std::vector<SoftwarePatchRecord> softwarePatches;
  std::vector<PatchHistoryRecord> patchHistory;
};

LocalServiceState QueryAgentServiceState();
std::wstring LocalServiceStateToString(LocalServiceState state);
bool StartAgentService();
bool StopAgentService();
bool RestartAgentService();

EndpointClientSnapshot LoadEndpointClientSnapshot(const AgentConfig& config, std::size_t threatLimit = 25,
                                                  std::size_t quarantineLimit = 50, std::size_t findingLimit = 50,
                                                  std::size_t updateLimit = 10);

QuarantineActionResult RestoreQuarantinedItem(const AgentConfig& config, const std::wstring& recordId);
QuarantineActionResult DeleteQuarantinedItem(const AgentConfig& config, const std::wstring& recordId);

}  // namespace antivirus::agent
