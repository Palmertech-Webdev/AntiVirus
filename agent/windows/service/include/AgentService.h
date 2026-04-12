#pragma once

#include <winsock2.h>
#include <Windows.h>

#include <filesystem>
#include <memory>
#include <vector>

#include "AgentConfig.h"
#include "AgentState.h"
#include "ControlPlaneClient.h"
#include "CommandJournalStore.h"
#include "DeviceInventoryCollector.h"
#include "EventEnvelope.h"
#include "FileDeltaTracker.h"
#include "HardeningManager.h"
#include "LocalStateStore.h"
#include "PolicySnapshot.h"
#include "ProcessDeltaTracker.h"
#include "RemediationEngine.h"
#include "ScanVerdict.h"
#include "TelemetryQueueStore.h"
#include "RealtimeProtectionBroker.h"
#include "UpdaterService.h"
#include "WscCoexistenceManager.h"
#include "../../sensor/etw/include/ProcessEtwSensor.h"
#include "../../sensor/wfp/include/NetworkIsolationManager.h"

namespace antivirus::agent {

enum class AgentRunMode {
  Console,
  Service
};

class AgentService {
 public:
  AgentService();
  ~AgentService();

  AgentService(const AgentService&) = delete;
  AgentService& operator=(const AgentService&) = delete;

  int Run(AgentRunMode mode);
  void RequestStop();

 private:
  static std::wstring BuildCyclePayload(int cycle, const std::wstring& extraFields = L"");

  std::vector<std::filesystem::path> BuildMonitoredRoots() const;
  void RunSyncLoop(AgentRunMode mode);
  bool WaitForNextCycle(AgentRunMode mode, int nextCycle);
  bool ShouldStop() const;
  void ProcessPamRequests();
  std::filesystem::path GetPamRequestPath() const;
  std::vector<std::filesystem::path> GetPamRequestPaths() const;
  std::filesystem::path GetPamAuditJournalPath() const;

  void SyncWithControlPlane(int cycle);
  void EnsureEnrollment();
  void ResetEnrollmentState();
  bool RecoverDeviceIdentity(const std::exception& error, const std::wstring& operationName);
  void RefreshPolicy(int cycle);
  void PollAndExecuteCommands(int cycle);
  std::wstring ExecuteCommand(const RemoteCommand& command);
  std::wstring ExecuteTargetedScan(const RemoteCommand& command);
  std::wstring ExecuteIsolationCommand(const RemoteCommand& command, bool isolate);
  std::wstring ExecuteQuarantineMutation(const RemoteCommand& command, bool restore);
  std::wstring ExecuteUpdateCommand(const RemoteCommand& command, bool rollback);
  std::wstring ExecuteRepairCommand(const RemoteCommand& command);
  std::wstring ExecuteProcessTerminationCommand(const RemoteCommand& command, bool includeChildren);
  std::wstring ExecutePersistenceCleanupCommand(const RemoteCommand& command);
  std::wstring ExecutePathRemediationCommand(const RemoteCommand& command);
  std::wstring ExecuteScriptCommand(const RemoteCommand& command);
  void PublishHeartbeat(int cycle);
  void PersistState();
  void LoadLocalPolicyCache();
  void StartTelemetrySpool() const;
  void StartCommandLoop() const;
  void PrintStatus() const;
  void QueueEndpointStatusTelemetry();
  void QueueDeviceInventoryTelemetry(int cycle);
  void DrainProcessTelemetry();
  void DrainRealtimeProtectionTelemetry();
  void DrainNetworkTelemetry();
  void QueueCycleTelemetry(int cycle);
  void QueueTelemetryEvent(const std::wstring& eventType, const std::wstring& source, const std::wstring& summary,
                           const std::wstring& payloadJson);
  void QueueTelemetryRecords(const std::vector<TelemetryRecord>& records);
  void FlushTelemetryQueue();
  ScanVerdict EvaluateEvent(const EventEnvelope& event) const;
  std::wstring ExecuteSoftwareCommand(const RemoteCommand& command, bool uninstall, bool searchOnly);
  std::wstring ExecuteSoftwareBlockCommand(const RemoteCommand& command);
  void EnforceBlockedSoftware();

  AgentConfig config_{};
  AgentState state_{};
  PolicySnapshot policy_{};
  std::unique_ptr<LocalStateStore> stateStore_{};
  std::unique_ptr<ControlPlaneClient> controlPlaneClient_{};
  std::unique_ptr<CommandJournalStore> commandJournalStore_{};
  std::unique_ptr<TelemetryQueueStore> telemetryQueueStore_{};
  ProcessDeltaTracker processDeltaTracker_{};
  FileDeltaTracker fileDeltaTracker_{};
  std::vector<TelemetryRecord> pendingTelemetry_{};
  std::unique_ptr<RealtimeProtectionBroker> realtimeProtectionBroker_{};
  std::unique_ptr<ProcessEtwSensor> processEtwSensor_{};
  std::unique_ptr<NetworkIsolationManager> networkIsolationManager_{};
  bool lastControlPlaneSyncFailed_{false};
  bool lastHardeningCheckFailed_{false};
  bool lastTelemetryFlushFailed_{false};
  HANDLE stopEvent_{nullptr};
  HANDLE pamRequestEvent_{nullptr};
};

}  // namespace antivirus::agent
