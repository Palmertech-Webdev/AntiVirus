#pragma once

#include <winsock2.h>
#include <Windows.h>
#include <fwpmu.h>

#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

#include "../../../service/include/AgentConfig.h"
#include "../../../service/include/TelemetryRecord.h"

namespace antivirus::agent {

class NetworkIsolationManager {
 public:
  explicit NetworkIsolationManager(AgentConfig config);
  ~NetworkIsolationManager();

  NetworkIsolationManager(const NetworkIsolationManager&) = delete;
  NetworkIsolationManager& operator=(const NetworkIsolationManager&) = delete;

  void Start();
  void Stop();

  void SetDeviceId(std::wstring deviceId);
  bool ApplyIsolation(bool isolate, std::wstring* errorMessage = nullptr);

  bool EngineReady() const;
  bool IsolationActive() const;

  std::vector<TelemetryRecord> DrainTelemetry();
  std::vector<TelemetryRecord> CollectConnectionSnapshotTelemetry(std::size_t maxRecords) const;

 private:
  static void CALLBACK NetEventCallback(void* context, const FWPM_NET_EVENT1* event);

  void EnsureProviderAndSubLayer();
  void SubscribeNetEvents();
  void UnsubscribeNetEvents();
  void RemoveIsolationFilters();
  void AddIsolationFilters();
  void HandleNetEvent(const FWPM_NET_EVENT1& event);
  void QueueTelemetry(const TelemetryRecord& record);
  void QueueStateEvent(const std::wstring& eventType, const std::wstring& summary,
                       const std::wstring& payloadJson);

  AgentConfig config_;
  mutable std::mutex stateMutex_{};
  mutable std::mutex telemetryMutex_{};
  std::wstring deviceId_{};
  std::vector<TelemetryRecord> pendingTelemetry_{};
  HANDLE engineHandle_{nullptr};
  HANDLE netEventHandle_{nullptr};
  bool engineReady_{false};
  bool isolationActive_{false};
  std::vector<UINT64> activeFilterIds_{};
  std::unordered_set<UINT64> activeFilterIdIndex_{};
};

}  // namespace antivirus::agent
