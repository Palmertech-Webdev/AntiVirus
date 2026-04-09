#pragma once

#include <stdexcept>
#include <string>
#include <vector>

#include "AgentState.h"
#include "PolicySnapshot.h"
#include "TelemetryRecord.h"

namespace antivirus::agent {

struct EnrollmentResult {
  std::wstring deviceId;
  std::wstring issuedAt;
  std::wstring commandChannelUrl;
  PolicySnapshot policy;
};

struct HeartbeatResult {
  std::wstring receivedAt;
  std::wstring effectivePolicyRevision;
  int commandsPending{0};
};

struct PolicyCheckInResult {
  std::wstring retrievedAt;
  bool changed{false};
  PolicySnapshot policy;
};

struct TelemetryBatchResult {
  std::wstring receivedAt;
  int accepted{0};
  int totalStored{0};
};

struct RemoteCommand {
  std::wstring commandId;
  std::wstring type;
  std::wstring issuedBy;
  std::wstring createdAt;
  std::wstring updatedAt;
  std::wstring targetPath;
  std::wstring recordId;
  std::wstring payloadJson;
};

struct CommandPollResult {
  std::wstring polledAt;
  std::vector<RemoteCommand> items;
};

class DeviceIdentityRejectedError final : public std::runtime_error {
 public:
  explicit DeviceIdentityRejectedError(const std::string& message) : std::runtime_error(message) {}
};

class ControlPlaneClient {
 public:
  explicit ControlPlaneClient(std::wstring baseUrl);

  EnrollmentResult Enroll(const AgentState& state) const;
  HeartbeatResult SendHeartbeat(const AgentState& state) const;
  PolicyCheckInResult CheckInPolicy(const AgentState& state) const;
  TelemetryBatchResult SendTelemetryBatch(const AgentState& state, const std::vector<TelemetryRecord>& records) const;
  CommandPollResult PollPendingCommands(const AgentState& state, int limit = 10) const;
  void CompleteCommand(const AgentState& state, const std::wstring& commandId, const std::wstring& status,
                       const std::wstring& resultJson) const;

 private:
  std::wstring baseUrl_;
};

}  // namespace antivirus::agent
