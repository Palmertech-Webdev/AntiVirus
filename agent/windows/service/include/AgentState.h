#pragma once

#include <string>

#include "PolicySnapshot.h"

namespace antivirus::agent {

struct AgentState {
  std::wstring deviceId;
  std::wstring hostname;
  std::wstring osVersion;
  std::wstring serialNumber;
  std::wstring agentVersion{L"0.1.0-alpha"};
  std::wstring platformVersion{L"platform-0.1.0"};
  std::wstring commandChannelUrl;
  std::wstring lastEnrollmentAt;
  std::wstring lastHeartbeatAt;
  std::wstring lastPolicySyncAt;
  std::wstring healthState{L"healthy"};
  bool isolated{false};
  PolicySnapshot policy{CreateDefaultPolicySnapshot()};
};

}  // namespace antivirus::agent
