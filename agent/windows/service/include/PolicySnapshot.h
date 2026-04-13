#pragma once

#include <string>
#include <vector>

namespace antivirus::agent {

struct PolicySnapshot {
  std::wstring policyId;
  std::wstring policyName;
  std::wstring revision;
  bool realtimeProtectionEnabled{true};
  bool cloudLookupEnabled{true};
  bool scriptInspectionEnabled{true};
  bool networkContainmentEnabled{false};
  bool quarantineOnMalicious{true};
  std::vector<std::wstring> suppressionPathRoots;
  std::vector<std::wstring> suppressionSha256;
  std::vector<std::wstring> suppressionSignerNames;
};

inline PolicySnapshot CreateDefaultPolicySnapshot() {
  return PolicySnapshot{
      .policyId = L"policy-default",
      .policyName = L"Business Baseline",
      .revision = L"local-bootstrap",
      .realtimeProtectionEnabled = true,
      .cloudLookupEnabled = true,
      .scriptInspectionEnabled = true,
      .networkContainmentEnabled = false,
      .quarantineOnMalicious = true,
      .suppressionPathRoots = {},
      .suppressionSha256 = {},
      .suppressionSignerNames = {}};
}

}  // namespace antivirus::agent
