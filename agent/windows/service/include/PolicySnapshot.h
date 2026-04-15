#pragma once

#include <cstdint>
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
  std::uint32_t scanMaliciousBlockThreshold{45};
  std::uint32_t scanMaliciousQuarantineThreshold{70};
  std::uint32_t scanBenignDampeningScore{20};
  std::uint32_t genericRuleScoreScalePercent{75};
  std::uint32_t realtimeExecuteBlockThreshold{65};
  std::uint32_t realtimeNonExecuteBlockThreshold{85};
  std::uint32_t realtimeQuarantineThreshold{90};
  std::uint32_t realtimeObserveTelemetryThreshold{45};
  bool realtimeObserveOnlyForNonExecute{true};
  bool archiveObserveOnly{false};
  bool networkObserveOnly{false};
  bool cloudLookupObserveOnly{false};
  bool requireSignerForSuppression{false};
  bool allowUnsignedSuppressionPathExecutables{false};
  bool enableCleanwareSignerDampening{true};
  bool enableKnownGoodHashDampening{true};
  std::vector<std::wstring> suppressionPathRoots;
  std::vector<std::wstring> suppressionSha256;
  std::vector<std::wstring> suppressionSignerNames;
};

inline PolicySnapshot CreateDefaultPolicySnapshot() {
  return PolicySnapshot{
      .policyId = L"policy-default",
      .policyName = L"Local Protection Baseline",
      .revision = L"local-bootstrap",
      .realtimeProtectionEnabled = true,
      .cloudLookupEnabled = true,
      .scriptInspectionEnabled = true,
      .networkContainmentEnabled = true,
      .quarantineOnMalicious = true,
      .scanMaliciousBlockThreshold = 45,
      .scanMaliciousQuarantineThreshold = 70,
      .scanBenignDampeningScore = 20,
      .genericRuleScoreScalePercent = 75,
      .realtimeExecuteBlockThreshold = 65,
      .realtimeNonExecuteBlockThreshold = 85,
      .realtimeQuarantineThreshold = 90,
      .realtimeObserveTelemetryThreshold = 45,
      .realtimeObserveOnlyForNonExecute = true,
      .archiveObserveOnly = false,
      .networkObserveOnly = false,
      .cloudLookupObserveOnly = false,
      .requireSignerForSuppression = false,
      .allowUnsignedSuppressionPathExecutables = false,
      .enableCleanwareSignerDampening = true,
      .enableKnownGoodHashDampening = true,
      .suppressionPathRoots = {},
      .suppressionSha256 = {},
      .suppressionSignerNames = {}};
}

}  // namespace antivirus::agent
