#pragma once

#include <filesystem>
#include <string>
#include <vector>

#include "AgentConfig.h"
#include "PolicySnapshot.h"

namespace antivirus::agent {

struct RemediationOutcome {
  bool success{false};
  int processesTerminated{0};
  int registryValuesRemoved{0};
  int startupArtifactsRemoved{0};
  bool quarantineApplied{false};
  std::wstring quarantineRecordId;
  std::wstring evidenceRecordId;
  std::wstring errorMessage;
  std::vector<std::wstring> removedArtifacts;
};

class RemediationEngine {
 public:
  explicit RemediationEngine(const AgentConfig& config);

  RemediationOutcome TerminateProcessesForPath(const std::filesystem::path& subjectPath, bool includeChildren) const;
  RemediationOutcome CleanupPersistenceForPath(const std::filesystem::path& subjectPath) const;
  RemediationOutcome RemediatePath(const std::filesystem::path& subjectPath, const PolicySnapshot& policy) const;

 private:
  AgentConfig config_;
};

}  // namespace antivirus::agent
