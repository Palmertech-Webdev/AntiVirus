#pragma once

#include <filesystem>

#include "DestinationProtection.h"
#include "ReputationLookup.h"

namespace antivirus::agent {

class DestinationVerdictEngine {
 public:
  explicit DestinationVerdictEngine(std::filesystem::path runtimeDatabasePath = {});

  DestinationVerdict Evaluate(const DestinationContext& context,
                              const DestinationPolicySnapshot& policy) const;

  DestinationEvidenceRecord BuildEvidenceRecord(const DestinationContext& context,
                                                const DestinationPolicySnapshot& policy,
                                                const DestinationVerdict& verdict,
                                                std::wstring policyId,
                                                std::wstring policyRevision) const;

 private:
  std::filesystem::path runtimeDatabasePath_;
};

DestinationThreatCategory MapReputationToDestinationCategory(const ReputationLookupResult& result);
std::wstring BuildDestinationDetails(const ReputationLookupResult& result,
                                     const DestinationContext& context,
                                     const DestinationVerdict& verdict);

}  // namespace antivirus::agent
