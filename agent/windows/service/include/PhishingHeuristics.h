#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "DestinationProtection.h"

namespace antivirus::agent {

struct PhishingHeuristicAssessment {
  DestinationThreatCategory category{DestinationThreatCategory::Unknown};
  std::uint32_t confidence{0};
  std::vector<DestinationReasonCode> reasonCodes{};
  std::wstring details;
  std::wstring impersonatedBrand;
  bool suspicious{false};
};

PhishingHeuristicAssessment ScorePhishingHeuristics(const DestinationContext& context);

}  // namespace antivirus::agent
