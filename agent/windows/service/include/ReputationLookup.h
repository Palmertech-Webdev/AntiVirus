#pragma once

#include <cstdint>
#include <string>

namespace antivirus::agent {

struct ReputationLookupResult {
  bool attempted{false};
  bool lookupSucceeded{false};
  bool knownGood{false};
  bool fromCache{false};
  std::uint32_t trustScore{0};
  std::wstring provider;
  std::wstring source;
  std::wstring summary;
  std::wstring details;
};

ReputationLookupResult LookupPublicFileReputation(const std::wstring& sha256);
std::wstring DescribeReputationLookup(const ReputationLookupResult& result);

}  // namespace antivirus::agent
