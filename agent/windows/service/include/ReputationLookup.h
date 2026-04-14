#pragma once

#include <filesystem>
#include <cstdint>
#include <string>

#include "ThreatIntelligence.h"

namespace antivirus::agent {

struct ReputationLookupResult {
  bool attempted{false};
  bool lookupSucceeded{false};
  bool knownGood{false};
  bool malicious{false};
  bool fromCache{false};
  bool localOnly{false};
  std::uint32_t trustScore{0};
  std::uint32_t providerWeight{0};
  ThreatIndicatorType indicatorType{ThreatIndicatorType::Unknown};
  std::wstring indicatorKey;
  std::wstring provider;
  std::wstring source;
  std::wstring summary;
  std::wstring details;
  std::wstring verdict;
  std::wstring expiresAt;
  std::wstring metadataJson;
};

struct ThreatIntelPackIngestResult {
  bool success{false};
  bool signatureVerified{false};
  std::size_t recordsLoaded{0};
  std::size_t recordsRejected{0};
  std::wstring provider;
  std::wstring errorMessage;
};

ReputationLookupResult LookupThreatIntel(ThreatIndicatorType indicatorType, const std::wstring& indicator,
                                         const std::filesystem::path& databasePath = {});
ReputationLookupResult LookupPublicFileReputation(const std::wstring& sha256,
                                                  const std::filesystem::path& databasePath = {});
ReputationLookupResult LookupDestinationReputation(const std::wstring& indicator,
                                                   const std::filesystem::path& databasePath = {});
ThreatIntelPackIngestResult IngestSignedThreatIntelPack(const std::filesystem::path& packPath,
                                                        const std::filesystem::path& databasePath = {});
std::wstring DescribeReputationLookup(const ReputationLookupResult& result);

}  // namespace antivirus::agent
