#pragma once

#include <cwctype>
#include <cstdint>
#include <string>

namespace antivirus::agent {

enum class ThreatIndicatorType {
  Unknown,
  Sha256,
  Domain,
  Url,
  Ip
};

inline std::wstring ThreatIndicatorTypeToString(const ThreatIndicatorType type) {
  switch (type) {
    case ThreatIndicatorType::Sha256:
      return L"sha256";
    case ThreatIndicatorType::Domain:
      return L"domain";
    case ThreatIndicatorType::Url:
      return L"url";
    case ThreatIndicatorType::Ip:
      return L"ip";
    default:
      return L"unknown";
  }
}

inline ThreatIndicatorType ThreatIndicatorTypeFromString(std::wstring value) {
  for (auto& ch : value) {
    ch = static_cast<wchar_t>(towlower(ch));
  }

  if (value == L"sha256" || value == L"hash") {
    return ThreatIndicatorType::Sha256;
  }
  if (value == L"domain" || value == L"host") {
    return ThreatIndicatorType::Domain;
  }
  if (value == L"url" || value == L"uri") {
    return ThreatIndicatorType::Url;
  }
  if (value == L"ip" || value == L"ipv4" || value == L"ipv6") {
    return ThreatIndicatorType::Ip;
  }
  return ThreatIndicatorType::Unknown;
}

struct ThreatIntelRecord {
  ThreatIndicatorType indicatorType{ThreatIndicatorType::Unknown};
  std::wstring indicatorKey;
  std::wstring provider;
  std::wstring source;
  std::wstring verdict;
  std::uint32_t trustScore{0};
  std::uint32_t providerWeight{0};
  std::wstring summary;
  std::wstring details;
  std::wstring metadataJson;
  std::wstring firstSeenAt;
  std::wstring lastSeenAt;
  std::wstring expiresAt;
  bool signedPack{false};
  bool localOnly{false};
};

struct ExclusionPolicyRecord {
  std::wstring ruleId;
  std::wstring path;
  std::wstring scope;
  std::wstring createdBy;
  std::wstring reason;
  std::wstring createdAt;
  std::wstring expiresAt;
  std::wstring warningState;
  std::wstring riskLevel;
  std::wstring state;
  bool dangerous{false};
  bool approved{false};
};

struct QuarantineApprovalRecord {
  std::wstring recordId;
  std::wstring action;
  std::wstring requestedBy;
  std::wstring approvedBy;
  std::wstring restorePath;
  std::wstring requestedAt;
  std::wstring decidedAt;
  std::wstring decision;
  std::wstring reason;
};

}  // namespace antivirus::agent
