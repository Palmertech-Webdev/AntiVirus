#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "ThreatIntelligence.h"

namespace antivirus::agent {

enum class DestinationAction {
  Unknown,
  Allow,
  Warn,
  Block,
  DegradedAllow,
};

enum class DestinationThreatCategory {
  Unknown,
  Clean,
  Suspicious,
  Malware,
  Phishing,
  Scam,
  CommandAndControl,
};

enum class DestinationReasonCode {
  None,
  KnownMaliciousDestination,
  KnownPhishingDestination,
  KnownScamDestination,
  SuspiciousNewlyRegisteredDomain,
  SuspiciousTld,
  TyposquattingMatch,
  HomographMatch,
  BrandImpersonation,
  SuspiciousRedirectChain,
  UrlShortenerRisk,
  EncodedParameters,
  MismatchedBrandDomain,
  ExcessiveSubdomainDepth,
  ExcessiveQueryTokens,
  CredentialHarvestingKeyword,
  EmailDeliveredLink,
  BrowserDeliveredNavigation,
  AttachmentDeliveredLink,
  RedirectDrivenNavigation,
  BrowserDownloadInitiation,
  BrowserLaunchedFile,
  BrowserExtensionHost,
  AbusiveNotificationPrompt,
  SuspiciousBrowserChildProcess,
  FakeUpdatePattern,
  LocalPolicyAllow,
  LocalPolicyWarn,
  LocalPolicyBlock,
  CacheHit,
  CloudLookupUnavailable,
};

struct DestinationPolicySnapshot {
  bool destinationProtectionEnabled{true};
  bool antiPhishingEnabled{true};
  bool webProtectionEnabled{true};
  bool emailLinkProtectionEnabled{true};
  bool evaluateDomains{true};
  bool evaluateUrls{true};
  bool blockKnownMaliciousDestinations{true};
  bool blockKnownPhishingDestinations{true};
  bool blockKnownScamDestinations{false};
  bool warnOnSuspiciousDestinations{true};
  bool warnOnNewlyRegisteredDomains{true};
  bool allowDegradedModeWhenOffline{true};
  bool browserContextRequiredForWarnOnly{false};
  std::uint32_t suspiciousWarnThreshold{45};
  std::uint32_t phishingWarnThreshold{55};
  std::uint32_t phishingBlockThreshold{80};
  std::uint32_t destinationCacheTtlMinutes{240};
};

struct DestinationContext {
  ThreatIndicatorType indicatorType{ThreatIndicatorType::Unknown};
  std::wstring originalIndicator;
  std::wstring normalizedIndicator;
  std::wstring canonicalUrl;
  std::wstring host;
  std::wstring source;
  std::wstring sourceApplication;
  std::wstring parentApplication;
  std::wstring userName;
  std::wstring browserFamily;
  std::wstring deliveryVector;
  std::wstring navigationType;
  std::wstring sourceDomain;
  std::wstring sourceUrl;
  std::wstring observedAt;
  bool browserInitiated{false};
  bool emailOriginated{false};
  bool attachmentOriginated{false};
  bool redirectNavigation{false};
  bool downloadInitiated{false};
  bool browserLaunchedFile{false};
  bool browserExtensionHost{false};
  bool abusivePermissionPrompt{false};
  bool suspiciousBrowserChildProcess{false};
  bool fakeUpdatePattern{false};
  bool fromCache{false};
  bool offlineMode{false};
};

struct DestinationIntelligenceRecord {
  ThreatIndicatorType indicatorType{ThreatIndicatorType::Unknown};
  std::wstring normalizedIndicator;
  std::wstring canonicalUrl;
  std::wstring host;
  std::wstring source;
  std::wstring provider;
  std::wstring verdict;
  DestinationAction action{DestinationAction::Unknown};
  DestinationThreatCategory category{DestinationThreatCategory::Unknown};
  std::uint32_t confidence{0};
  std::vector<DestinationReasonCode> reasonCodes{};
  std::wstring metadataJson;
  std::wstring firstSeenAt;
  std::wstring lastSeenAt;
  std::wstring expiresAt;
  bool suspicious{false};
  bool knownBad{false};
  bool fromCloud{false};
};

struct DestinationVerdict {
  ThreatIndicatorType indicatorType{ThreatIndicatorType::Unknown};
  std::wstring indicator;
  std::wstring canonicalUrl;
  std::wstring host;
  std::wstring summary;
  std::wstring details;
  std::wstring source;
  std::wstring provider;
  DestinationAction action{DestinationAction::Unknown};
  DestinationThreatCategory category{DestinationThreatCategory::Unknown};
  std::uint32_t confidence{0};
  std::vector<DestinationReasonCode> reasonCodes{};
  std::wstring alertTitle;
  bool suspicious{false};
  bool knownBad{false};
  bool fromCache{false};
  bool degradedMode{false};
  bool userOverrideAllowed{false};
};

struct DestinationEvidenceRecord {
  std::wstring evidenceId;
  std::wstring occurredAt;
  std::wstring source;
  std::wstring sourceApplication;
  std::wstring parentApplication;
  std::wstring userName;
  ThreatIndicatorType indicatorType{ThreatIndicatorType::Unknown};
  std::wstring originalIndicator;
  std::wstring normalizedIndicator;
  std::wstring canonicalUrl;
  std::wstring host;
  DestinationAction action{DestinationAction::Unknown};
  DestinationThreatCategory category{DestinationThreatCategory::Unknown};
  std::uint32_t confidence{0};
  std::vector<DestinationReasonCode> reasonCodes{};
  std::wstring policyId;
  std::wstring policyRevision;
  std::wstring metadataJson;
};

DestinationPolicySnapshot CreateDefaultDestinationPolicySnapshot();
std::wstring DestinationActionToString(DestinationAction value);
DestinationAction DestinationActionFromString(std::wstring value);
std::wstring DestinationThreatCategoryToString(DestinationThreatCategory value);
DestinationThreatCategory DestinationThreatCategoryFromString(std::wstring value);
std::wstring DestinationReasonCodeToString(DestinationReasonCode value);
DestinationReasonCode DestinationReasonCodeFromString(std::wstring value);
std::wstring JoinDestinationReasonCodes(const std::vector<DestinationReasonCode>& values);
std::vector<DestinationReasonCode> SplitDestinationReasonCodes(std::wstring_view value);
std::wstring NormalizeDestinationIndicator(ThreatIndicatorType indicatorType, std::wstring value);
std::wstring BuildDestinationSummary(const DestinationVerdict& verdict);
DestinationAction DetermineDestinationAction(const DestinationPolicySnapshot& policy,
                                             DestinationThreatCategory category,
                                             std::uint32_t confidence,
                                             bool knownBad,
                                             bool suspicious,
                                             bool offlineMode);
std::wstring SerializeDestinationVerdictJson(const DestinationVerdict& verdict,
                                             const DestinationContext& context);

}  // namespace antivirus::agent
