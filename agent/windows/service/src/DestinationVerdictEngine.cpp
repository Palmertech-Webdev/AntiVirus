#include "DestinationVerdictEngine.h"

#include <algorithm>
#include <cwctype>
#include <utility>

#include "ReputationLookup.h"
#include "StringUtils.h"

namespace antivirus::agent {
namespace {

std::wstring ToLowerCopy(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return value;
}

std::vector<DestinationReasonCode> BuildReasonCodes(const ReputationLookupResult& result,
                                                    const DestinationContext& context,
                                                    const DestinationVerdict& verdict) {
  std::vector<DestinationReasonCode> reasons;

  const auto verdictLower = ToLowerCopy(result.verdict);
  if (result.malicious) {
    if (verdict.category == DestinationThreatCategory::Phishing) {
      reasons.push_back(DestinationReasonCode::KnownPhishingDestination);
    } else if (verdict.category == DestinationThreatCategory::Scam) {
      reasons.push_back(DestinationReasonCode::KnownScamDestination);
    } else {
      reasons.push_back(DestinationReasonCode::KnownMaliciousDestination);
    }
  }

  if (verdictLower.find(L"suspicious") != std::wstring::npos && !result.malicious) {
    reasons.push_back(DestinationReasonCode::SuspiciousTld);
  }

  if (context.browserInitiated) {
    reasons.push_back(DestinationReasonCode::BrowserDeliveredNavigation);
  }
  if (context.emailOriginated) {
    reasons.push_back(DestinationReasonCode::EmailDeliveredLink);
  }
  if (context.attachmentOriginated) {
    reasons.push_back(DestinationReasonCode::AttachmentDeliveredLink);
  }
  if (context.redirectNavigation) {
    reasons.push_back(DestinationReasonCode::RedirectDrivenNavigation);
  }
  if (context.downloadInitiated) {
    reasons.push_back(DestinationReasonCode::BrowserDownloadInitiation);
  }
  if (context.browserLaunchedFile) {
    reasons.push_back(DestinationReasonCode::BrowserLaunchedFile);
  }
  if (context.browserExtensionHost) {
    reasons.push_back(DestinationReasonCode::BrowserExtensionHost);
  }
  if (context.abusivePermissionPrompt) {
    reasons.push_back(DestinationReasonCode::AbusiveNotificationPrompt);
  }
  if (context.suspiciousBrowserChildProcess) {
    reasons.push_back(DestinationReasonCode::SuspiciousBrowserChildProcess);
  }
  if (context.fakeUpdatePattern) {
    reasons.push_back(DestinationReasonCode::FakeUpdatePattern);
  }
  if (result.fromCache || context.fromCache) {
    reasons.push_back(DestinationReasonCode::CacheHit);
  }
  if (!result.lookupSucceeded && context.offlineMode) {
    reasons.push_back(DestinationReasonCode::CloudLookupUnavailable);
  }

  if (reasons.empty()) {
    reasons.push_back(DestinationReasonCode::None);
  }

  return reasons;
}

std::uint32_t ApplyContextConfidenceUplift(const DestinationContext& context, std::uint32_t confidence) {
  std::uint32_t uplift = 0;
  if (context.emailOriginated) {
    uplift += 16;
  }
  if (context.attachmentOriginated) {
    uplift += 8;
  }
  if (context.redirectNavigation) {
    uplift += 10;
  }
  if (context.downloadInitiated || context.browserLaunchedFile) {
    uplift += 8;
  }
  if (context.browserExtensionHost) {
    uplift += 6;
  }
  if (context.abusivePermissionPrompt) {
    uplift += 12;
  }
  if (context.suspiciousBrowserChildProcess) {
    uplift += 14;
  }
  if (context.fakeUpdatePattern) {
    uplift += 14;
  }
  return std::min<std::uint32_t>(100, confidence + uplift);
}

}  // namespace

DestinationVerdictEngine::DestinationVerdictEngine(std::filesystem::path runtimeDatabasePath)
    : runtimeDatabasePath_(std::move(runtimeDatabasePath)) {}

DestinationVerdict DestinationVerdictEngine::Evaluate(const DestinationContext& context,
                                                      const DestinationPolicySnapshot& policy) const {
  DestinationVerdict verdict{};
  verdict.indicatorType = context.indicatorType;
  verdict.indicator = context.normalizedIndicator.empty() ? context.originalIndicator : context.normalizedIndicator;
  verdict.canonicalUrl = context.canonicalUrl;
  verdict.host = context.host;
  verdict.source = context.source;

  if (!policy.destinationProtectionEnabled) {
    verdict.action = DestinationAction::Allow;
    verdict.category = DestinationThreatCategory::Clean;
    verdict.summary = BuildDestinationSummary(verdict);
    verdict.details = L"Destination protection is disabled by policy.";
    return verdict;
  }

  const auto lookup = LookupDestinationReputation(verdict.indicator, runtimeDatabasePath_);
  verdict.provider = lookup.provider;
  verdict.category = MapReputationToDestinationCategory(lookup);
  verdict.confidence = ApplyContextConfidenceUplift(context, lookup.trustScore);
  verdict.knownBad = lookup.malicious;
  verdict.suspicious = verdict.category == DestinationThreatCategory::Suspicious ||
                       verdict.category == DestinationThreatCategory::Phishing ||
                       verdict.category == DestinationThreatCategory::Scam;
  verdict.fromCache = lookup.fromCache;
  verdict.degradedMode = context.offlineMode && !lookup.lookupSucceeded;
  verdict.action = DetermineDestinationAction(policy, verdict.category, verdict.confidence, verdict.knownBad,
                                              verdict.suspicious, context.offlineMode);
  verdict.userOverrideAllowed = verdict.action == DestinationAction::Warn ||
                                verdict.action == DestinationAction::DegradedAllow;
  verdict.reasonCodes = BuildReasonCodes(lookup, context, verdict);
  verdict.alertTitle = BuildDestinationSummary(verdict);
  verdict.summary = BuildDestinationSummary(verdict);
  verdict.details = BuildDestinationDetails(lookup, context, verdict);
  return verdict;
}

DestinationEvidenceRecord DestinationVerdictEngine::BuildEvidenceRecord(const DestinationContext& context,
                                                                        const DestinationPolicySnapshot& policy,
                                                                        const DestinationVerdict& verdict,
                                                                        std::wstring policyId,
                                                                        std::wstring policyRevision) const {
  DestinationEvidenceRecord record{};
  record.evidenceId = GenerateGuidString();
  record.occurredAt = context.observedAt.empty() ? CurrentUtcTimestamp() : context.observedAt;
  record.source = context.source;
  record.sourceApplication = context.sourceApplication;
  record.parentApplication = context.parentApplication;
  record.userName = context.userName;
  record.indicatorType = context.indicatorType;
  record.originalIndicator = context.originalIndicator;
  record.normalizedIndicator = context.normalizedIndicator;
  record.canonicalUrl = context.canonicalUrl;
  record.host = context.host;
  record.action = verdict.action;
  record.category = verdict.category;
  record.confidence = verdict.confidence;
  record.reasonCodes = verdict.reasonCodes;
  record.policyId = std::move(policyId);
  record.policyRevision = std::move(policyRevision);
  record.metadataJson = SerializeDestinationVerdictJson(verdict, context);
  (void)policy;
  return record;
}

DestinationThreatCategory MapReputationToDestinationCategory(const ReputationLookupResult& result) {
  const auto verdictLower = ToLowerCopy(result.verdict);
  if (result.knownGood) {
    return DestinationThreatCategory::Clean;
  }
  if (verdictLower.find(L"phish") != std::wstring::npos) {
    return DestinationThreatCategory::Phishing;
  }
  if (verdictLower.find(L"scam") != std::wstring::npos || verdictLower.find(L"fraud") != std::wstring::npos) {
    return DestinationThreatCategory::Scam;
  }
  if (verdictLower.find(L"command") != std::wstring::npos || verdictLower.find(L"c2") != std::wstring::npos) {
    return DestinationThreatCategory::CommandAndControl;
  }
  if (result.malicious || verdictLower.find(L"malicious") != std::wstring::npos) {
    return DestinationThreatCategory::Malware;
  }
  if (verdictLower.find(L"suspicious") != std::wstring::npos) {
    return DestinationThreatCategory::Suspicious;
  }
  return DestinationThreatCategory::Unknown;
}

std::wstring BuildDestinationDetails(const ReputationLookupResult& result,
                                     const DestinationContext& context,
                                     const DestinationVerdict& verdict) {
  std::wstring details;
  if (!result.summary.empty()) {
    details += result.summary;
  }
  if (!result.details.empty()) {
    if (!details.empty()) {
      details += L" ";
    }
    details += result.details;
  }

  if (context.browserInitiated) {
    details += details.empty() ? L"Browser-initiated request." : L" Browser-initiated request.";
  }
  if (context.emailOriginated) {
    details += details.empty() ? L"Email-originated request." : L" Email-originated request.";
  }
  if (context.attachmentOriginated) {
    details += details.empty() ? L"Attachment-originated request." : L" Attachment-originated request.";
  }
  if (context.redirectNavigation) {
    details += details.empty() ? L"Redirect-driven navigation." : L" Redirect-driven navigation.";
  }
  if (context.downloadInitiated) {
    details += details.empty() ? L"Download initiation detected." : L" Download initiation detected.";
  }
  if (context.browserLaunchedFile) {
    details += details.empty() ? L"Browser launched a local file." : L" Browser launched a local file.";
  }
  if (context.browserExtensionHost) {
    details += details.empty() ? L"Browser extension host context." : L" Browser extension host context.";
  }
  if (context.abusivePermissionPrompt) {
    details += details.empty() ? L"Notification or permission prompt abuse indicators present."
                               : L" Notification or permission prompt abuse indicators present.";
  }
  if (context.suspiciousBrowserChildProcess) {
    details += details.empty() ? L"Suspicious browser child process activity."
                               : L" Suspicious browser child process activity.";
  }
  if (context.fakeUpdatePattern) {
    details += details.empty() ? L"Fake update or fake download pattern present."
                               : L" Fake update or fake download pattern present.";
  }
  if (verdict.degradedMode) {
    details += details.empty() ? L"Decision produced in degraded mode." : L" Decision produced in degraded mode.";
  }

  if (details.empty()) {
    return L"Fenrir evaluated the destination using local reputation and destination policy controls.";
  }
  return details;
}

}  // namespace antivirus::agent
