#include "DestinationEventRecorder.h"

#include <chrono>
#include <cwctype>
#include <sstream>

#include "DestinationProtection.h"
#include "StringUtils.h"

namespace antivirus::agent {
namespace {

std::wstring CalculateExpiryTimestamp(const std::wstring& firstSeenAt, const std::uint32_t cacheTtlMinutes) {
  if (firstSeenAt.empty()) {
    return CurrentUtcTimestamp();
  }

  // Keep this simple and deterministic for the current phase: runtime users can overwrite on refresh.
  // A fuller implementation can parse/offset the timestamp later.
  (void)cacheTtlMinutes;
  return firstSeenAt;
}

std::wstring BuildReasonSummary(const std::vector<DestinationReasonCode>& reasonCodes) {
  std::vector<std::wstring> phrases;
  for (const auto reason : reasonCodes) {
    switch (reason) {
      case DestinationReasonCode::KnownMaliciousDestination:
        phrases.push_back(L"known malicious destination");
        break;
      case DestinationReasonCode::KnownPhishingDestination:
        phrases.push_back(L"known phishing destination");
        break;
      case DestinationReasonCode::KnownScamDestination:
        phrases.push_back(L"known scam destination");
        break;
      case DestinationReasonCode::SuspiciousNewlyRegisteredDomain:
        phrases.push_back(L"new campaign-style domain");
        break;
      case DestinationReasonCode::SuspiciousTld:
        phrases.push_back(L"high-risk domain ending");
        break;
      case DestinationReasonCode::TyposquattingMatch:
        phrases.push_back(L"lookalike spelling of a trusted brand");
        break;
      case DestinationReasonCode::HomographMatch:
        phrases.push_back(L"lookalike characters in the domain");
        break;
      case DestinationReasonCode::BrandImpersonation:
        phrases.push_back(L"brand impersonation");
        break;
      case DestinationReasonCode::SuspiciousRedirectChain:
        phrases.push_back(L"redirect-style URL behaviour");
        break;
      case DestinationReasonCode::UrlShortenerRisk:
        phrases.push_back(L"URL shortener often used in phishing");
        break;
      case DestinationReasonCode::EncodedParameters:
        phrases.push_back(L"heavily encoded URL parameters");
        break;
      case DestinationReasonCode::MismatchedBrandDomain:
        phrases.push_back(L"brand and domain mismatch");
        break;
      case DestinationReasonCode::ExcessiveSubdomainDepth:
        phrases.push_back(L"unusually deep subdomain chain");
        break;
      case DestinationReasonCode::ExcessiveQueryTokens:
        phrases.push_back(L"too many tracking or control parameters");
        break;
      case DestinationReasonCode::CredentialHarvestingKeyword:
        phrases.push_back(L"login, payment, or verification wording");
        break;
      case DestinationReasonCode::EmailDeliveredLink:
        phrases.push_back(L"email-delivered link");
        break;
      case DestinationReasonCode::BrowserDeliveredNavigation:
        phrases.push_back(L"browser navigation");
        break;
      case DestinationReasonCode::AttachmentDeliveredLink:
        phrases.push_back(L"attachment-delivered link");
        break;
      case DestinationReasonCode::RedirectDrivenNavigation:
        phrases.push_back(L"redirect-driven navigation");
        break;
      case DestinationReasonCode::BrowserDownloadInitiation:
        phrases.push_back(L"download started from a browser");
        break;
      case DestinationReasonCode::BrowserLaunchedFile:
        phrases.push_back(L"browser-launched file");
        break;
      case DestinationReasonCode::BrowserExtensionHost:
        phrases.push_back(L"browser extension host");
        break;
      case DestinationReasonCode::AbusiveNotificationPrompt:
        phrases.push_back(L"abusive notification or permission prompt");
        break;
      case DestinationReasonCode::SuspiciousBrowserChildProcess:
        phrases.push_back(L"suspicious browser child process");
        break;
      case DestinationReasonCode::FakeUpdatePattern:
        phrases.push_back(L"fake update or fake download pattern");
        break;
      default:
        break;
    }
  }

  if (phrases.empty()) {
    return {};
  }

  std::wstringstream summary;
  for (std::size_t index = 0; index < phrases.size(); ++index) {
    if (index != 0) {
      summary << (index + 1 == phrases.size() ? L" and " : L", ");
    }
    summary << phrases[index];
  }
  return summary.str();
}

std::wstring BuildPlainLanguageDetail(const DestinationContext& context,
                                      const DestinationVerdict& verdict) {
  std::wstringstream detail;
  const auto target = verdict.host.empty() ? (verdict.indicator.empty() ? L"this destination" : verdict.indicator)
                                           : verdict.host;
  const auto app = context.sourceApplication.empty() ? L"an app on this device"
                                                     : std::filesystem::path(context.sourceApplication).filename().wstring();
  const auto browserLabel = context.browserFamily.empty() ? app
                                                          : std::wstring(1, static_cast<wchar_t>(std::towupper(context.browserFamily[0]))) +
                                                                context.browserFamily.substr(1);
  const auto reasonSummary = BuildReasonSummary(verdict.reasonCodes);

  if (verdict.action == DestinationAction::Block) {
    detail << L"Fenrir blocked " << browserLabel << L" from opening " << target << L".";
  } else if (verdict.action == DestinationAction::Warn) {
    detail << L"Fenrir warned about " << target << L" before " << browserLabel << L" continued.";
  } else if (verdict.action == DestinationAction::DegradedAllow) {
    detail << L"Fenrir allowed " << target << L" in degraded mode while protection data was limited.";
  } else {
    detail << L"Fenrir recorded a destination check for " << target << L".";
  }

  if (!reasonSummary.empty()) {
    detail << L" Reason: " << reasonSummary << L".";
  }

  if (verdict.confidence != 0) {
    detail << L" Confidence: " << verdict.confidence << L".";
  }

  if (!verdict.details.empty()) {
    detail << L" " << verdict.details;
  }

  return detail.str();
}

}  // namespace

DestinationPolicySnapshot ProjectDestinationPolicy(const PolicySnapshot& policy) {
  DestinationPolicySnapshot projected{};
  projected.destinationProtectionEnabled = policy.destinationProtectionEnabled;
  projected.antiPhishingEnabled = policy.antiPhishingEnabled;
  projected.webProtectionEnabled = policy.webProtectionEnabled;
  projected.emailLinkProtectionEnabled = policy.emailLinkProtectionEnabled;
  projected.evaluateDomains = policy.evaluateDomains;
  projected.evaluateUrls = policy.evaluateUrls;
  projected.blockKnownMaliciousDestinations = policy.blockKnownMaliciousDestinations;
  projected.blockKnownPhishingDestinations = policy.blockKnownPhishingDestinations;
  projected.blockKnownScamDestinations = policy.blockKnownScamDestinations;
  projected.warnOnSuspiciousDestinations = policy.warnOnSuspiciousDestinations;
  projected.warnOnNewlyRegisteredDomains = policy.warnOnNewlyRegisteredDomains;
  projected.allowDegradedModeWhenOffline = policy.allowDegradedDestinationModeWhenOffline;
  projected.browserContextRequiredForWarnOnly = policy.browserContextRequiredForWarnOnly;
  projected.suspiciousWarnThreshold = policy.suspiciousDestinationWarnThreshold;
  projected.phishingWarnThreshold = policy.phishingWarnThreshold;
  projected.phishingBlockThreshold = policy.phishingBlockThreshold;
  projected.destinationCacheTtlMinutes = policy.destinationCacheTtlMinutes;
  return projected;
}

ScanHistoryRecord BuildDestinationScanHistoryRecord(const DestinationContext& context,
                                                    const DestinationVerdict& verdict,
                                                    const DestinationEvidenceRecord& evidence) {
  ScanHistoryRecord record{};
  record.recordedAt = evidence.occurredAt.empty() ? CurrentUtcTimestamp() : evidence.occurredAt;
  record.source = context.source.empty() ? L"destination-protection" : context.source;
  record.subjectPath = std::filesystem::path(verdict.host.empty() ? verdict.indicator : verdict.host);
  record.sha256.clear();
  record.contentType = L"destination";
  record.reputation = BuildPlainLanguageDetail(context, verdict);
  record.disposition = DestinationActionToString(verdict.action);
  record.confidence = verdict.confidence;
  record.tacticId = L"TA0001";
  record.techniqueId = verdict.category == DestinationThreatCategory::Phishing ? L"T1566" : L"T1583";
  record.remediationStatus = verdict.action == DestinationAction::Block ? L"blocked" :
                             (verdict.action == DestinationAction::Warn ? L"warned" : L"observed");
  record.evidenceRecordId = evidence.evidenceId;
  record.quarantineRecordId.clear();
  record.alertTitle = verdict.alertTitle.empty() ? BuildDestinationSummary(verdict) : verdict.alertTitle;
  record.contextType = context.emailOriginated ? L"email" : (context.browserInitiated ? L"browser" : L"destination");
  record.sourceApplication = context.sourceApplication;
  record.originReference = !context.sourceDomain.empty() ? context.sourceDomain
                                                         : (!context.sourceUrl.empty() ? context.sourceUrl
                                                                                       : context.navigationType);
  record.contextJson = evidence.metadataJson;
  return record;
}

DestinationIntelligenceRecord BuildDestinationIntelligenceRecord(const DestinationContext& context,
                                                                 const DestinationVerdict& verdict,
                                                                 const DestinationEvidenceRecord& evidence,
                                                                 const std::uint32_t cacheTtlMinutes) {
  DestinationIntelligenceRecord record{};
  record.indicatorType = context.indicatorType;
  record.normalizedIndicator = context.normalizedIndicator.empty() ? verdict.indicator : context.normalizedIndicator;
  record.canonicalUrl = verdict.canonicalUrl;
  record.host = verdict.host;
  record.source = context.source;
  record.provider = verdict.provider;
  record.verdict = DestinationThreatCategoryToString(verdict.category);
  record.action = verdict.action;
  record.category = verdict.category;
  record.confidence = verdict.confidence;
  record.reasonCodes = verdict.reasonCodes;
  record.metadataJson = evidence.metadataJson;
  record.firstSeenAt = evidence.occurredAt.empty() ? CurrentUtcTimestamp() : evidence.occurredAt;
  record.lastSeenAt = record.firstSeenAt;
  record.expiresAt = CalculateExpiryTimestamp(record.firstSeenAt, cacheTtlMinutes);
  record.suspicious = verdict.suspicious;
  record.knownBad = verdict.knownBad;
  record.fromCloud = !verdict.provider.empty() && _wcsicmp(verdict.provider.c_str(), L"local-cache") != 0;
  return record;
}

std::wstring BuildDestinationTelemetryPayload(const DestinationContext& context,
                                              const DestinationVerdict& verdict,
                                              const DestinationEvidenceRecord& evidence) {
  return std::wstring(L"{\"indicator\":\"") + Utf8ToWide(EscapeJsonString(verdict.indicator)) +
         L"\",\"host\":\"" + Utf8ToWide(EscapeJsonString(verdict.host)) +
         L"\",\"category\":\"" + DestinationThreatCategoryToString(verdict.category) +
         L"\",\"action\":\"" + DestinationActionToString(verdict.action) +
         L"\",\"confidence\":" + std::to_wstring(verdict.confidence) +
         L",\"sourceApplication\":\"" + Utf8ToWide(EscapeJsonString(context.sourceApplication)) +
         L"\",\"browserInitiated\":" + (context.browserInitiated ? std::wstring(L"true") : std::wstring(L"false")) +
         L",\"emailOriginated\":" + (context.emailOriginated ? std::wstring(L"true") : std::wstring(L"false")) +
         L",\"contextType\":\"" + Utf8ToWide(EscapeJsonString(context.emailOriginated ? L"email"
                                                                                      : (context.browserInitiated ? L"browser"
                                                                                                                  : L"destination"))) +
         L"\",\"navigationType\":\"" + Utf8ToWide(EscapeJsonString(context.navigationType)) +
         L"\",\"sourceDomain\":\"" + Utf8ToWide(EscapeJsonString(context.sourceDomain)) +
         L"\""
         L",\"reasonCodes\":\"" + Utf8ToWide(EscapeJsonString(JoinDestinationReasonCodes(verdict.reasonCodes))) +
         L"\",\"plainDetail\":\"" + Utf8ToWide(EscapeJsonString(BuildPlainLanguageDetail(context, verdict))) +
         L"\",\"evidenceRecordId\":\"" + Utf8ToWide(EscapeJsonString(evidence.evidenceId)) + L"\"}";
}

std::wstring BuildDestinationEventType(const DestinationVerdict& verdict) {
  switch (verdict.action) {
    case DestinationAction::Block:
      return L"destination.blocked";
    case DestinationAction::Warn:
      return L"destination.warned";
    case DestinationAction::DegradedAllow:
      return L"destination.degraded_allow";
    default:
      return L"destination.observed";
  }
}

std::wstring BuildDestinationEventSummary(const DestinationVerdict& verdict) {
  if (!verdict.summary.empty()) {
    return verdict.summary;
  }
  return BuildDestinationSummary(verdict);
}

}  // namespace antivirus::agent
