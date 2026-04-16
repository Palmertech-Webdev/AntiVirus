#include "DestinationEventRecorder.h"

#include <chrono>

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
  record.reputation = DestinationThreatCategoryToString(verdict.category);
  record.disposition = DestinationActionToString(verdict.action);
  record.confidence = verdict.confidence;
  record.tacticId = L"TA0001";
  record.techniqueId = verdict.category == DestinationThreatCategory::Phishing ? L"T1566" : L"T1583";
  record.remediationStatus = verdict.action == DestinationAction::Block ? L"blocked" :
                             (verdict.action == DestinationAction::Warn ? L"warned" : L"observed");
  record.evidenceRecordId = evidence.evidenceId;
  record.quarantineRecordId.clear();
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
         L",\"evidenceRecordId\":\"" + Utf8ToWide(EscapeJsonString(evidence.evidenceId)) + L"\"}";
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
