#include "DestinationEventRecorder.h"
#include "DestinationProtection.h"
#include "DestinationRuntimeStore.h"
#include "DestinationVerdictEngine.h"

#define LookupDestinationReputation LookupDestinationReputation_Legacy
#include "ReputationLookup.cpp"
#undef LookupDestinationReputation

namespace antivirus::agent {
namespace {

DestinationPolicySnapshot LoadDestinationPolicyOrDefault(const std::filesystem::path& databasePath) {
  DestinationRuntimeStore store(databasePath);
  auto policy = CreateDefaultDestinationPolicySnapshot();
  if (!store.LoadPolicy(policy)) {
    store.SavePolicy(policy);
  }
  return policy;
}

std::vector<DestinationReasonCode> BuildPhase1DestinationReasonCodes(const ReputationLookupResult& result,
                                                                     const DestinationThreatCategory category) {
  std::vector<DestinationReasonCode> reasons;
  switch (category) {
    case DestinationThreatCategory::Phishing:
      reasons.push_back(DestinationReasonCode::KnownPhishingDestination);
      break;
    case DestinationThreatCategory::Scam:
      reasons.push_back(DestinationReasonCode::KnownScamDestination);
      break;
    case DestinationThreatCategory::Malware:
    case DestinationThreatCategory::CommandAndControl:
      reasons.push_back(DestinationReasonCode::KnownMaliciousDestination);
      break;
    case DestinationThreatCategory::Suspicious:
      reasons.push_back(DestinationReasonCode::SuspiciousTld);
      break;
    default:
      break;
  }

  if (result.fromCache) {
    reasons.push_back(DestinationReasonCode::CacheHit);
  }
  if (!result.lookupSucceeded) {
    reasons.push_back(DestinationReasonCode::CloudLookupUnavailable);
  }

  if (reasons.empty()) {
    reasons.push_back(DestinationReasonCode::None);
  }
  return reasons;
}

std::uint32_t BuildDestinationRiskConfidence(const ReputationLookupResult& result,
                                             const DestinationThreatCategory category) {
  if (category == DestinationThreatCategory::Clean) {
    return 0;
  }

  const auto trust = std::min<std::uint32_t>(result.trustScore, 100);
  if (result.malicious || category == DestinationThreatCategory::Phishing ||
      category == DestinationThreatCategory::Scam ||
      category == DestinationThreatCategory::CommandAndControl) {
    const auto inverted = 100u - trust;
    return std::clamp<std::uint32_t>(inverted + 20u, 1u, 100u);
  }

  return std::clamp<std::uint32_t>(100u - trust, 1u, 100u);
}

DestinationVerdict BuildPhase1DestinationVerdict(const DestinationContext& context,
                                                 const DestinationPolicySnapshot& policy,
                                                 const ReputationLookupResult& result) {
  DestinationVerdict verdict{};
  verdict.indicatorType = context.indicatorType;
  verdict.indicator = context.normalizedIndicator.empty() ? context.originalIndicator : context.normalizedIndicator;
  verdict.canonicalUrl = context.canonicalUrl;
  verdict.host = context.host.empty() ? verdict.indicator : context.host;
  verdict.source = context.source;
  verdict.provider = result.provider;
  verdict.category = MapReputationToDestinationCategory(result);
  verdict.confidence = BuildDestinationRiskConfidence(result, verdict.category);
  verdict.knownBad = result.malicious;
  verdict.suspicious = verdict.category == DestinationThreatCategory::Suspicious ||
                       verdict.category == DestinationThreatCategory::Phishing ||
                       verdict.category == DestinationThreatCategory::Scam;
  verdict.fromCache = result.fromCache;
  verdict.degradedMode = !result.lookupSucceeded;
  verdict.reasonCodes = BuildPhase1DestinationReasonCodes(result, verdict.category);
  verdict.action = DetermineDestinationAction(policy, verdict.category, verdict.confidence,
                                              verdict.knownBad, verdict.suspicious, false);
  verdict.userOverrideAllowed = verdict.action == DestinationAction::Warn ||
                                verdict.action == DestinationAction::DegradedAllow;
  verdict.summary = BuildDestinationSummary(verdict);
  verdict.details = BuildDestinationDetails(result, context, verdict);
  return verdict;
}

bool IsDestinationLikeIndicator(const ThreatIndicatorType indicatorType) {
  return indicatorType == ThreatIndicatorType::Domain || indicatorType == ThreatIndicatorType::Url ||
         indicatorType == ThreatIndicatorType::Ip;
}

}  // namespace

ReputationLookupResult LookupDestinationReputation(const std::wstring& indicator,
                                                   const std::filesystem::path& databasePath) {
  const auto resolvedDatabasePath = ResolveDatabasePath(databasePath);
  const auto result = LookupDestinationReputation_Legacy(indicator, resolvedDatabasePath);
  if (!result.attempted || !IsDestinationLikeIndicator(result.indicatorType)) {
    return result;
  }

  const auto destinationPolicy = LoadDestinationPolicyOrDefault(resolvedDatabasePath);

  DestinationContext context{};
  context.indicatorType = result.indicatorType;
  context.originalIndicator = indicator;
  context.normalizedIndicator = NormalizeDestinationIndicator(result.indicatorType, indicator);
  context.canonicalUrl = result.indicatorType == ThreatIndicatorType::Url ? context.normalizedIndicator : L"";
  context.host = result.indicatorType == ThreatIndicatorType::Domain || result.indicatorType == ThreatIndicatorType::Ip
                     ? context.normalizedIndicator
                     : L"";
  context.source = L"reputation-lookup";
  context.observedAt = CurrentUtcTimestamp();
  context.fromCache = result.fromCache;
  context.offlineMode = !result.lookupSucceeded;

  const auto verdict = BuildPhase1DestinationVerdict(context, destinationPolicy, result);
  DestinationVerdictEngine evidenceBuilder(resolvedDatabasePath);
  const auto evidence = evidenceBuilder.BuildEvidenceRecord(context, destinationPolicy, verdict,
                                                            L"policy-default", L"phase1-chunk1");

  DestinationRuntimeStore destinationStore(resolvedDatabasePath);
  destinationStore.UpsertIntelligenceRecord(BuildDestinationIntelligenceRecord(
      context, verdict, evidence, destinationPolicy.destinationCacheTtlMinutes));

  if (verdict.action == DestinationAction::Warn || verdict.action == DestinationAction::Block ||
      verdict.action == DestinationAction::DegradedAllow) {
    RuntimeDatabase(resolvedDatabasePath).RecordScanHistory(
        BuildDestinationScanHistoryRecord(context, verdict, evidence));
  }

  return result;
}

}  // namespace antivirus::agent
