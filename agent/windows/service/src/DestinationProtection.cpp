#include "DestinationProtection.h"

#include <algorithm>
#include <cwctype>
#include <sstream>

#include "StringUtils.h"

namespace antivirus::agent {
namespace {

std::wstring ToLowerCopy(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return value;
}

std::wstring TrimCopy(std::wstring value) {
  const auto first = value.find_first_not_of(L" \t\r\n");
  if (first == std::wstring::npos) {
    return {};
  }

  const auto last = value.find_last_not_of(L" \t\r\n");
  return value.substr(first, last - first + 1);
}

std::wstring JsonEscape(const std::wstring& value) {
  return Utf8ToWide(EscapeJsonString(value));
}

}  // namespace

DestinationPolicySnapshot CreateDefaultDestinationPolicySnapshot() {
  return DestinationPolicySnapshot{};
}

std::wstring DestinationActionToString(const DestinationAction value) {
  switch (value) {
    case DestinationAction::Allow:
      return L"allow";
    case DestinationAction::Warn:
      return L"warn";
    case DestinationAction::Block:
      return L"block";
    case DestinationAction::DegradedAllow:
      return L"degraded_allow";
    default:
      return L"unknown";
  }
}

DestinationAction DestinationActionFromString(std::wstring value) {
  value = ToLowerCopy(TrimCopy(std::move(value)));
  if (value == L"allow") {
    return DestinationAction::Allow;
  }
  if (value == L"warn") {
    return DestinationAction::Warn;
  }
  if (value == L"block") {
    return DestinationAction::Block;
  }
  if (value == L"degraded_allow" || value == L"degraded-allow") {
    return DestinationAction::DegradedAllow;
  }
  return DestinationAction::Unknown;
}

std::wstring DestinationThreatCategoryToString(const DestinationThreatCategory value) {
  switch (value) {
    case DestinationThreatCategory::Clean:
      return L"clean";
    case DestinationThreatCategory::Suspicious:
      return L"suspicious";
    case DestinationThreatCategory::Malware:
      return L"malware";
    case DestinationThreatCategory::Phishing:
      return L"phishing";
    case DestinationThreatCategory::Scam:
      return L"scam";
    case DestinationThreatCategory::CommandAndControl:
      return L"command_and_control";
    default:
      return L"unknown";
  }
}

DestinationThreatCategory DestinationThreatCategoryFromString(std::wstring value) {
  value = ToLowerCopy(TrimCopy(std::move(value)));
  if (value == L"clean") {
    return DestinationThreatCategory::Clean;
  }
  if (value == L"suspicious") {
    return DestinationThreatCategory::Suspicious;
  }
  if (value == L"malware") {
    return DestinationThreatCategory::Malware;
  }
  if (value == L"phishing") {
    return DestinationThreatCategory::Phishing;
  }
  if (value == L"scam") {
    return DestinationThreatCategory::Scam;
  }
  if (value == L"command_and_control" || value == L"command-and-control" || value == L"c2") {
    return DestinationThreatCategory::CommandAndControl;
  }
  return DestinationThreatCategory::Unknown;
}

std::wstring DestinationReasonCodeToString(const DestinationReasonCode value) {
  switch (value) {
    case DestinationReasonCode::KnownMaliciousDestination:
      return L"known_malicious_destination";
    case DestinationReasonCode::KnownPhishingDestination:
      return L"known_phishing_destination";
    case DestinationReasonCode::KnownScamDestination:
      return L"known_scam_destination";
    case DestinationReasonCode::SuspiciousNewlyRegisteredDomain:
      return L"suspicious_newly_registered_domain";
    case DestinationReasonCode::SuspiciousTld:
      return L"suspicious_tld";
    case DestinationReasonCode::TyposquattingMatch:
      return L"typosquatting_match";
    case DestinationReasonCode::HomographMatch:
      return L"homograph_match";
    case DestinationReasonCode::BrandImpersonation:
      return L"brand_impersonation";
    case DestinationReasonCode::SuspiciousRedirectChain:
      return L"suspicious_redirect_chain";
    case DestinationReasonCode::UrlShortenerRisk:
      return L"url_shortener_risk";
    case DestinationReasonCode::EncodedParameters:
      return L"encoded_parameters";
    case DestinationReasonCode::MismatchedBrandDomain:
      return L"mismatched_brand_domain";
    case DestinationReasonCode::ExcessiveSubdomainDepth:
      return L"excessive_subdomain_depth";
    case DestinationReasonCode::ExcessiveQueryTokens:
      return L"excessive_query_tokens";
    case DestinationReasonCode::CredentialHarvestingKeyword:
      return L"credential_harvesting_keyword";
    case DestinationReasonCode::EmailDeliveredLink:
      return L"email_delivered_link";
    case DestinationReasonCode::BrowserDeliveredNavigation:
      return L"browser_delivered_navigation";
    case DestinationReasonCode::AttachmentDeliveredLink:
      return L"attachment_delivered_link";
    case DestinationReasonCode::LocalPolicyAllow:
      return L"local_policy_allow";
    case DestinationReasonCode::LocalPolicyWarn:
      return L"local_policy_warn";
    case DestinationReasonCode::LocalPolicyBlock:
      return L"local_policy_block";
    case DestinationReasonCode::CacheHit:
      return L"cache_hit";
    case DestinationReasonCode::CloudLookupUnavailable:
      return L"cloud_lookup_unavailable";
    default:
      return L"none";
  }
}

DestinationReasonCode DestinationReasonCodeFromString(std::wstring value) {
  value = ToLowerCopy(TrimCopy(std::move(value)));
  if (value == L"known_malicious_destination") {
    return DestinationReasonCode::KnownMaliciousDestination;
  }
  if (value == L"known_phishing_destination") {
    return DestinationReasonCode::KnownPhishingDestination;
  }
  if (value == L"known_scam_destination") {
    return DestinationReasonCode::KnownScamDestination;
  }
  if (value == L"suspicious_newly_registered_domain") {
    return DestinationReasonCode::SuspiciousNewlyRegisteredDomain;
  }
  if (value == L"suspicious_tld") {
    return DestinationReasonCode::SuspiciousTld;
  }
  if (value == L"typosquatting_match") {
    return DestinationReasonCode::TyposquattingMatch;
  }
  if (value == L"homograph_match") {
    return DestinationReasonCode::HomographMatch;
  }
  if (value == L"brand_impersonation") {
    return DestinationReasonCode::BrandImpersonation;
  }
  if (value == L"suspicious_redirect_chain") {
    return DestinationReasonCode::SuspiciousRedirectChain;
  }
  if (value == L"url_shortener_risk") {
    return DestinationReasonCode::UrlShortenerRisk;
  }
  if (value == L"encoded_parameters") {
    return DestinationReasonCode::EncodedParameters;
  }
  if (value == L"mismatched_brand_domain") {
    return DestinationReasonCode::MismatchedBrandDomain;
  }
  if (value == L"excessive_subdomain_depth") {
    return DestinationReasonCode::ExcessiveSubdomainDepth;
  }
  if (value == L"excessive_query_tokens") {
    return DestinationReasonCode::ExcessiveQueryTokens;
  }
  if (value == L"credential_harvesting_keyword") {
    return DestinationReasonCode::CredentialHarvestingKeyword;
  }
  if (value == L"email_delivered_link") {
    return DestinationReasonCode::EmailDeliveredLink;
  }
  if (value == L"browser_delivered_navigation") {
    return DestinationReasonCode::BrowserDeliveredNavigation;
  }
  if (value == L"attachment_delivered_link") {
    return DestinationReasonCode::AttachmentDeliveredLink;
  }
  if (value == L"local_policy_allow") {
    return DestinationReasonCode::LocalPolicyAllow;
  }
  if (value == L"local_policy_warn") {
    return DestinationReasonCode::LocalPolicyWarn;
  }
  if (value == L"local_policy_block") {
    return DestinationReasonCode::LocalPolicyBlock;
  }
  if (value == L"cache_hit") {
    return DestinationReasonCode::CacheHit;
  }
  if (value == L"cloud_lookup_unavailable") {
    return DestinationReasonCode::CloudLookupUnavailable;
  }
  return DestinationReasonCode::None;
}

std::wstring JoinDestinationReasonCodes(const std::vector<DestinationReasonCode>& values) {
  std::wstringstream stream;
  bool first = true;
  for (const auto value : values) {
    const auto token = DestinationReasonCodeToString(value);
    if (token.empty() || token == L"none") {
      continue;
    }

    if (!first) {
      stream << L";";
    }
    stream << token;
    first = false;
  }
  return stream.str();
}

std::vector<DestinationReasonCode> SplitDestinationReasonCodes(std::wstring_view value) {
  std::vector<DestinationReasonCode> results;
  std::wstring current;

  for (const auto ch : value) {
    if (ch == L';' || ch == L',') {
      const auto parsed = DestinationReasonCodeFromString(current);
      if (parsed != DestinationReasonCode::None) {
        results.push_back(parsed);
      }
      current.clear();
      continue;
    }
    current.push_back(ch);
  }

  const auto parsed = DestinationReasonCodeFromString(current);
  if (parsed != DestinationReasonCode::None) {
    results.push_back(parsed);
  }
  return results;
}

std::wstring NormalizeDestinationIndicator(const ThreatIndicatorType indicatorType, std::wstring value) {
  value = TrimCopy(std::move(value));
  if (value.empty()) {
    return {};
  }

  if (indicatorType == ThreatIndicatorType::Domain || indicatorType == ThreatIndicatorType::Url ||
      indicatorType == ThreatIndicatorType::Ip) {
    value = ToLowerCopy(std::move(value));
  }

  while (!value.empty() && (value.back() == L'/' || value.back() == L'.')) {
    value.pop_back();
  }

  return value;
}

std::wstring BuildDestinationSummary(const DestinationVerdict& verdict) {
  std::wstring subject = verdict.host.empty() ? verdict.indicator : verdict.host;
  if (subject.empty()) {
    subject = verdict.canonicalUrl;
  }
  if (subject.empty()) {
    subject = L"destination";
  }

  switch (verdict.action) {
    case DestinationAction::Block:
      return L"Blocked risky destination: " + subject;
    case DestinationAction::Warn:
      return L"Suspicious destination warning: " + subject;
    case DestinationAction::DegradedAllow:
      return L"Allowed destination in degraded mode: " + subject;
    case DestinationAction::Allow:
      return L"Allowed destination: " + subject;
    default:
      return L"Destination evaluation recorded: " + subject;
  }
}

DestinationAction DetermineDestinationAction(const DestinationPolicySnapshot& policy,
                                             const DestinationThreatCategory category,
                                             const std::uint32_t confidence,
                                             const bool knownBad,
                                             const bool suspicious,
                                             const bool offlineMode) {
  if (!policy.destinationProtectionEnabled) {
    return DestinationAction::Allow;
  }

  if (offlineMode && policy.allowDegradedModeWhenOffline) {
    return DestinationAction::DegradedAllow;
  }

  switch (category) {
    case DestinationThreatCategory::Malware:
    case DestinationThreatCategory::CommandAndControl:
      return policy.blockKnownMaliciousDestinations || knownBad ? DestinationAction::Block
                                                                : DestinationAction::Warn;
    case DestinationThreatCategory::Phishing:
      if ((policy.blockKnownPhishingDestinations && knownBad) || confidence >= policy.phishingBlockThreshold) {
        return DestinationAction::Block;
      }
      if (confidence >= policy.phishingWarnThreshold || suspicious) {
        return DestinationAction::Warn;
      }
      return DestinationAction::Allow;
    case DestinationThreatCategory::Scam:
      if (policy.blockKnownScamDestinations && knownBad) {
        return DestinationAction::Block;
      }
      return policy.warnOnSuspiciousDestinations ? DestinationAction::Warn : DestinationAction::Allow;
    case DestinationThreatCategory::Suspicious:
      if (policy.warnOnSuspiciousDestinations &&
          (confidence >= policy.suspiciousWarnThreshold || suspicious)) {
        return DestinationAction::Warn;
      }
      return DestinationAction::Allow;
    default:
      return DestinationAction::Allow;
  }
}

std::wstring SerializeDestinationVerdictJson(const DestinationVerdict& verdict,
                                             const DestinationContext& context) {
  std::wstringstream stream;
  stream << L"{"
         << L"\"indicatorType\":\"" << JsonEscape(ThreatIndicatorTypeToString(verdict.indicatorType)) << L"\"," 
         << L"\"indicator\":\"" << JsonEscape(verdict.indicator) << L"\"," 
         << L"\"canonicalUrl\":\"" << JsonEscape(verdict.canonicalUrl) << L"\"," 
         << L"\"host\":\"" << JsonEscape(verdict.host) << L"\"," 
         << L"\"source\":\"" << JsonEscape(verdict.source) << L"\"," 
         << L"\"provider\":\"" << JsonEscape(verdict.provider) << L"\"," 
         << L"\"action\":\"" << JsonEscape(DestinationActionToString(verdict.action)) << L"\"," 
         << L"\"category\":\"" << JsonEscape(DestinationThreatCategoryToString(verdict.category)) << L"\"," 
         << L"\"confidence\":" << verdict.confidence << L"," 
         << L"\"reasonCodes\":\"" << JsonEscape(JoinDestinationReasonCodes(verdict.reasonCodes)) << L"\"," 
         << L"\"knownBad\":" << (verdict.knownBad ? L"true" : L"false") << L"," 
         << L"\"suspicious\":" << (verdict.suspicious ? L"true" : L"false") << L"," 
         << L"\"fromCache\":" << (verdict.fromCache ? L"true" : L"false") << L"," 
         << L"\"degradedMode\":" << (verdict.degradedMode ? L"true" : L"false") << L"," 
         << L"\"browserInitiated\":" << (context.browserInitiated ? L"true" : L"false") << L"," 
         << L"\"emailOriginated\":" << (context.emailOriginated ? L"true" : L"false") << L"," 
         << L"\"attachmentOriginated\":" << (context.attachmentOriginated ? L"true" : L"false") << L"," 
         << L"\"browserFamily\":\"" << JsonEscape(context.browserFamily) << L"\"," 
         << L"\"deliveryVector\":\"" << JsonEscape(context.deliveryVector) << L"\"," 
         << L"\"sourceApplication\":\"" << JsonEscape(context.sourceApplication) << L"\""
         << L"}";
  return stream.str();
}

}  // namespace antivirus::agent
