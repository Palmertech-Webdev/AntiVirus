#pragma once

#include <filesystem>
#include <string>

#include "DestinationProtection.h"
#include "PolicySnapshot.h"
#include "RuntimeDatabase.h"

namespace antivirus::agent {

DestinationPolicySnapshot ProjectDestinationPolicy(const PolicySnapshot& policy);

ScanHistoryRecord BuildDestinationScanHistoryRecord(const DestinationContext& context,
                                                    const DestinationVerdict& verdict,
                                                    const DestinationEvidenceRecord& evidence);

DestinationIntelligenceRecord BuildDestinationIntelligenceRecord(const DestinationContext& context,
                                                                 const DestinationVerdict& verdict,
                                                                 const DestinationEvidenceRecord& evidence,
                                                                 std::uint32_t cacheTtlMinutes);

std::wstring BuildDestinationTelemetryPayload(const DestinationContext& context,
                                              const DestinationVerdict& verdict,
                                              const DestinationEvidenceRecord& evidence);

std::wstring BuildDestinationEventType(const DestinationVerdict& verdict);
std::wstring BuildDestinationEventSummary(const DestinationVerdict& verdict);

}  // namespace antivirus::agent
