#include "ServiceSnapshotCollector.h"

#include <algorithm>
#include <sstream>

#include "StringUtils.h"

namespace antivirus::agent {
namespace {

std::wstring BuildServicePayload(const ServiceObservation& entry) {
  return std::wstring(L"{\"serviceName\":\"") + Utf8ToWide(EscapeJsonString(entry.serviceName)) +
         L"\",\"displayName\":\"" + Utf8ToWide(EscapeJsonString(entry.displayName)) +
         L"\",\"binaryPath\":\"" + Utf8ToWide(EscapeJsonString(entry.binaryPath)) +
         L"\",\"accountName\":\"" + Utf8ToWide(EscapeJsonString(entry.accountName)) +
         L"\",\"startType\":\"" + entry.startType + L"\",\"currentState\":\"" + entry.currentState +
         L"\",\"processId\":" + std::to_wstring(entry.processId) + L",\"risky\":" +
         (entry.risky ? std::wstring(L"true") : std::wstring(L"false")) + L"}";
}

}  // namespace

std::vector<TelemetryRecord> BuildServiceSnapshotTelemetry(const std::vector<ServiceObservation>& inventory,
                                                           const std::size_t maxRecords) {
  std::vector<TelemetryRecord> results;
  const auto recordCount = maxRecords == 0 ? inventory.size() : std::min<std::size_t>(inventory.size(), maxRecords);
  results.reserve(recordCount);

  for (std::size_t index = 0; index < recordCount; ++index) {
    const auto& service = inventory[index];
    std::wstringstream summary;
    summary << L"Observed service " << service.displayName << L" (" << service.serviceName << L")";
    if (service.risky) {
      summary << L" and flagged it for review.";
    } else {
      summary << L".";
    }

    results.push_back(TelemetryRecord{
        .eventId = GenerateGuidString(),
        .eventType = L"service.snapshot",
        .source = L"service-snapshot",
        .summary = summary.str(),
        .occurredAt = CurrentUtcTimestamp(),
        .payloadJson = BuildServicePayload(service)});
  }

  return results;
}

std::vector<TelemetryRecord> CollectServiceSnapshotTelemetry(const std::size_t maxRecords) {
  return BuildServiceSnapshotTelemetry(CollectServiceInventory(maxRecords), maxRecords);
}

}  // namespace antivirus::agent