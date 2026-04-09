#include "ProcessSnapshotCollector.h"

#include <sstream>

#include "ProcessInventory.h"
#include "StringUtils.h"

namespace antivirus::agent {
namespace {

std::wstring BuildProcessPayload(const ProcessObservation& entry) {
  return std::wstring(L"{\"pid\":") + std::to_wstring(entry.pid) + L",\"parentPid\":" +
         std::to_wstring(entry.parentPid) + L",\"imageName\":\"" +
         Utf8ToWide(EscapeJsonString(entry.imageName)) + L"\"}";
}

}  // namespace

std::vector<TelemetryRecord> BuildProcessSnapshotTelemetry(const std::vector<ProcessObservation>& inventory,
                                                           std::size_t maxRecords) {
  std::vector<TelemetryRecord> results;
  const auto recordCount = maxRecords == 0 ? inventory.size() : std::min<std::size_t>(inventory.size(), maxRecords);
  results.reserve(recordCount);

  for (std::size_t index = 0; index < recordCount; ++index) {
    const auto& process = inventory[index];
    std::wstringstream summary;
    summary << L"Observed process " << process.imageName << L" (PID " << process.pid << L", parent PID "
            << process.parentPid << L").";

    results.push_back(TelemetryRecord{
        .eventId = GenerateGuidString(),
        .eventType = L"process.snapshot",
        .source = L"process-snapshot",
        .summary = summary.str(),
        .occurredAt = CurrentUtcTimestamp(),
        .payloadJson = BuildProcessPayload(process)});
  }

  return results;
}

std::vector<TelemetryRecord> CollectProcessSnapshotTelemetry(std::size_t maxRecords) {
  return BuildProcessSnapshotTelemetry(CollectProcessInventory(maxRecords), maxRecords);
}

}  // namespace antivirus::agent
