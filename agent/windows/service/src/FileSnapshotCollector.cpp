#include "FileSnapshotCollector.h"

#include <sstream>

#include "FileInventory.h"
#include "StringUtils.h"

namespace antivirus::agent {
namespace {

std::wstring BuildFilePayload(const FileObservation& entry) {
  return std::wstring(L"{\"path\":\"") + Utf8ToWide(EscapeJsonString(entry.path.wstring())) + L"\",\"sizeBytes\":" +
         std::to_wstring(entry.sizeBytes) + L",\"lastWriteTime\":\"" + entry.lastWriteTimeUtc + L"\"}";
}

}  // namespace

std::vector<TelemetryRecord> BuildRecentFileTelemetry(const std::vector<FileObservation>& inventory,
                                                      std::size_t maxRecords) {
  const auto recordCount = maxRecords == 0 ? inventory.size() : std::min<std::size_t>(inventory.size(), maxRecords);
  std::vector<TelemetryRecord> results;
  results.reserve(recordCount);

  for (std::size_t index = 0; index < recordCount; ++index) {
    const auto& file = inventory[index];
    std::wstringstream summary;
    summary << L"Observed file " << file.path.filename().wstring() << L" (" << file.sizeBytes << L" bytes) in "
            << file.path.parent_path().wstring() << L".";

    results.push_back(TelemetryRecord{
        .eventId = GenerateGuidString(),
        .eventType = L"file.snapshot",
        .source = L"file-snapshot",
        .summary = summary.str(),
        .occurredAt = CurrentUtcTimestamp(),
        .payloadJson = BuildFilePayload(file)});
  }

  return results;
}

std::vector<TelemetryRecord> CollectRecentFileTelemetry(const std::vector<std::filesystem::path>& roots,
                                                        std::size_t maxRecords) {
  return BuildRecentFileTelemetry(CollectFileInventory(roots, maxRecords), maxRecords);
}

}  // namespace antivirus::agent
