#include "FileDeltaTracker.h"

#include <algorithm>
#include <sstream>

#include "StringUtils.h"

namespace antivirus::agent {
namespace {

std::wstring BuildPayload(const FileObservation& observation) {
  return std::wstring(L"{\"path\":\"") + Utf8ToWide(EscapeJsonString(observation.path.wstring())) +
         L"\",\"sizeBytes\":" + std::to_wstring(observation.sizeBytes) + L",\"lastWriteTime\":\"" +
         observation.lastWriteTimeUtc + L"\"}";
}

TelemetryRecord BuildTelemetryRecord(const std::wstring& eventType, const FileObservation& observation,
                                     const std::wstring& summary) {
  return TelemetryRecord{
      .eventId = GenerateGuidString(),
      .eventType = eventType,
      .source = L"file-delta",
      .summary = summary,
      .occurredAt = CurrentUtcTimestamp(),
      .payloadJson = BuildPayload(observation)};
}

}  // namespace

std::vector<TelemetryRecord> FileDeltaTracker::CollectDeltaTelemetry(const std::vector<FileObservation>& currentInventory) {
  std::unordered_map<std::wstring, FileObservation> currentByPath;
  currentByPath.reserve(currentInventory.size());

  for (const auto& observation : currentInventory) {
    currentByPath.insert_or_assign(observation.path.wstring(), observation);
  }

  std::vector<TelemetryRecord> records;

  if (!initialized_) {
    previousByPath_ = std::move(currentByPath);
    initialized_ = true;
    return records;
  }

  for (const auto& [path, observation] : currentByPath) {
    const auto previous = previousByPath_.find(path);
    if (previous == previousByPath_.end()) {
      std::wstringstream summary;
      summary << L"File " << observation.path.filename().wstring() << L" was created in "
              << observation.path.parent_path().wstring() << L".";
      records.push_back(BuildTelemetryRecord(L"file.created", observation, summary.str()));
      continue;
    }

    if (previous->second.sizeBytes != observation.sizeBytes ||
        previous->second.lastWriteTimeUtc != observation.lastWriteTimeUtc) {
      std::wstringstream summary;
      summary << L"File " << observation.path.filename().wstring() << L" changed in "
              << observation.path.parent_path().wstring() << L".";
      records.push_back(BuildTelemetryRecord(L"file.modified", observation, summary.str()));
    }
  }

  for (const auto& [path, observation] : previousByPath_) {
    if (!currentByPath.contains(path)) {
      std::wstringstream summary;
      summary << L"File " << observation.path.filename().wstring() << L" was removed from "
              << observation.path.parent_path().wstring() << L".";
      records.push_back(BuildTelemetryRecord(L"file.deleted", observation, summary.str()));
    }
  }

  previousByPath_ = std::move(currentByPath);

  std::sort(records.begin(), records.end(), [](const TelemetryRecord& left, const TelemetryRecord& right) {
    return left.eventType < right.eventType;
  });

  return records;
}

}  // namespace antivirus::agent
