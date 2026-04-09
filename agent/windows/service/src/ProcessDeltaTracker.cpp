#include "ProcessDeltaTracker.h"

#include <algorithm>
#include <sstream>

#include "StringUtils.h"

namespace antivirus::agent {
namespace {

std::wstring BuildPayload(const ProcessObservation& observation) {
  return std::wstring(L"{\"pid\":") + std::to_wstring(observation.pid) + L",\"parentPid\":" +
         std::to_wstring(observation.parentPid) + L",\"imageName\":\"" +
         Utf8ToWide(EscapeJsonString(observation.imageName)) + L"\"}";
}

TelemetryRecord BuildTelemetryRecord(const std::wstring& eventType, const ProcessObservation& observation,
                                     const std::wstring& summary) {
  return TelemetryRecord{
      .eventId = GenerateGuidString(),
      .eventType = eventType,
      .source = L"process-delta",
      .summary = summary,
      .occurredAt = CurrentUtcTimestamp(),
      .payloadJson = BuildPayload(observation)};
}

}  // namespace

std::vector<TelemetryRecord> ProcessDeltaTracker::CollectDeltaTelemetry(
    const std::vector<ProcessObservation>& currentInventory) {
  std::unordered_map<unsigned long, ProcessObservation> currentByPid;
  currentByPid.reserve(currentInventory.size());

  for (const auto& observation : currentInventory) {
    currentByPid.insert_or_assign(observation.pid, observation);
  }

  std::vector<TelemetryRecord> records;

  if (!initialized_) {
    previousByPid_ = std::move(currentByPid);
    initialized_ = true;
    return records;
  }

  for (const auto& [pid, observation] : currentByPid) {
    if (!previousByPid_.contains(pid)) {
      std::wstringstream summary;
      summary << L"Process " << observation.imageName << L" started with PID " << observation.pid
              << L" and parent PID " << observation.parentPid << L".";
      records.push_back(BuildTelemetryRecord(L"process.started", observation, summary.str()));
    }
  }

  for (const auto& [pid, observation] : previousByPid_) {
    if (!currentByPid.contains(pid)) {
      std::wstringstream summary;
      summary << L"Process " << observation.imageName << L" exited after running with PID " << observation.pid
              << L".";
      records.push_back(BuildTelemetryRecord(L"process.exited", observation, summary.str()));
    }
  }

  previousByPid_ = std::move(currentByPid);

  std::sort(records.begin(), records.end(), [](const TelemetryRecord& left, const TelemetryRecord& right) {
    return left.eventType < right.eventType;
  });

  return records;
}

}  // namespace antivirus::agent
