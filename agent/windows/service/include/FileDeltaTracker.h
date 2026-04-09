#pragma once

#include <unordered_map>
#include <vector>

#include "FileInventory.h"
#include "TelemetryRecord.h"

namespace antivirus::agent {

class FileDeltaTracker {
 public:
  std::vector<TelemetryRecord> CollectDeltaTelemetry(const std::vector<FileObservation>& currentInventory);

 private:
  bool initialized_{false};
  std::unordered_map<std::wstring, FileObservation> previousByPath_{};
};

}  // namespace antivirus::agent
