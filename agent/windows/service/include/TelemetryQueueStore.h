#pragma once

#include <filesystem>
#include <vector>

#include "TelemetryRecord.h"

namespace antivirus::agent {

class TelemetryQueueStore {
 public:
  TelemetryQueueStore(std::filesystem::path databasePath, std::filesystem::path legacyQueueFilePath = {});

  std::vector<TelemetryRecord> LoadPending() const;
  void SavePending(const std::vector<TelemetryRecord>& events) const;

 private:
  std::filesystem::path databasePath_;
  std::filesystem::path legacyQueueFilePath_;
};

}  // namespace antivirus::agent
