#pragma once

#include <unordered_map>
#include <vector>

#include "ProcessInventory.h"
#include "TelemetryRecord.h"

namespace antivirus::agent {

class ProcessDeltaTracker {
 public:
  std::vector<TelemetryRecord> CollectDeltaTelemetry(const std::vector<ProcessObservation>& currentInventory);

 private:
  bool initialized_{false};
  std::unordered_map<unsigned long, ProcessObservation> previousByPid_{};
};

}  // namespace antivirus::agent
