#pragma once

#include <vector>

#include "ProcessInventory.h"
#include "TelemetryRecord.h"

namespace antivirus::agent {

std::vector<TelemetryRecord> BuildProcessSnapshotTelemetry(const std::vector<ProcessObservation>& inventory,
                                                           std::size_t maxRecords);
std::vector<TelemetryRecord> CollectProcessSnapshotTelemetry(std::size_t maxRecords);

}  // namespace antivirus::agent
