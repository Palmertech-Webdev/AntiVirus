#pragma once

#include <vector>

#include "ServiceInventory.h"
#include "TelemetryRecord.h"

namespace antivirus::agent {

std::vector<TelemetryRecord> BuildServiceSnapshotTelemetry(const std::vector<ServiceObservation>& inventory,
                                                           std::size_t maxRecords);
std::vector<TelemetryRecord> CollectServiceSnapshotTelemetry(std::size_t maxRecords);

}  // namespace antivirus::agent