#pragma once

#include <filesystem>
#include <vector>

#include "FileInventory.h"
#include "TelemetryRecord.h"

namespace antivirus::agent {

std::vector<TelemetryRecord> BuildRecentFileTelemetry(const std::vector<FileObservation>& inventory,
                                                      std::size_t maxRecords);
std::vector<TelemetryRecord> CollectRecentFileTelemetry(const std::vector<std::filesystem::path>& roots,
                                                        std::size_t maxRecords);

}  // namespace antivirus::agent
