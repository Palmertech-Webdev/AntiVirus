#pragma once

#include <filesystem>
#include <string>

#include "AgentConfig.h"
#include "AgentState.h"
#include "PolicySnapshot.h"

namespace antivirus::agent {

struct SupportBundleResult {
  bool success{false};
  bool sanitized{true};
  std::filesystem::path bundleRoot;
  std::filesystem::path manifestPath;
  std::size_t copiedFileCount{0};
  std::wstring errorMessage;
};

struct StorageMaintenanceResult {
  bool success{false};
  std::size_t deletedEntries{0};
  std::uintmax_t reclaimedBytes{0};
  std::wstring summary;
  std::wstring errorMessage;
};

SupportBundleResult ExportSupportBundle(const AgentConfig& config, const AgentState& state,
                                       const PolicySnapshot& policy, bool sanitized);

StorageMaintenanceResult RunStorageMaintenance(const AgentConfig& config);

}  // namespace antivirus::agent
