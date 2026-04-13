#include "SupportBundleService.h"

#include <Windows.h>

#include <algorithm>
#include <chrono>
#include <fstream>
#include <system_error>
#include <vector>

#include "RuntimeDatabase.h"
#include "StringUtils.h"
#include "WscCoexistenceManager.h"

namespace antivirus::agent {
namespace {

constexpr int kSupportBundleRetentionDays = 30;
constexpr int kEvidenceRetentionDays = 30;
constexpr int kUpdateArtifactRetentionDays = 30;

std::wstring SanitizeFileNameComponent(std::wstring value) {
  for (auto& ch : value) {
    switch (ch) {
      case L'\\':
      case L'/':
      case L':':
      case L'*':
      case L'?':
      case L'"':
      case L'<':
      case L'>':
      case L'|':
        ch = L'-';
        break;
      default:
        break;
    }
  }
  return value;
}

std::wstring JsonBool(const bool value) {
  return value ? L"true" : L"false";
}

std::wstring JsonString(const std::wstring& value) {
  return L"\"" + Utf8ToWide(EscapeJsonString(value)) + L"\"";
}

std::wstring JsonPath(const std::filesystem::path& path) {
  return JsonString(path.wstring());
}

std::wstring StatusToJson(const WscCoexistenceSnapshot& snapshot) {
  return WscCoexistenceManager::ToJson(snapshot);
}

bool CopyIfExists(const std::filesystem::path& source, const std::filesystem::path& destination) {
  std::error_code error;
  if (!std::filesystem::exists(source, error) || error) {
    return false;
  }

  std::filesystem::create_directories(destination.parent_path(), error);
  error.clear();
  return std::filesystem::copy_file(source, destination, std::filesystem::copy_options::overwrite_existing, error) &&
         !error;
}

std::wstring BuildSupportBundleManifest(const AgentConfig& config, const AgentState& state,
                                        const PolicySnapshot& policy, const bool sanitized) {
  RuntimeDatabase database(config.runtimeDatabasePath);
  const auto quarantine = database.ListQuarantineRecords(50);
  const auto evidence = database.ListEvidenceRecords(50);
  const auto scans = database.ListScanHistory(50);
  const auto updates = database.ListUpdateJournal(20);
  const auto patchHistory = database.ListPatchHistoryRecords(50);
  const auto softwarePatches = database.ListSoftwarePatchRecords(50);
  const auto windowsUpdates = database.ListWindowsUpdateRecords(50);
  RebootCoordinatorRecord reboot{};
  database.LoadRebootCoordinator(reboot);

  const WscCoexistenceManager wscManager;
  const auto wsc = wscManager.CaptureSnapshot();

  std::wstring json = L"{";
  json += L"\"formatVersion\":\"fenrir-support-bundle-v1\",";
  json += L"\"generatedAt\":" + JsonString(CurrentUtcTimestamp()) + L",";
  json += L"\"sanitized\":" + JsonBool(sanitized) + L",";
  json += L"\"deviceId\":" + JsonString(state.deviceId) + L",";
  json += L"\"hostname\":" + JsonString(state.hostname) + L",";
  json += L"\"healthState\":" + JsonString(state.healthState) + L",";
  json += L"\"agentVersion\":" + JsonString(state.agentVersion) + L",";
  json += L"\"platformVersion\":" + JsonString(state.platformVersion) + L",";
  json += L"\"policy\":{";
  json += L"\"policyName\":" + JsonString(policy.policyName) + L",";
  json += L"\"revision\":" + JsonString(policy.revision) + L",";
  json += L"\"realtimeProtectionEnabled\":" + JsonBool(policy.realtimeProtectionEnabled) + L",";
  json += L"\"scriptInspectionEnabled\":" + JsonBool(policy.scriptInspectionEnabled) + L",";
  json += L"\"networkContainmentEnabled\":" + JsonBool(policy.networkContainmentEnabled) + L"},";
  json += L"\"paths\":{";
  json += L"\"runtimeDatabasePath\":" + JsonPath(config.runtimeDatabasePath) + L",";
  json += L"\"stateFilePath\":" + JsonPath(config.stateFilePath) + L",";
  json += L"\"telemetryQueuePath\":" + JsonPath(config.telemetryQueuePath) + L",";
  json += L"\"updateRootPath\":" + JsonPath(config.updateRootPath) + L",";
  json += L"\"journalRootPath\":" + JsonPath(config.journalRootPath) + L",";
  json += L"\"quarantineRootPath\":" + JsonPath(config.quarantineRootPath) + L",";
  json += L"\"evidenceRootPath\":" + JsonPath(config.evidenceRootPath) + L"},";
  json += L"\"counts\":{";
  json += L"\"quarantine\":" + std::to_wstring(quarantine.size()) + L",";
  json += L"\"evidence\":" + std::to_wstring(evidence.size()) + L",";
  json += L"\"scanHistory\":" + std::to_wstring(scans.size()) + L",";
  json += L"\"updateJournal\":" + std::to_wstring(updates.size()) + L",";
  json += L"\"patchHistory\":" + std::to_wstring(patchHistory.size()) + L",";
  json += L"\"softwarePatches\":" + std::to_wstring(softwarePatches.size()) + L",";
  json += L"\"windowsUpdates\":" + std::to_wstring(windowsUpdates.size()) + L"},";
  json += L"\"reboot\":{";
  json += L"\"required\":" + JsonBool(reboot.rebootRequired) + L",";
  json += L"\"reasons\":" + JsonString(reboot.rebootReasons) + L",";
  json += L"\"status\":" + JsonString(reboot.status) + L"},";
  json += L"\"windowsSecurityCenter\":" + StatusToJson(wsc) + L",";

  json += L"\"recentThreats\":[";
  for (std::size_t index = 0; index < scans.size(); ++index) {
    const auto& record = scans[index];
    if (index != 0) {
      json += L",";
    }
    json += L"{\"recordedAt\":" + JsonString(record.recordedAt) + L",\"source\":" + JsonString(record.source) +
            L",\"subjectPath\":" + JsonPath(sanitized ? record.subjectPath.filename() : record.subjectPath) +
            L",\"sha256\":" + JsonString(record.sha256) + L",\"disposition\":" + JsonString(record.disposition) +
            L",\"techniqueId\":" + JsonString(record.techniqueId) + L",\"remediationStatus\":" +
            JsonString(record.remediationStatus) + L"}";
  }
  json += L"],";

  json += L"\"patchHistory\":[";
  for (std::size_t index = 0; index < patchHistory.size(); ++index) {
    const auto& record = patchHistory[index];
    if (index != 0) {
      json += L",";
    }
    json += L"{\"recordId\":" + JsonString(record.recordId) + L",\"targetType\":" + JsonString(record.targetType) +
            L",\"targetId\":" + JsonString(record.targetId) + L",\"title\":" + JsonString(record.title) +
            L",\"provider\":" + JsonString(record.provider) + L",\"action\":" + JsonString(record.action) +
            L",\"status\":" + JsonString(record.status) + L",\"errorCode\":" + JsonString(record.errorCode) +
            L",\"rebootRequired\":" + JsonBool(record.rebootRequired) + L"}";
  }
  json += L"],";

  json += L"\"updateJournal\":[";
  for (std::size_t index = 0; index < updates.size(); ++index) {
    const auto& record = updates[index];
    if (index != 0) {
      json += L",";
    }
    json += L"{\"transactionId\":" + JsonString(record.transactionId) + L",\"packageId\":" +
            JsonString(record.packageId) + L",\"packageType\":" + JsonString(record.packageType) +
            L",\"targetVersion\":" + JsonString(record.targetVersion) + L",\"status\":" +
            JsonString(record.status) + L",\"requiresRestart\":" + JsonBool(record.requiresRestart) + L"}";
  }
  json += L"]";

  json += L"}";
  return json;
}

bool IsOlderThanDays(const std::filesystem::path& path, const int days) {
  std::error_code error;
  const auto lastWrite = std::filesystem::last_write_time(path, error);
  if (error) {
    return false;
  }

  const auto now = std::filesystem::file_time_type::clock::now();
  const auto age = now - lastWrite;
  const auto maxAge = std::chrono::hours(24 * days);
  return age > maxAge;
}

void ReclaimPath(const std::filesystem::path& path, std::size_t* deletedEntries, std::uintmax_t* reclaimedBytes) {
  std::error_code error;
  if (!std::filesystem::exists(path, error) || error) {
    return;
  }

  const auto size = std::filesystem::is_regular_file(path, error) ? std::filesystem::file_size(path, error) : 0;
  error.clear();
  const auto removed = std::filesystem::remove_all(path, error);
  if (!error && removed > 0) {
    *deletedEntries += static_cast<std::size_t>(removed);
    *reclaimedBytes += size;
  }
}

void PruneDirectory(const std::filesystem::path& root, const int retentionDays, std::size_t* deletedEntries,
                    std::uintmax_t* reclaimedBytes) {
  std::error_code error;
  if (!std::filesystem::exists(root, error) || error) {
    return;
  }

  for (const auto& entry : std::filesystem::directory_iterator(root, error)) {
    if (error) {
      error.clear();
      continue;
    }

    if (IsOlderThanDays(entry.path(), retentionDays)) {
      ReclaimPath(entry.path(), deletedEntries, reclaimedBytes);
    }
  }
}

}  // namespace

SupportBundleResult ExportSupportBundle(const AgentConfig& config, const AgentState& state,
                                       const PolicySnapshot& policy, const bool sanitized) {
  SupportBundleResult result{};
  result.sanitized = sanitized;

  try {
    const auto bundleRoot =
        config.journalRootPath / L"support" /
        (SanitizeFileNameComponent(CurrentUtcTimestamp()) + L"-" + GenerateGuidString());
    std::error_code error;
    std::filesystem::create_directories(bundleRoot, error);
    if (error) {
      throw std::runtime_error("Could not create support bundle directory");
    }

    const auto manifestPath = bundleRoot / L"support-bundle.json";
    std::wofstream manifestStream(manifestPath, std::ios::binary | std::ios::trunc);
    if (!manifestStream.is_open()) {
      throw std::runtime_error("Could not create support bundle manifest");
    }
    manifestStream << BuildSupportBundleManifest(config, state, policy, sanitized);
    manifestStream.close();

    result.bundleRoot = bundleRoot;
    result.manifestPath = manifestPath;
    result.copiedFileCount = 1;

    if (!sanitized) {
      const auto filesRoot = bundleRoot / L"files";
      std::error_code fileError;
      std::filesystem::create_directories(filesRoot, fileError);

      if (CopyIfExists(config.runtimeDatabasePath, filesRoot / L"agent-runtime.db")) {
        ++result.copiedFileCount;
      }
      if (CopyIfExists(config.stateFilePath, filesRoot / config.stateFilePath.filename())) {
        ++result.copiedFileCount;
      }
      if (CopyIfExists(config.telemetryQueuePath, filesRoot / config.telemetryQueuePath.filename())) {
        ++result.copiedFileCount;
      }
    }

    result.success = true;
    return result;
  } catch (const std::exception& error) {
    result.errorMessage = Utf8ToWide(error.what());
    return result;
  }
}

StorageMaintenanceResult RunStorageMaintenance(const AgentConfig& config) {
  StorageMaintenanceResult result{};

  try {
    PruneDirectory(config.journalRootPath / L"support", kSupportBundleRetentionDays, &result.deletedEntries,
                   &result.reclaimedBytes);
    PruneDirectory(config.updateRootPath / L"staged", kUpdateArtifactRetentionDays, &result.deletedEntries,
                   &result.reclaimedBytes);
    PruneDirectory(config.updateRootPath / L"backups", kUpdateArtifactRetentionDays, &result.deletedEntries,
                   &result.reclaimedBytes);
    PruneDirectory(config.evidenceRootPath, kEvidenceRetentionDays, &result.deletedEntries, &result.reclaimedBytes);

    result.success = true;
    result.summary = L"Deleted " + std::to_wstring(result.deletedEntries) + L" expired maintenance entries and reclaimed " +
                     std::to_wstring(result.reclaimedBytes) + L" byte(s).";
    return result;
  } catch (const std::exception& error) {
    result.errorMessage = Utf8ToWide(error.what());
    return result;
  }
}

}  // namespace antivirus::agent
