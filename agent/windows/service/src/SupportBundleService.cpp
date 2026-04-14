#include "SupportBundleService.h"

#include <Windows.h>

#include <algorithm>
#include <chrono>
#include <cwctype>
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
constexpr int kQuarantineRetentionDays = 60;
constexpr int kJournalRetentionDays = 30;

struct StorageGovernancePolicy {
  int supportRetentionDays{kSupportBundleRetentionDays};
  int evidenceRetentionDays{kEvidenceRetentionDays};
  int updateRetentionDays{kUpdateArtifactRetentionDays};
  int quarantineRetentionDays{kQuarantineRetentionDays};
  int journalRetentionDays{kJournalRetentionDays};
  std::uintmax_t supportQuotaBytes{1024ull * 1024ull * 1024ull};
  std::uintmax_t evidenceQuotaBytes{1024ull * 1024ull * 1024ull};
  std::uintmax_t updateQuotaBytes{1024ull * 1024ull * 2048ull};
  std::uintmax_t quarantineQuotaBytes{1024ull * 1024ull * 2048ull};
  std::uintmax_t journalQuotaBytes{1024ull * 1024ull * 512ull};
  std::uintmax_t lowDiskBytes{1024ull * 1024ull * 2048ull};
  bool secureDelete{false};
  int secureDeletePasses{1};
  bool aggressiveOnLowDisk{true};
};

int ParsePositiveInt(const std::wstring& rawValue, const int fallback) {
  if (rawValue.empty()) {
    return fallback;
  }

  try {
    return std::max(std::stoi(rawValue), 1);
  } catch (...) {
    return fallback;
  }
}

bool ParseBooleanValue(const std::wstring& rawValue, const bool fallback) {
  if (rawValue.empty()) {
    return fallback;
  }

  auto value = rawValue;
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  if (value == L"1" || value == L"true" || value == L"yes" || value == L"on") {
    return true;
  }
  if (value == L"0" || value == L"false" || value == L"no" || value == L"off") {
    return false;
  }

  return fallback;
}

std::uintmax_t MegabytesToBytes(const int megabytes) {
  return static_cast<std::uintmax_t>(std::max(megabytes, 1)) * 1024ull * 1024ull;
}

StorageGovernancePolicy LoadStorageGovernancePolicy() {
  StorageGovernancePolicy policy{};
  policy.supportRetentionDays =
      ParsePositiveInt(ReadEnvironmentVariable(L"ANTIVIRUS_SUPPORT_RETENTION_DAYS"), policy.supportRetentionDays);
  policy.evidenceRetentionDays =
      ParsePositiveInt(ReadEnvironmentVariable(L"ANTIVIRUS_EVIDENCE_RETENTION_DAYS"), policy.evidenceRetentionDays);
  policy.updateRetentionDays =
      ParsePositiveInt(ReadEnvironmentVariable(L"ANTIVIRUS_UPDATE_RETENTION_DAYS"), policy.updateRetentionDays);
  policy.quarantineRetentionDays =
      ParsePositiveInt(ReadEnvironmentVariable(L"ANTIVIRUS_QUARANTINE_RETENTION_DAYS"), policy.quarantineRetentionDays);
  policy.journalRetentionDays =
      ParsePositiveInt(ReadEnvironmentVariable(L"ANTIVIRUS_JOURNAL_RETENTION_DAYS"), policy.journalRetentionDays);

  policy.supportQuotaBytes = MegabytesToBytes(
      ParsePositiveInt(ReadEnvironmentVariable(L"ANTIVIRUS_STORAGE_QUOTA_SUPPORT_MB"), 1024));
  policy.evidenceQuotaBytes = MegabytesToBytes(
      ParsePositiveInt(ReadEnvironmentVariable(L"ANTIVIRUS_STORAGE_QUOTA_EVIDENCE_MB"), 1024));
  policy.updateQuotaBytes = MegabytesToBytes(
      ParsePositiveInt(ReadEnvironmentVariable(L"ANTIVIRUS_STORAGE_QUOTA_UPDATE_MB"), 2048));
  policy.quarantineQuotaBytes = MegabytesToBytes(
      ParsePositiveInt(ReadEnvironmentVariable(L"ANTIVIRUS_STORAGE_QUOTA_QUARANTINE_MB"), 2048));
  policy.journalQuotaBytes = MegabytesToBytes(
      ParsePositiveInt(ReadEnvironmentVariable(L"ANTIVIRUS_STORAGE_QUOTA_JOURNAL_MB"), 512));
  policy.lowDiskBytes = MegabytesToBytes(
      ParsePositiveInt(ReadEnvironmentVariable(L"ANTIVIRUS_STORAGE_LOW_DISK_MB"), 2048));

  policy.secureDelete =
      ParseBooleanValue(ReadEnvironmentVariable(L"ANTIVIRUS_STORAGE_SECURE_DELETE"), policy.secureDelete);
  policy.secureDeletePasses =
      ParsePositiveInt(ReadEnvironmentVariable(L"ANTIVIRUS_STORAGE_SECURE_DELETE_PASSES"), policy.secureDeletePasses);
  policy.aggressiveOnLowDisk =
      ParseBooleanValue(ReadEnvironmentVariable(L"ANTIVIRUS_STORAGE_AGGRESSIVE_LOW_DISK"), policy.aggressiveOnLowDisk);
  return policy;
}

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

std::uintmax_t ComputePathSizeBytes(const std::filesystem::path& path) {
  std::error_code error;
  if (!std::filesystem::exists(path, error) || error) {
    return 0;
  }

  if (std::filesystem::is_regular_file(path, error) && !error) {
    const auto fileSize = std::filesystem::file_size(path, error);
    return error ? 0 : fileSize;
  }

  std::uintmax_t total = 0;
  for (const auto& entry : std::filesystem::recursive_directory_iterator(path, error)) {
    if (error) {
      error.clear();
      continue;
    }
    if (entry.is_regular_file(error) && !error) {
      const auto fileSize = entry.file_size(error);
      if (!error) {
        total += fileSize;
      } else {
        error.clear();
      }
    }
  }

  return total;
}

bool SecureDeleteFile(const std::filesystem::path& path, const int passes) {
  if (passes <= 0) {
    return true;
  }

  const HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                  FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    return false;
  }

  LARGE_INTEGER size{};
  if (GetFileSizeEx(file, &size) == FALSE || size.QuadPart < 0) {
    CloseHandle(file);
    return false;
  }

  std::vector<char> zeroBuffer(64 * 1024, 0);
  for (int pass = 0; pass < passes; ++pass) {
    LARGE_INTEGER seek{};
    if (SetFilePointerEx(file, seek, nullptr, FILE_BEGIN) == FALSE) {
      CloseHandle(file);
      return false;
    }

    auto remaining = static_cast<std::uint64_t>(size.QuadPart);
    while (remaining > 0) {
      const auto toWrite = static_cast<DWORD>(std::min<std::uint64_t>(remaining, zeroBuffer.size()));
      DWORD written = 0;
      if (WriteFile(file, zeroBuffer.data(), toWrite, &written, nullptr) == FALSE || written != toWrite) {
        CloseHandle(file);
        return false;
      }
      remaining -= written;
    }
    FlushFileBuffers(file);
  }

  CloseHandle(file);
  return true;
}

void SecureDeleteTree(const std::filesystem::path& path, const int passes) {
  std::error_code error;
  if (!std::filesystem::exists(path, error) || error) {
    return;
  }

  if (std::filesystem::is_regular_file(path, error) && !error) {
    SecureDeleteFile(path, passes);
    return;
  }

  for (const auto& entry : std::filesystem::recursive_directory_iterator(path, error)) {
    if (error) {
      error.clear();
      continue;
    }

    if (entry.is_regular_file(error) && !error) {
      SecureDeleteFile(entry.path(), passes);
    } else {
      error.clear();
    }
  }
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
  const auto threatIntel = database.ListThreatIntelRecords(50);
  const auto exclusionPolicy = database.ListExclusionPolicyRecords(50);
  const auto quarantineApprovals = database.ListQuarantineApprovalRecords(50);
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
  json += L"\"governanceCounts\":{";
  json += L"\"threatIntel\":" + std::to_wstring(threatIntel.size()) + L",";
  json += L"\"exclusionPolicy\":" + std::to_wstring(exclusionPolicy.size()) + L",";
  json += L"\"quarantineApprovals\":" + std::to_wstring(quarantineApprovals.size()) + L"},";
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

void ReclaimPath(const std::filesystem::path& path, std::size_t* deletedEntries, std::uintmax_t* reclaimedBytes,
                 const bool secureDelete, const int secureDeletePasses) {
  std::error_code error;
  if (!std::filesystem::exists(path, error) || error) {
    return;
  }

  const auto size = ComputePathSizeBytes(path);
  if (secureDelete) {
    SecureDeleteTree(path, secureDeletePasses);
  }

  error.clear();
  const auto removed = std::filesystem::remove_all(path, error);
  if (!error && removed > 0) {
    *deletedEntries += static_cast<std::size_t>(removed);
    *reclaimedBytes += size;
  }
}

void PruneDirectory(const std::filesystem::path& root, const int retentionDays, std::size_t* deletedEntries,
                    std::uintmax_t* reclaimedBytes, const bool secureDelete, const int secureDeletePasses) {
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
      ReclaimPath(entry.path(), deletedEntries, reclaimedBytes, secureDelete, secureDeletePasses);
    }
  }
}

void ApplyDirectoryQuota(const std::filesystem::path& root, const std::uintmax_t maxBytes,
                         std::size_t* deletedEntries, std::uintmax_t* reclaimedBytes, const bool secureDelete,
                         const int secureDeletePasses) {
  if (maxBytes == 0) {
    return;
  }

  std::error_code error;
  if (!std::filesystem::exists(root, error) || error) {
    return;
  }

  struct EntryState {
    std::filesystem::path path;
    std::filesystem::file_time_type lastWrite;
    std::uintmax_t sizeBytes;
  };

  std::vector<EntryState> entries;
  std::uintmax_t totalBytes = 0;
  for (const auto& entry : std::filesystem::directory_iterator(root, error)) {
    if (error) {
      error.clear();
      continue;
    }

    const auto sizeBytes = ComputePathSizeBytes(entry.path());
    const auto lastWrite = std::filesystem::last_write_time(entry.path(), error);
    if (error) {
      error.clear();
      continue;
    }

    entries.push_back(EntryState{.path = entry.path(), .lastWrite = lastWrite, .sizeBytes = sizeBytes});
    totalBytes += sizeBytes;
  }

  if (totalBytes <= maxBytes) {
    return;
  }

  std::sort(entries.begin(), entries.end(),
            [](const EntryState& left, const EntryState& right) { return left.lastWrite < right.lastWrite; });

  for (const auto& entry : entries) {
    if (totalBytes <= maxBytes) {
      break;
    }

    const auto sizeBefore = entry.sizeBytes;
    ReclaimPath(entry.path, deletedEntries, reclaimedBytes, secureDelete, secureDeletePasses);
    if (totalBytes > sizeBefore) {
      totalBytes -= sizeBefore;
    } else {
      totalBytes = 0;
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
    auto policy = LoadStorageGovernancePolicy();

    PruneDirectory(config.journalRootPath / L"support", policy.supportRetentionDays, &result.deletedEntries,
                   &result.reclaimedBytes, policy.secureDelete, policy.secureDeletePasses);
    PruneDirectory(config.updateRootPath / L"staged", policy.updateRetentionDays, &result.deletedEntries,
                   &result.reclaimedBytes, policy.secureDelete, policy.secureDeletePasses);
    PruneDirectory(config.updateRootPath / L"backups", policy.updateRetentionDays, &result.deletedEntries,
                   &result.reclaimedBytes, policy.secureDelete, policy.secureDeletePasses);
    PruneDirectory(config.evidenceRootPath, policy.evidenceRetentionDays, &result.deletedEntries, &result.reclaimedBytes,
                   policy.secureDelete, policy.secureDeletePasses);
    PruneDirectory(config.quarantineRootPath / L"files", policy.quarantineRetentionDays, &result.deletedEntries,
                   &result.reclaimedBytes, policy.secureDelete, policy.secureDeletePasses);
    PruneDirectory(config.quarantineRootPath / L"records", policy.quarantineRetentionDays, &result.deletedEntries,
                   &result.reclaimedBytes, policy.secureDelete, policy.secureDeletePasses);
    PruneDirectory(config.journalRootPath, policy.journalRetentionDays, &result.deletedEntries, &result.reclaimedBytes,
                   policy.secureDelete, policy.secureDeletePasses);

    ApplyDirectoryQuota(config.journalRootPath / L"support", policy.supportQuotaBytes, &result.deletedEntries,
                        &result.reclaimedBytes, policy.secureDelete, policy.secureDeletePasses);
    ApplyDirectoryQuota(config.evidenceRootPath, policy.evidenceQuotaBytes, &result.deletedEntries,
                        &result.reclaimedBytes, policy.secureDelete, policy.secureDeletePasses);
    ApplyDirectoryQuota(config.updateRootPath, policy.updateQuotaBytes, &result.deletedEntries, &result.reclaimedBytes,
                        policy.secureDelete, policy.secureDeletePasses);
    ApplyDirectoryQuota(config.quarantineRootPath, policy.quarantineQuotaBytes, &result.deletedEntries,
                        &result.reclaimedBytes, policy.secureDelete, policy.secureDeletePasses);
    ApplyDirectoryQuota(config.journalRootPath, policy.journalQuotaBytes, &result.deletedEntries,
                        &result.reclaimedBytes, policy.secureDelete, policy.secureDeletePasses);

    auto runtimeRoot = config.runtimeDatabasePath.parent_path();
    if (runtimeRoot.empty()) {
      runtimeRoot = config.runtimeDatabasePath;
    }

    ULARGE_INTEGER freeBytesAvailable{};
    ULARGE_INTEGER totalBytes{};
    ULARGE_INTEGER totalFreeBytes{};
    if (policy.aggressiveOnLowDisk && !runtimeRoot.empty() &&
        GetDiskFreeSpaceExW(runtimeRoot.c_str(), &freeBytesAvailable, &totalBytes, &totalFreeBytes) != FALSE &&
        freeBytesAvailable.QuadPart < policy.lowDiskBytes) {
      policy.supportQuotaBytes = std::max<std::uintmax_t>(policy.supportQuotaBytes / 2, 64ull * 1024ull * 1024ull);
      policy.evidenceQuotaBytes = std::max<std::uintmax_t>(policy.evidenceQuotaBytes / 2, 128ull * 1024ull * 1024ull);
      policy.updateQuotaBytes = std::max<std::uintmax_t>(policy.updateQuotaBytes / 2, 256ull * 1024ull * 1024ull);
      policy.quarantineQuotaBytes =
          std::max<std::uintmax_t>(policy.quarantineQuotaBytes / 2, 256ull * 1024ull * 1024ull);
      policy.journalQuotaBytes = std::max<std::uintmax_t>(policy.journalQuotaBytes / 2, 64ull * 1024ull * 1024ull);

      ApplyDirectoryQuota(config.journalRootPath / L"support", policy.supportQuotaBytes, &result.deletedEntries,
                          &result.reclaimedBytes, policy.secureDelete, policy.secureDeletePasses);
      ApplyDirectoryQuota(config.evidenceRootPath, policy.evidenceQuotaBytes, &result.deletedEntries,
                          &result.reclaimedBytes, policy.secureDelete, policy.secureDeletePasses);
      ApplyDirectoryQuota(config.updateRootPath, policy.updateQuotaBytes, &result.deletedEntries,
                          &result.reclaimedBytes, policy.secureDelete, policy.secureDeletePasses);
      ApplyDirectoryQuota(config.quarantineRootPath, policy.quarantineQuotaBytes, &result.deletedEntries,
                          &result.reclaimedBytes, policy.secureDelete, policy.secureDeletePasses);
      ApplyDirectoryQuota(config.journalRootPath, policy.journalQuotaBytes, &result.deletedEntries,
                          &result.reclaimedBytes, policy.secureDelete, policy.secureDeletePasses);
    }

    result.success = true;
    result.summary = L"Deleted " + std::to_wstring(result.deletedEntries) + L" expired maintenance entries and reclaimed " +
                     std::to_wstring(result.reclaimedBytes) + L" byte(s) under retention/quota policy.";
    return result;
  } catch (const std::exception& error) {
    result.errorMessage = Utf8ToWide(error.what());
    return result;
  }
}

}  // namespace antivirus::agent
