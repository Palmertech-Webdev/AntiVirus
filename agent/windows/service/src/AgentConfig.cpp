#include "AgentConfig.h"

#include <Windows.h>

#include <algorithm>
#include <cwctype>
#include <optional>
#include <set>
#include <system_error>

#include "StringUtils.h"

namespace antivirus::agent {
namespace {

constexpr wchar_t kRegistryRoot[] = L"SOFTWARE\\FenrirAgent";
constexpr wchar_t kLegacyRegistryRoot[] = L"SOFTWARE\\AntiVirusAgent";
constexpr wchar_t kControlPlaneBaseUrlValueName[] = L"ControlPlaneBaseUrl";
constexpr wchar_t kScanExcludePathsValueName[] = L"ScanExcludePaths";
constexpr wchar_t kRuntimeRootValueName[] = L"RuntimeRoot";
constexpr wchar_t kRuntimeDatabasePathValueName[] = L"RuntimeDatabasePath";
constexpr wchar_t kInstallRootValueName[] = L"InstallRoot";
constexpr wchar_t kLastSeenAtValueName[] = L"LastSeenAt";

int ParsePositiveInt(const std::wstring& rawValue, const int fallback) {
  if (rawValue.empty()) {
    return fallback;
  }

  try {
    const auto parsed = std::stoi(rawValue);
    return std::max(parsed, 1);
  } catch (...) {
    return fallback;
  }
}

bool ParseBooleanValue(const std::wstring& rawValue, const bool fallback) {
  if (rawValue.empty()) {
    return fallback;
  }

  const auto lower = [&rawValue]() {
    std::wstring value = rawValue;
    std::transform(value.begin(), value.end(), value.begin(),
                   [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
    return value;
  }();

  if (lower == L"1" || lower == L"true" || lower == L"yes" || lower == L"on") {
    return true;
  }

  if (lower == L"0" || lower == L"false" || lower == L"no" || lower == L"off") {
    return false;
  }

  return fallback;
}

std::wstring ToLowerCopy(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return value;
}

std::filesystem::path NormalizeAbsolutePath(const std::filesystem::path& value) {
  if (value.empty()) {
    return {};
  }

  std::error_code error;
  const auto absolute = std::filesystem::absolute(value, error);
  if (error) {
    return value.lexically_normal();
  }

  return absolute.lexically_normal();
}

std::wstring NormalizePathForCompare(const std::filesystem::path& value) {
  auto normalized = ToLowerCopy(NormalizeAbsolutePath(value).wstring());
  if (!normalized.empty() && normalized.back() != L'\\' && normalized.back() != L'/') {
    normalized.push_back(L'\\');
  }
  return normalized;
}

bool IsPathWithinRoot(const std::filesystem::path& candidate, const std::filesystem::path& root) {
  if (candidate.empty() || root.empty()) {
    return false;
  }

  const auto normalizedCandidate = NormalizePathForCompare(candidate);
  const auto normalizedRoot = NormalizePathForCompare(root);
  return !normalizedCandidate.empty() && !normalizedRoot.empty() && normalizedCandidate.starts_with(normalizedRoot);
}

std::filesystem::path NormalizeRuntimeArtifactPath(const std::filesystem::path& candidate,
                                                   const std::filesystem::path& runtimeRoot,
                                                   const std::filesystem::path& fallbackLeafName) {
  if (runtimeRoot.empty()) {
    return NormalizeAbsolutePath(candidate);
  }

  if (candidate.empty()) {
    return runtimeRoot / fallbackLeafName;
  }

  const auto normalizedCandidate = NormalizeAbsolutePath(candidate);
  if (IsPathWithinRoot(normalizedCandidate, runtimeRoot)) {
    return normalizedCandidate;
  }

  const auto leafName = normalizedCandidate.filename();
  if (!leafName.empty() && leafName != L"." && leafName != L"..") {
    return runtimeRoot / leafName;
  }

  return runtimeRoot / fallbackLeafName;
}

std::vector<std::wstring> ParseWideList(const std::wstring& rawValue) {
  std::vector<std::wstring> results;
  std::wstring current;

  const auto flushCurrent = [&results, &current]() {
    const auto first = current.find_first_not_of(L" \t\r\n");
    if (first == std::wstring::npos) {
      current.clear();
      return;
    }

    const auto last = current.find_last_not_of(L" \t\r\n");
    results.push_back(current.substr(first, last - first + 1));
    current.clear();
  };

  for (const auto ch : rawValue) {
    if (ch == L',' || ch == L';') {
      flushCurrent();
      continue;
    }

    current.push_back(ch);
  }

  flushCurrent();
  return results;
}

std::wstring JoinWideList(const std::vector<std::filesystem::path>& values) {
  std::wstring joined;
  for (const auto& value : values) {
    const auto text = value.wstring();
    if (text.empty()) {
      continue;
    }

    if (!joined.empty()) {
      joined += L";";
    }

    joined += text;
  }

  return joined;
}

std::wstring NormalizeRegistryPathText(const std::wstring& value) {
  std::wstring normalized = value;
  std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return normalized;
}

std::filesystem::path GetModuleDirectory(HMODULE moduleHandle) {
  std::wstring buffer(MAX_PATH, L'\0');
  const auto written = GetModuleFileNameW(moduleHandle, buffer.data(), static_cast<DWORD>(buffer.size()));
  if (written == 0) {
    return std::filesystem::current_path();
  }

  buffer.resize(written);
  const auto modulePath = std::filesystem::path(buffer);
  return modulePath.has_parent_path() ? modulePath.parent_path() : std::filesystem::current_path();
}

std::wstring ReadRegistryStringFromRoot(HKEY hive, const wchar_t* registryRoot, const wchar_t* valueName) {
  HKEY key = nullptr;
  if (RegOpenKeyExW(hive, registryRoot, 0, KEY_READ, &key) != ERROR_SUCCESS) {
    return {};
  }

  DWORD type = 0;
  DWORD bytes = 0;
  if (RegQueryValueExW(key, valueName, nullptr, &type, nullptr, &bytes) != ERROR_SUCCESS || type != REG_SZ ||
      bytes == 0) {
    RegCloseKey(key);
    return {};
  }

  std::wstring value(bytes / sizeof(wchar_t), L'\0');
  if (RegQueryValueExW(key, valueName, nullptr, &type, reinterpret_cast<LPBYTE>(value.data()), &bytes) !=
      ERROR_SUCCESS) {
    RegCloseKey(key);
    return {};
  }

  RegCloseKey(key);
  while (!value.empty() && value.back() == L'\0') {
    value.pop_back();
  }
  return value;
}

std::wstring ReadRegistryString(HKEY hive, const wchar_t* valueName) {
  const auto fenrirValue = ReadRegistryStringFromRoot(hive, kRegistryRoot, valueName);
  if (!fenrirValue.empty()) {
    return fenrirValue;
  }

  return ReadRegistryStringFromRoot(hive, kLegacyRegistryRoot, valueName);
}

bool WriteRegistryStringToRoot(HKEY hive, const wchar_t* registryRoot, const wchar_t* valueName,
                               const std::wstring& value) {
  HKEY key = nullptr;
  if (RegCreateKeyExW(hive, registryRoot, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_READ | KEY_WRITE, nullptr, &key,
                      nullptr) != ERROR_SUCCESS) {
    return false;
  }

  const auto result = RegSetValueExW(key, valueName, 0, REG_SZ, reinterpret_cast<const BYTE*>(value.c_str()),
                                     static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t))) == ERROR_SUCCESS;
  RegCloseKey(key);
  return result;
}

bool WriteRegistryString(HKEY hive, const wchar_t* valueName, const std::wstring& value) {
  return WriteRegistryStringToRoot(hive, kRegistryRoot, valueName, value);
}

void AppendRegistryExclusionsFromRoot(HKEY hive, const wchar_t* rootName,
                                      std::vector<std::filesystem::path>& exclusions,
                                      std::set<std::wstring>& seen) {
  const auto rawValue = ReadRegistryStringFromRoot(hive, rootName, kScanExcludePathsValueName);
  if (rawValue.empty()) {
    return;
  }

  for (const auto& excludedPath : ParseWideList(rawValue)) {
    if (excludedPath.empty()) {
      continue;
    }

    const auto normalized = NormalizeRegistryPathText(excludedPath);
    if (seen.insert(normalized).second) {
      exclusions.emplace_back(excludedPath);
    }
  }
}

std::vector<std::filesystem::path> LoadConfiguredScanExclusionsFromRegistry() {
  std::vector<std::filesystem::path> exclusions;
  std::set<std::wstring> seen;
  for (const auto hive : {HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER}) {
    AppendRegistryExclusionsFromRoot(hive, kRegistryRoot, exclusions, seen);
    AppendRegistryExclusionsFromRoot(hive, kLegacyRegistryRoot, exclusions, seen);
  }
  return exclusions;
}

std::optional<std::filesystem::path> ReadRegisteredRuntimeRoot() {
  for (const auto hive : {HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER}) {
    const auto runtimeRoot = ReadRegistryString(hive, kRuntimeRootValueName);
    if (!runtimeRoot.empty()) {
      return std::filesystem::path(runtimeRoot);
    }

    const auto runtimeDatabasePath = ReadRegistryString(hive, kRuntimeDatabasePathValueName);
    if (!runtimeDatabasePath.empty()) {
      const auto runtimePath = std::filesystem::path(runtimeDatabasePath).parent_path();
      if (!runtimePath.empty()) {
        return runtimePath;
      }
    }
  }

  return std::nullopt;
}

std::filesystem::path BuildDefaultSharedRuntimeRoot() {
  const auto programData = ReadEnvironmentVariable(L"PROGRAMDATA");
  if (!programData.empty()) {
    return std::filesystem::path(programData) / L"FenrirAgent" / L"runtime";
  }

  const auto localAppData = ReadEnvironmentVariable(L"LOCALAPPDATA");
  if (!localAppData.empty()) {
    return std::filesystem::path(localAppData) / L"FenrirAgent" / L"runtime";
  }

  return {};
}

std::vector<std::filesystem::path> BuildLegacySharedRuntimeRoots() {
  std::vector<std::filesystem::path> results;

  const auto programData = ReadEnvironmentVariable(L"PROGRAMDATA");
  if (!programData.empty()) {
    results.push_back(std::filesystem::path(programData) / L"AntiVirusAgent" / L"runtime");
  }

  const auto localAppData = ReadEnvironmentVariable(L"LOCALAPPDATA");
  if (!localAppData.empty()) {
    results.push_back(std::filesystem::path(localAppData) / L"AntiVirusAgent" / L"runtime");
  }

  return results;
}

bool RuntimeRootHasState(const std::filesystem::path& runtimeRoot) {
  std::error_code error;
  return std::filesystem::exists(runtimeRoot / L"agent-runtime.db", error) ||
         std::filesystem::exists(runtimeRoot / L"agent-state.ini", error) ||
         std::filesystem::exists(runtimeRoot / L"telemetry-queue.tsv", error);
}

void TryMigrateLegacyRuntimeRoot(const std::filesystem::path& sourceRuntimeRoot,
                                const std::filesystem::path& destinationRuntimeRoot) {
  if (sourceRuntimeRoot.empty() || destinationRuntimeRoot.empty() || sourceRuntimeRoot == destinationRuntimeRoot ||
      !RuntimeRootHasState(sourceRuntimeRoot) || RuntimeRootHasState(destinationRuntimeRoot)) {
    return;
  }

  std::error_code error;
  std::filesystem::create_directories(destinationRuntimeRoot, error);
  if (error) {
    return;
  }

  for (const auto& entry : std::filesystem::directory_iterator(sourceRuntimeRoot, error)) {
    if (error) {
      return;
    }

    const auto destinationPath = destinationRuntimeRoot / entry.path().filename();
    std::filesystem::copy(entry.path(), destinationPath,
                          std::filesystem::copy_options::recursive | std::filesystem::copy_options::overwrite_existing,
                          error);
    if (error) {
      return;
    }
  }
}

std::optional<std::filesystem::path> DeterminePreferredRuntimeRoot(HMODULE moduleHandle) {
  if (const auto registeredRuntimeRoot = ReadRegisteredRuntimeRoot(); registeredRuntimeRoot.has_value()) {
    return registeredRuntimeRoot;
  }

  const auto sharedRuntimeRoot = BuildDefaultSharedRuntimeRoot();
  if (sharedRuntimeRoot.empty()) {
    return std::nullopt;
  }

  for (const auto& legacySharedRuntimeRoot : BuildLegacySharedRuntimeRoots()) {
    TryMigrateLegacyRuntimeRoot(legacySharedRuntimeRoot, sharedRuntimeRoot);
  }

  const auto legacyRuntimeRoot = GetModuleDirectory(moduleHandle) / L"runtime";
  TryMigrateLegacyRuntimeRoot(legacyRuntimeRoot, sharedRuntimeRoot);
  return sharedRuntimeRoot;
}

void PersistRuntimeRootMarker(const std::filesystem::path& runtimeRoot, const std::filesystem::path& installRoot) {
  if (runtimeRoot.empty()) {
    return;
  }

  for (const auto hive : {HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER}) {
    const auto runtimeRootWritten = WriteRegistryString(hive, kRuntimeRootValueName, runtimeRoot.wstring());
    const auto runtimeDatabaseWritten =
        WriteRegistryString(hive, kRuntimeDatabasePathValueName, (runtimeRoot / L"agent-runtime.db").wstring());
    const auto installRootWritten = WriteRegistryString(hive, kInstallRootValueName, installRoot.wstring());
    const auto lastSeenWritten = WriteRegistryString(hive, kLastSeenAtValueName, CurrentUtcTimestamp());
    if (runtimeRootWritten && runtimeDatabaseWritten && installRootWritten && lastSeenWritten) {
      return;
    }
  }
}

}  // namespace

std::vector<std::filesystem::path> LoadConfiguredScanExclusions() {
  return LoadConfiguredScanExclusionsFromRegistry();
}

bool SaveConfiguredScanExclusions(const std::vector<std::filesystem::path>& exclusions) {
  const auto joined = JoinWideList(exclusions);
  bool saved = false;
  for (const auto hive : {HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER}) {
    if (WriteRegistryStringToRoot(hive, kRegistryRoot, kScanExcludePathsValueName, joined)) {
      saved = true;
    }
  }
  return saved;
}

std::filesystem::path ResolveConfiguredPathWithinRuntimeRoot(const std::filesystem::path& configuredPath,
                                                             const std::filesystem::path& runtimeRoot) {
  if (configuredPath.empty()) {
    return runtimeRoot;
  }

  std::filesystem::path relative;
  bool firstComponent = true;
  for (const auto& component : configuredPath) {
    if (firstComponent) {
      firstComponent = false;
      if (ToLowerCopy(component.wstring()) == L"runtime") {
        continue;
      }
    }

    relative /= component;
  }

  return relative.empty() ? runtimeRoot : runtimeRoot / relative;
}

std::filesystem::path ResolveRuntimePath(const std::filesystem::path& configuredPath, HMODULE moduleHandle,
                                         const std::optional<std::filesystem::path>& runtimeRoot = std::nullopt) {
  if (configuredPath.is_absolute()) {
    return configuredPath;
  }

  if (runtimeRoot.has_value()) {
    return ResolveConfiguredPathWithinRuntimeRoot(configuredPath, *runtimeRoot);
  }

  return GetModuleDirectory(moduleHandle) / configuredPath;
}

AgentConfig LoadAgentConfig() {
  return LoadAgentConfigForModule(nullptr);
}

AgentConfig LoadAgentConfigForModule(HMODULE moduleHandle) {
  AgentConfig config;
  const auto installRoot = GetModuleDirectory(moduleHandle);
  config.installRootPath = NormalizeAbsolutePath(installRoot);

  for (const auto hive : {HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER}) {
    const auto registeredControlPlaneUrl = ReadRegistryString(hive, kControlPlaneBaseUrlValueName);
    if (!registeredControlPlaneUrl.empty()) {
      config.controlPlaneBaseUrl = registeredControlPlaneUrl;
      break;
    }
  }

  const auto controlPlaneBaseUrl = ReadEnvironmentVariable(L"ANTIVIRUS_CONTROL_PLANE_URL");
  if (!controlPlaneBaseUrl.empty() && config.controlPlaneBaseUrl == AgentConfig{}.controlPlaneBaseUrl) {
    config.controlPlaneBaseUrl = controlPlaneBaseUrl;
  }

  const auto runtimeDatabasePath = ReadEnvironmentVariable(L"ANTIVIRUS_RUNTIME_DB_PATH");
  const auto runtimeDatabasePathOverridden = !runtimeDatabasePath.empty();
  if (!runtimeDatabasePath.empty()) {
    config.runtimeDatabasePath = std::filesystem::path(runtimeDatabasePath);
  }

  const auto stateFilePath = ReadEnvironmentVariable(L"ANTIVIRUS_AGENT_STATE_FILE");
  const auto stateFilePathOverridden = !stateFilePath.empty();
  if (!stateFilePath.empty()) {
    config.stateFilePath = std::filesystem::path(stateFilePath);
  }

  const auto telemetryQueuePath = ReadEnvironmentVariable(L"ANTIVIRUS_TELEMETRY_QUEUE_FILE");
  const auto telemetryQueuePathOverridden = !telemetryQueuePath.empty();
  if (!telemetryQueuePath.empty()) {
    config.telemetryQueuePath = std::filesystem::path(telemetryQueuePath);
  }

  const auto updateRootPath = ReadEnvironmentVariable(L"ANTIVIRUS_UPDATE_ROOT");
  const auto updateRootPathOverridden = !updateRootPath.empty();
  if (!updateRootPath.empty()) {
    config.updateRootPath = std::filesystem::path(updateRootPath);
  }

  const auto journalRootPath = ReadEnvironmentVariable(L"ANTIVIRUS_JOURNAL_ROOT");
  const auto journalRootPathOverridden = !journalRootPath.empty();
  if (!journalRootPath.empty()) {
    config.journalRootPath = std::filesystem::path(journalRootPath);
  }

  const auto elamDriverPath = ReadEnvironmentVariable(L"ANTIVIRUS_ELAM_DRIVER_PATH");
  if (!elamDriverPath.empty()) {
    config.elamDriverPath = std::filesystem::path(elamDriverPath);
  }

  const auto quarantineRootPath = ReadEnvironmentVariable(L"ANTIVIRUS_QUARANTINE_ROOT");
  const auto quarantineRootPathOverridden = !quarantineRootPath.empty();
  if (!quarantineRootPath.empty()) {
    config.quarantineRootPath = std::filesystem::path(quarantineRootPath);
  }

  const auto evidenceRootPath = ReadEnvironmentVariable(L"ANTIVIRUS_EVIDENCE_ROOT");
  const auto evidenceRootPathOverridden = !evidenceRootPath.empty();
  if (!evidenceRootPath.empty()) {
    config.evidenceRootPath = std::filesystem::path(evidenceRootPath);
  }

  const auto realtimeProtectionPortName = ReadEnvironmentVariable(L"ANTIVIRUS_REALTIME_PORT_NAME");
  if (!realtimeProtectionPortName.empty()) {
    config.realtimeProtectionPortName = realtimeProtectionPortName;
  }

  const auto agentVersion = ReadEnvironmentVariable(L"ANTIVIRUS_AGENT_VERSION");
  if (!agentVersion.empty()) {
    config.agentVersion = agentVersion;
  }

  const auto platformVersion = ReadEnvironmentVariable(L"ANTIVIRUS_PLATFORM_VERSION");
  if (!platformVersion.empty()) {
    config.platformVersion = platformVersion;
  }

  config.syncIntervalSeconds =
      ParsePositiveInt(ReadEnvironmentVariable(L"ANTIVIRUS_SYNC_INTERVAL_SECONDS"), config.syncIntervalSeconds);
  config.syncIterations =
      ParsePositiveInt(ReadEnvironmentVariable(L"ANTIVIRUS_SYNC_ITERATIONS"), config.syncIterations);
  config.telemetryBatchSize =
      ParsePositiveInt(ReadEnvironmentVariable(L"ANTIVIRUS_TELEMETRY_BATCH_SIZE"), config.telemetryBatchSize);
  config.realtimeBrokerRetrySeconds =
      ParsePositiveInt(ReadEnvironmentVariable(L"ANTIVIRUS_REALTIME_BROKER_RETRY_SECONDS"),
                       config.realtimeBrokerRetrySeconds);
  config.isolationAllowLoopback =
      ParseBooleanValue(ReadEnvironmentVariable(L"ANTIVIRUS_ISOLATION_ALLOW_LOOPBACK"), config.isolationAllowLoopback);
  config.isolationAllowedRemoteAddresses =
      ParseWideList(ReadEnvironmentVariable(L"ANTIVIRUS_ISOLATION_ALLOW_REMOTE"));
  config.isolationAllowedApplications =
      ParseWideList(ReadEnvironmentVariable(L"ANTIVIRUS_ISOLATION_ALLOW_APPLICATIONS"));
  config.scanExcludedPaths = {};
  for (const auto& excludedPath : ParseWideList(ReadEnvironmentVariable(L"ANTIVIRUS_SCAN_EXCLUDE_PATHS"))) {
    config.scanExcludedPaths.emplace_back(excludedPath);
  }
  for (const auto& excludedPath : LoadConfiguredScanExclusions()) {
    if (!excludedPath.empty()) {
      config.scanExcludedPaths.push_back(excludedPath);
    }
  }

  const auto runtimeRootOverridden =
      runtimeDatabasePathOverridden || stateFilePathOverridden || telemetryQueuePathOverridden ||
      updateRootPathOverridden || journalRootPathOverridden || quarantineRootPathOverridden ||
      evidenceRootPathOverridden;
  const std::optional<std::filesystem::path> preferredRuntimeRoot =
      runtimeRootOverridden ? std::optional<std::filesystem::path>{} : DeterminePreferredRuntimeRoot(moduleHandle);

  config.runtimeDatabasePath = ResolveRuntimePath(config.runtimeDatabasePath, moduleHandle, preferredRuntimeRoot);
  config.stateFilePath = ResolveRuntimePath(config.stateFilePath, moduleHandle, preferredRuntimeRoot);
  config.telemetryQueuePath = ResolveRuntimePath(config.telemetryQueuePath, moduleHandle, preferredRuntimeRoot);
  config.updateRootPath = ResolveRuntimePath(config.updateRootPath, moduleHandle, preferredRuntimeRoot);
  config.journalRootPath = ResolveRuntimePath(config.journalRootPath, moduleHandle, preferredRuntimeRoot);
  if (!config.elamDriverPath.empty()) {
    config.elamDriverPath = ResolveRuntimePath(config.elamDriverPath, moduleHandle);
    config.elamDriverPath = NormalizeAbsolutePath(config.elamDriverPath);
  }
  config.quarantineRootPath = ResolveRuntimePath(config.quarantineRootPath, moduleHandle, preferredRuntimeRoot);
  config.evidenceRootPath = ResolveRuntimePath(config.evidenceRootPath, moduleHandle, preferredRuntimeRoot);

  auto runtimeRoot = NormalizeAbsolutePath(config.runtimeDatabasePath.parent_path());
  if (runtimeRoot.empty()) {
    runtimeRoot = preferredRuntimeRoot.has_value() ? NormalizeAbsolutePath(*preferredRuntimeRoot)
                                                   : NormalizeAbsolutePath(config.installRootPath / L"runtime");
  }

  config.runtimeDatabasePath = NormalizeRuntimeArtifactPath(config.runtimeDatabasePath, runtimeRoot, L"agent-runtime.db");
  runtimeRoot = NormalizeAbsolutePath(config.runtimeDatabasePath.parent_path());
  config.stateFilePath = NormalizeRuntimeArtifactPath(config.stateFilePath, runtimeRoot, L"agent-state.ini");
  config.telemetryQueuePath =
      NormalizeRuntimeArtifactPath(config.telemetryQueuePath, runtimeRoot, L"telemetry-queue.tsv");
  config.updateRootPath = NormalizeRuntimeArtifactPath(config.updateRootPath, runtimeRoot, L"updates");
  config.journalRootPath = NormalizeRuntimeArtifactPath(config.journalRootPath, runtimeRoot, L"journal");
  config.quarantineRootPath = NormalizeRuntimeArtifactPath(config.quarantineRootPath, runtimeRoot, L"quarantine");
  config.evidenceRootPath = NormalizeRuntimeArtifactPath(config.evidenceRootPath, runtimeRoot, L"evidence");

  const auto appendScanExclusion = [&config](const std::filesystem::path& path) {
    if (!path.empty()) {
      config.scanExcludedPaths.push_back(path);
    }
  };

  appendScanExclusion(installRoot);
  appendScanExclusion(config.runtimeDatabasePath);
  appendScanExclusion(config.stateFilePath);
  appendScanExclusion(config.telemetryQueuePath);
  appendScanExclusion(config.updateRootPath);
  appendScanExclusion(config.journalRootPath);
  appendScanExclusion(config.quarantineRootPath);
  appendScanExclusion(config.evidenceRootPath);

  if (preferredRuntimeRoot.has_value()) {
    PersistRuntimeRootMarker(runtimeRoot, config.installRootPath);
  }

  return config;
}

RuntimePathValidation ValidateRuntimePaths(const AgentConfig& config) {
  RuntimePathValidation validation;
  validation.installRootPath = NormalizeAbsolutePath(config.installRootPath);

  auto runtimeRoot = config.runtimeDatabasePath.parent_path();
  if (runtimeRoot.empty()) {
    runtimeRoot = config.runtimeDatabasePath;
  }
  validation.runtimeRootPath = NormalizeAbsolutePath(runtimeRoot);

  if (validation.installRootPath.empty() || !validation.installRootPath.is_absolute()) {
    validation.message = L"Install root path is not fully resolved.";
    return validation;
  }

  if (validation.runtimeRootPath.empty() || !validation.runtimeRootPath.is_absolute()) {
    validation.message = L"Runtime root path is not fully resolved.";
    return validation;
  }

  if (NormalizeAbsolutePath(validation.runtimeRootPath.root_path()) == validation.runtimeRootPath) {
    validation.message = L"Runtime root path cannot be a drive root.";
    return validation;
  }

  const auto ensurePathWithinRuntimeRoot = [&validation](const std::filesystem::path& path,
                                                         const wchar_t* label) -> bool {
    const auto normalizedPath = NormalizeAbsolutePath(path);
    if (normalizedPath.empty() || !normalizedPath.is_absolute()) {
      validation.message = std::wstring(label) + L" is not an absolute path.";
      return false;
    }

    if (!IsPathWithinRoot(normalizedPath, validation.runtimeRootPath)) {
      validation.message = std::wstring(label) + L" escaped the trusted runtime root boundary.";
      return false;
    }

    return true;
  };

  if (!ensurePathWithinRuntimeRoot(config.runtimeDatabasePath, L"Runtime database path") ||
      !ensurePathWithinRuntimeRoot(config.stateFilePath, L"State file path") ||
      !ensurePathWithinRuntimeRoot(config.telemetryQueuePath, L"Telemetry queue path") ||
      !ensurePathWithinRuntimeRoot(config.updateRootPath, L"Update root path") ||
      !ensurePathWithinRuntimeRoot(config.journalRootPath, L"Journal root path") ||
      !ensurePathWithinRuntimeRoot(config.quarantineRootPath, L"Quarantine root path") ||
      !ensurePathWithinRuntimeRoot(config.evidenceRootPath, L"Evidence root path")) {
    return validation;
  }

  validation.trusted = true;
  validation.message = L"Trusted runtime boundaries are configured.";
  return validation;
}

}  // namespace antivirus::agent
