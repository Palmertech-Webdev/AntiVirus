#include <winsock2.h>
#include "SelfTestRunner.h"

#include <algorithm>
#include <chrono>
#include <cwchar>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "../../../sensor/etw/include/ProcessEtwSensor.h"
#include "../../../sensor/wfp/include/NetworkIsolationManager.h"
#include "AgentConfig.h"
#include "CryptoUtils.h"
#include "HardeningManager.h"
#include "RealtimeProtectionBroker.h"
#include "RuntimeDatabase.h"
#include "RuntimeTrustValidator.h"
#include "ScanEngine.h"
#include "StringUtils.h"
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

std::wstring JsonEscape(const std::wstring& value) { return Utf8ToWide(EscapeJsonString(value)); }

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

    std::error_code cleanupError;
    std::filesystem::remove_all(phaseValidationRoot, cleanupError);
  }

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
