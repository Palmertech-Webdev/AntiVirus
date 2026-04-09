#include <winsock2.h>
#include "SelfTestRunner.h"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "../../../sensor/etw/include/ProcessEtwSensor.h"
#include "../../../sensor/wfp/include/NetworkIsolationManager.h"
#include "AgentConfig.h"
#include "CryptoUtils.h"
#include "HardeningManager.h"
#include "RuntimeDatabase.h"
#include "StringUtils.h"
#include "WscCoexistenceManager.h"

namespace antivirus::agent {
namespace {

constexpr wchar_t kAmsiProviderName[] = L"AntiVirus AMSI Provider";
constexpr wchar_t kMinifilterServiceName[] = L"AntivirusMinifilter";
constexpr wchar_t kServiceExecutableName[] = L"antivirus-agent-service.exe";
constexpr wchar_t kAmsiProviderDllName[] = L"antivirus-amsi-provider.dll";
constexpr wchar_t kSignatureBundleRelativePath[] = L"signatures\\default-signatures.tsv";

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
           L"Run antivirus-agent-service.exe --register-amsi-provider from an elevated context.");

  if (PathExists(servicePath)) {
    const auto signedBinary = VerifyFileAuthenticodeSignature(servicePath);
    AddCheck(report, L"binary_signing", L"Binary signing",
             signedBinary ? SelfTestStatus::Pass : SelfTestStatus::Warning,
             signedBinary ? L"The service binary has a valid Authenticode signature."
                          : L"The service binary is not Authenticode-signed in this build context.",
             L"Sign production binaries before packaging, rollout, and protected-service onboarding.");
  }

  const auto hardeningManager = HardeningManager(config, installRoot);
  const auto hardeningStatus = hardeningManager.QueryStatus();
  AddCheck(report, L"hardening", L"Service hardening",
           hardeningStatus.registryConfigured && hardeningStatus.runtimePathsProtected ? SelfTestStatus::Pass
                                                                                      : SelfTestStatus::Warning,
           hardeningStatus.statusMessage.empty() ? L"Hardening status is available." : hardeningStatus.statusMessage,
           L"Run antivirus-agent-service.exe --repair from an elevated context to reapply registry and ACL hardening.");

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

  const auto minifilterInf = installRoot / L"AntivirusMinifilter.inf";
  const auto minifilterSys = installRoot / L"AntivirusMinifilter.sys";
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

  const auto serviceState = QueryServiceState(L"AntiVirusAgent");
  AddCheck(report, L"service_registration", L"Windows service registration",
           !serviceState.empty() ? SelfTestStatus::Pass : SelfTestStatus::Warning,
           !serviceState.empty() ? L"The AntiVirusAgent service is registered with state " + serviceState + L"."
                                 : L"The AntiVirusAgent service is not installed in the SCM on this host.",
           L"Run antivirus-agent-service.exe --install from an elevated install context.");

  if (std::filesystem::create_directories(config.updateRootPath) || PathExists(config.updateRootPath)) {
    AddCheck(report, L"update_root", L"Update staging root", SelfTestStatus::Pass,
             L"The update root is available at " + config.updateRootPath.wstring() + L".");
  } else {
    AddCheck(report, L"update_root", L"Update staging root", SelfTestStatus::Fail,
             L"The update root could not be created at " + config.updateRootPath.wstring() + L".",
             L"Ensure the runtime update directory is writable before testing rollback-aware upgrades.");
  }

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
