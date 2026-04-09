#include <Windows.h>
#include <commctrl.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <shellapi.h>
#include <strsafe.h>
#include <tlhelp32.h>
#include <wrl/client.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include "SetupResourceIds.h"

namespace {

constexpr wchar_t kWindowClassName[] = L"FenrirSetupWindow";
constexpr wchar_t kWindowTitle[] = L"Fenrir Endpoint Setup";
constexpr wchar_t kCompanyName[] = L"Fenrir";
constexpr wchar_t kProductName[] = L"Fenrir Endpoint";
constexpr wchar_t kServiceName[] = L"FenrirAgent";
constexpr wchar_t kAgentRegistryRoot[] = L"SOFTWARE\\FenrirAgent";
constexpr wchar_t kControlPlaneBaseUrlValueName[] = L"ControlPlaneBaseUrl";
constexpr wchar_t kArpRegistryRoot[] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\FenrirEndpoint";
constexpr wchar_t kRunRegistryRoot[] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
constexpr wchar_t kRunValueName[] = L"FenrirEndpointClient";
constexpr wchar_t kInstallFolderName[] = L"Fenrir Endpoint";
constexpr wchar_t kServiceExeName[] = L"fenrir-agent-service.exe";
constexpr wchar_t kEndpointExeName[] = L"fenrir-endpoint-client.exe";
constexpr wchar_t kAmsiDllName[] = L"fenrir-amsi-provider.dll";
constexpr wchar_t kScannerCliName[] = L"fenrir-scannercli.exe";
constexpr wchar_t kAmsiTestCliName[] = L"fenrir-amsitestcli.exe";
constexpr wchar_t kEtwTestCliName[] = L"fenrir-etwtestcli.exe";
constexpr wchar_t kWfpTestCliName[] = L"fenrir-wfptestcli.exe";
constexpr wchar_t kWinpthreadDllName[] = L"libwinpthread-1.dll";
constexpr wchar_t kSetupExeName[] = L"FenrirSetup.exe";
constexpr wchar_t kSignatureBundleRelativePath[] = L"signatures\\default-signatures.tsv";
constexpr wchar_t kToolsRelativePath[] = L"tools\\fenrir-scannercli.exe";
constexpr wchar_t kToolsAmsiTestCliRelativePath[] = L"tools\\fenrir-amsitestcli.exe";
constexpr wchar_t kToolsEtwTestCliRelativePath[] = L"tools\\fenrir-etwtestcli.exe";
constexpr wchar_t kToolsWfpTestCliRelativePath[] = L"tools\\fenrir-wfptestcli.exe";
constexpr wchar_t kToolsWinpthreadRelativePath[] = L"tools\\libwinpthread-1.dll";

constexpr UINT kInstallerLogMessage = WM_APP + 1;
constexpr UINT kInstallerStatusMessage = WM_APP + 2;
constexpr UINT kInstallerCompleteMessage = WM_APP + 3;

enum : int {
  IDC_TITLE = 1001,
  IDC_SUBTITLE = 1002,
  IDC_PATH_LABEL = 1003,
  IDC_PATH_VALUE = 1004,
  IDC_CONTROL_PLANE_LABEL = 1005,
  IDC_CONTROL_PLANE_EDIT = 1006,
  IDC_STATUS = 1007,
  IDC_PROGRESS = 1008,
  IDC_LOG = 1009,
  IDC_PRIMARY_BUTTON = 1010,
  IDC_UNINSTALL_BUTTON = 1011,
  IDC_OPEN_FOLDER_BUTTON = 1012,
  IDC_CLOSE_BUTTON = 1013
};

struct LogMessagePayload {
  std::wstring text;
};

struct StatusMessagePayload {
  std::wstring text;
  int progress{0};
};

struct CompletionPayload {
  bool success{false};
  bool installed{false};
  bool closeAfter{false};
  std::wstring message;
};

struct UiContext {
  HINSTANCE instance{};
  HWND hwnd{};
  HWND titleLabel{};
  HWND subtitleLabel{};
  HWND pathLabel{};
  HWND pathValue{};
  HWND controlPlaneLabel{};
  HWND controlPlaneEdit{};
  HWND statusLabel{};
  HWND progressBar{};
  HWND logEdit{};
  HWND primaryButton{};
  HWND uninstallButton{};
  HWND openFolderButton{};
  HWND closeButton{};
  HFONT titleFont{};
  HFONT bodyFont{};
  std::filesystem::path installRoot;
  std::filesystem::path setupPath;
  std::wstring controlPlaneBaseUrl;
  bool installed{false};
  bool busy{false};
};

struct InstallWorkerArgs {
  HWND hwnd{};
  UiContext* context{};
  bool repair{false};
};

struct UninstallWorkerArgs {
  HWND hwnd{};
  UiContext* context{};
};

UiContext* GetContext(HWND hwnd) {
  return reinterpret_cast<UiContext*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

std::wstring QuotePath(const std::filesystem::path& path) {
  return L"\"" + path.wstring() + L"\"";
}

void AppendLog(HWND edit, const std::wstring& line) {
  if (edit == nullptr) {
    return;
  }

  const auto message = line + L"\r\n";
  SendMessageW(edit, EM_SETSEL, static_cast<WPARAM>(-1), static_cast<LPARAM>(-1));
  SendMessageW(edit, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(message.c_str()));
}

std::wstring ReadEditText(HWND edit) {
  if (edit == nullptr) {
    return {};
  }

  const auto length = GetWindowTextLengthW(edit);
  std::wstring value(static_cast<std::size_t>(length), L'\0');
  GetWindowTextW(edit, value.data(), length + 1);
  return value;
}

std::wstring TrimCopy(const std::wstring& value) {
  const auto first = value.find_first_not_of(L" \t\r\n");
  if (first == std::wstring::npos) {
    return {};
  }

  const auto last = value.find_last_not_of(L" \t\r\n");
  return value.substr(first, last - first + 1);
}

std::wstring ReadRegistryString(HKEY root, const wchar_t* subKey, const wchar_t* valueName);
bool WriteRegistryString(HKEY root, const wchar_t* subKey, const wchar_t* valueName, const std::wstring& value);
bool WriteRegistryDword(HKEY root, const wchar_t* subKey, const wchar_t* valueName, DWORD value);
bool DeleteRegistryTree(HKEY root, const wchar_t* subKey);
std::filesystem::path GetDefaultInstallRoot();
std::filesystem::path QueryInstallRoot();
bool ServiceExists();
bool IsInstalledAt(const std::filesystem::path& installRoot);
bool EnsureDirectory(const std::filesystem::path& path, std::wstring* errorMessage = nullptr);
bool ExtractResourceToFile(HINSTANCE instance, int resourceId, const std::filesystem::path& targetPath,
                           std::wstring* errorMessage);
bool RunProcessHidden(const std::filesystem::path& executable, const std::wstring& arguments,
                      const std::filesystem::path& workingDirectory, DWORD* exitCode, std::wstring* errorMessage);
bool WaitForServiceState(DWORD targetState, DWORD timeoutMs);
bool StartInstalledService(std::wstring* errorMessage);
bool StopInstalledService(std::wstring* errorMessage);
bool StopMatchingProcess(const std::filesystem::path& imagePath);
bool CreateShortcut(const std::filesystem::path& linkPath, const std::filesystem::path& targetPath,
                    const std::wstring& arguments, const std::wstring& description);
bool CreateStartMenuShortcuts(const std::filesystem::path& installRoot);
bool RemoveStartMenuShortcuts();
bool RegisterEndpointAutoStart(const std::filesystem::path& installRoot);
bool RemoveEndpointAutoStart();
DWORD EstimateInstallSizeKb(const std::filesystem::path& installRoot);
bool WriteArpEntry(const std::filesystem::path& installRoot);
std::wstring QueryConfiguredControlPlaneUrl();
bool ValidateControlPlaneUrl(const std::wstring& value, std::wstring* errorMessage);
bool PersistControlPlaneUrl(const std::wstring& value, std::wstring* errorMessage);
void PostLog(HWND hwnd, const std::wstring& text);
void PostStatus(HWND hwnd, const std::wstring& text, int progress);
void PostComplete(HWND hwnd, bool success, bool installed, bool closeAfter, const std::wstring& message);
bool CopySelfToInstallRoot(const std::filesystem::path& currentPath, const std::filesystem::path& installRoot,
                           std::wstring* errorMessage);
bool LaunchInstalledEndpointClient(const std::filesystem::path& installRoot, bool backgroundMode);
bool InstallPayloadFiles(HWND hwnd, UiContext* context, bool repair, std::wstring* errorMessage);
void RunInstallOrRepair(HWND hwnd, UiContext* context, bool repair);
std::filesystem::path GetTemporaryHelperPath();
void LaunchCleanupHelper(const std::filesystem::path& currentSetupPath, const std::filesystem::path& installRoot);
void RunUninstall(HWND hwnd, UiContext* context);
DWORD WINAPI InstallWorkerThread(LPVOID parameter);
DWORD WINAPI UninstallWorkerThread(LPVOID parameter);
DWORD ParseWaitPid(int argc, wchar_t* argv[]);
std::optional<std::filesystem::path> ParseCleanupRoot(int argc, wchar_t* argv[]);
void WaitForProcessExit(DWORD pid);
void DeleteSelfWithCmd(const std::filesystem::path& helperPath);
int RunCleanupMode(int argc, wchar_t* argv[]);
void RefreshUi(UiContext& context);
void LayoutControls(UiContext& context);
LRESULT CALLBACK WindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
bool HasArgument(int argc, wchar_t* argv[], const wchar_t* name);

std::wstring ReadRegistryString(HKEY root, const wchar_t* subKey, const wchar_t* valueName) {
  HKEY key = nullptr;
  if (RegOpenKeyExW(root, subKey, 0, KEY_READ, &key) != ERROR_SUCCESS) {
    return {};
  }

  DWORD type = 0;
  DWORD bytes = 0;
  if (RegQueryValueExW(key, valueName, nullptr, &type, nullptr, &bytes) != ERROR_SUCCESS || type != REG_SZ || bytes == 0) {
    RegCloseKey(key);
    return {};
  }

  std::wstring value(bytes / sizeof(wchar_t), L'\0');
  if (RegQueryValueExW(key, valueName, nullptr, &type, reinterpret_cast<LPBYTE>(value.data()), &bytes) != ERROR_SUCCESS) {
    RegCloseKey(key);
    return {};
  }

  RegCloseKey(key);
  if (!value.empty() && value.back() == L'\0') {
    value.pop_back();
  }
  return value;
}

bool WriteRegistryString(HKEY root, const wchar_t* subKey, const wchar_t* valueName, const std::wstring& value) {
  HKEY key = nullptr;
  if (RegCreateKeyExW(root, subKey, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &key, nullptr) != ERROR_SUCCESS) {
    return false;
  }

  const auto ok = RegSetValueExW(key, valueName, 0, REG_SZ, reinterpret_cast<const BYTE*>(value.c_str()),
                                 static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t))) == ERROR_SUCCESS;
  RegCloseKey(key);
  return ok;
}

bool WriteRegistryDword(HKEY root, const wchar_t* subKey, const wchar_t* valueName, const DWORD value) {
  HKEY key = nullptr;
  if (RegCreateKeyExW(root, subKey, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &key, nullptr) != ERROR_SUCCESS) {
    return false;
  }

  const auto ok =
      RegSetValueExW(key, valueName, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&value), sizeof(value)) == ERROR_SUCCESS;
  RegCloseKey(key);
  return ok;
}

bool DeleteRegistryTree(HKEY root, const wchar_t* subKey) {
  const auto status = RegDeleteTreeW(root, subKey);
  return status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND;
}

std::wstring QueryConfiguredControlPlaneUrl() {
  const auto persistedValue = ReadRegistryString(HKEY_LOCAL_MACHINE, kAgentRegistryRoot, kControlPlaneBaseUrlValueName);
  if (!persistedValue.empty()) {
    return persistedValue;
  }

  const auto environmentValue = _wgetenv(L"ANTIVIRUS_CONTROL_PLANE_URL");
  if (environmentValue != nullptr && *environmentValue != L'\0') {
    return environmentValue;
  }

  return L"http://127.0.0.1:4000";
}

bool ValidateControlPlaneUrl(const std::wstring& value, std::wstring* errorMessage) {
  if (value.empty()) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Enter the control plane URL for this endpoint.";
    }
    return false;
  }

  if (value.rfind(L"http://", 0) != 0 && value.rfind(L"https://", 0) != 0) {
    if (errorMessage != nullptr) {
      *errorMessage = L"The control plane URL must start with http:// or https://";
    }
    return false;
  }

  return true;
}

bool PersistControlPlaneUrl(const std::wstring& value, std::wstring* errorMessage) {
  if (WriteRegistryString(HKEY_LOCAL_MACHINE, kAgentRegistryRoot, kControlPlaneBaseUrlValueName, value)) {
    return true;
  }

  if (errorMessage != nullptr) {
    *errorMessage = L"Could not save the configured control plane URL.";
  }
  return false;
}

std::filesystem::path GetDefaultInstallRoot() {
  PWSTR programFiles = nullptr;
  std::filesystem::path installRoot;
  if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_ProgramFiles, 0, nullptr, &programFiles))) {
    installRoot = std::filesystem::path(programFiles) / kInstallFolderName;
    CoTaskMemFree(programFiles);
    return installRoot;
  }

  const auto env = _wgetenv(L"ProgramFiles");
  if (env != nullptr && *env != L'\0') {
    return std::filesystem::path(env) / kInstallFolderName;
  }

  return std::filesystem::current_path() / kInstallFolderName;
}

std::filesystem::path QueryInstallRoot() {
  return GetDefaultInstallRoot();
}

bool ServiceExists() {
  const auto manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (manager == nullptr) {
    return false;
  }

  const auto service = OpenServiceW(manager, kServiceName, SERVICE_QUERY_STATUS);
  if (service != nullptr) {
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return true;
  }

  CloseServiceHandle(manager);
  return false;
}

bool IsInstalledAt(const std::filesystem::path& installRoot) {
  return ServiceExists() || std::filesystem::exists(installRoot / kServiceExeName) ||
         !ReadRegistryString(HKEY_LOCAL_MACHINE, kArpRegistryRoot, L"InstallLocation").empty();
}

bool EnsureDirectory(const std::filesystem::path& path, std::wstring* errorMessage) {
  std::error_code error;
  std::filesystem::create_directories(path, error);
  if (error) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Could not create " + path.wstring();
    }
    return false;
  }
  return true;
}

bool ExtractResourceToFile(HINSTANCE instance, const int resourceId, const std::filesystem::path& targetPath,
                           std::wstring* errorMessage) {
  const auto resource = FindResourceW(instance, MAKEINTRESOURCEW(resourceId), RT_RCDATA);
  if (resource == nullptr) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Embedded setup payload is missing.";
    }
    return false;
  }

  const auto loaded = LoadResource(instance, resource);
  if (loaded == nullptr) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Could not load embedded setup payload.";
    }
    return false;
  }

  const auto size = SizeofResource(instance, resource);
  const auto bytes = LockResource(loaded);
  if (bytes == nullptr || size == 0) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Embedded setup payload was empty.";
    }
    return false;
  }

  if (!EnsureDirectory(targetPath.parent_path(), errorMessage)) {
    return false;
  }

  const auto temporaryPath = targetPath.wstring() + L".setup-new";
  DeleteFileW(temporaryPath.c_str());

  const auto fileHandle =
      CreateFileW(temporaryPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (fileHandle == INVALID_HANDLE_VALUE) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Could not write " + temporaryPath;
    }
    return false;
  }

  DWORD written = 0;
  const auto ok = WriteFile(fileHandle, bytes, size, &written, nullptr) != FALSE && written == size;
  CloseHandle(fileHandle);
  if (!ok) {
    DeleteFileW(temporaryPath.c_str());
    if (errorMessage != nullptr) {
      *errorMessage = L"Could not fully extract " + targetPath.wstring();
    }
    return false;
  }

  if (MoveFileExW(temporaryPath.c_str(), targetPath.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) !=
      FALSE) {
    return true;
  }

  const auto replaceError = GetLastError();
  if (MoveFileExW(temporaryPath.c_str(), targetPath.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_DELAY_UNTIL_REBOOT) !=
      FALSE) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Scheduled replacement of " + targetPath.wstring() +
                      L" for the next reboot because the existing file is currently in use.";
    }
    return true;
  }

  DeleteFileW(temporaryPath.c_str());

  if (errorMessage != nullptr) {
    *errorMessage = L"Could not replace " + targetPath.wstring() + L" (error " + std::to_wstring(replaceError) + L")";
  }
  return false;
}

bool RunProcessHidden(const std::filesystem::path& executable, const std::wstring& arguments,
                      const std::filesystem::path& workingDirectory, DWORD* exitCode, std::wstring* errorMessage) {
  std::wstring commandLine = QuotePath(executable);
  if (!arguments.empty()) {
    commandLine += L" ";
    commandLine += arguments;
  }

  STARTUPINFOW startupInfo{};
  startupInfo.cb = sizeof(startupInfo);
  startupInfo.dwFlags = STARTF_USESHOWWINDOW;
  startupInfo.wShowWindow = SW_HIDE;

  PROCESS_INFORMATION processInfo{};
  auto mutableCommandLine = commandLine;
  const auto launched = CreateProcessW(nullptr, mutableCommandLine.data(), nullptr, nullptr, FALSE,
                                       CREATE_NO_WINDOW, nullptr,
                                       workingDirectory.empty() ? nullptr : workingDirectory.c_str(),
                                       &startupInfo, &processInfo);
  if (!launched) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Could not start " + executable.wstring();
    }
    return false;
  }

  WaitForSingleObject(processInfo.hProcess, INFINITE);
  DWORD processExitCode = 0;
  GetExitCodeProcess(processInfo.hProcess, &processExitCode);
  CloseHandle(processInfo.hThread);
  CloseHandle(processInfo.hProcess);
  if (exitCode != nullptr) {
    *exitCode = processExitCode;
  }
  if (processExitCode != 0 && errorMessage != nullptr) {
    *errorMessage = executable.filename().wstring() + L" exited with code " + std::to_wstring(processExitCode);
  }
  return processExitCode == 0;
}

bool WaitForServiceState(const DWORD targetState, const DWORD timeoutMs) {
  const auto manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (manager == nullptr) {
    return false;
  }

  const auto service = OpenServiceW(manager, kServiceName, SERVICE_QUERY_STATUS);
  if (service == nullptr) {
    CloseServiceHandle(manager);
    return false;
  }

  SERVICE_STATUS_PROCESS status{};
  DWORD bytesNeeded = 0;
  const auto deadline = GetTickCount64() + timeoutMs;
  bool reachedTarget = false;

  while (GetTickCount64() < deadline) {
    if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status),
                             &bytesNeeded) == FALSE) {
      break;
    }

    if (status.dwCurrentState == targetState) {
      reachedTarget = true;
      break;
    }

    Sleep(500);
  }

  CloseServiceHandle(service);
  CloseServiceHandle(manager);
  return reachedTarget;
}

bool StartInstalledService(std::wstring* errorMessage) {
  const auto manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (manager == nullptr) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Could not open the Service Control Manager.";
    }
    return false;
  }

  const auto service = OpenServiceW(manager, kServiceName, SERVICE_START | SERVICE_QUERY_STATUS);
  if (service == nullptr) {
    CloseServiceHandle(manager);
    if (errorMessage != nullptr) {
      *errorMessage = L"Could not open the installed protection service.";
    }
    return false;
  }

  const auto started = StartServiceW(service, 0, nullptr) != FALSE || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
  CloseServiceHandle(service);
  CloseServiceHandle(manager);
  if (!started) {
    if (errorMessage != nullptr) {
      *errorMessage = L"The protection service could not be started.";
    }
    return false;
  }

  if (!WaitForServiceState(SERVICE_RUNNING, 20'000)) {
    if (errorMessage != nullptr) {
      *errorMessage = L"The protection service did not reach the running state.";
    }
    return false;
  }

  return true;
}

bool StopInstalledService(std::wstring* errorMessage) {
  const auto manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (manager == nullptr) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Could not open the Service Control Manager.";
    }
    return false;
  }

  const auto service = OpenServiceW(manager, kServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS);
  if (service == nullptr) {
    const auto error = GetLastError();
    CloseServiceHandle(manager);
    if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
      return true;
    }
    if (errorMessage != nullptr) {
      *errorMessage = L"Could not open the installed protection service.";
    }
    return false;
  }

  SERVICE_STATUS_PROCESS status{};
  DWORD bytesNeeded = 0;
  if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status),
                           &bytesNeeded) == FALSE) {
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    if (errorMessage != nullptr) {
      *errorMessage = L"Could not query the installed protection service state.";
    }
    return false;
  }

  if (status.dwCurrentState == SERVICE_STOPPED) {
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return true;
  }

  SERVICE_STATUS controlStatus{};
  if (ControlService(service, SERVICE_CONTROL_STOP, &controlStatus) == FALSE) {
    const auto error = GetLastError();
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    if (error != ERROR_SERVICE_NOT_ACTIVE) {
      if (errorMessage != nullptr) {
        *errorMessage = L"The protection service could not be stopped.";
      }
      return false;
    }
  }

  const auto stopped = WaitForServiceState(SERVICE_STOPPED, 20'000);
  CloseServiceHandle(service);
  CloseServiceHandle(manager);
  if (!stopped) {
    if (errorMessage != nullptr) {
      *errorMessage = L"The protection service did not stop in time.";
    }
    return false;
  }

  return true;
}

bool StopMatchingProcess(const std::filesystem::path& imagePath) {
  const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) {
    return false;
  }

  PROCESSENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  bool stoppedAny = false;
  if (Process32FirstW(snapshot, &entry) != FALSE) {
    do {
      const auto processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | SYNCHRONIZE, FALSE,
                                             entry.th32ProcessID);
      if (processHandle == nullptr) {
        continue;
      }

      std::wstring buffer(MAX_PATH, L'\0');
      DWORD bufferSize = static_cast<DWORD>(buffer.size());
      if (QueryFullProcessImageNameW(processHandle, 0, buffer.data(), &bufferSize) != FALSE) {
        buffer.resize(bufferSize);
        if (_wcsicmp(buffer.c_str(), imagePath.c_str()) == 0) {
          TerminateProcess(processHandle, 0);
          WaitForSingleObject(processHandle, 5'000);
          stoppedAny = true;
        }
      }

      CloseHandle(processHandle);
    } while (Process32NextW(snapshot, &entry) != FALSE);
  }

  CloseHandle(snapshot);
  return stoppedAny;
}

bool CreateShortcut(const std::filesystem::path& linkPath, const std::filesystem::path& targetPath,
                    const std::wstring& arguments, const std::wstring& description) {
  EnsureDirectory(linkPath.parent_path(), nullptr);

  const auto coInit = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
  const auto shouldCoUninitialize = SUCCEEDED(coInit);

  Microsoft::WRL::ComPtr<IShellLinkW> shellLink;
  if (FAILED(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&shellLink)))) {
    if (shouldCoUninitialize) {
      CoUninitialize();
    }
    return false;
  }

  shellLink->SetPath(targetPath.c_str());
  shellLink->SetArguments(arguments.c_str());
  shellLink->SetDescription(description.c_str());
  shellLink->SetWorkingDirectory(targetPath.parent_path().c_str());
  shellLink->SetIconLocation(targetPath.c_str(), 0);

  Microsoft::WRL::ComPtr<IPersistFile> persistFile;
  if (FAILED(shellLink.As(&persistFile))) {
    if (shouldCoUninitialize) {
      CoUninitialize();
    }
    return false;
  }

  const auto saved = SUCCEEDED(persistFile->Save(linkPath.c_str(), TRUE));
  if (shouldCoUninitialize) {
    CoUninitialize();
  }

  return saved;
}

std::optional<std::filesystem::path> GetProgramsFolder(const KNOWNFOLDERID& folderId) {
  PWSTR programs = nullptr;
  if (FAILED(SHGetKnownFolderPath(folderId, 0, nullptr, &programs))) {
    return std::nullopt;
  }

  std::filesystem::path result(programs);
  CoTaskMemFree(programs);
  return result;
}

bool CreateStartMenuShortcuts(const std::filesystem::path& installRoot) {
  for (const auto folderId : {FOLDERID_CommonPrograms, FOLDERID_Programs}) {
    const auto programsRoot = GetProgramsFolder(folderId);
    if (!programsRoot.has_value()) {
      continue;
    }

    const auto shortcutRoot = *programsRoot / kProductName;
    const auto endpointShortcut = shortcutRoot / L"Fenrir Endpoint.lnk";
    const auto uninstallShortcut = shortcutRoot / L"Uninstall Fenrir Endpoint.lnk";

    if (CreateShortcut(endpointShortcut, installRoot / kEndpointExeName, L"", L"Open Fenrir Endpoint") &&
        CreateShortcut(uninstallShortcut, installRoot / kSetupExeName, L"--uninstall", L"Remove Fenrir Endpoint")) {
      return true;
    }
  }

  return false;
}

bool RemoveStartMenuShortcuts() {
  bool removedAny = false;
  bool attempted = false;

  for (const auto folderId : {FOLDERID_CommonPrograms, FOLDERID_Programs}) {
    const auto programsRoot = GetProgramsFolder(folderId);
    if (!programsRoot.has_value()) {
      continue;
    }

    attempted = true;
    const auto shortcutRoot = *programsRoot / kProductName;
    std::error_code error;
    std::filesystem::remove_all(shortcutRoot, error);
    if (!error) {
      removedAny = true;
    }
  }

  return attempted ? removedAny : false;
}

bool RegisterEndpointAutoStart(const std::filesystem::path& installRoot) {
  return WriteRegistryString(HKEY_LOCAL_MACHINE, kRunRegistryRoot, kRunValueName,
                             QuotePath(installRoot / kEndpointExeName) + L" --background");
}

bool RemoveEndpointAutoStart() {
  HKEY key = nullptr;
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kRunRegistryRoot, 0, KEY_SET_VALUE, &key) != ERROR_SUCCESS) {
    return true;
  }

  const auto status = RegDeleteValueW(key, kRunValueName);
  RegCloseKey(key);
  return status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND;
}

DWORD EstimateInstallSizeKb(const std::filesystem::path& installRoot) {
  std::uintmax_t totalBytes = 0;
  std::error_code error;
  for (std::filesystem::recursive_directory_iterator it(
           installRoot, std::filesystem::directory_options::skip_permission_denied, error);
       it != std::filesystem::recursive_directory_iterator(); it.increment(error)) {
    if (error) {
      error.clear();
      continue;
    }
    if (it->is_regular_file(error)) {
      totalBytes += it->file_size(error);
    }
    if (error) {
      error.clear();
    }
  }

  return static_cast<DWORD>((totalBytes + 1023) / 1024);
}

bool WriteArpEntry(const std::filesystem::path& installRoot) {
  const auto uninstallCommand = QuotePath(installRoot / kSetupExeName) + L" --uninstall";
  const auto installDate = [] {
    SYSTEMTIME now{};
    GetLocalTime(&now);
    wchar_t buffer[9]{};
    StringCchPrintfW(buffer, std::size(buffer), L"%04u%02u%02u", now.wYear, now.wMonth, now.wDay);
    return std::wstring(buffer);
  }();

  return WriteRegistryString(HKEY_LOCAL_MACHINE, kArpRegistryRoot, L"DisplayName", kProductName) &&
         WriteRegistryString(HKEY_LOCAL_MACHINE, kArpRegistryRoot, L"Publisher", kCompanyName) &&
         WriteRegistryString(HKEY_LOCAL_MACHINE, kArpRegistryRoot, L"InstallLocation", installRoot.wstring()) &&
         WriteRegistryString(HKEY_LOCAL_MACHINE, kArpRegistryRoot, L"DisplayIcon",
                             (installRoot / kEndpointExeName).wstring()) &&
         WriteRegistryString(HKEY_LOCAL_MACHINE, kArpRegistryRoot, L"DisplayVersion", L"0.1.0-alpha") &&
         WriteRegistryString(HKEY_LOCAL_MACHINE, kArpRegistryRoot, L"InstallDate", installDate) &&
         WriteRegistryString(HKEY_LOCAL_MACHINE, kArpRegistryRoot, L"UninstallString", uninstallCommand) &&
         WriteRegistryString(HKEY_LOCAL_MACHINE, kArpRegistryRoot, L"QuietUninstallString", uninstallCommand) &&
         WriteRegistryDword(HKEY_LOCAL_MACHINE, kArpRegistryRoot, L"EstimatedSize", EstimateInstallSizeKb(installRoot)) &&
         WriteRegistryDword(HKEY_LOCAL_MACHINE, kArpRegistryRoot, L"NoModify", 1) &&
         WriteRegistryDword(HKEY_LOCAL_MACHINE, kArpRegistryRoot, L"NoRepair", 0);
}

void PostLog(HWND hwnd, const std::wstring& text) {
  if (!IsWindow(hwnd)) {
    return;
  }
  auto* payload = new LogMessagePayload{.text = text};
  PostMessageW(hwnd, kInstallerLogMessage, 0, reinterpret_cast<LPARAM>(payload));
}

void PostStatus(HWND hwnd, const std::wstring& text, const int progress) {
  if (!IsWindow(hwnd)) {
    return;
  }
  auto* payload = new StatusMessagePayload{.text = text, .progress = progress};
  PostMessageW(hwnd, kInstallerStatusMessage, 0, reinterpret_cast<LPARAM>(payload));
}

void PostComplete(HWND hwnd, const bool success, const bool installed, const bool closeAfter,
                  const std::wstring& message) {
  if (!IsWindow(hwnd)) {
    return;
  }
  auto* payload = new CompletionPayload{.success = success, .installed = installed, .closeAfter = closeAfter, .message = message};
  PostMessageW(hwnd, kInstallerCompleteMessage, 0, reinterpret_cast<LPARAM>(payload));
}

bool CopySelfToInstallRoot(const std::filesystem::path& currentPath, const std::filesystem::path& installRoot,
                           std::wstring* errorMessage) {
  const auto targetPath = installRoot / kSetupExeName;
  if (_wcsicmp(currentPath.c_str(), targetPath.c_str()) == 0) {
    return true;
  }

  if (!CopyFileW(currentPath.c_str(), targetPath.c_str(), FALSE)) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Could not place the setup executable into the install directory.";
    }
    return false;
  }

  return true;
}

bool LaunchInstalledEndpointClient(const std::filesystem::path& installRoot, const bool backgroundMode) {
  const auto arguments = backgroundMode ? L"--background" : L"";
  return reinterpret_cast<std::intptr_t>(ShellExecuteW(nullptr, L"open", (installRoot / kEndpointExeName).c_str(),
                                                       arguments, installRoot.c_str(),
                                                       backgroundMode ? SW_HIDE : SW_SHOWNORMAL)) > 32;
}

bool InstallPayloadFiles(HWND hwnd, UiContext* context, const bool repair, std::wstring* errorMessage) {
  const auto installRoot = context->installRoot;
  PostStatus(hwnd, repair ? L"Preparing repair..." : L"Preparing install...", 5);
  PostLog(hwnd, L"Using install path " + installRoot.wstring());

  if (repair) {
    PostLog(hwnd, L"Stopping the running endpoint client before replacing payloads");
    StopMatchingProcess(installRoot / kEndpointExeName);

    std::wstring stopError;
    PostLog(hwnd, L"Stopping the protection service before replacing payloads");
    if (!StopInstalledService(&stopError)) {
      if (errorMessage != nullptr) {
        *errorMessage = stopError;
      }
      return false;
    }
  }

  if (!EnsureDirectory(installRoot, errorMessage) ||
      !EnsureDirectory(installRoot / L"tools", errorMessage) ||
      !EnsureDirectory(installRoot / L"signatures", errorMessage)) {
    return false;
  }

  struct PayloadItem {
    int resourceId;
    std::filesystem::path relativePath;
    int progress;
    const wchar_t* label;
  };

  const std::vector<PayloadItem> payloadItems{
      {IDR_PAYLOAD_SERVICE, kServiceExeName, 15, L"Installing service binary"},
      {IDR_PAYLOAD_ENDPOINT_CLIENT, kEndpointExeName, 25, L"Installing endpoint client"},
      {IDR_PAYLOAD_AMSI_PROVIDER, kAmsiDllName, 35, L"Installing AMSI provider"},
      {IDR_PAYLOAD_SCANNERCLI, kToolsRelativePath, 45, L"Installing diagnostic scanner"},
      {IDR_PAYLOAD_AMSITESTCLI, kToolsAmsiTestCliRelativePath, 50, L"Installing AMSI diagnostic tool"},
      {IDR_PAYLOAD_ETWTESTCLI, kToolsEtwTestCliRelativePath, 54, L"Installing ETW diagnostic tool"},
      {IDR_PAYLOAD_WFPTESTCLI, kToolsWfpTestCliRelativePath, 58, L"Installing WFP diagnostic tool"},
      {IDR_PAYLOAD_WINPTHREAD, kWinpthreadDllName, 62, L"Installing runtime dependencies"},
      {IDR_PAYLOAD_WINPTHREAD, kToolsWinpthreadRelativePath, 66, L"Installing tool runtime dependencies"},
      {IDR_PAYLOAD_SIGNATURES, kSignatureBundleRelativePath, 70, L"Installing signature bundle"},
  };

  for (const auto& item : payloadItems) {
    PostStatus(hwnd, item.label, item.progress);
    PostLog(hwnd, item.label);
    if (!ExtractResourceToFile(context->instance, item.resourceId, installRoot / item.relativePath, errorMessage)) {
      return false;
    }
  }

  PostStatus(hwnd, L"Registering maintenance assets...", 75);
  PostLog(hwnd, L"Copying setup executable into the install directory");
  if (!CopySelfToInstallRoot(context->setupPath, installRoot, errorMessage)) {
    return false;
  }

  return true;
}

void RunInstallOrRepair(HWND hwnd, UiContext* context, const bool repair) {
  std::wstring errorMessage;
  if (!InstallPayloadFiles(hwnd, context, repair, &errorMessage)) {
    PostComplete(hwnd, false, false, false, errorMessage);
    return;
  }

  PostLog(hwnd, L"Saving control plane URL: " + context->controlPlaneBaseUrl);
  if (!PersistControlPlaneUrl(context->controlPlaneBaseUrl, &errorMessage)) {
    PostComplete(hwnd, false, false, false, errorMessage);
    return;
  }

  const auto serviceExe = context->installRoot / kServiceExeName;
  DWORD exitCode = 0;
  PostStatus(hwnd, repair ? L"Repairing service registration..." : L"Registering protection service...", 80);
  PostLog(hwnd, repair ? L"Running service repair" : L"Installing the protection service");
  if (!RunProcessHidden(serviceExe, repair ? L"--repair" : L"--install", context->installRoot, &exitCode, &errorMessage)) {
    PostComplete(hwnd, false, false, false, errorMessage);
    return;
  }

  PostStatus(hwnd, L"Starting protection service...", 87);
  PostLog(hwnd, L"Starting the installed protection service");
  if (!StartInstalledService(&errorMessage)) {
    PostComplete(hwnd, false, false, false, errorMessage);
    return;
  }

  PostStatus(hwnd, L"Configuring startup and shortcuts...", 93);
  PostLog(hwnd, L"Registering endpoint client auto-start");
  if (!RegisterEndpointAutoStart(context->installRoot)) {
    PostComplete(hwnd, false, false, false, L"Could not register endpoint auto-start.");
    return;
  }

  PostLog(hwnd, L"Creating Start menu shortcuts");
  if (!CreateStartMenuShortcuts(context->installRoot)) {
    PostComplete(hwnd, false, false, false, L"Could not create Start menu shortcuts.");
    return;
  }

  PostStatus(hwnd, L"Writing Add/Remove Programs entry...", 97);
  PostLog(hwnd, L"Registering the uninstall entry");
  if (!WriteArpEntry(context->installRoot)) {
    PostComplete(hwnd, false, false, false, L"Could not register the Add/Remove Programs entry.");
    return;
  }

  PostStatus(hwnd, L"Launching background companion...", 100);
  PostLog(hwnd, L"Starting the installed endpoint client in silent tray mode");
  LaunchInstalledEndpointClient(context->installRoot, true);
  PostComplete(hwnd, true, true, false, repair ? L"Fenrir Endpoint was repaired successfully."
                                               : L"Fenrir Endpoint was installed successfully.");
}

std::filesystem::path GetTemporaryHelperPath() {
  wchar_t tempPath[MAX_PATH]{};
  GetTempPathW(static_cast<DWORD>(std::size(tempPath)), tempPath);
  return std::filesystem::path(tempPath) / L"FenrirSetup-Cleanup.exe";
}

void LaunchCleanupHelper(const std::filesystem::path& currentSetupPath, const std::filesystem::path& installRoot) {
  const auto helperPath = GetTemporaryHelperPath();
  CopyFileW(currentSetupPath.c_str(), helperPath.c_str(), FALSE);

  std::wstringstream args;
  args << L"--cleanup " << QuotePath(installRoot) << L" --wait-pid " << GetCurrentProcessId();
  STARTUPINFOW startupInfo{};
  startupInfo.cb = sizeof(startupInfo);
  startupInfo.dwFlags = STARTF_USESHOWWINDOW;
  startupInfo.wShowWindow = SW_HIDE;
  PROCESS_INFORMATION processInfo{};
  auto commandLine = QuotePath(helperPath) + L" " + args.str();
  auto mutableCommandLine = commandLine;
  if (CreateProcessW(nullptr, mutableCommandLine.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr,
                     helperPath.parent_path().c_str(), &startupInfo, &processInfo) != FALSE) {
    CloseHandle(processInfo.hThread);
    CloseHandle(processInfo.hProcess);
  }
}

void RunUninstall(HWND hwnd, UiContext* context) {
  const auto installRoot = context->installRoot;
  const auto endpointClientPath = installRoot / kEndpointExeName;
  const auto serviceExe = installRoot / kServiceExeName;

  StopMatchingProcess(endpointClientPath);

  std::wstring errorMessage;
  DWORD exitCode = 0;
  if (std::filesystem::exists(serviceExe)) {
    PostStatus(hwnd, L"Removing protection service...", 30);
    PostLog(hwnd, L"Uninstalling the protection service");
    if (!RunProcessHidden(serviceExe, L"--uninstall", installRoot, &exitCode, &errorMessage)) {
      PostComplete(hwnd, false, true, false, errorMessage);
      return;
    }
  }

  PostStatus(hwnd, L"Removing startup and shortcuts...", 55);
  PostLog(hwnd, L"Removing endpoint client auto-start");
  RemoveEndpointAutoStart();
  PostLog(hwnd, L"Removing Start menu shortcuts");
  RemoveStartMenuShortcuts();

  PostStatus(hwnd, L"Removing installation registry entries...", 75);
  DeleteRegistryTree(HKEY_LOCAL_MACHINE, kArpRegistryRoot);
  DeleteRegistryTree(HKEY_LOCAL_MACHINE, kAgentRegistryRoot);

  PostStatus(hwnd, L"Finalizing removal...", 100);
  LaunchCleanupHelper(context->setupPath, installRoot);
  PostComplete(hwnd, true, false, true, L"Fenrir Endpoint was removed. The setup window will close to finish cleanup.");
}

DWORD WINAPI InstallWorkerThread(LPVOID parameter) {
  std::unique_ptr<InstallWorkerArgs> args(reinterpret_cast<InstallWorkerArgs*>(parameter));
  RunInstallOrRepair(args->hwnd, args->context, args->repair);
  return 0;
}

DWORD WINAPI UninstallWorkerThread(LPVOID parameter) {
  std::unique_ptr<UninstallWorkerArgs> args(reinterpret_cast<UninstallWorkerArgs*>(parameter));
  RunUninstall(args->hwnd, args->context);
  return 0;
}

DWORD ParseWaitPid(int argc, wchar_t* argv[]) {
  for (int index = 1; index < argc - 1; ++index) {
    if (_wcsicmp(argv[index], L"--wait-pid") == 0) {
      return static_cast<DWORD>(_wtoi(argv[index + 1]));
    }
  }
  return 0;
}

std::optional<std::filesystem::path> ParseCleanupRoot(int argc, wchar_t* argv[]) {
  for (int index = 1; index < argc - 1; ++index) {
    if (_wcsicmp(argv[index], L"--cleanup") == 0) {
      return std::filesystem::path(argv[index + 1]);
    }
  }
  return std::nullopt;
}

void WaitForProcessExit(const DWORD pid) {
  if (pid == 0) {
    Sleep(1500);
    return;
  }

  const auto process = OpenProcess(SYNCHRONIZE, FALSE, pid);
  if (process == nullptr) {
    Sleep(1500);
    return;
  }

  WaitForSingleObject(process, 30'000);
  CloseHandle(process);
}

void DeleteSelfWithCmd(const std::filesystem::path& helperPath) {
  const auto command = L"/c ping 127.0.0.1 -n 3 > nul & del /f /q " + QuotePath(helperPath);
  ShellExecuteW(nullptr, L"open", L"cmd.exe", command.c_str(), nullptr, SW_HIDE);
}

int RunCleanupMode(int argc, wchar_t* argv[]) {
  const auto cleanupRoot = ParseCleanupRoot(argc, argv);
  if (!cleanupRoot.has_value()) {
    return 1;
  }

  const auto waitPid = ParseWaitPid(argc, argv);
  WaitForProcessExit(waitPid);

  std::error_code error;
  std::filesystem::remove_all(*cleanupRoot, error);
  if (error) {
    for (std::filesystem::recursive_directory_iterator it(
             *cleanupRoot, std::filesystem::directory_options::skip_permission_denied, error);
         it != std::filesystem::recursive_directory_iterator(); it.increment(error)) {
      if (error) {
        error.clear();
        continue;
      }
      MoveFileExW(it->path().c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
    }
    MoveFileExW(cleanupRoot->c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
  }

  std::wstring helperPath(MAX_PATH, L'\0');
  const auto written = GetModuleFileNameW(nullptr, helperPath.data(), static_cast<DWORD>(helperPath.size()));
  helperPath.resize(written);
  DeleteSelfWithCmd(helperPath);
  return 0;
}

void RefreshUi(UiContext& context) {
  context.installed = IsInstalledAt(context.installRoot);
  SetWindowTextW(context.pathValue, context.installRoot.c_str());
  SetWindowTextW(context.statusLabel,
                 context.installed ? L"Existing installation detected. You can repair or remove it."
                                  : L"Ready to install Fenrir Endpoint on this device.");
  SetWindowTextW(context.primaryButton, context.installed ? L"Repair" : L"Install");
  EnableWindow(context.uninstallButton, context.installed && !context.busy);
  EnableWindow(context.primaryButton, !context.busy);
  EnableWindow(context.closeButton, !context.busy);
  EnableWindow(context.openFolderButton, !context.busy);
}

void LayoutControls(UiContext& context) {
  RECT client{};
  GetClientRect(context.hwnd, &client);

  const int padding = 18;
  const int width = client.right - client.left;
  const int contentWidth = width - (padding * 2);

  MoveWindow(context.titleLabel, padding, padding, contentWidth, 34, TRUE);
  MoveWindow(context.subtitleLabel, padding, padding + 38, contentWidth, 42, TRUE);
  MoveWindow(context.pathLabel, padding, padding + 88, 120, 22, TRUE);
  MoveWindow(context.pathValue, padding + 126, padding + 84, contentWidth - 126, 28, TRUE);
  MoveWindow(context.controlPlaneLabel, padding, padding + 122, 120, 22, TRUE);
  MoveWindow(context.controlPlaneEdit, padding + 126, padding + 118, contentWidth - 126, 28, TRUE);
  MoveWindow(context.statusLabel, padding, padding + 156, contentWidth, 24, TRUE);
  MoveWindow(context.progressBar, padding, padding + 188, contentWidth, 18, TRUE);
  MoveWindow(context.logEdit, padding, padding + 216, contentWidth, 206, TRUE);

  const int buttonTop = padding + 434;
  MoveWindow(context.primaryButton, padding, buttonTop, 140, 36, TRUE);
  MoveWindow(context.uninstallButton, padding + 152, buttonTop, 140, 36, TRUE);
  MoveWindow(context.openFolderButton, padding + 304, buttonTop, 160, 36, TRUE);
  MoveWindow(context.closeButton, width - padding - 120, buttonTop, 120, 36, TRUE);
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
  switch (message) {
    case WM_CREATE: {
      auto* context = new UiContext{};
      context->instance = reinterpret_cast<LPCREATESTRUCTW>(lParam)->hInstance;
      context->hwnd = hwnd;
      context->installRoot = QueryInstallRoot();
      context->controlPlaneBaseUrl = QueryConfiguredControlPlaneUrl();

      std::wstring setupPath(MAX_PATH, L'\0');
      const auto written = GetModuleFileNameW(nullptr, setupPath.data(), static_cast<DWORD>(setupPath.size()));
      setupPath.resize(written);
      context->setupPath = setupPath;
      SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(context));

      NONCLIENTMETRICSW metrics{};
      metrics.cbSize = sizeof(metrics);
      SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(metrics), &metrics, 0);
      wcscpy_s(metrics.lfMessageFont.lfFaceName, L"Segoe UI");
      context->bodyFont = CreateFontIndirectW(&metrics.lfMessageFont);
      auto titleFont = metrics.lfMessageFont;
      titleFont.lfHeight = 28;
      titleFont.lfWeight = FW_BOLD;
      wcscpy_s(titleFont.lfFaceName, L"Segoe UI Variable Display Semibold");
      context->titleFont = CreateFontIndirectW(&titleFont);

      context->titleLabel = CreateWindowW(L"STATIC", L"Fenrir Endpoint Setup", WS_CHILD | WS_VISIBLE,
                                          0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_TITLE), nullptr, nullptr);
      context->subtitleLabel = CreateWindowW(
          L"STATIC",
          L"Install, repair, or remove the Fenrir Endpoint service, local protection client, and signature bundle.",
          WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_SUBTITLE), nullptr, nullptr);
      context->pathLabel = CreateWindowW(L"STATIC", L"Install path", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd,
                                         reinterpret_cast<HMENU>(IDC_PATH_LABEL), nullptr, nullptr);
      context->pathValue = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd,
                                         reinterpret_cast<HMENU>(IDC_PATH_VALUE), nullptr, nullptr);
      context->controlPlaneLabel = CreateWindowW(L"STATIC", L"Control plane", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd,
                                                 reinterpret_cast<HMENU>(IDC_CONTROL_PLANE_LABEL), nullptr, nullptr);
      context->controlPlaneEdit =
          CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", context->controlPlaneBaseUrl.c_str(),
                          WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                          0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_CONTROL_PLANE_EDIT), nullptr, nullptr);
      context->statusLabel = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd,
                                           reinterpret_cast<HMENU>(IDC_STATUS), nullptr, nullptr);
      context->progressBar = CreateWindowExW(0, PROGRESS_CLASSW, nullptr, WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
                                             0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_PROGRESS), nullptr, nullptr);
      context->logEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_MULTILINE |
                                                                  ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL,
                                         0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_LOG), nullptr, nullptr);
      context->primaryButton = CreateWindowW(L"BUTTON", L"Install", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd,
                                             reinterpret_cast<HMENU>(IDC_PRIMARY_BUTTON), nullptr, nullptr);
      context->uninstallButton = CreateWindowW(L"BUTTON", L"Uninstall", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd,
                                               reinterpret_cast<HMENU>(IDC_UNINSTALL_BUTTON), nullptr, nullptr);
      context->openFolderButton = CreateWindowW(L"BUTTON", L"Open install folder", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0,
                                                hwnd, reinterpret_cast<HMENU>(IDC_OPEN_FOLDER_BUTTON), nullptr, nullptr);
      context->closeButton = CreateWindowW(L"BUTTON", L"Close", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd,
                                           reinterpret_cast<HMENU>(IDC_CLOSE_BUTTON), nullptr, nullptr);

      const std::array<HWND, 11> controls{context->titleLabel,        context->subtitleLabel, context->pathLabel,
                                          context->pathValue,         context->controlPlaneLabel,
                                          context->controlPlaneEdit,  context->statusLabel,   context->logEdit,
                                          context->primaryButton,     context->uninstallButton,
                                          context->openFolderButton};
      for (const auto control : controls) {
        SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(context->bodyFont), TRUE);
      }
      SendMessageW(context->titleLabel, WM_SETFONT, reinterpret_cast<WPARAM>(context->titleFont), TRUE);
      SendMessageW(context->progressBar, PBM_SETRANGE32, 0, 100);
      SendMessageW(context->progressBar, PBM_SETPOS, 0, 0);

      LayoutControls(*context);
      RefreshUi(*context);
      AppendLog(context->logEdit, L"Setup initialized.");
      return 0;
    }

    case WM_SIZE: {
      if (auto* context = GetContext(hwnd)) {
        LayoutControls(*context);
      }
      return 0;
    }

    case WM_COMMAND: {
      auto* context = GetContext(hwnd);
      if (context == nullptr) {
        break;
      }

      switch (LOWORD(wParam)) {
        case IDC_PRIMARY_BUTTON:
          if (!context->busy) {
            const auto configuredControlPlaneUrl = TrimCopy(ReadEditText(context->controlPlaneEdit));
            std::wstring validationMessage;
            if (!ValidateControlPlaneUrl(configuredControlPlaneUrl, &validationMessage)) {
              MessageBoxW(hwnd, validationMessage.c_str(), kWindowTitle, MB_OK | MB_ICONWARNING);
              return 0;
            }

            context->controlPlaneBaseUrl = configuredControlPlaneUrl;
            context->busy = true;
            RefreshUi(*context);
            const auto repair = context->installed;
            AppendLog(context->logEdit, repair ? L"Starting repair..." : L"Starting installation...");
            auto* workerArgs = new InstallWorkerArgs{.hwnd = hwnd, .context = context, .repair = repair};
            const auto threadHandle =
                CreateThread(nullptr, 0, InstallWorkerThread, workerArgs, 0, nullptr);
            if (threadHandle != nullptr) {
              CloseHandle(threadHandle);
            }
          }
          return 0;
        case IDC_UNINSTALL_BUTTON:
          if (!context->busy &&
              MessageBoxW(hwnd, L"Remove Fenrir Endpoint from this device?", kWindowTitle,
                          MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) == IDYES) {
            context->busy = true;
            RefreshUi(*context);
            AppendLog(context->logEdit, L"Starting uninstall...");
            auto* workerArgs = new UninstallWorkerArgs{.hwnd = hwnd, .context = context};
            const auto threadHandle =
                CreateThread(nullptr, 0, UninstallWorkerThread, workerArgs, 0, nullptr);
            if (threadHandle != nullptr) {
              CloseHandle(threadHandle);
            }
          }
          return 0;
        case IDC_OPEN_FOLDER_BUTTON:
          EnsureDirectory(context->installRoot);
          ShellExecuteW(hwnd, L"open", context->installRoot.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
          return 0;
        case IDC_CLOSE_BUTTON:
          DestroyWindow(hwnd);
          return 0;
        default:
          return 0;
      }
    }

    case kInstallerLogMessage: {
      auto* context = GetContext(hwnd);
      auto* payload = reinterpret_cast<LogMessagePayload*>(lParam);
      if (context != nullptr && payload != nullptr) {
        AppendLog(context->logEdit, payload->text);
      }
      delete payload;
      return 0;
    }

    case kInstallerStatusMessage: {
      auto* context = GetContext(hwnd);
      auto* payload = reinterpret_cast<StatusMessagePayload*>(lParam);
      if (context != nullptr && payload != nullptr) {
        SetWindowTextW(context->statusLabel, payload->text.c_str());
        SendMessageW(context->progressBar, PBM_SETPOS, payload->progress, 0);
      }
      delete payload;
      return 0;
    }

    case kInstallerCompleteMessage: {
      auto* context = GetContext(hwnd);
      auto* payload = reinterpret_cast<CompletionPayload*>(lParam);
      if (context != nullptr && payload != nullptr) {
        context->busy = false;
        context->installed = payload->installed;
        SetWindowTextW(context->statusLabel, payload->message.c_str());
        AppendLog(context->logEdit, payload->message);
        RefreshUi(*context);
        MessageBoxW(hwnd, payload->message.c_str(), kWindowTitle,
                    MB_OK | (payload->success ? MB_ICONINFORMATION : MB_ICONWARNING));
        if (payload->closeAfter) {
          DestroyWindow(hwnd);
        }
      }
      delete payload;
      return 0;
    }

    case WM_DESTROY: {
      if (auto* context = GetContext(hwnd)) {
        if (context->titleFont != nullptr) {
          DeleteObject(context->titleFont);
        }
        if (context->bodyFont != nullptr) {
          DeleteObject(context->bodyFont);
        }
        delete context;
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
      }
      PostQuitMessage(0);
      return 0;
    }
  }

  return DefWindowProcW(hwnd, message, wParam, lParam);
}

bool HasArgument(int argc, wchar_t* argv[], const wchar_t* name) {
  for (int index = 1; index < argc; ++index) {
    if (_wcsicmp(argv[index], name) == 0) {
      return true;
    }
  }
  return false;
}

}  // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int showCommand) {
  int argc = 0;
  wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
  if (argv != nullptr && HasArgument(argc, argv, L"--cleanup")) {
    const auto result = RunCleanupMode(argc, argv);
    LocalFree(argv);
    return result;
  }

  INITCOMMONCONTROLSEX controls{};
  controls.dwSize = sizeof(controls);
  controls.dwICC = ICC_STANDARD_CLASSES | ICC_PROGRESS_CLASS;
  InitCommonControlsEx(&controls);
  CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

  WNDCLASSEXW windowClass{};
  windowClass.cbSize = sizeof(windowClass);
  windowClass.lpfnWndProc = WindowProc;
  windowClass.hInstance = instance;
  windowClass.lpszClassName = kWindowClassName;
  windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
  windowClass.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(IDI_SETUP_ICON));
  windowClass.hIconSm = LoadIconW(instance, MAKEINTRESOURCEW(IDI_SETUP_ICON));
  windowClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
  RegisterClassExW(&windowClass);

  HWND hwnd = CreateWindowExW(0, kWindowClassName, kWindowTitle,
                              WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                              CW_USEDEFAULT, CW_USEDEFAULT, 760, 560,
                              nullptr, nullptr, instance, nullptr);
  if (hwnd == nullptr) {
    if (argv != nullptr) {
      LocalFree(argv);
    }
    CoUninitialize();
    return 1;
  }

  ShowWindow(hwnd, showCommand == 0 ? SW_SHOWDEFAULT : showCommand);
  UpdateWindow(hwnd);

  if (argv != nullptr && HasArgument(argc, argv, L"--uninstall")) {
    PostMessageW(hwnd, WM_COMMAND, IDC_UNINSTALL_BUTTON, 0);
  }

  if (argv != nullptr) {
    LocalFree(argv);
  }

  MSG message{};
  while (GetMessageW(&message, nullptr, 0, 0) > 0) {
    TranslateMessage(&message);
    DispatchMessageW(&message);
  }

  CoUninitialize();
  return static_cast<int>(message.wParam);
}
