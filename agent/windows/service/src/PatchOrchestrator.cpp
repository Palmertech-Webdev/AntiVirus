#include "PatchOrchestrator.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "RuntimeDatabase.h"
#include "StringUtils.h"

namespace antivirus::agent {
namespace {

struct ProcessExecutionResult {
  DWORD exitCode{0};
  std::wstring output;
};

struct SoftwareProviderResolution {
  PatchProviderKind provider{PatchProviderKind::Manual};
  std::wstring providerId;
  std::wstring supportedSource;
  std::wstring summary;
  bool supported{false};
  bool manualOnly{false};
};

std::wstring ToLowerCopy(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return value;
}

std::vector<std::wstring> SplitLines(const std::wstring& value) {
  std::vector<std::wstring> lines;
  std::wstringstream stream(value);
  std::wstring line;
  while (std::getline(stream, line)) {
    if (!line.empty() && line.back() == L'\r') {
      line.pop_back();
    }
    if (!line.empty()) {
      lines.push_back(line);
    }
  }
  return lines;
}

std::vector<std::wstring> SplitWide(const std::wstring& value, const wchar_t separator) {
  std::vector<std::wstring> parts;
  std::wstring current;
  for (const auto ch : value) {
    if (ch == separator) {
      parts.push_back(current);
      current.clear();
      continue;
    }
    current.push_back(ch);
  }
  parts.push_back(current);
  return parts;
}

std::wstring JoinStrings(const std::vector<std::wstring>& values, const wchar_t separator = L';') {
  std::wstring joined;
  for (std::size_t index = 0; index < values.size(); ++index) {
    if (index != 0) {
      joined.push_back(separator);
    }
    joined += values[index];
  }
  return joined;
}

std::wstring QuoteForPowerShellSingleQuoted(const std::wstring& value) {
  std::wstring escaped;
  for (const auto ch : value) {
    if (ch == L'\'') {
      escaped += L"''";
    } else {
      escaped.push_back(ch);
    }
  }
  return escaped;
}

ProcessExecutionResult ExecuteHiddenProcessCapture(const std::wstring& commandLine,
                                                   const std::wstring& workingDirectory = {}) {
  SECURITY_ATTRIBUTES securityAttributes{};
  securityAttributes.nLength = sizeof(securityAttributes);
  securityAttributes.bInheritHandle = TRUE;

  HANDLE readHandle = nullptr;
  HANDLE writeHandle = nullptr;
  if (CreatePipe(&readHandle, &writeHandle, &securityAttributes, 0) == FALSE) {
    throw std::runtime_error("CreatePipe failed");
  }

  SetHandleInformation(readHandle, HANDLE_FLAG_INHERIT, 0);

  std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
  mutableCommandLine.push_back(L'\0');

  STARTUPINFOW startupInfo{};
  startupInfo.cb = sizeof(startupInfo);
  startupInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
  startupInfo.wShowWindow = SW_HIDE;
  startupInfo.hStdOutput = writeHandle;
  startupInfo.hStdError = writeHandle;
  startupInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

  PROCESS_INFORMATION processInfo{};
  const auto created =
      CreateProcessW(nullptr, mutableCommandLine.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr,
                     workingDirectory.empty() ? nullptr : workingDirectory.c_str(), &startupInfo, &processInfo);
  CloseHandle(writeHandle);
  if (!created) {
    CloseHandle(readHandle);
    throw std::runtime_error("CreateProcessW failed");
  }

  std::string output;
  std::array<char, 4096> buffer{};
  DWORD bytesRead = 0;
  while (ReadFile(readHandle, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, nullptr) != FALSE &&
         bytesRead > 0) {
    output.append(buffer.data(), bytesRead);
  }

  WaitForSingleObject(processInfo.hProcess, INFINITE);

  DWORD exitCode = 0;
  GetExitCodeProcess(processInfo.hProcess, &exitCode);
  CloseHandle(readHandle);
  CloseHandle(processInfo.hThread);
  CloseHandle(processInfo.hProcess);

  return ProcessExecutionResult{
      .exitCode = exitCode,
      .output = Utf8ToWide(output)};
}

std::filesystem::path WriteTempPowerShellScript(const AgentConfig& config, const std::wstring& scriptContent,
                                                const std::wstring& prefix) {
  const auto jobsRoot = config.updateRootPath / L"patch-orchestrator";
  std::error_code error;
  std::filesystem::create_directories(jobsRoot, error);
  const auto scriptPath = jobsRoot / (prefix + L"-" + GenerateGuidString() + L".ps1");

  std::ofstream output(scriptPath, std::ios::binary | std::ios::trunc);
  if (!output.is_open()) {
    throw std::runtime_error("Unable to create temporary patch orchestrator script");
  }

  const auto utf8Content = WideToUtf8(scriptContent);
  output.write(utf8Content.data(), static_cast<std::streamsize>(utf8Content.size()));
  return scriptPath;
}

ProcessExecutionResult ExecutePowerShellScript(const AgentConfig& config, const std::wstring& scriptContent,
                                               const std::wstring& prefix,
                                               const std::vector<std::wstring>& arguments = {}) {
  const auto scriptPath = WriteTempPowerShellScript(config, scriptContent, prefix);
  std::wstring commandLine = L"powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File \"" + scriptPath.wstring() + L"\"";
  for (const auto& argument : arguments) {
    commandLine += L" '";
    commandLine += QuoteForPowerShellSingleQuoted(argument);
    commandLine += L"'";
  }

  const auto result = ExecuteHiddenProcessCapture(commandLine, config.updateRootPath.wstring());
  std::error_code removeError;
  std::filesystem::remove(scriptPath, removeError);
  return result;
}

std::vector<PackageRecipeRecord> BuildDefaultRecipes() {
  const auto now = CurrentUtcTimestamp();
  return {
      PackageRecipeRecord{.recipeId = L"google-chrome",
                          .displayName = L"Google Chrome",
                          .publisher = L"Google",
                          .matchPattern = L"google chrome",
                          .wingetId = L"Google.Chrome",
                          .requiredSigner = L"Google",
                          .rebootBehavior = L"none",
                          .updatedAt = now,
                          .priority = 100},
      PackageRecipeRecord{.recipeId = L"microsoft-edge",
                          .displayName = L"Microsoft Edge",
                          .publisher = L"Microsoft",
                          .matchPattern = L"microsoft edge",
                          .wingetId = L"Microsoft.Edge",
                          .requiredSigner = L"Microsoft",
                          .rebootBehavior = L"none",
                          .updatedAt = now,
                          .priority = 100},
      PackageRecipeRecord{.recipeId = L"mozilla-firefox",
                          .displayName = L"Mozilla Firefox",
                          .publisher = L"Mozilla",
                          .matchPattern = L"firefox",
                          .wingetId = L"Mozilla.Firefox",
                          .requiredSigner = L"Mozilla",
                          .rebootBehavior = L"none",
                          .updatedAt = now,
                          .priority = 120},
      PackageRecipeRecord{.recipeId = L"adobe-reader",
                          .displayName = L"Adobe Acrobat Reader",
                          .publisher = L"Adobe",
                          .matchPattern = L"adobe",
                          .wingetId = L"Adobe.Acrobat.Reader.64-bit",
                          .requiredSigner = L"Adobe",
                          .rebootBehavior = L"none",
                          .updatedAt = now,
                          .priority = 120},
      PackageRecipeRecord{.recipeId = L"7zip",
                          .displayName = L"7-Zip",
                          .publisher = L"Igor Pavlov",
                          .matchPattern = L"7-zip",
                          .wingetId = L"7zip.7zip",
                          .requiredSigner = L"Igor Pavlov",
                          .rebootBehavior = L"none",
                          .updatedAt = now,
                          .priority = 140},
      PackageRecipeRecord{.recipeId = L"java-runtime",
                          .displayName = L"Java",
                          .publisher = L"Oracle",
                          .matchPattern = L"java",
                          .wingetId = L"Oracle.JavaRuntimeEnvironment",
                          .requiredSigner = L"Oracle",
                          .rebootBehavior = L"none",
                          .updatedAt = now,
                          .priority = 140},
      PackageRecipeRecord{.recipeId = L"vlc-media-player",
                          .displayName = L"VLC media player",
                          .publisher = L"VideoLAN",
                          .matchPattern = L"vlc",
                          .wingetId = L"VideoLAN.VLC",
                          .requiredSigner = L"VideoLAN",
                          .rebootBehavior = L"none",
                          .updatedAt = now,
                          .priority = 150},
      PackageRecipeRecord{.recipeId = L"notepad-plus-plus",
                          .displayName = L"Notepad++",
                          .publisher = L"Notepad++ Team",
                          .matchPattern = L"notepad++",
                          .wingetId = L"Notepad++.Notepad++",
                          .requiredSigner = L"Notepad++",
                          .rebootBehavior = L"none",
                          .updatedAt = now,
                          .priority = 150},
      PackageRecipeRecord{.recipeId = L"microsoft-teams",
                          .displayName = L"Microsoft Teams",
                          .publisher = L"Microsoft",
                          .matchPattern = L"teams",
                          .wingetId = L"Microsoft.Teams",
                          .requiredSigner = L"Microsoft",
                          .rebootBehavior = L"none",
                          .updatedAt = now,
                          .priority = 160},
      PackageRecipeRecord{.recipeId = L"zoom",
                          .displayName = L"Zoom",
                          .publisher = L"Zoom",
                          .matchPattern = L"zoom",
                          .wingetId = L"Zoom.Zoom",
                          .requiredSigner = L"Zoom",
                          .rebootBehavior = L"none",
                          .updatedAt = now,
                          .priority = 160},
      PackageRecipeRecord{.recipeId = L"vcpp-redistributable",
                          .displayName = L"Microsoft Visual C++ Redistributable",
                          .publisher = L"Microsoft",
                          .matchPattern = L"visual c++",
                          .wingetId = L"Microsoft.VCRedist.2015+.x64",
                          .requiredSigner = L"Microsoft",
                          .rebootBehavior = L"possible",
                          .updatedAt = now,
                          .priority = 180},
  };
}

bool IsHighRiskSoftware(const InstalledSoftwareInventoryItem& item) {
  const auto lowerName = ToLowerCopy(item.displayName);
  const std::vector<std::wstring> patterns = {
      L"chrome", L"edge", L"firefox", L"adobe", L"reader", L"java", L"zoom", L"teams",
      L"vpn",    L"remote", L"support", L"7-zip",  L"vlc",   L"notepad++", L"redistributable"};

  return std::any_of(patterns.begin(), patterns.end(),
                     [&lowerName](const auto& pattern) { return lowerName.find(pattern) != std::wstring::npos; });
}

std::optional<PackageRecipeRecord> MatchRecipe(const InstalledSoftwareInventoryItem& item,
                                               const std::vector<PackageRecipeRecord>& recipes) {
  const auto lowerName = ToLowerCopy(item.displayName);
  const auto lowerPublisher = ToLowerCopy(item.publisher);
  for (const auto& recipe : recipes) {
    if (!recipe.enabled) {
      continue;
    }

    if (!recipe.matchPattern.empty() && lowerName.find(ToLowerCopy(recipe.matchPattern)) != std::wstring::npos) {
      return recipe;
    }

    if (!recipe.publisher.empty() && !item.publisher.empty() &&
        lowerPublisher.find(ToLowerCopy(recipe.publisher)) != std::wstring::npos &&
        lowerName.find(ToLowerCopy(recipe.displayName)) != std::wstring::npos) {
      return recipe;
    }
  }

  return std::nullopt;
}

std::filesystem::path FindNativeUpdaterExecutable(const InstalledSoftwareInventoryItem& item, const std::wstring& updaterName) {
  const auto localAppData = ReadEnvironmentVariable(L"LOCALAPPDATA");
  const auto programFiles = ReadEnvironmentVariable(L"ProgramFiles");
  const auto programFilesX86 = ReadEnvironmentVariable(L"ProgramFiles(x86)");

  std::vector<std::filesystem::path> candidates;
  if (!item.installLocation.empty()) {
    candidates.emplace_back(std::filesystem::path(item.installLocation) / updaterName);
    candidates.emplace_back(std::filesystem::path(item.installLocation).parent_path() / L"Update" / updaterName);
  }
  if (!localAppData.empty()) {
    candidates.emplace_back(std::filesystem::path(localAppData) / L"Google" / L"Update" / updaterName);
    candidates.emplace_back(std::filesystem::path(localAppData) / L"Microsoft" / L"EdgeUpdate" / updaterName);
  }
  if (!programFiles.empty()) {
    candidates.emplace_back(std::filesystem::path(programFiles) / L"Google" / L"Update" / updaterName);
    candidates.emplace_back(std::filesystem::path(programFiles) / L"Microsoft" / L"EdgeUpdate" / updaterName);
  }
  if (!programFilesX86.empty()) {
    candidates.emplace_back(std::filesystem::path(programFilesX86) / L"Google" / L"Update" / updaterName);
    candidates.emplace_back(std::filesystem::path(programFilesX86) / L"Microsoft" / L"EdgeUpdate" / updaterName);
  }

  std::error_code error;
  for (const auto& candidate : candidates) {
    if (std::filesystem::exists(candidate, error)) {
      return candidate;
    }
  }

  return {};
}

bool WingetAvailable() {
  try {
    const auto result = ExecuteHiddenProcessCapture(L"cmd.exe /c winget --version");
    return result.exitCode == 0;
  } catch (...) {
    return false;
  }
}

std::wstring BuildWindowsUpdateDiscoveryScript() {
  return LR"(
$ErrorActionPreference = 'Stop'
function Sanitize([string]$value) {
  if ($null -eq $value) { return '' }
  return ($value -replace "`t", ' ' -replace "`r", ' ' -replace "`n", ' ').Trim()
}

$reasons = New-Object System.Collections.Generic.List[string]
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $reasons.Add('windows_update') | Out-Null }
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $reasons.Add('component_servicing') | Out-Null }
if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager') {
  $pending = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction SilentlyContinue).PendingFileRenameOperations
  if ($pending) { $reasons.Add('pending_file_rename') | Out-Null }
}
$computerName = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -ErrorAction SilentlyContinue).ComputerName
$pendingComputerName = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -ErrorAction SilentlyContinue).ComputerName
if ($computerName -and $pendingComputerName -and $computerName -ne $pendingComputerName) { $reasons.Add('computer_rename') | Out-Null }
Write-Output ("REBOOT`t{0}`t{1}" -f ($(if ($reasons.Count -gt 0) { '1' } else { '0' })), (Sanitize ($reasons -join ';')))

$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$criteriaList = @("IsInstalled=0 and Type='Software'", "IsInstalled=0 and Type='Driver'")
foreach ($criteria in $criteriaList) {
  try {
    $searchResult = $searcher.Search($criteria)
    foreach ($update in $searchResult.Updates) {
      $categories = @($update.Categories | ForEach-Object { $_.Name }) -join ';'
      $kbs = @($update.KBArticleIDs) -join ';'
      $type = if ($criteria -like "*Driver*") { 'driver' } else { 'software' }
      Write-Output ("UPDATE`t{0}`t{1}`t{2}`t{3}`t{4}`t{5}`t{6}`t{7}`t{8}`t{9}`t{10}`t{11}`t{12}" -f `
        (Sanitize $update.Identity.UpdateID), `
        (Sanitize ([string]$update.Identity.RevisionNumber)), `
        (Sanitize $update.Title), `
        (Sanitize $kbs), `
        (Sanitize $categories), `
        (Sanitize $type), `
        (Sanitize $update.MsrcSeverity), `
        (Sanitize ([string]$update.InstallationBehavior.RebootBehavior)), `
        ($(if ($update.IsDownloaded) { '1' } else { '0' })), `
        ($(if ($update.IsHidden) { '1' } else { '0' })), `
        ($(if ($update.AutoSelectOnWebSites) { '1' } else { '0' })), `
        ($(if ($update.BrowseOnly) { '1' } else { '0' })), `
        ($(if ($update.InstallationBehavior.CanRequestUserInput) { '1' } else { '0' })))
    }
  } catch {
    Write-Output ("ERROR`tSEARCH`t{0}" -f (Sanitize $_.Exception.Message))
  }
}

try {
  $count = $searcher.GetTotalHistoryCount()
  if ($count -gt 0) {
    $history = $searcher.QueryHistory(0, [Math]::Min($count, 25))
    foreach ($entry in $history) {
      if ($entry.ResultCode -ne 2) {
        Write-Output ("HISTORY`t{0}`t{1}`t{2}`t{3}`t{4}`t{5}" -f `
          (Sanitize $entry.UpdateIdentity.UpdateID), `
          (Sanitize $entry.Title), `
          (Sanitize ([string]$entry.ResultCode)), `
          (Sanitize ([string]$entry.HResult)), `
          (Sanitize ([string]$entry.Operation)), `
          (Sanitize ($entry.Date.ToString('o'))))
      }
    }
  }
} catch {
  Write-Output ("ERROR`tHISTORY`t{0}" -f (Sanitize $_.Exception.Message))
}
)";
}

std::wstring BuildWindowsUpdateInstallScript() {
  return LR"PATCH(
param([string]$securityOnly, [string]$includeDrivers, [string]$includeOptional, [string]$deferFeatureUpdates)
$ErrorActionPreference = 'Stop'
function Sanitize([string]$value) {
  if ($null -eq $value) { return '' }
  return ($value -replace "`t", ' ' -replace "`r", ' ' -replace "`n", ' ').Trim()
}
function IsMatch([string]$text, [string[]]$patterns) {
  $lower = ([string]::IsNullOrEmpty($text) ? '' : $text).ToLowerInvariant()
  foreach ($pattern in $patterns) {
    if ($lower.Contains($pattern)) { return $true }
  }
  return $false
}
$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$criteriaList = @("IsInstalled=0 and Type='Software'")
if ($includeDrivers -eq '1') { $criteriaList += "IsInstalled=0 and Type='Driver'" }
$collection = New-Object -ComObject Microsoft.Update.UpdateColl
foreach ($criteria in $criteriaList) {
  $searchResult = $searcher.Search($criteria)
  foreach ($update in $searchResult.Updates) {
    $categories = @($update.Categories | ForEach-Object { $_.Name }) -join ';'
    $title = $update.Title
    $feature = (IsMatch $title @('feature update', 'windows 11, version', 'windows 10, version')) -or (IsMatch $categories @('feature packs', 'upgrades'))
    $optional = $update.BrowseOnly
    $securityLike = (IsMatch $title @('security', 'cumulative', '.net', 'defender', 'critical')) -or (IsMatch $categories @('security updates', 'critical updates', 'definition updates', 'update rollups', '.net'))
    if ($deferFeatureUpdates -eq '1' -and $feature) { continue }
    if ($includeOptional -ne '1' -and $optional) { continue }
    if ($securityOnly -eq '1' -and -not $securityLike) { continue }
    [void]$collection.Add($update)
  }
}
if ($collection.Count -eq 0) {
  Write-Output "RESULT`tno_updates`t0`t0"
  exit 0
}
$downloader = $session.CreateUpdateDownloader()
$downloader.Updates = $collection
$downloadResult = $downloader.Download()
$installer = $session.CreateUpdateInstaller()
$installer.Updates = $collection
$installResult = $installer.Install()
Write-Output ("RESULT`t{0}`t{1}`t{2}" -f (Sanitize ([string]$installResult.ResultCode)), ($(if ($installResult.RebootRequired) { '1' } else { '0' })), (Sanitize ([string]$downloadResult.ResultCode)))
for ($i = 0; $i -lt $collection.Count; $i++) {
  $update = $collection.Item($i)
  $result = $installResult.GetUpdateResult($i)
  Write-Output ("INSTALLED`t{0}`t{1}`t{2}`t{3}" -f (Sanitize $update.Identity.UpdateID), (Sanitize $update.Title), (Sanitize ([string]$result.ResultCode)), (Sanitize ([string]$result.HResult)))
}
)PATCH";
}

std::wstring BuildRecipeInstallScript() {
  return LR"PATCH(
param([string]$sourceUrl, [string]$targetPath, [string]$expectedSha256, [string]$requiredSigner, [string]$silentArgs)
$ErrorActionPreference = 'Stop'
Invoke-WebRequest -Uri $sourceUrl -OutFile $targetPath
if ($expectedSha256) {
  $hash = (Get-FileHash -Path $targetPath -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($hash -ne $expectedSha256.ToLowerInvariant()) {
    Write-Output ("RESULT`tfailed_hash`t0`t" + $hash)
    exit 3
  }
}
if ($requiredSigner) {
  $signature = Get-AuthenticodeSignature -FilePath $targetPath
  if (-not $signature.SignerCertificate -or $signature.SignerCertificate.Subject -notlike ("*" + $requiredSigner + "*")) {
    Write-Output ("RESULT`tfailed_signer`t0`t" + ($signature.Status.ToString()))
    exit 4
  }
}
$process = Start-Process -FilePath $targetPath -ArgumentList $silentArgs -Wait -PassThru -WindowStyle Hidden
Write-Output ("RESULT`tcompleted`t0`t" + $process.ExitCode)
)PATCH";
}

std::wstring ClassifyWindowsUpdate(const std::wstring& title, const std::wstring& categories, const bool driver,
                                   const bool optional) {
  const auto lowerTitle = ToLowerCopy(title);
  const auto lowerCategories = ToLowerCopy(categories);
  if (driver) {
    return L"driver";
  }
  if (lowerTitle.find(L"feature update") != std::wstring::npos || lowerCategories.find(L"upgrades") != std::wstring::npos) {
    return L"feature";
  }
  if (lowerTitle.find(L".net") != std::wstring::npos || lowerCategories.find(L".net") != std::wstring::npos) {
    return L"dotnet";
  }
  if (lowerTitle.find(L"defender") != std::wstring::npos || lowerCategories.find(L"definition") != std::wstring::npos) {
    return L"defender";
  }
  if (lowerTitle.find(L"security") != std::wstring::npos || lowerCategories.find(L"security updates") != std::wstring::npos) {
    return L"security";
  }
  if (lowerTitle.find(L"critical") != std::wstring::npos || lowerCategories.find(L"critical updates") != std::wstring::npos) {
    return L"critical";
  }
  if (lowerTitle.find(L"cumulative") != std::wstring::npos || lowerCategories.find(L"update rollups") != std::wstring::npos) {
    return L"cumulative";
  }
  if (optional) {
    return L"optional";
  }
  return L"quality";
}

std::wstring ComputeUpdateStatusFromOutput(const ProcessExecutionResult& result) {
  const auto lower = ToLowerCopy(result.output);
  if (result.exitCode != 0) {
    return L"failed";
  }
  if (lower.find(L"no available upgrade found") != std::wstring::npos) {
    return L"current";
  }
  if (lower.find(L"no installed package found") != std::wstring::npos) {
    return L"unsupported";
  }
  if (lower.find(L"available") != std::wstring::npos || lower.find(L"upgrade") != std::wstring::npos) {
    return L"available";
  }
  return L"unknown";
}

PatchPolicyRecord LoadOrCreatePolicy(RuntimeDatabase& database) {
  PatchPolicyRecord policy;
  if (!database.LoadPatchPolicy(policy)) {
    policy.updatedAt = CurrentUtcTimestamp();
    database.SavePatchPolicy(policy);
  }
  return policy;
}

SoftwareProviderResolution ResolveProvider(const InstalledSoftwareInventoryItem& item, const PatchPolicyRecord& policy,
                                           const std::vector<PackageRecipeRecord>& recipes) {
  SoftwareProviderResolution resolution{};
  const auto recipe = MatchRecipe(item, recipes);
  if (!recipe.has_value()) {
    resolution.summary = L"Fenrir does not currently have a trusted update provider for this software.";
    resolution.manualOnly = true;
    return resolution;
  }

  const auto lowerName = ToLowerCopy(item.displayName);
  if (policy.allowNativeUpdaters &&
      (lowerName.find(L"google chrome") != std::wstring::npos || lowerName.find(L"microsoft edge") != std::wstring::npos)) {
    const auto updaterPath =
        lowerName.find(L"google chrome") != std::wstring::npos
            ? FindNativeUpdaterExecutable(item, L"GoogleUpdate.exe")
            : FindNativeUpdaterExecutable(item, L"MicrosoftEdgeUpdate.exe");
    if (!updaterPath.empty()) {
      resolution.provider = PatchProviderKind::NativeUpdater;
      resolution.providerId = updaterPath.wstring();
      resolution.supportedSource = L"native-updater";
      resolution.supported = true;
      resolution.summary = L"Fenrir can patch this application using its trusted native silent updater.";
      return resolution;
    }
  }

  if (policy.allowWinget && !recipe->wingetId.empty()) {
    resolution.provider = PatchProviderKind::Winget;
    resolution.providerId = recipe->wingetId;
    resolution.supportedSource = L"winget";
    resolution.supported = true;
    resolution.summary = L"Fenrir can patch this application using winget.";
    return resolution;
  }

  if (policy.allowRecipes && !recipe->sourceUrl.empty()) {
    resolution.provider = PatchProviderKind::Recipe;
    resolution.providerId = recipe->recipeId;
    resolution.supportedSource = L"recipe";
    resolution.supported = true;
    resolution.summary = L"Fenrir can patch this application using a maintained package recipe.";
    resolution.manualOnly = recipe->manualOnly;
    return resolution;
  }

  resolution.provider = PatchProviderKind::Manual;
  resolution.providerId = recipe->recipeId;
  resolution.supportedSource = L"manual";
  resolution.supported = false;
  resolution.manualOnly = true;
  resolution.summary = L"Fenrir can inventory this application but patching currently requires a manual workflow.";
  return resolution;
}

std::optional<std::wstring> QueryWingetAvailableVersion(const std::wstring& wingetId) {
  const auto result = ExecuteHiddenProcessCapture(
      std::wstring(L"cmd.exe /c winget upgrade --id \"") + wingetId +
      L"\" --accept-source-agreements --disable-interactivity");
  if (result.exitCode != 0) {
    return std::nullopt;
  }

  const auto lower = ToLowerCopy(result.output);
  if (lower.find(L"no available upgrade found") != std::wstring::npos ||
      lower.find(L"no installed package found") != std::wstring::npos) {
    return std::nullopt;
  }

  return L"available";
}

std::vector<SoftwarePatchRecord> BuildSoftwarePatchInventory(const DeviceInventorySnapshot& snapshot,
                                                             const PatchPolicyRecord& policy,
                                                             const std::vector<PackageRecipeRecord>& recipes) {
  const auto wingetAvailable = WingetAvailable();
  std::vector<SoftwarePatchRecord> records;
  records.reserve(snapshot.installedSoftware.size());

  for (const auto& item : snapshot.installedSoftware) {
    const auto resolution = ResolveProvider(item, policy, recipes);
    auto updateState = resolution.manualOnly ? std::wstring(L"manual") : (resolution.supported ? L"current" : L"unsupported");
    auto availableVersion = std::wstring{};
    auto summary = resolution.summary;

    if (resolution.provider == PatchProviderKind::Winget && wingetAvailable) {
      if (const auto version = QueryWingetAvailableVersion(resolution.providerId); version.has_value()) {
        updateState = L"available";
        availableVersion = *version;
        summary = L"Fenrir found an available upgrade for this application through winget.";
      } else if (resolution.supported) {
        summary = L"Fenrir did not find a newer winget package for this application.";
      }
    } else if (resolution.provider == PatchProviderKind::NativeUpdater && !resolution.providerId.empty()) {
      summary = L"Fenrir can invoke the product's native updater during a maintenance window.";
      updateState = L"provider_ready";
    }

    records.push_back(SoftwarePatchRecord{
        .softwareId = item.softwareId,
        .displayName = item.displayName,
        .displayVersion = item.displayVersion,
        .availableVersion = availableVersion,
        .publisher = item.publisher,
        .installLocation = item.installLocation,
        .uninstallCommand = item.uninstallCommand,
        .quietUninstallCommand = item.quietUninstallCommand,
        .executableNames = JoinStrings(item.executableNames),
        .executablePaths = JoinStrings(item.executablePaths),
        .provider = PatchProviderKindToString(resolution.provider),
        .providerId = resolution.providerId,
        .supportedSource = resolution.supportedSource,
        .updateState = updateState,
        .updateSummary = summary,
        .lastCheckedAt = CurrentUtcTimestamp(),
        .blocked = item.blocked,
        .supported = resolution.supported,
        .manualOnly = resolution.manualOnly,
        .highRisk = IsHighRiskSoftware(item)});
  }

  return records;
}

std::vector<WindowsUpdateRecord> DiscoverWindowsUpdates(const AgentConfig& config, RebootCoordinatorRecord* rebootState,
                                                        std::vector<PatchHistoryRecord>* history) {
  const auto result = ExecutePowerShellScript(config, BuildWindowsUpdateDiscoveryScript(), L"wu-discovery");
  std::vector<WindowsUpdateRecord> updates;
  for (const auto& line : SplitLines(result.output)) {
    const auto parts = SplitWide(line, L'\t');
    if (parts.empty()) {
      continue;
    }

    if (parts[0] == L"REBOOT" && rebootState != nullptr) {
      rebootState->detectedAt = CurrentUtcTimestamp();
      rebootState->status = L"current";
      rebootState->rebootRequired = parts.size() >= 2 && parts[1] == L"1";
      rebootState->rebootReasons = parts.size() >= 3 ? parts[2] : L"";
      rebootState->pendingWindowsUpdate = rebootState->rebootReasons.find(L"windows_update") != std::wstring::npos;
      rebootState->pendingFileRename = rebootState->rebootReasons.find(L"pending_file_rename") != std::wstring::npos;
      rebootState->pendingComputerRename = rebootState->rebootReasons.find(L"computer_rename") != std::wstring::npos;
      rebootState->pendingComponentServicing = rebootState->rebootReasons.find(L"component_servicing") != std::wstring::npos;
      continue;
    }

    if (parts[0] == L"UPDATE" && parts.size() >= 13) {
      const auto driver = parts[5] == L"driver";
      const auto optional = parts[11] == L"1";
      const auto classification = ClassifyWindowsUpdate(parts[3], parts[5], driver, optional);
      updates.push_back(WindowsUpdateRecord{
          .updateId = parts[1],
          .revision = parts[2],
          .title = parts[3],
          .kbArticles = parts[4],
          .categories = parts[5],
          .classification = classification,
          .severity = parts[6],
          .updateType = parts[5],
          .deploymentAction = parts[7],
          .discoveredAt = CurrentUtcTimestamp(),
          .status = L"available",
          .detailJson = std::wstring(L"{\"canRequestUserInput\":") + (parts[12] == L"1" ? L"true" : L"false") + L"}",
          .hidden = parts[9] == L"1",
          .downloaded = parts[8] == L"1",
          .mandatory = parts[10] == L"1",
          .browseOnly = optional,
          .rebootRequired = parts[7] != L"0",
          .driver = driver,
          .featureUpdate = classification == L"feature",
          .optional = optional});
      continue;
    }

    if (parts[0] == L"HISTORY" && parts.size() >= 7 && history != nullptr) {
      history->push_back(PatchHistoryRecord{
          .recordId = GenerateGuidString(),
          .targetType = L"windows-update",
          .targetId = parts[1],
          .title = parts[2],
          .provider = L"windows-update-agent",
          .action = L"history",
          .status = parts[3] == L"2" ? L"succeeded" : L"failed",
          .startedAt = parts[6],
          .completedAt = parts[6],
          .errorCode = parts[4],
          .detailJson = std::wstring(L"{\"operation\":\"") + Utf8ToWide(EscapeJsonString(parts[5])) + L"\"}"});
    }
  }
  return updates;
}

PatchExecutionResult ExecuteWingetOperation(const std::wstring& wingetId, const bool searchOnly) {
  const auto command = searchOnly
                           ? std::wstring(L"cmd.exe /c winget upgrade --id \"") + wingetId +
                                 L"\" --accept-source-agreements --disable-interactivity"
                           : std::wstring(L"cmd.exe /c winget upgrade --id \"") + wingetId +
                                 L"\" --accept-package-agreements --accept-source-agreements --silent --disable-interactivity";
  const auto result = ExecuteHiddenProcessCapture(command);
  return PatchExecutionResult{
      .success = result.exitCode == 0,
      .action = searchOnly ? L"search" : L"install",
      .provider = L"winget",
      .status = searchOnly ? ComputeUpdateStatusFromOutput(result) : (result.exitCode == 0 ? L"completed" : L"failed"),
      .detailJson = std::wstring(L"{\"output\":\"") + Utf8ToWide(EscapeJsonString(result.output)) + L"\"}"};
}

PatchExecutionResult ExecuteNativeOperation(const std::wstring& providerId) {
  const auto lowerProvider = ToLowerCopy(providerId);
  std::wstring commandLine;
  if (lowerProvider.find(L"googleupdate.exe") != std::wstring::npos ||
      lowerProvider.find(L"microsoftedgeupdate.exe") != std::wstring::npos) {
    commandLine = L"\"" + providerId + L"\" /ua /installsource scheduler";
  } else {
    return PatchExecutionResult{
        .success = false,
        .action = L"install",
        .provider = L"native-updater",
        .status = L"unsupported",
        .errorCode = L"NATIVE_PROVIDER_UNSUPPORTED",
        .detailJson = L"{\"message\":\"Fenrir does not have a vetted native updater command for this product.\"}"};
  }

  const auto result = ExecuteHiddenProcessCapture(commandLine);
  return PatchExecutionResult{
      .success = result.exitCode == 0,
      .action = L"install",
      .provider = L"native-updater",
      .status = result.exitCode == 0 ? L"completed" : L"failed",
      .detailJson = std::wstring(L"{\"output\":\"") + Utf8ToWide(EscapeJsonString(result.output)) + L"\"}"};
}

PatchExecutionResult ExecuteRecipeOperation(const AgentConfig& config, const PackageRecipeRecord& recipe) {
  if (recipe.sourceUrl.empty()) {
    return PatchExecutionResult{
        .success = false,
        .action = L"install",
        .provider = L"recipe",
        .status = L"manual",
        .errorCode = L"RECIPE_SOURCE_MISSING",
        .detailJson = L"{\"message\":\"Recipe has no source URL and requires manual fulfillment.\"}"};
  }

  const auto downloadRoot = config.updateRootPath / L"third-party";
  std::error_code error;
  std::filesystem::create_directories(downloadRoot, error);
  const auto targetPath = downloadRoot / (recipe.recipeId + L".bin");
  const auto result = ExecutePowerShellScript(
      config, BuildRecipeInstallScript(), L"recipe-install",
      {recipe.sourceUrl, targetPath.wstring(), recipe.installerSha256, recipe.requiredSigner, recipe.silentArgs});

  std::wstring status = L"failed";
  std::wstring errorCode;
  for (const auto& line : SplitLines(result.output)) {
    const auto parts = SplitWide(line, L'\t');
    if (!parts.empty() && parts[0] == L"RESULT") {
      status = parts.size() >= 2 ? parts[1] : L"failed";
      errorCode = parts.size() >= 4 ? parts[3] : L"";
      break;
    }
  }

  return PatchExecutionResult{
      .success = result.exitCode == 0 && status == L"completed",
      .action = L"install",
      .provider = L"recipe",
      .status = status,
      .errorCode = errorCode,
      .detailJson = std::wstring(L"{\"output\":\"") + Utf8ToWide(EscapeJsonString(result.output)) + L"\"}"};
}

}  // namespace

std::wstring PatchProviderKindToString(const PatchProviderKind provider) {
  switch (provider) {
    case PatchProviderKind::NativeUpdater:
      return L"native-updater";
    case PatchProviderKind::Winget:
      return L"winget";
    case PatchProviderKind::Recipe:
      return L"recipe";
    default:
      return L"manual";
  }
}

PatchProviderKind PatchProviderKindFromString(const std::wstring& value) {
  const auto lower = ToLowerCopy(value);
  if (lower == L"native-updater") {
    return PatchProviderKind::NativeUpdater;
  }
  if (lower == L"winget") {
    return PatchProviderKind::Winget;
  }
  if (lower == L"recipe") {
    return PatchProviderKind::Recipe;
  }
  return PatchProviderKind::Manual;
}

PatchOrchestrator::PatchOrchestrator(const AgentConfig& config) : config_(config) {}

PatchRefreshSummary PatchOrchestrator::RefreshPatchState() const {
  RuntimeDatabase database(config_.runtimeDatabasePath);
  auto policy = LoadOrCreatePolicy(database);
  if (policy.updatedAt.empty()) {
    policy.updatedAt = CurrentUtcTimestamp();
    database.SavePatchPolicy(policy);
  }

  const auto recipes = BuildDefaultRecipes();
  database.ReplacePackageRecipes(recipes);

  std::vector<PatchHistoryRecord> historyFromDiscovery;
  RebootCoordinatorRecord rebootState{
      .gracePeriodMinutes = policy.rebootGracePeriodMinutes,
      .status = L"current"};
  const auto windowsUpdates = DiscoverWindowsUpdates(config_, &rebootState, &historyFromDiscovery);
  database.ReplaceWindowsUpdateRecords(windowsUpdates);
  database.SaveRebootCoordinator(rebootState);
  for (const auto& historyRecord : historyFromDiscovery) {
    database.UpsertPatchHistoryRecord(historyRecord);
  }

  const auto deviceInventory = CollectDeviceInventorySnapshot();
  const auto software = BuildSoftwarePatchInventory(deviceInventory, policy, recipes);
  database.ReplaceSoftwarePatchRecords(software);

  return PatchRefreshSummary{
      .windowsUpdateCount = windowsUpdates.size(),
      .softwareCount = software.size(),
      .recipeCount = recipes.size(),
      .rebootPending = rebootState.rebootRequired};
}

PatchSnapshot PatchOrchestrator::LoadSnapshot(const std::size_t windowsLimit, const std::size_t softwareLimit,
                                              const std::size_t historyLimit, const std::size_t recipeLimit) const {
  RuntimeDatabase database(config_.runtimeDatabasePath);
  PatchSnapshot snapshot{};
  snapshot.policy = LoadPolicy();
  database.LoadRebootCoordinator(snapshot.rebootState);
  snapshot.windowsUpdates = database.ListWindowsUpdateRecords(windowsLimit);
  snapshot.software = database.ListSoftwarePatchRecords(softwareLimit);
  snapshot.history = database.ListPatchHistoryRecords(historyLimit);
  snapshot.recipes = database.ListPackageRecipes(recipeLimit);
  return snapshot;
}

PatchExecutionResult PatchOrchestrator::InstallWindowsUpdates(const bool securityOnly) const {
  RuntimeDatabase database(config_.runtimeDatabasePath);
  const auto policy = LoadPolicy();

  PatchHistoryRecord history{
      .recordId = GenerateGuidString(),
      .targetType = L"windows-update",
      .targetId = securityOnly ? L"security-only" : L"policy-selected",
      .title = securityOnly ? L"Windows security patch cycle" : L"Windows patch cycle",
      .provider = L"windows-update-agent",
      .action = L"install",
      .status = L"started",
      .startedAt = CurrentUtcTimestamp()};
  database.UpsertPatchHistoryRecord(history);

  const auto result = ExecutePowerShellScript(
      config_, BuildWindowsUpdateInstallScript(), L"wu-install",
      {securityOnly ? L"1" : L"0", policy.includeDriverUpdates ? L"1" : L"0", policy.includeOptionalUpdates ? L"1" : L"0",
       policy.deferFeatureUpdates ? L"1" : L"0"});

  PatchExecutionResult execution{
      .action = L"install",
      .targetId = history.targetId,
      .provider = L"windows-update-agent",
      .status = result.exitCode == 0 ? L"completed" : L"failed",
      .detailJson = std::wstring(L"{\"output\":\"") + Utf8ToWide(EscapeJsonString(result.output)) + L"\"}"};

  for (const auto& line : SplitLines(result.output)) {
    const auto parts = SplitWide(line, L'\t');
    if (!parts.empty() && parts[0] == L"RESULT") {
      execution.status = parts.size() >= 2 ? parts[1] : execution.status;
      execution.rebootRequired = parts.size() >= 3 && parts[2] == L"1";
      execution.errorCode = parts.size() >= 4 ? parts[3] : L"";
      break;
    }
  }

  execution.success = result.exitCode == 0 && execution.status != L"failed";
  history.status = execution.status;
  history.completedAt = CurrentUtcTimestamp();
  history.errorCode = execution.errorCode;
  history.detailJson = execution.detailJson;
  history.rebootRequired = execution.rebootRequired;
  database.UpsertPatchHistoryRecord(history);

  if (execution.rebootRequired) {
    auto rebootState = RebootCoordinatorRecord{
        .rebootRequired = true,
        .pendingWindowsUpdate = true,
        .rebootReasons = L"windows_update",
        .detectedAt = CurrentUtcTimestamp(),
        .gracePeriodMinutes = policy.rebootGracePeriodMinutes,
        .status = L"pending"};
    database.SaveRebootCoordinator(rebootState);
  }

  RefreshPatchState();
  return execution;
}

PatchExecutionResult PatchOrchestrator::UpdateSoftware(const std::wstring& softwareId, const bool searchOnly) const {
  RuntimeDatabase database(config_.runtimeDatabasePath);
  const auto software = database.ListSoftwarePatchRecords(1000);
  const auto match = std::find_if(software.begin(), software.end(),
                                  [&](const auto& candidate) { return candidate.softwareId == softwareId; });
  if (match == software.end()) {
    throw std::runtime_error("Requested software patch target was not found");
  }

  PatchHistoryRecord history{
      .recordId = GenerateGuidString(),
      .targetType = L"software",
      .targetId = match->softwareId,
      .title = match->displayName,
      .provider = match->provider,
      .action = searchOnly ? L"search" : L"install",
      .status = L"started",
      .startedAt = CurrentUtcTimestamp()};
  database.UpsertPatchHistoryRecord(history);

  PatchExecutionResult execution{};
  switch (PatchProviderKindFromString(match->provider)) {
    case PatchProviderKind::Winget:
      execution = ExecuteWingetOperation(match->providerId, searchOnly);
      break;
    case PatchProviderKind::NativeUpdater:
      execution = searchOnly ? PatchExecutionResult{.success = true,
                                                    .action = L"search",
                                                    .targetId = match->softwareId,
                                                    .provider = L"native-updater",
                                                    .status = L"provider_ready",
                                                    .detailJson = L"{\"message\":\"Native updater available; search mode is advisory only.\"}"}
                             : ExecuteNativeOperation(match->providerId);
      break;
    case PatchProviderKind::Recipe: {
      const auto recipes = database.ListPackageRecipes(500);
      const auto recipe = std::find_if(recipes.begin(), recipes.end(),
                                       [&](const auto& candidate) { return candidate.recipeId == match->providerId; });
      execution = recipe == recipes.end()
                      ? PatchExecutionResult{.success = false,
                                             .action = searchOnly ? L"search" : L"install",
                                             .targetId = match->softwareId,
                                             .provider = L"recipe",
                                             .status = L"missing_recipe",
                                             .errorCode = L"RECIPE_NOT_FOUND"}
                      : (searchOnly ? PatchExecutionResult{.success = true,
                                                           .action = L"search",
                                                           .targetId = match->softwareId,
                                                           .provider = L"recipe",
                                                           .status = recipe->manualOnly ? L"manual" : L"provider_ready",
                                                           .detailJson = L"{\"message\":\"Recipe provider is registered for this software.\"}"}
                                    : ExecuteRecipeOperation(config_, *recipe));
      break;
    }
    default:
      execution = PatchExecutionResult{
          .success = false,
          .action = searchOnly ? L"search" : L"install",
          .targetId = match->softwareId,
          .provider = L"manual",
          .status = L"manual",
          .errorCode = L"MANUAL_ONLY",
          .detailJson = L"{\"message\":\"This software currently requires a manual update workflow.\"}"};
      break;
  }

  execution.targetId = match->softwareId;
  history.status = execution.status;
  history.completedAt = CurrentUtcTimestamp();
  history.errorCode = execution.errorCode;
  history.detailJson = execution.detailJson;
  history.rebootRequired = execution.rebootRequired;
  database.UpsertPatchHistoryRecord(history);

  RefreshPatchState();
  return execution;
}

PatchExecutionResult PatchOrchestrator::RunPatchCycle() const {
  RefreshPatchState();
  RuntimeDatabase database(config_.runtimeDatabasePath);
  const auto policy = LoadPolicy();
  if (policy.paused) {
    return PatchExecutionResult{
        .success = false,
        .action = L"cycle",
        .provider = L"policy",
        .status = L"paused",
        .errorCode = L"PATCH_POLICY_PAUSED"};
  }

  const auto windowsResult = InstallWindowsUpdates(true);
  const auto software = database.ListSoftwarePatchRecords(500);
  for (const auto& record : software) {
    if (!record.supported || record.manualOnly || record.blocked) {
      continue;
    }
    if (policy.autoUpdateHighRiskAppsOnly && !record.highRisk && !policy.autoUpdateAllSupportedApps) {
      continue;
    }
    if (record.updateState != L"available" && !policy.autoUpdateAllSupportedApps) {
      continue;
    }
    UpdateSoftware(record.softwareId, false);
  }

  RefreshPatchState();
  return PatchExecutionResult{
      .success = windowsResult.success,
      .rebootRequired = windowsResult.rebootRequired,
      .action = L"cycle",
      .provider = L"fenrir",
      .status = L"completed"};
}

void PatchOrchestrator::SavePolicy(const PatchPolicyRecord& policy) const {
  RuntimeDatabase database(config_.runtimeDatabasePath);
  auto persisted = policy;
  persisted.updatedAt = CurrentUtcTimestamp();
  database.SavePatchPolicy(persisted);
}

PatchPolicyRecord PatchOrchestrator::LoadPolicy() const {
  RuntimeDatabase database(config_.runtimeDatabasePath);
  return LoadOrCreatePolicy(database);
}

}  // namespace antivirus::agent
