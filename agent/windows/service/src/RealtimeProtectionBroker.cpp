#include "RealtimeProtectionBroker.h"

#include <Windows.h>
#include <TlHelp32.h>
#include <sddl.h>
#include <winternl.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cwctype>
#include <deque>
#include <filesystem>
#include <initializer_list>
#include <numeric>
#include <optional>
#include <string>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

#include "CryptoUtils.h"
#include "EvidenceRecorder.h"
#include "QuarantineStore.h"
#include "RemediationEngine.h"
#include "StringUtils.h"

namespace antivirus::agent {
namespace {

struct FilterMessageHeader {
  ULONG replyLength;
  ULONGLONG messageId;
};

struct FilterReplyHeader {
  LONG status;
  ULONGLONG messageId;
};

using FilterConnectCommunicationPortFn =
    HRESULT(WINAPI*)(LPCWSTR, DWORD, LPVOID, WORD, LPSECURITY_ATTRIBUTES, HANDLE*);
using FilterGetMessageFn = HRESULT(WINAPI*)(HANDLE, FilterMessageHeader*, DWORD, LPOVERLAPPED);
using FilterReplyMessageFn = HRESULT(WINAPI*)(HANDLE, FilterReplyHeader*, DWORD);

struct FilterApi {
  HMODULE module{nullptr};
  FilterConnectCommunicationPortFn connect{nullptr};
  FilterGetMessageFn getMessage{nullptr};
  FilterReplyMessageFn replyMessage{nullptr};

  bool Load() {
    module = LoadLibraryW(L"fltlib.dll");
    if (module == nullptr) {
      return false;
    }

    connect = reinterpret_cast<FilterConnectCommunicationPortFn>(
        GetProcAddress(module, "FilterConnectCommunicationPort"));
    getMessage = reinterpret_cast<FilterGetMessageFn>(GetProcAddress(module, "FilterGetMessage"));
    replyMessage = reinterpret_cast<FilterReplyMessageFn>(GetProcAddress(module, "FilterReplyMessage"));
    if (connect == nullptr || getMessage == nullptr || replyMessage == nullptr) {
      FreeLibrary(module);
      module = nullptr;
      connect = nullptr;
      getMessage = nullptr;
      replyMessage = nullptr;
      return false;
    }

    return true;
  }

  ~FilterApi() {
    if (module != nullptr) {
      FreeLibrary(module);
      module = nullptr;
    }
  }
};

#pragma pack(push, 8)
struct BrokerPortMessage {
  FilterMessageHeader header;
  RealtimeFileScanRequest request;
};

struct BrokerPortReply {
  FilterReplyHeader header;
  RealtimeFileScanReply reply;
};
#pragma pack(pop)

constexpr DWORD kBrokerMessageWaitMilliseconds = 1'000;
constexpr auto kProcessContextCacheTtl = std::chrono::seconds(15);
constexpr std::size_t kProcessContextCacheMaxEntries = 512;

struct CachedRealtimeProcessContext {
  DWORD parentPid{0};
  std::wstring imagePath;
  std::wstring parentImagePath;
  std::wstring commandLine;
  std::wstring userSid;
  std::chrono::steady_clock::time_point cachedAt{};
};

struct EnrichedRealtimeRequest {
  RealtimeFileScanRequest request{};
  bool contextEnriched{false};
};

std::mutex gProcessContextCacheMutex;
std::unordered_map<DWORD, CachedRealtimeProcessContext> gProcessContextCache;

std::wstring ToLowerCopy(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return value;
}

std::wstring SafeCopy(const wchar_t* value) {
  if (value == nullptr) {
    return {};
  }

  return std::wstring(value);
}

template <std::size_t N>
void CopyWideField(wchar_t (&destination)[N], const std::wstring& source) {
  std::fill(std::begin(destination), std::end(destination), L'\0');
  if constexpr (N == 0) {
    return;
  }

  wcsncpy_s(destination, N, source.c_str(), _TRUNCATE);
}

void PruneProcessContextCacheLocked(const std::chrono::steady_clock::time_point now) {
  for (auto iterator = gProcessContextCache.begin(); iterator != gProcessContextCache.end();) {
    if ((now - iterator->second.cachedAt) > kProcessContextCacheTtl) {
      iterator = gProcessContextCache.erase(iterator);
      continue;
    }

    ++iterator;
  }

  if (gProcessContextCache.size() > kProcessContextCacheMaxEntries) {
    gProcessContextCache.clear();
  }
}

std::wstring QueryProcessImagePath(const DWORD pid) {
  if (pid == 0) {
    return {};
  }

  const HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (processHandle == nullptr) {
    return {};
  }

  std::wstring buffer(4096, L'\0');
  DWORD length = static_cast<DWORD>(buffer.size());
  const auto succeeded = QueryFullProcessImageNameW(processHandle, 0, buffer.data(), &length) != FALSE;
  CloseHandle(processHandle);

  if (!succeeded) {
    return {};
  }

  buffer.resize(length);
  return buffer;
}

DWORD QueryParentProcessId(const DWORD pid) {
  if (pid == 0) {
    return 0;
  }

  const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) {
    return 0;
  }

  PROCESSENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  DWORD parentPid = 0;

  if (Process32FirstW(snapshot, &entry) != FALSE) {
    do {
      if (entry.th32ProcessID == pid) {
        parentPid = entry.th32ParentProcessID;
        break;
      }
    } while (Process32NextW(snapshot, &entry) != FALSE);
  }

  CloseHandle(snapshot);
  return parentPid;
}

std::wstring QueryProcessUserSid(const DWORD pid) {
  if (pid == 0) {
    return {};
  }

  const HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (processHandle == nullptr) {
    return {};
  }

  HANDLE tokenHandle = nullptr;
  if (OpenProcessToken(processHandle, TOKEN_QUERY, &tokenHandle) == FALSE) {
    CloseHandle(processHandle);
    return {};
  }

  DWORD requiredBytes = 0;
  GetTokenInformation(tokenHandle, TokenUser, nullptr, 0, &requiredBytes);
  if (requiredBytes == 0) {
    CloseHandle(tokenHandle);
    CloseHandle(processHandle);
    return {};
  }

  std::vector<unsigned char> buffer(requiredBytes);
  if (GetTokenInformation(tokenHandle, TokenUser, buffer.data(), requiredBytes, &requiredBytes) == FALSE) {
    CloseHandle(tokenHandle);
    CloseHandle(processHandle);
    return {};
  }

  const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(buffer.data());
  LPWSTR sidString = nullptr;
  const auto converted = ConvertSidToStringSidW(tokenUser->User.Sid, &sidString) != FALSE;

  std::wstring userSid;
  if (converted && sidString != nullptr) {
    userSid = sidString;
    LocalFree(sidString);
  }

  CloseHandle(tokenHandle);
  CloseHandle(processHandle);
  return userSid;
}

std::wstring QueryProcessCommandLine(const DWORD pid) {
  if (pid == 0) {
    return {};
  }

  const HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (processHandle == nullptr) {
    return {};
  }

  using NtQueryInformationProcessFn = LONG(WINAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
  static const auto ntQueryInformationProcess = reinterpret_cast<NtQueryInformationProcessFn>(
      GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
  if (ntQueryInformationProcess == nullptr) {
    CloseHandle(processHandle);
    return {};
  }

  ULONG requiredBytes = 0;
  constexpr auto kProcessCommandLineInformation =
      static_cast<PROCESSINFOCLASS>(60);
  (void)ntQueryInformationProcess(processHandle, kProcessCommandLineInformation, nullptr, 0, &requiredBytes);
  if (requiredBytes < sizeof(UNICODE_STRING)) {
    CloseHandle(processHandle);
    return {};
  }

  std::vector<unsigned char> buffer(requiredBytes);
  const auto status =
      ntQueryInformationProcess(processHandle, kProcessCommandLineInformation, buffer.data(), requiredBytes,
                                &requiredBytes);
  CloseHandle(processHandle);

  if (status < 0) {
    return {};
  }

  const auto* commandLine = reinterpret_cast<const UNICODE_STRING*>(buffer.data());
  if (commandLine->Length == 0 || commandLine->Buffer == nullptr) {
    return {};
  }

  return std::wstring(commandLine->Buffer, commandLine->Length / sizeof(wchar_t));
}

std::optional<CachedRealtimeProcessContext> QueryRealtimeProcessContext(const DWORD pid) {
  if (pid == 0) {
    return std::nullopt;
  }

  const auto now = std::chrono::steady_clock::now();
  {
    const std::scoped_lock lock(gProcessContextCacheMutex);
    PruneProcessContextCacheLocked(now);
    if (const auto existing = gProcessContextCache.find(pid); existing != gProcessContextCache.end()) {
      return existing->second;
    }
  }

  CachedRealtimeProcessContext context{
      .parentPid = QueryParentProcessId(pid),
      .imagePath = QueryProcessImagePath(pid),
      .parentImagePath = {},
      .commandLine = QueryProcessCommandLine(pid),
      .userSid = QueryProcessUserSid(pid),
      .cachedAt = now};

  if (context.parentPid != 0 && context.parentPid != pid) {
    context.parentImagePath = QueryProcessImagePath(context.parentPid);
  }

  if (context.imagePath.empty() && context.parentImagePath.empty() && context.commandLine.empty() &&
      context.userSid.empty()) {
    return std::nullopt;
  }

  {
    const std::scoped_lock lock(gProcessContextCacheMutex);
    PruneProcessContextCacheLocked(now);
    gProcessContextCache[pid] = context;
  }

  return context;
}

EnrichedRealtimeRequest EnrichRequestProcessContext(const RealtimeFileScanRequest& request) {
  if (request.processId == 0) {
    return EnrichedRealtimeRequest{.request = request, .contextEnriched = false};
  }

  const auto context = QueryRealtimeProcessContext(request.processId);
  if (!context.has_value()) {
    return EnrichedRealtimeRequest{.request = request, .contextEnriched = false};
  }

  auto enriched = request;
  bool changed = false;
  const auto processImage = SafeCopy(request.processImage);
  const auto parentImage = SafeCopy(request.parentImage);
  const auto commandLine = SafeCopy(request.commandLine);
  const auto userSid = SafeCopy(request.userSid);

  if (!context->imagePath.empty() && (processImage.empty() || processImage.find(L'\\') == std::wstring::npos)) {
    CopyWideField(enriched.processImage, context->imagePath);
    changed = true;
  }

  if (!context->parentImagePath.empty() && (parentImage.empty() || parentImage.find(L'\\') == std::wstring::npos)) {
    CopyWideField(enriched.parentImage, context->parentImagePath);
    changed = true;
  }

  if (!context->commandLine.empty() && commandLine.empty()) {
    CopyWideField(enriched.commandLine, context->commandLine);
    changed = true;
  }

  if (!context->userSid.empty() && userSid.empty()) {
    CopyWideField(enriched.userSid, context->userSid);
    changed = true;
  }

  return EnrichedRealtimeRequest{.request = enriched, .contextEnriched = changed};
}

std::wstring OperationToString(const RealtimeFileOperation operation) {
  switch (operation) {
    case ANTIVIRUS_REALTIME_FILE_OPERATION_CREATE:
      return L"create";
    case ANTIVIRUS_REALTIME_FILE_OPERATION_OPEN:
      return L"open";
    case ANTIVIRUS_REALTIME_FILE_OPERATION_WRITE:
      return L"write";
    case ANTIVIRUS_REALTIME_FILE_OPERATION_EXECUTE:
      return L"execute";
    default:
      return L"unknown";
  }
}

std::wstring EventKindToString(const EventKind kind) {
  switch (kind) {
    case EventKind::FileCreate:
      return L"file-create";
    case EventKind::FileOpen:
      return L"file-open";
    case EventKind::FileWrite:
      return L"file-write";
    case EventKind::FileExecute:
      return L"file-execute";
    case EventKind::ProcessStart:
      return L"process-start";
    case EventKind::ScriptScan:
      return L"script-scan";
    case EventKind::NetworkConnect:
      return L"network-connect";
    default:
      return L"unknown";
  }
}

RealtimeFileOperation EventKindToRealtimeOperation(const EventKind kind) {
  switch (kind) {
    case EventKind::FileCreate:
      return ANTIVIRUS_REALTIME_FILE_OPERATION_CREATE;
    case EventKind::FileOpen:
      return ANTIVIRUS_REALTIME_FILE_OPERATION_OPEN;
    case EventKind::FileWrite:
      return ANTIVIRUS_REALTIME_FILE_OPERATION_WRITE;
    case EventKind::NetworkConnect:
      return ANTIVIRUS_REALTIME_FILE_OPERATION_OPEN;
    case EventKind::ProcessStart:
    case EventKind::ScriptScan:
    case EventKind::FileExecute:
    default:
      return ANTIVIRUS_REALTIME_FILE_OPERATION_EXECUTE;
  }
}

EventKind OperationToEventKind(const RealtimeFileOperation operation) {
  switch (operation) {
    case ANTIVIRUS_REALTIME_FILE_OPERATION_CREATE:
      return EventKind::FileCreate;
    case ANTIVIRUS_REALTIME_FILE_OPERATION_OPEN:
      return EventKind::FileOpen;
    case ANTIVIRUS_REALTIME_FILE_OPERATION_WRITE:
      return EventKind::FileWrite;
    case ANTIVIRUS_REALTIME_FILE_OPERATION_EXECUTE:
    default:
      return EventKind::FileExecute;
  }
}

bool PathContains(const std::wstring& path, const std::wstring& pattern) {
  return path.find(pattern) != std::wstring::npos;
}

bool ContainsAnyToken(std::wstring_view haystack, std::initializer_list<std::wstring_view> needles) {
  return std::any_of(needles.begin(), needles.end(),
                     [haystack](const auto needle) { return haystack.find(needle) != std::wstring_view::npos; });
}

bool ImageContainsAny(std::wstring_view imageLower, std::initializer_list<std::wstring_view> candidates) {
  return ContainsAnyToken(imageLower, candidates);
}

bool IsUserControlledPath(const std::filesystem::path& path) {
  const auto lower = ToLowerCopy(path.wstring());
  return PathContains(lower, L"\\users\\") || PathContains(lower, L"\\programdata\\") ||
         PathContains(lower, L"\\temp\\") || PathContains(lower, L"\\downloads\\") ||
         PathContains(lower, L"\\desktop\\") || PathContains(lower, L"\\appdata\\local\\temp\\") ||
         PathContains(lower, L"\\start menu\\programs\\startup\\");
}

bool IsExecutableExtension(const std::wstring& extension) {
  return extension == L".exe" || extension == L".dll" || extension == L".scr" || extension == L".msi";
}

bool IsScriptExtension(const std::wstring& extension) {
  return extension == L".ps1" || extension == L".bat" || extension == L".cmd" || extension == L".js" ||
         extension == L".jse" || extension == L".vbs" || extension == L".vbe" || extension == L".hta";
}

bool IsContainerExtension(const std::wstring& extension) {
  return extension == L".lnk" || extension == L".iso" || extension == L".zip";
}

bool IsScriptingHostImage(std::wstring_view imageLower) {
  return ImageContainsAny(imageLower, {L"powershell.exe", L"pwsh.exe", L"cmd.exe", L"wscript.exe", L"cscript.exe"});
}

bool IsLolbinImage(std::wstring_view imageLower) {
  return ImageContainsAny(imageLower, {L"mshta.exe", L"rundll32.exe", L"regsvr32.exe", L"wmic.exe", L"msbuild.exe",
                                       L"installutil.exe", L"regasm.exe", L"regsvcs.exe"});
}

bool IsOfficeOrMailImage(std::wstring_view imageLower) {
  return ImageContainsAny(imageLower, {L"winword.exe", L"excel.exe", L"powerpnt.exe", L"outlook.exe",
                                       L"onenote.exe", L"acrord32.exe"});
}

bool IsBrowserImage(std::wstring_view imageLower) {
  return ImageContainsAny(imageLower, {L"chrome.exe", L"msedge.exe", L"firefox.exe", L"iexplore.exe", L"brave.exe"});
}

bool IsTrustedInstallerImage(std::wstring_view imageLower) {
  return ImageContainsAny(imageLower,
                          {L"msiexec.exe", L"winget.exe", L"choco.exe", L"scoop.exe", L"trustedinstaller.exe"});
}

bool IsExecuteLikeOperation(const RealtimeFileOperation operation) {
  return operation == ANTIVIRUS_REALTIME_FILE_OPERATION_EXECUTE || operation == ANTIVIRUS_REALTIME_FILE_OPERATION_CREATE;
}

bool LooksLikeDoubleExtensionLure(const std::wstring& fileNameLower) {
  return ContainsAnyToken(fileNameLower, {L".pdf.exe", L".doc.exe", L".docx.exe", L".xls.exe", L".xlsx.exe",
                                          L".jpg.exe", L".jpeg.exe", L".png.exe", L".txt.exe", L".html.exe"});
}

bool IsHighRiskPersistencePath(const std::filesystem::path& path) {
  const auto lower = ToLowerCopy(path.wstring());
  return ContainsAnyToken(lower, {L"\\start menu\\programs\\startup\\", L"\\currentversion\\run",
                                  L"\\currentversion\\runonce"});
}

struct RealtimeHit {
  std::wstring code;
  std::wstring message;
  std::wstring tacticId;
  std::wstring techniqueId;
  int score{0};
};

void AddRealtimeHit(std::vector<RealtimeHit>& hits, RealtimeHit hit) {
  const auto exists = std::any_of(hits.begin(), hits.end(),
                                  [&hit](const auto& existing) { return existing.code == hit.code; });
  if (!exists) {
    hits.push_back(std::move(hit));
  }
}

int ScoreRealtimeHits(const std::vector<RealtimeHit>& hits) {
  return std::accumulate(hits.begin(), hits.end(), 0,
                         [](const int total, const auto& hit) { return total + hit.score; });
}

void AddContextualRealtimeHits(std::vector<RealtimeHit>& hits, const std::filesystem::path& path,
                               const std::wstring& extension, const RealtimeFileOperation operation,
                               const std::wstring& processImageLower, const std::wstring& parentImageLower,
                               const std::wstring& commandLineLower, const bool userControlledPath) {
  const auto executeLike = IsExecuteLikeOperation(operation);
  const auto highRiskFileType = IsExecutableExtension(extension) || IsScriptExtension(extension) ||
                                IsContainerExtension(extension) || extension == L".hta";
  const auto fileNameLower = ToLowerCopy(path.filename().wstring());

  const auto hasEncodedPayload = ContainsAnyToken(commandLineLower, {L"-enc ", L"-encodedcommand", L"frombase64string"});
  const auto hasDownloadCradle =
      ContainsAnyToken(commandLineLower, {L"downloadstring", L"downloadfile", L"invoke-webrequest", L"invoke-restmethod",
                                          L"start-bitstransfer", L"iwr "});
  const auto hasDynamicExecution = ContainsAnyToken(commandLineLower, {L"invoke-expression", L" iex", L"iex("});
  const auto hasRecoveryInhibition =
      ContainsAnyToken(commandLineLower, {L"vssadmin delete shadows", L"wbadmin delete", L"wmic shadowcopy delete",
                                          L"bcdedit /set", L"reagentc /disable"});
  const auto hasProcessInjectionKeywords =
      ContainsAnyToken(commandLineLower, {L"createremotethread", L"writeprocessmemory", L"queueuserapc",
                                          L"rundll32", L"regsvr32", L"mshta"});

  if (hasEncodedPayload) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_ENCODED_COMMANDLINE",
                                     L"The invoking process used encoded command-line content.",
                                     L"TA0005", L"T1027", 34});
  }

  if (hasDownloadCradle) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_DOWNLOAD_CRADLE",
                                     L"The invoking process used download cradle command-line patterns.",
                                     L"TA0011", L"T1105", 32});
  }

  if (hasDynamicExecution) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_DYNAMIC_EXECUTION",
                                     L"The invoking process used dynamic execution command-line patterns.",
                                     L"TA0002", L"T1059.001", 30});
  }

  if (hasRecoveryInhibition) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_RECOVERY_INHIBITION",
                                     L"The invoking process attempted recovery inhibition commands.",
                                     L"TA0040", L"T1490", 45});
  }

  if (hasProcessInjectionKeywords) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_PROCESS_INJECTION_CHAIN",
                                     L"The command-line included process-injection or proxy-execution patterns.",
                                     L"TA0005", L"T1055", 36});
  }

  if (hasDownloadCradle && hasDynamicExecution) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_STAGED_PAYLOAD_CHAIN",
                                     L"The command-line combined staging download and immediate execution behavior.",
                                     L"TA0002", L"T1204.002", 44});
  }

  if (LooksLikeDoubleExtensionLure(fileNameLower)) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_DOUBLE_EXTENSION_LURE",
                                     L"The target file name resembles a deceptive double-extension lure.",
                                     L"TA0001", L"T1566", 40});
  }

  if (IsHighRiskPersistencePath(path)) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_PERSISTENCE_PATH",
                                     L"The target path is associated with user startup persistence.",
                                     L"TA0003", L"T1547.001", 30});
  }

  if (IsScriptingHostImage(processImageLower) && highRiskFileType && executeLike) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_SCRIPTING_HOST_CHAIN",
                                     L"A scripting host process attempted to launch high-risk content.",
                                     L"TA0002", L"T1059", 34});
  }

  if (IsLolbinImage(processImageLower) && highRiskFileType && executeLike) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_LOLBIN_PROXY_CHAIN",
                                     L"A Windows LOLBin process attempted to proxy high-risk content execution.",
                                     L"TA0005", L"T1218", 38});
  }

  if ((IsOfficeOrMailImage(parentImageLower) || IsBrowserImage(parentImageLower)) && highRiskFileType &&
      userControlledPath && executeLike) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_PARENT_CHILD_LURE_CHAIN",
                                     L"High-risk content was launched from Office, mail, or browser parent context.",
                                     L"TA0002", L"T1204.002", 42});
  }

  if (IsTrustedInstallerImage(processImageLower) && (extension == L".msi" || extension == L".exe") && !hasEncodedPayload &&
      !hasDownloadCradle && !hasDynamicExecution) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_TRUSTED_INSTALLER_CONTEXT",
                                     L"Execution context matches a trusted installer workflow.",
                                     L"TA0000", L"T0000", -24});
  }
}

void ApplyRealtimeHitsToFinding(ScanFinding& finding, const std::vector<RealtimeHit>& hits,
                                const RealtimeFileOperation operation, const bool allowQuarantine) {
  if (hits.empty()) {
    return;
  }

  const auto topHit = std::max_element(hits.begin(), hits.end(),
                                       [](const auto& left, const auto& right) { return left.score < right.score; });
  const auto totalScore = std::clamp(ScoreRealtimeHits(hits), 0, 99);
  const auto executeLike = IsExecuteLikeOperation(operation);

  finding.verdict.confidence = std::max<std::uint32_t>(finding.verdict.confidence, static_cast<std::uint32_t>(totalScore));
  if (topHit != hits.end() && !topHit->tacticId.empty() && topHit->tacticId != L"TA0000") {
    finding.verdict.tacticId = topHit->tacticId;
  }
  if (topHit != hits.end() && !topHit->techniqueId.empty() && topHit->techniqueId != L"T0000") {
    finding.verdict.techniqueId = topHit->techniqueId;
  }

  for (const auto& hit : hits) {
    finding.verdict.reasons.push_back({hit.code, hit.message});
  }

  if (finding.verdict.disposition == VerdictDisposition::Allow) {
    if (totalScore >= 85) {
      finding.verdict.disposition = allowQuarantine ? VerdictDisposition::Quarantine : VerdictDisposition::Block;
    } else if (totalScore >= 65 && executeLike) {
      finding.verdict.disposition = VerdictDisposition::Block;
    }
  } else if (finding.verdict.disposition == VerdictDisposition::Block && allowQuarantine && totalScore >= 90) {
    finding.verdict.disposition = VerdictDisposition::Quarantine;
  }
}

struct BehaviorHistoryEntry {
  std::chrono::steady_clock::time_point observedAt{};
  std::wstring fingerprint;
  std::uint32_t signals{0};
};

struct BehaviorCorrelationSnapshot {
  std::uint32_t historicalSignals{0};
  std::size_t recentSignalEvents{0};
};

constexpr std::uint32_t kSignalDownload = 1u << 0;
constexpr std::uint32_t kSignalEncoded = 1u << 1;
constexpr std::uint32_t kSignalDynamicExecution = 1u << 2;
constexpr std::uint32_t kSignalScriptHost = 1u << 3;
constexpr std::uint32_t kSignalLolbin = 1u << 4;
constexpr std::uint32_t kSignalPersistence = 1u << 5;
constexpr std::uint32_t kSignalRecoveryInhibition = 1u << 6;
constexpr std::uint32_t kSignalUserPathExecutable = 1u << 7;
constexpr std::uint32_t kSignalLure = 1u << 8;
constexpr std::uint32_t kSignalInjection = 1u << 9;

constexpr auto kBehaviorHistoryWindow = std::chrono::minutes(6);
constexpr auto kBehaviorBurstWindow = std::chrono::minutes(2);
constexpr std::size_t kBehaviorHistoryMaxEntries = 2048;

std::mutex gBehaviorHistoryMutex;
std::deque<BehaviorHistoryEntry> gBehaviorHistory;

void PruneBehaviorHistoryLocked(const std::chrono::steady_clock::time_point now) {
  while (!gBehaviorHistory.empty() && (now - gBehaviorHistory.front().observedAt) > kBehaviorHistoryWindow) {
    gBehaviorHistory.pop_front();
  }

  while (gBehaviorHistory.size() > kBehaviorHistoryMaxEntries) {
    gBehaviorHistory.pop_front();
  }
}

std::wstring BuildBehaviorFingerprint(const RealtimeFileScanRequest& request, const std::filesystem::path& path) {
  const auto processImage = ToLowerCopy(SafeCopy(request.processImage));
  const auto parentImage = ToLowerCopy(SafeCopy(request.parentImage));
  const auto userSid = ToLowerCopy(SafeCopy(request.userSid));
  const auto correlationId = ToLowerCopy(SafeCopy(request.correlationId));
  const auto directory = ToLowerCopy(path.parent_path().wstring());

  if (processImage.empty() && parentImage.empty() && userSid.empty()) {
    if (!correlationId.empty()) {
      return L"correlation:" + correlationId;
    }
    if (!directory.empty()) {
      return L"path:" + directory;
    }
    return L"global";
  }

  return processImage + L"|" + parentImage + L"|" + userSid;
}

std::wstring BuildBehaviorFingerprintFromEvent(const EventEnvelope& event) {
  const auto processImage = ToLowerCopy(event.process.imagePath);
  const auto parentImage = ToLowerCopy(event.process.parentImagePath);
  const auto userSid = ToLowerCopy(event.process.userSid);
  const auto correlationId = ToLowerCopy(event.correlationId);
  const auto targetPath = ToLowerCopy(event.targetPath);

  if (processImage.empty() && parentImage.empty() && userSid.empty()) {
    if (!correlationId.empty()) {
      return L"correlation:" + correlationId;
    }
    if (!targetPath.empty()) {
      return L"path:" + targetPath;
    }
    return L"global";
  }

  return processImage + L"|" + parentImage + L"|" + userSid;
}

std::uint32_t DeriveBehaviorSignals(const ScanFinding& finding, const RealtimeFileScanRequest& request,
                                    const RealtimeFileOperation operation) {
  std::uint32_t signals = 0;
  const auto extension = ToLowerCopy(finding.path.extension().wstring());
  const auto executeLike = IsExecuteLikeOperation(operation);
  const auto commandLineLower = ToLowerCopy(SafeCopy(request.commandLine));

  for (const auto& reason : finding.verdict.reasons) {
    const auto codeLower = ToLowerCopy(reason.code);
    if (ContainsAnyToken(codeLower, {L"download_cradle", L"pe_download_and_execute"})) {
      signals |= kSignalDownload;
    }
    if (ContainsAnyToken(codeLower, {L"encoded_payload", L"encoded_commandline", L"long_base64_blob", L"script_obfuscation"})) {
      signals |= kSignalEncoded;
    }
    if (ContainsAnyToken(codeLower, {L"dynamic_execution"})) {
      signals |= kSignalDynamicExecution;
    }
    if (ContainsAnyToken(codeLower, {L"script_host_abuse", L"scripting_host_chain", L"script_intercept"})) {
      signals |= kSignalScriptHost;
    }
    if (ContainsAnyToken(codeLower, {L"lolbin", L"lnk_proxy_execution"})) {
      signals |= kSignalLolbin;
    }
    if (ContainsAnyToken(codeLower, {L"run_key_persistence", L"scheduled_task_persistence", L"service_persistence",
                                     L"persistence_path"})) {
      signals |= kSignalPersistence;
    }
    if (ContainsAnyToken(codeLower, {L"recovery_inhibition", L"ransom_note_artifact", L"encrypted_impact_artifact"})) {
      signals |= kSignalRecoveryInhibition;
    }
    if (ContainsAnyToken(codeLower, {L"user_path_unsigned_executable", L"user_path_executable", L"executable_drop"})) {
      signals |= kSignalUserPathExecutable;
    }
    if (ContainsAnyToken(codeLower, {L"double_extension_lure", L"archive_double_extension", L"container_lure"})) {
      signals |= kSignalLure;
    }
    if (ContainsAnyToken(codeLower, {L"process_injection"})) {
      signals |= kSignalInjection;
    }
  }

  if (IsExecutableExtension(extension) && executeLike && IsUserControlledPath(finding.path)) {
    signals |= kSignalUserPathExecutable;
  }
  if (LooksLikeDoubleExtensionLure(ToLowerCopy(finding.path.filename().wstring()))) {
    signals |= kSignalLure;
  }
  if (IsHighRiskPersistencePath(finding.path)) {
    signals |= kSignalPersistence;
  }

  if (ContainsAnyToken(commandLineLower, {L"downloadstring", L"downloadfile", L"invoke-webrequest", L"invoke-restmethod",
                                          L"start-bitstransfer", L"iwr "})) {
    signals |= kSignalDownload;
  }
  if (ContainsAnyToken(commandLineLower, {L"-enc ", L"-encodedcommand", L"frombase64string"})) {
    signals |= kSignalEncoded;
  }
  if (ContainsAnyToken(commandLineLower, {L"invoke-expression", L" iex", L"iex("})) {
    signals |= kSignalDynamicExecution;
  }
  if (ContainsAnyToken(commandLineLower, {L"vssadmin delete shadows", L"wbadmin delete", L"wmic shadowcopy delete",
                                          L"bcdedit /set", L"reagentc /disable"})) {
    signals |= kSignalRecoveryInhibition;
  }
  if (ContainsAnyToken(commandLineLower, {L"createremotethread", L"writeprocessmemory", L"queueuserapc"})) {
    signals |= kSignalInjection;
  }

  return signals;
}

std::uint32_t DeriveBehaviorSignalsFromEvent(const EventEnvelope& event) {
  std::uint32_t signals = 0;

  const auto processImageLower = ToLowerCopy(event.process.imagePath);
  const auto parentImageLower = ToLowerCopy(event.process.parentImagePath);
  const auto commandLineLower = ToLowerCopy(event.process.commandLine);
  const auto targetLower = ToLowerCopy(event.targetPath);
  const std::filesystem::path targetPath(event.targetPath);
  const auto extension = ToLowerCopy(targetPath.extension().wstring());
  const auto executeLike =
      event.kind == EventKind::FileExecute || event.kind == EventKind::ProcessStart || event.kind == EventKind::ScriptScan;

  if (IsScriptingHostImage(processImageLower) || IsScriptingHostImage(parentImageLower)) {
    signals |= kSignalScriptHost;
  }
  if (IsLolbinImage(processImageLower) || IsLolbinImage(parentImageLower)) {
    signals |= kSignalLolbin;
  }

  if (ContainsAnyToken(commandLineLower, {L"downloadstring", L"downloadfile", L"invoke-webrequest", L"invoke-restmethod",
                                          L"start-bitstransfer", L"iwr ", L"curl ", L"bitsadmin"})) {
    signals |= kSignalDownload;
  }
  if (ContainsAnyToken(commandLineLower, {L"-enc ", L"-encodedcommand", L"frombase64string"})) {
    signals |= kSignalEncoded;
  }
  if (ContainsAnyToken(commandLineLower, {L"invoke-expression", L" iex", L"iex("})) {
    signals |= kSignalDynamicExecution;
  }
  if (ContainsAnyToken(commandLineLower, {L"vssadmin delete shadows", L"wbadmin delete", L"wmic shadowcopy delete",
                                          L"bcdedit /set", L"reagentc /disable"})) {
    signals |= kSignalRecoveryInhibition;
  }
  if (ContainsAnyToken(commandLineLower, {L"createremotethread", L"writeprocessmemory", L"queueuserapc"})) {
    signals |= kSignalInjection;
  }

  if (!event.targetPath.empty()) {
    const auto userControlledTarget = IsUserControlledPath(targetPath);
    if (IsExecutableExtension(extension) && userControlledTarget && executeLike) {
      signals |= kSignalUserPathExecutable;
    }
    if (LooksLikeDoubleExtensionLure(ToLowerCopy(targetPath.filename().wstring()))) {
      signals |= kSignalLure;
    }
    if (IsHighRiskPersistencePath(targetPath)) {
      signals |= kSignalPersistence;
    }
    if (IsScriptExtension(extension) && executeLike) {
      signals |= kSignalScriptHost;
    }
  }

  if (event.kind == EventKind::ProcessStart &&
      (IsOfficeOrMailImage(parentImageLower) || IsBrowserImage(parentImageLower)) &&
      IsExecutableExtension(extension) && IsUserControlledPath(targetPath)) {
    signals |= (kSignalUserPathExecutable | kSignalLure);
  }

  if (event.kind == EventKind::NetworkConnect &&
      (IsScriptingHostImage(processImageLower) || IsLolbinImage(processImageLower) || IsBrowserImage(processImageLower))) {
    signals |= kSignalDownload;
    if (ContainsAnyToken(targetLower, {L".onion", L":4444", L":8080", L":8443"})) {
      signals |= kSignalDynamicExecution;
    }
  }

  return signals;
}

BehaviorCorrelationSnapshot QueryBehaviorCorrelation(const std::wstring& fingerprint,
                                                     const std::chrono::steady_clock::time_point now) {
  BehaviorCorrelationSnapshot snapshot{};
  if (fingerprint.empty()) {
    return snapshot;
  }

  for (const auto& entry : gBehaviorHistory) {
    if (entry.fingerprint != fingerprint) {
      continue;
    }

    snapshot.historicalSignals |= entry.signals;
    if (entry.signals != 0 && (now - entry.observedAt) <= kBehaviorBurstWindow) {
      ++snapshot.recentSignalEvents;
    }
  }

  return snapshot;
}

std::vector<RealtimeHit> BuildBehaviorCorrelationHits(const std::uint32_t currentSignals,
                                                      const BehaviorCorrelationSnapshot& snapshot,
                                                      const RealtimeFileOperation operation) {
  std::vector<RealtimeHit> hits;
  if (currentSignals == 0) {
    return hits;
  }

  const auto historical = snapshot.historicalSignals;
  const auto executeLike = IsExecuteLikeOperation(operation);

  const auto hasCurrentStager = (currentSignals & (kSignalUserPathExecutable | kSignalLure | kSignalScriptHost)) != 0;
  const auto hasHistoricalInitialAccess = (historical & (kSignalDownload | kSignalEncoded | kSignalDynamicExecution)) != 0;
  if (hasCurrentStager && hasHistoricalInitialAccess && executeLike) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_CHAIN_STAGED_PAYLOAD",
                                     L"Fenrir correlated this event with earlier staging behavior from the same process lineage.",
                                     L"TA0002", L"T1204.002", 46});
  }

  const auto hasCurrentPersistence = (currentSignals & kSignalPersistence) != 0;
  const auto hasHistoricalExecutionProxy = (historical & (kSignalScriptHost | kSignalLolbin | kSignalDownload)) != 0;
  if (hasCurrentPersistence && hasHistoricalExecutionProxy) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_CHAIN_PERSISTENCE",
                                     L"Fenrir correlated persistence behavior with earlier execution-proxy activity.",
                                     L"TA0003", L"T1547.001", 42});
  }

  const auto hasCurrentImpact = (currentSignals & kSignalRecoveryInhibition) != 0;
  const auto hasHistoricalPreImpact =
      (historical & (kSignalUserPathExecutable | kSignalDownload | kSignalPersistence | kSignalScriptHost)) != 0;
  if (hasCurrentImpact && hasHistoricalPreImpact) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_CHAIN_RANSOMWARE_IMPACT",
                                     L"Fenrir correlated recovery-inhibition behavior with prior compromise staging signals.",
                                     L"TA0040", L"T1490", 58});
  }

  const auto hasCurrentInjection = (currentSignals & kSignalInjection) != 0;
  const auto hasHistoricalStaging = (historical & (kSignalDownload | kSignalEncoded | kSignalDynamicExecution)) != 0;
  if (hasCurrentInjection && hasHistoricalStaging) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_CHAIN_INJECTION_STAGE",
                                     L"Fenrir correlated process-injection behavior with earlier staged payload activity.",
                                     L"TA0005", L"T1055", 44});
  }

  if (snapshot.recentSignalEvents >= 2 && executeLike) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_CHAIN_BURST_ACTIVITY",
                                     L"Fenrir observed multiple suspicious events from this process lineage in a short window.",
                                     L"TA0005", L"T1204.002", 36});
  }

  return hits;
}

TelemetryRecord BuildBehaviorObservationTelemetry(const EventEnvelope& event, const std::wstring& deviceId,
                                                  const std::uint32_t currentSignals,
                                                  const BehaviorCorrelationSnapshot& snapshot,
                                                  const std::vector<RealtimeHit>& chainHits) {
  std::wstring subject = event.targetPath;
  if (subject.empty()) {
    subject = event.process.imagePath;
  }
  if (subject.empty()) {
    subject = L"(unknown target)";
  }

  std::wstring summary = L"Fenrir correlated runtime behavior signals for ";
  summary += subject;
  summary += L".";

  std::wstring payload = L"{\"deviceId\":\"";
  payload += Utf8ToWide(EscapeJsonString(deviceId));
  payload += L"\",\"correlationId\":\"";
  payload += Utf8ToWide(EscapeJsonString(event.correlationId));
  payload += L"\",\"kind\":\"";
  payload += EventKindToString(event.kind);
  payload += L"\",\"targetPath\":\"";
  payload += Utf8ToWide(EscapeJsonString(event.targetPath));
  payload += L"\",\"processImage\":\"";
  payload += Utf8ToWide(EscapeJsonString(event.process.imagePath));
  payload += L"\",\"parentImage\":\"";
  payload += Utf8ToWide(EscapeJsonString(event.process.parentImagePath));
  payload += L"\",\"userSid\":\"";
  payload += Utf8ToWide(EscapeJsonString(event.process.userSid));
  payload += L"\",\"signalMask\":";
  payload += std::to_wstring(currentSignals);
  payload += L",\"historicalSignalMask\":";
  payload += std::to_wstring(snapshot.historicalSignals);
  payload += L",\"recentSignalEvents\":";
  payload += std::to_wstring(snapshot.recentSignalEvents);
  payload += L",\"reasonCodes\":[";
  for (std::size_t index = 0; index < chainHits.size(); ++index) {
    if (index > 0) {
      payload += L",";
    }
    payload += L"\"";
    payload += Utf8ToWide(EscapeJsonString(chainHits[index].code));
    payload += L"\"";
  }
  payload += L"]}";

  return TelemetryRecord{
      .eventId = GenerateGuidString(),
      .eventType = L"realtime.behavior.chain",
      .source = L"realtime-protection",
      .summary = summary,
      .occurredAt = CurrentUtcTimestamp(),
      .payloadJson = payload};
}

bool ApplyBehaviorChainCorrelation(const RealtimeFileScanRequest& request, const RealtimeFileOperation operation,
                                   const PolicySnapshot& policy, ScanFinding& finding) {
  const auto fingerprint = BuildBehaviorFingerprint(request, finding.path);
  const auto now = std::chrono::steady_clock::now();
  const auto currentSignals = DeriveBehaviorSignals(finding, request, operation);

  BehaviorCorrelationSnapshot snapshot{};
  {
    const std::scoped_lock lock(gBehaviorHistoryMutex);
    PruneBehaviorHistoryLocked(now);
    snapshot = QueryBehaviorCorrelation(fingerprint, now);
    if (!fingerprint.empty()) {
      gBehaviorHistory.push_back(BehaviorHistoryEntry{
          .observedAt = now,
          .fingerprint = fingerprint,
          .signals = currentSignals});
      PruneBehaviorHistoryLocked(now);
    }
  }

  const auto chainHits = BuildBehaviorCorrelationHits(currentSignals, snapshot, operation);
  if (chainHits.empty()) {
    return false;
  }

  ApplyRealtimeHitsToFinding(finding, chainHits, operation, policy.quarantineOnMalicious);
  finding.verdict.reasons.push_back(
      {L"REALTIME_CHAIN_CORRELATED",
       L"Fenrir correlated this event with recent behavior from the same process lineage."});
  return true;
}

ScanFinding BuildRealtimeFinding(const std::filesystem::path& path, const RealtimeFileOperation operation,
                                 const RealtimeFileScanRequest& request, const PolicySnapshot& policy,
                                 const std::vector<std::filesystem::path>& excludedPaths) {
  if (const auto allowOverride = BuildAllowOverrideFinding(path, policy, excludedPaths); allowOverride.has_value()) {
    return *allowOverride;
  }

  const auto extension = ToLowerCopy(path.extension().wstring());
  const auto userControlledPath = IsUserControlledPath(path);
  const auto processImageLower = ToLowerCopy(SafeCopy(request.processImage));
  const auto parentImageLower = ToLowerCopy(SafeCopy(request.parentImage));
  const auto commandLineLower = ToLowerCopy(SafeCopy(request.commandLine));

  ScanFinding finding{
      .path = path,
      .sizeBytes = 0,
      .sha256 = {},
      .verdict = {},
      .remediationStatus = RemediationStatus::None,
      .quarantinedPath = {},
      .quarantineRecordId = {},
      .evidenceRecordId = {},
      .remediationError = {}};

  std::error_code error;
  if (std::filesystem::exists(path, error)) {
    error.clear();
    if (std::filesystem::is_regular_file(path, error)) {
      finding.sizeBytes = std::filesystem::file_size(path, error);
      try {
        finding.sha256 = ComputeFileSha256(path);
      } catch (...) {
        finding.verdict.reasons.push_back(
            {L"HASH_UNAVAILABLE", L"SHA-256 computation failed during real-time evaluation."});
      }

      if (const auto analyzedFinding = ScanFile(path, policy, excludedPaths); analyzedFinding.has_value()) {
        auto promoted = *analyzedFinding;
        if (promoted.verdict.disposition == VerdictDisposition::Block &&
            operation == ANTIVIRUS_REALTIME_FILE_OPERATION_EXECUTE) {
          promoted.verdict.confidence = std::min<std::uint32_t>(99, promoted.verdict.confidence + 5);
        }
        std::vector<RealtimeHit> contextualHits;
        AddContextualRealtimeHits(contextualHits, path, extension, operation, processImageLower, parentImageLower,
                                  commandLineLower, userControlledPath);
        ApplyRealtimeHitsToFinding(promoted, contextualHits, operation, policy.quarantineOnMalicious);
        return promoted;
      }
    }
  }

  std::vector<RealtimeHit> hits;
  const auto executeLike = IsExecuteLikeOperation(operation);
  const auto highRiskFileType = IsExecutableExtension(extension) || IsScriptExtension(extension) ||
                                IsContainerExtension(extension) || extension == L".hta";

  if (IsExecutableExtension(extension) && userControlledPath) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_EXECUTABLE_DROP",
                                     L"Executable content in a user-controlled path was intercepted by real-time protection.",
                                     L"TA0002", L"T1204.002", executeLike ? 72 : 52});
  }

  if (extension == L".hta") {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_HTA_CONTENT",
                                     L"HTA content was intercepted before it could be proxied through MSHTA.",
                                     L"TA0005", L"T1218.005", executeLike ? 68 : 54});
  }

  if (IsScriptExtension(extension)) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_SCRIPT_INTERCEPT",
                                     L"Script content was intercepted by real-time protection.",
                                     L"TA0002", extension == L".ps1" ? L"T1059.001" : L"T1059",
                                     executeLike ? (userControlledPath ? 56 : 45) : 28});
  }

  if (IsContainerExtension(extension) && userControlledPath &&
      (operation == ANTIVIRUS_REALTIME_FILE_OPERATION_OPEN || executeLike)) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_CONTAINER_LURE",
                                     L"User-writable lure or archive content was intercepted before staging could continue.",
                                     L"TA0002", extension == L".lnk" ? L"T1204.001" : L"T1204.002",
                                     executeLike ? 36 : 24});
  }

  AddContextualRealtimeHits(hits, path, extension, operation, processImageLower, parentImageLower, commandLineLower,
                            userControlledPath);

  const auto topHit = std::max_element(hits.begin(), hits.end(),
                                       [](const auto& left, const auto& right) { return left.score < right.score; });
  const auto score = std::clamp(ScoreRealtimeHits(hits), 0, 99);

  if (score >= 85 || (score >= 65 && executeLike)) {
    finding.verdict.disposition = policy.quarantineOnMalicious && highRiskFileType && score >= 85
                                      ? VerdictDisposition::Quarantine
                                      : VerdictDisposition::Block;
    finding.verdict.confidence = static_cast<std::uint32_t>(score);
    finding.verdict.tacticId = topHit != hits.end() && !topHit->tacticId.empty() ? topHit->tacticId : L"TA0002";
    finding.verdict.techniqueId =
        topHit != hits.end() && !topHit->techniqueId.empty() ? topHit->techniqueId : L"T1204.002";
    for (const auto& hit : hits) {
      finding.verdict.reasons.push_back({hit.code, hit.message});
    }
    return finding;
  }

  finding.verdict.disposition = VerdictDisposition::Allow;
  finding.verdict.confidence = static_cast<std::uint32_t>(std::max(score, 5));
  if (topHit != hits.end() && topHit->score > 0 && !topHit->tacticId.empty()) {
    finding.verdict.tacticId = topHit->tacticId;
  }
  if (topHit != hits.end() && topHit->score > 0 && !topHit->techniqueId.empty()) {
    finding.verdict.techniqueId = topHit->techniqueId;
  }
  for (const auto& hit : hits) {
    if (hit.score > 0) {
      finding.verdict.reasons.push_back({hit.code, hit.message});
    }
  }
  finding.verdict.reasons.push_back({L"REALTIME_ALLOW", L"No blocking rule matched the intercepted file event."});
  return finding;
}

TelemetryRecord BuildRealtimeProtectionTelemetry(const ScanFinding& finding, const std::wstring& source,
                                                 const std::wstring& deviceId, const std::wstring& correlationId,
                                                 const RealtimeFileOperation operation,
                                                 const RealtimeResponseAction action,
                                                 const RealtimeFileScanRequest& request,
                                                 const bool contextEnriched) {
  const auto actionValue = action == ANTIVIRUS_REALTIME_RESPONSE_ACTION_BLOCK ? L"block" : L"allow";
  const auto dispositionValue = VerdictDispositionToString(finding.verdict.disposition);
  const auto techniqueId = finding.verdict.techniqueId.empty() ? L"unknown" : finding.verdict.techniqueId;
  auto subject = finding.path.filename().wstring();
  if (subject.empty()) {
    subject = finding.path.wstring();
  }

  std::wstring summary = L"Real-time protection ";
  summary += actionValue;
  summary += L"ed ";
  summary += subject;
  summary += L" during ";
  summary += OperationToString(operation);
  summary += L".";

  std::wstring payload = L"{\"deviceId\":\"";
  payload += Utf8ToWide(EscapeJsonString(deviceId));
  payload += L"\",\"correlationId\":\"";
  payload += Utf8ToWide(EscapeJsonString(correlationId));
  payload += L"\",\"path\":\"";
  payload += Utf8ToWide(EscapeJsonString(finding.path.wstring()));
  payload += L"\",\"operation\":\"";
  payload += OperationToString(operation);
  payload += L"\",\"action\":\"";
  payload += actionValue;
  payload += L"\",\"disposition\":\"";
  payload += dispositionValue;
  payload += L"\",\"tacticId\":\"";
  payload += finding.verdict.tacticId;
  payload += L"\",\"techniqueId\":\"";
  payload += techniqueId;
  payload += L"\",\"sha256\":\"";
  payload += finding.sha256;
  payload += L"\",\"quarantineRecordId\":\"";
  payload += finding.quarantineRecordId;
  payload += L"\",\"evidenceRecordId\":\"";
  payload += finding.evidenceRecordId;
  payload += L"\",\"remediationStatus\":\"";
  payload += RemediationStatusToString(finding.remediationStatus);
  payload += L"\",\"processId\":";
  payload += std::to_wstring(request.processId);
  payload += L",\"threadId\":";
  payload += std::to_wstring(request.threadId);
  payload += L",\"fileSizeBytes\":";
  payload += std::to_wstring(request.fileSizeBytes);
  payload += L",\"processImage\":\"";
  payload += Utf8ToWide(EscapeJsonString(SafeCopy(request.processImage)));
  payload += L"\",\"parentImage\":\"";
  payload += Utf8ToWide(EscapeJsonString(SafeCopy(request.parentImage)));
  payload += L"\",\"commandLine\":\"";
  payload += Utf8ToWide(EscapeJsonString(SafeCopy(request.commandLine)));
  payload += L"\",\"userSid\":\"";
  payload += Utf8ToWide(EscapeJsonString(SafeCopy(request.userSid)));
  payload += L"\",\"contextEnriched\":";
  payload += contextEnriched ? L"true" : L"false";
  payload += L"}";

  return TelemetryRecord{
      .eventId = GenerateGuidString(),
      .eventType = L"realtime.protection.action",
      .source = source,
      .summary = summary,
      .occurredAt = CurrentUtcTimestamp(),
      .payloadJson = payload};
}

}  // namespace

RealtimeProtectionBroker::RealtimeProtectionBroker(AgentConfig config) : config_(std::move(config)) {
  stopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
}

RealtimeProtectionBroker::~RealtimeProtectionBroker() {
  Stop();
  if (stopEvent_ != nullptr) {
    CloseHandle(stopEvent_);
    stopEvent_ = nullptr;
  }
}

void RealtimeProtectionBroker::Start() {
  if (workerThread_ != nullptr || stopEvent_ == nullptr) {
    return;
  }

  ResetEvent(stopEvent_);
  workerActive_.store(false);
  portConnected_.store(false);
  workerThread_ = CreateThread(nullptr, 0, ThreadEntry, this, 0, nullptr);
  if (workerThread_ == nullptr) {
    QueueBrokerStateEvent(L"realtime.broker.failed",
                          L"The real-time protection broker could not start its communication worker.",
                          std::wstring(L"{\"portName\":\"") +
                              Utf8ToWide(EscapeJsonString(config_.realtimeProtectionPortName)) + L"\"}");
  }
}

void RealtimeProtectionBroker::Stop() {
  if (stopEvent_ != nullptr) {
    SetEvent(stopEvent_);
  }

  if (workerThread_ != nullptr) {
    WaitForSingleObject(workerThread_, 5'000);
    CloseHandle(workerThread_);
    workerThread_ = nullptr;
  }

  portConnected_.store(false);
  workerActive_.store(false);
}

void RealtimeProtectionBroker::SetPolicy(const PolicySnapshot& policy) {
  const std::scoped_lock lock(stateMutex_);
  policy_ = policy;
}

void RealtimeProtectionBroker::SetDeviceId(std::wstring deviceId) {
  const std::scoped_lock lock(stateMutex_);
  deviceId_ = std::move(deviceId);
}

bool RealtimeProtectionBroker::IsRealtimeCoverageHealthy() const {
  return workerActive_.load() && portConnected_.load();
}

RealtimeInspectionOutcome RealtimeProtectionBroker::InspectFile(const RealtimeFileScanRequest& request) {
  PolicySnapshot policy;
  std::wstring deviceId;
  {
    const std::scoped_lock lock(stateMutex_);
    policy = policy_;
    deviceId = deviceId_;
  }

  const auto effectiveRequest = EnrichRequestProcessContext(request);
  const auto operation = static_cast<RealtimeFileOperation>(request.operation);
  const std::filesystem::path targetPath(SafeCopy(request.path));

  if (!policy.realtimeProtectionEnabled) {
    return RealtimeInspectionOutcome{
        .action = ANTIVIRUS_REALTIME_RESPONSE_ACTION_ALLOW,
        .detection = false,
        .finding =
            ScanFinding{
                .path = targetPath,
                .verdict =
                    ScanVerdict{
                        .disposition = VerdictDisposition::Allow,
                        .confidence = 0,
                        .tacticId = L"",
                        .techniqueId = L"",
                        .reasons = {{L"REALTIME_DISABLED", L"Real-time protection is disabled by policy."}}}}};
  }

  auto finding =
      BuildRealtimeFinding(targetPath, operation, effectiveRequest.request, policy, config_.scanExcludedPaths);
  const auto correlatedChain = ApplyBehaviorChainCorrelation(effectiveRequest.request, operation, policy, finding);
  if (finding.verdict.disposition == VerdictDisposition::Allow) {
    const auto elevatedAllowSignal =
        correlatedChain ||
        finding.verdict.confidence >= 45 ||
        std::any_of(finding.verdict.reasons.begin(), finding.verdict.reasons.end(), [](const auto& reason) {
          return reason.code != L"REALTIME_ALLOW";
        });
    if (elevatedAllowSignal) {
      QueueTelemetry(BuildRealtimeProtectionTelemetry(finding, L"realtime-protection", deviceId,
                                                     SafeCopy(effectiveRequest.request.correlationId), operation,
                                                     ANTIVIRUS_REALTIME_RESPONSE_ACTION_ALLOW,
                                                     effectiveRequest.request, effectiveRequest.contextEnriched));
    }

    return RealtimeInspectionOutcome{
        .action = ANTIVIRUS_REALTIME_RESPONSE_ACTION_ALLOW,
        .detection = false,
        .finding = std::move(finding)};
  }

  if (policy.quarantineOnMalicious && !finding.path.empty()) {
    QuarantineStore quarantineStore(config_.quarantineRootPath, config_.runtimeDatabasePath);
    auto quarantineResult = quarantineStore.QuarantineFile(finding);
    if (!quarantineResult.success) {
      RemediationEngine remediationEngine(config_);
      const auto containment = remediationEngine.TerminateProcessesForPath(finding.path, true);
      if (containment.processesTerminated > 0) {
        finding.verdict.reasons.push_back(
            {L"PROCESS_TREE_CONTAINED",
             L"Fenrir terminated " + std::to_wstring(containment.processesTerminated) +
                 L" related process(es) before retrying quarantine."});
        quarantineResult = quarantineStore.QuarantineFile(finding);
      }
    }

    if (quarantineResult.success) {
      finding.remediationStatus = RemediationStatus::Quarantined;
      finding.quarantineRecordId = quarantineResult.recordId;
      finding.quarantinedPath = quarantineResult.quarantinedPath;
      finding.verdict.reasons.push_back(
          {L"QUARANTINE_APPLIED", L"Fenrir moved the intercepted artifact into local quarantine."});
      if (!quarantineResult.localStatus.empty()) {
        finding.verdict.reasons.push_back(
            {L"QUARANTINE_STATUS", L"Quarantine status: " + quarantineResult.localStatus + L"."});
      }
      if (!quarantineResult.verificationDetail.empty()) {
        finding.verdict.reasons.push_back({L"QUARANTINE_VERIFIED", quarantineResult.verificationDetail});
      }
    } else {
      if (!quarantineResult.recordId.empty()) {
        finding.quarantineRecordId = quarantineResult.recordId;
      }
      if (!quarantineResult.quarantinedPath.empty()) {
        finding.quarantinedPath = quarantineResult.quarantinedPath;
      }
      finding.remediationStatus = RemediationStatus::Failed;
      finding.remediationError =
          quarantineResult.errorMessage.empty() ? L"Real-time quarantine failed during interception."
                                                : quarantineResult.errorMessage;
      if (!quarantineResult.localStatus.empty()) {
        finding.verdict.reasons.push_back(
            {L"QUARANTINE_STATUS", L"Quarantine status: " + quarantineResult.localStatus + L"."});
      }
      if (!quarantineResult.verificationDetail.empty()) {
        finding.verdict.reasons.push_back(
            {L"QUARANTINE_VERIFICATION_FAILED", quarantineResult.verificationDetail});
      }
      finding.verdict.reasons.push_back({L"QUARANTINE_FAILED", finding.remediationError});
    }
  }

  EvidenceRecorder evidenceRecorder(config_.evidenceRootPath, config_.runtimeDatabasePath);
  const auto evidence = evidenceRecorder.RecordScanFinding(finding, policy, L"realtime-protection");
  finding.evidenceRecordId = evidence.recordId;

  QueueTelemetry(BuildScanFindingTelemetry(finding, L"realtime-protection"));
  QueueTelemetry(BuildRealtimeProtectionTelemetry(finding, L"realtime-protection", deviceId,
                                                 SafeCopy(effectiveRequest.request.correlationId), operation,
                                                 ANTIVIRUS_REALTIME_RESPONSE_ACTION_BLOCK,
                                                 effectiveRequest.request, effectiveRequest.contextEnriched));

  return RealtimeInspectionOutcome{
      .action = ANTIVIRUS_REALTIME_RESPONSE_ACTION_BLOCK,
      .detection = true,
      .finding = std::move(finding)};
}

void RealtimeProtectionBroker::ObserveBehaviorEvent(const EventEnvelope& event) {
  const auto currentSignals = DeriveBehaviorSignalsFromEvent(event);
  if (currentSignals == 0) {
    return;
  }

  const auto fingerprint = BuildBehaviorFingerprintFromEvent(event);
  const auto operation = EventKindToRealtimeOperation(event.kind);
  const auto now = std::chrono::steady_clock::now();

  BehaviorCorrelationSnapshot snapshot{};
  {
    const std::scoped_lock lock(gBehaviorHistoryMutex);
    PruneBehaviorHistoryLocked(now);
    snapshot = QueryBehaviorCorrelation(fingerprint, now);
    if (!fingerprint.empty()) {
      gBehaviorHistory.push_back(BehaviorHistoryEntry{
          .observedAt = now,
          .fingerprint = fingerprint,
          .signals = currentSignals});
      PruneBehaviorHistoryLocked(now);
    }
  }

  const auto chainHits = BuildBehaviorCorrelationHits(currentSignals, snapshot, operation);
  if (chainHits.empty()) {
    return;
  }

  std::wstring deviceId;
  {
    const std::scoped_lock lock(stateMutex_);
    deviceId = deviceId_;
  }
  QueueTelemetry(BuildBehaviorObservationTelemetry(event, deviceId, currentSignals, snapshot, chainHits));
}

ScanVerdict RealtimeProtectionBroker::EvaluateEvent(const EventEnvelope& event) {
  RealtimeFileScanRequest request{};
  request.protocolVersion = ANTIVIRUS_REALTIME_PROTOCOL_VERSION;
  request.requestSize = sizeof(request);
  request.requestId = 0;
  request.operation = EventKindToRealtimeOperation(event.kind);

  CopyWideField(request.correlationId, event.correlationId);
  CopyWideField(request.path, event.targetPath);
  CopyWideField(request.processImage, event.process.imagePath);
  CopyWideField(request.commandLine, event.process.commandLine);
  CopyWideField(request.parentImage, event.process.parentImagePath);
  CopyWideField(request.userSid, event.process.userSid);

  const auto outcome = InspectFile(request);
  return outcome.finding.verdict;
}

std::vector<TelemetryRecord> RealtimeProtectionBroker::DrainTelemetry() {
  const std::scoped_lock lock(telemetryMutex_);
  auto telemetry = pendingTelemetry_;
  pendingTelemetry_.clear();
  return telemetry;
}

DWORD WINAPI RealtimeProtectionBroker::ThreadEntry(LPVOID context) {
  auto* broker = reinterpret_cast<RealtimeProtectionBroker*>(context);
  broker->PumpLoop();
  return 0;
}

void RealtimeProtectionBroker::PumpLoop() {
  workerActive_.store(true);
  portConnected_.store(false);

  FilterApi api;
  if (!api.Load()) {
    workerActive_.store(false);
    portConnected_.store(false);
    QueueBrokerStateEvent(L"realtime.broker.unavailable",
                          L"The real-time protection broker could not load Filter Manager user-mode APIs.",
                          std::wstring(L"{\"portName\":\"") +
                              Utf8ToWide(EscapeJsonString(config_.realtimeProtectionPortName)) + L"\"}");
    return;
  }

  while (WaitForSingleObject(stopEvent_, 0) != WAIT_OBJECT_0) {
    HANDLE port = nullptr;
    const auto connectResult =
        api.connect(config_.realtimeProtectionPortName.c_str(), 0, nullptr, 0, nullptr, &port);
    if (FAILED(connectResult) || port == nullptr) {
      portConnected_.store(false);
      QueueBrokerStateEvent(L"realtime.broker.waiting",
                            L"The real-time protection broker is waiting for the minifilter communication port.",
                            std::wstring(L"{\"portName\":\"") +
                                Utf8ToWide(EscapeJsonString(config_.realtimeProtectionPortName)) + L"\"}");
      const auto retryMilliseconds =
          static_cast<DWORD>(std::max(config_.realtimeBrokerRetrySeconds, 1) * 1000);
      if (WaitForSingleObject(stopEvent_, retryMilliseconds) == WAIT_OBJECT_0) {
        return;
      }
      continue;
    }

    portConnected_.store(true);
    QueueBrokerStateEvent(L"realtime.broker.connected",
                          L"The real-time protection broker connected to the minifilter communication port.",
                          std::wstring(L"{\"portName\":\"") +
                              Utf8ToWide(EscapeJsonString(config_.realtimeProtectionPortName)) + L"\"}");

    while (WaitForSingleObject(stopEvent_, 0) != WAIT_OBJECT_0) {
      BrokerPortMessage message{};
      OVERLAPPED overlapped{};
      overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
      if (overlapped.hEvent == nullptr) {
        break;
      }

      const auto getMessageResult =
          api.getMessage(port, &message.header, static_cast<DWORD>(sizeof(message)), &overlapped);
      bool messageReady = SUCCEEDED(getMessageResult);

      if (!messageReady && getMessageResult == HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {
        const auto waitResult = WaitForSingleObject(overlapped.hEvent, kBrokerMessageWaitMilliseconds);
        if (waitResult == WAIT_OBJECT_0) {
          DWORD transferred = 0;
          messageReady = GetOverlappedResult(port, &overlapped, &transferred, FALSE) != FALSE;
        } else if (waitResult == WAIT_TIMEOUT) {
          CloseHandle(overlapped.hEvent);
          continue;
        }
      }

      if (!messageReady) {
        CancelIoEx(port, &overlapped);
        CloseHandle(overlapped.hEvent);
        break;
      }

      CloseHandle(overlapped.hEvent);

      const auto outcome = InspectFile(message.request);
      BrokerPortReply reply{};
      reply.header.status = 0;
      reply.header.messageId = message.header.messageId;
      reply.reply.protocolVersion = ANTIVIRUS_REALTIME_PROTOCOL_VERSION;
      reply.reply.replySize = sizeof(reply.reply);
      reply.reply.requestId = message.request.requestId;
      reply.reply.action = outcome.action;
      reply.reply.disposition = outcome.detection ? ANTIVIRUS_REALTIME_RESPONSE_DISPOSITION_MALICIOUS
                                                  : ANTIVIRUS_REALTIME_RESPONSE_DISPOSITION_CLEAN;
      reply.reply.confidence = outcome.finding.verdict.confidence;

      if (!outcome.finding.verdict.reasons.empty()) {
        CopyWideField(reply.reply.reasonCode, outcome.finding.verdict.reasons.front().code);
        CopyWideField(reply.reply.reasonMessage, outcome.finding.verdict.reasons.front().message);
      }

      CopyWideField(reply.reply.tacticId, outcome.finding.verdict.tacticId);
      CopyWideField(reply.reply.techniqueId, outcome.finding.verdict.techniqueId);
      CopyWideField(reply.reply.quarantineRecordId, outcome.finding.quarantineRecordId);
      CopyWideField(reply.reply.evidenceRecordId, outcome.finding.evidenceRecordId);

      api.replyMessage(port, &reply.header, static_cast<DWORD>(sizeof(reply)));
    }

    CloseHandle(port);
    portConnected_.store(false);
    QueueBrokerStateEvent(L"realtime.broker.disconnected",
                          L"The real-time protection broker lost its connection to the minifilter communication port.",
                          std::wstring(L"{\"portName\":\"") +
                              Utf8ToWide(EscapeJsonString(config_.realtimeProtectionPortName)) + L"\"}");
  }

  workerActive_.store(false);
  portConnected_.store(false);
}

void RealtimeProtectionBroker::QueueTelemetry(const TelemetryRecord& record) {
  const std::scoped_lock lock(telemetryMutex_);
  pendingTelemetry_.push_back(record);
}

void RealtimeProtectionBroker::QueueBrokerStateEvent(const std::wstring& eventType, const std::wstring& summary,
                                                     const std::wstring& payloadJson) {
  QueueTelemetry(TelemetryRecord{
      .eventId = GenerateGuidString(),
      .eventType = eventType,
      .source = L"realtime-protection",
      .summary = summary,
      .occurredAt = CurrentUtcTimestamp(),
      .payloadJson = payloadJson});
}

}  // namespace antivirus::agent
