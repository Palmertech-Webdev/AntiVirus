#include "AgentService.h"

#include <WtsApi32.h>
#include <lm.h>
#include <sddl.h>
#include <userenv.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <vector>

#include "EvidenceRecorder.h"
#include "DeviceInventoryCollector.h"
#include "FileInventory.h"
#include "FileSnapshotCollector.h"
#include "HardeningManager.h"
#include "LocalSecurity.h"
#include "ProcessInventory.h"
#include "ProcessSnapshotCollector.h"
#include "ServiceSnapshotCollector.h"
#include "QuarantineStore.h"
#include "RemediationEngine.h"
#include "RuntimeDatabase.h"
#include "RuntimeTrustValidator.h"
#include "ScanEngine.h"
#include "StringUtils.h"
#include "UpdaterService.h"
#include "WscCoexistenceManager.h"

namespace antivirus::agent {

namespace {

struct ProcessExecutionResult {
  DWORD exitCode{0};
  std::wstring output;
};

constexpr wchar_t kPamRequestEventName[] = L"Global\\FenrirPamRequestReady";
constexpr wchar_t kPamRequestFileName[] = L"pam-request.json";
constexpr wchar_t kPamAuditFileName[] = L"privilege-requests.jsonl";
constexpr wchar_t kPamPolicyFileName[] = L"pam-policy.json";
constexpr wchar_t kLocalApprovalQueueFileName[] = L"local-approval-requests.jsonl";
constexpr wchar_t kLocalApprovalLedgerFileName[] = L"local-approval-ledger.jsonl";
constexpr wchar_t kLocalAdminBaselineFileName[] = L"local-admin-baseline.jsonl";
constexpr std::size_t kMaxCommandPayloadChars = 64 * 1024;

struct PamRequestPayload {
  std::wstring requestedAt;
  std::wstring requester;
  std::wstring action;
  std::wstring targetPath;
  std::wstring arguments;
  std::wstring reason;
};

struct PamLaunchPlan {
  std::wstring executablePath;
  std::wstring arguments;
  std::wstring targetPath;
  std::optional<std::uint32_t> maxRuntimeSeconds;
};

struct PamPolicySnapshot {
  bool enabled{true};
  bool requireReason{true};
  bool allowBuiltInAdminTools{true};
  bool allowArbitraryApplications{true};
  std::uint32_t maxTimedRuntimeSeconds{120};
  std::vector<std::wstring> allowedActions;
  std::vector<std::wstring> allowedRequesters;
  std::vector<std::wstring> blockedPathPrefixes;
  std::vector<std::wstring> allowedPathPrefixes;
};

struct QueuedLocalApprovalRequest {
  std::wstring requestId;
  std::wstring createdAt;
  std::wstring type;
  std::wstring requester;
  std::wstring callerSid;
  std::wstring role;
  std::wstring reason;
  std::wstring recordId;
  std::wstring targetPath;
  std::wstring payloadJson;
};

struct LocalAdminMember {
  std::wstring accountName;
  std::wstring sid;
};

std::string EscapeRegex(const std::string& value) {
  std::string escaped;
  escaped.reserve(value.size() * 2);

  for (const auto ch : value) {
    switch (ch) {
      case '\\':
      case '^':
      case '$':
      case '.':
      case '|':
      case '?':
      case '*':
      case '+':
      case '(':
      case ')':
      case '[':
      case ']':
      case '{':
      case '}':
        escaped.push_back('\\');
        break;
      default:
        break;
    }

    escaped.push_back(ch);
  }

  return escaped;
}

std::string UnescapeJsonString(const std::string& value) {
  std::string result;
  result.reserve(value.size());

  bool escaping = false;
  for (const auto ch : value) {
    if (!escaping) {
      if (ch == '\\') {
        escaping = true;
      } else {
        result.push_back(ch);
      }
      continue;
    }

    switch (ch) {
      case '\\':
        result.push_back('\\');
        break;
      case '"':
        result.push_back('"');
        break;
      case 'n':
        result.push_back('\n');
        break;
      case 'r':
        result.push_back('\r');
        break;
      case 't':
        result.push_back('\t');
        break;
      default:
        result.push_back(ch);
        break;
    }

    escaping = false;
  }

  if (escaping) {
    result.push_back('\\');
  }

  return result;
}

std::optional<std::wstring> ExtractPayloadString(const std::wstring& json, const std::string& key) {
  if (json.size() > kMaxCommandPayloadChars) {
    return std::nullopt;
  }

  const auto utf8Json = WideToUtf8(json);
  const std::regex pattern("\"" + EscapeRegex(key) + "\"\\s*:\\s*\"((?:\\\\.|[^\"])*)\"");
  std::smatch match;
  if (std::regex_search(utf8Json, match, pattern)) {
    return Utf8ToWide(UnescapeJsonString(match[1].str()));
  }

  return std::nullopt;
}

std::optional<std::uint32_t> ExtractPayloadUInt32(const std::wstring& json, const std::string& key) {
  if (json.size() > kMaxCommandPayloadChars) {
    return std::nullopt;
  }

  const auto utf8Json = WideToUtf8(json);
  const std::regex pattern("\"" + EscapeRegex(key) + "\"\\s*:\\s*(\\d+)");
  std::smatch match;
  if (std::regex_search(utf8Json, match, pattern)) {
    return static_cast<std::uint32_t>(std::stoul(match[1].str()));
  }

  return std::nullopt;
}

std::optional<bool> ExtractPayloadBool(const std::wstring& json, const std::string& key) {
  if (json.size() > kMaxCommandPayloadChars) {
    return std::nullopt;
  }

  const auto utf8Json = WideToUtf8(json);
  const std::regex pattern("\"" + EscapeRegex(key) + "\"\\s*:\\s*(true|false|1|0)");
  std::smatch match;
  if (!std::regex_search(utf8Json, match, pattern)) {
    return std::nullopt;
  }

  const auto token = match[1].str();
  return token == "true" || token == "1";
}

std::vector<std::wstring> ExtractPayloadStringArray(const std::wstring& json, const std::string& key) {
  std::vector<std::wstring> values;
  if (json.size() > kMaxCommandPayloadChars) {
    return values;
  }

  const auto utf8Json = WideToUtf8(json);
  const std::regex arrayPattern("\"" + EscapeRegex(key) + "\"\\s*:\\s*\\[(.*?)\\]");
  std::smatch arrayMatch;
  if (!std::regex_search(utf8Json, arrayMatch, arrayPattern)) {
    return values;
  }

  const std::regex itemPattern("\"((?:\\\\.|[^\"])*)\"");
  auto begin = std::sregex_iterator(arrayMatch[1].first, arrayMatch[1].second, itemPattern);
  const auto end = std::sregex_iterator();
  for (auto iterator = begin; iterator != end; ++iterator) {
    values.push_back(Utf8ToWide(UnescapeJsonString((*iterator)[1].str())));
  }

  return values;
}

std::wstring ToLowerCopy(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return value;
}

bool PathStartsWith(std::wstring path, std::wstring prefix) {
  if (path.empty() || prefix.empty()) {
    return false;
  }

  path = ToLowerCopy(path);
  prefix = ToLowerCopy(prefix);
  if (!prefix.empty() && prefix.back() != L'\\') {
    prefix += L'\\';
  }

  return path == prefix.substr(0, prefix.size() - 1) || path.starts_with(prefix);
}

std::filesystem::path ResolveRuntimeRoot(const AgentConfig& config) {
  auto runtimeRoot = config.runtimeDatabasePath.parent_path();
  if (runtimeRoot.empty()) {
    runtimeRoot = config.runtimeDatabasePath;
  }
  return runtimeRoot;
}

std::filesystem::path ResolveInstallRootForConfig(const AgentConfig& config) {
  if (!config.installRootPath.empty()) {
    return config.installRootPath;
  }

  const auto runtimeRoot = ResolveRuntimeRoot(config);
  return runtimeRoot.has_parent_path() ? runtimeRoot.parent_path() : std::filesystem::current_path();
}

std::filesystem::path ResolveLocalApprovalRuntimeRoot() {
  const auto programData = ReadEnvironmentVariable(L"PROGRAMDATA");
  if (!programData.empty()) {
    return std::filesystem::path(programData) / L"FenrirAgent" / L"runtime";
  }

  return std::filesystem::current_path() / L"runtime";
}

std::filesystem::path ResolveLocalApprovalQueuePath() {
  return ResolveLocalApprovalRuntimeRoot() / kLocalApprovalQueueFileName;
}

std::filesystem::path ResolveLocalApprovalLedgerPath() {
  return ResolveLocalApprovalRuntimeRoot() / kLocalApprovalLedgerFileName;
}

std::filesystem::path ResolveLocalAdminBaselinePath(const AgentConfig& config) {
  return ResolveRuntimeRoot(config) / kLocalAdminBaselineFileName;
}

std::wstring BuildJsonStringArray(const std::vector<std::wstring>& values) {
  std::wstring result = L"[";
  for (std::size_t index = 0; index < values.size(); ++index) {
    if (index != 0) {
      result += L",";
    }
    result += L"\"" + Utf8ToWide(EscapeJsonString(values[index])) + L"\"";
  }
  result += L"]";
  return result;
}

std::wstring BuildLocalAdminMembersJson(const std::vector<LocalAdminMember>& members) {
  std::wstring result = L"[";
  for (std::size_t index = 0; index < members.size(); ++index) {
    if (index != 0) {
      result += L",";
    }

    result += L"{\"accountName\":\"" + Utf8ToWide(EscapeJsonString(members[index].accountName)) +
              L"\",\"sid\":\"" + Utf8ToWide(EscapeJsonString(members[index].sid)) + L"\"}";
  }
  result += L"]";
  return result;
}

std::vector<std::wstring> NormalizeSidList(const std::vector<std::wstring>& sids) {
  std::vector<std::wstring> normalized;
  normalized.reserve(sids.size());
  for (const auto& sid : sids) {
    auto lowered = ToLowerCopy(sid);
    lowered.erase(std::remove_if(lowered.begin(), lowered.end(),
                                 [](const wchar_t ch) {
                                   return ch == L' ' || ch == L'\t' || ch == L'\r' || ch == L'\n';
                                 }),
                 lowered.end());
    if (!lowered.empty()) {
      normalized.push_back(std::move(lowered));
    }
  }
  std::sort(normalized.begin(), normalized.end());
  normalized.erase(std::unique(normalized.begin(), normalized.end()), normalized.end());
  return normalized;
}

std::vector<LocalAdminMember> EnumerateLocalAdminMembers(std::wstring* errorMessage) {
  std::vector<LocalAdminMember> members;

  DWORD_PTR resumeHandle = 0;
  NET_API_STATUS status = NERR_Success;
  do {
    LPLOCALGROUP_MEMBERS_INFO_2 records = nullptr;
    DWORD entriesRead = 0;
    DWORD totalEntries = 0;
    status = NetLocalGroupGetMembers(nullptr, L"Administrators", 2, reinterpret_cast<LPBYTE*>(&records),
                                     MAX_PREFERRED_LENGTH, &entriesRead, &totalEntries, &resumeHandle);
    if (status != NERR_Success && status != ERROR_MORE_DATA) {
      if (records != nullptr) {
        NetApiBufferFree(records);
      }
      if (errorMessage != nullptr) {
        *errorMessage = L"Fenrir could not enumerate local Administrators group members (status " +
                        std::to_wstring(status) + L").";
      }
      return {};
    }

    for (DWORD index = 0; index < entriesRead; ++index) {
      LocalAdminMember member{};
      if (records[index].lgrmi2_domainandname != nullptr) {
        member.accountName = records[index].lgrmi2_domainandname;
      }

      if (records[index].lgrmi2_sid != nullptr) {
        LPWSTR sidString = nullptr;
        if (ConvertSidToStringSidW(records[index].lgrmi2_sid, &sidString) != FALSE && sidString != nullptr) {
          member.sid = sidString;
          LocalFree(sidString);
        }
      }

      if (member.accountName.empty()) {
        member.accountName = member.sid.empty() ? L"<unknown>" : member.sid;
      }

      members.push_back(std::move(member));
    }

    if (records != nullptr) {
      NetApiBufferFree(records);
    }
  } while (status == ERROR_MORE_DATA);

  std::sort(members.begin(), members.end(), [](const LocalAdminMember& left, const LocalAdminMember& right) {
    return ToLowerCopy(left.accountName) < ToLowerCopy(right.accountName);
  });

  return members;
}

bool IsProtectedLocalAdminMember(const LocalAdminMember& member, const std::wstring& ownerSidLower,
                                 const std::vector<std::wstring>& keepSidsLower) {
  if (member.sid.empty()) {
    return true;
  }

  const auto sidLower = ToLowerCopy(member.sid);
  if (!ownerSidLower.empty() && sidLower == ownerSidLower) {
    return true;
  }

  if (std::find(keepSidsLower.begin(), keepSidsLower.end(), sidLower) != keepSidsLower.end()) {
    return true;
  }

  if (sidLower == L"s-1-5-18" || sidLower == L"s-1-5-19" || sidLower == L"s-1-5-20" ||
      sidLower == L"s-1-5-32-544" || sidLower.ends_with(L"-500")) {
    return true;
  }

  return false;
}

std::vector<LocalAdminMember> BuildReducibleLocalAdminMembers(const std::vector<LocalAdminMember>& members,
                                                              const std::wstring& ownerSid,
                                                              const std::vector<std::wstring>& keepSids) {
  std::vector<LocalAdminMember> reducible;
  const auto ownerSidLower = ToLowerCopy(ownerSid);
  const auto keepSidsLower = NormalizeSidList(keepSids);

  for (const auto& member : members) {
    if (IsProtectedLocalAdminMember(member, ownerSidLower, keepSidsLower)) {
      continue;
    }
    reducible.push_back(member);
  }

  return reducible;
}

bool SaveLocalAdminBaselineSnapshot(const std::filesystem::path& baselinePath,
                                    const std::vector<LocalAdminMember>& members,
                                    std::wstring* errorMessage) {
  std::error_code directoryError;
  std::filesystem::create_directories(baselinePath.parent_path(), directoryError);
  if (directoryError) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir could not create local admin baseline directory.";
    }
    return false;
  }

  std::ofstream output(baselinePath, std::ios::binary | std::ios::trunc);
  if (!output.is_open()) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir could not open the local admin baseline snapshot file.";
    }
    return false;
  }

  for (const auto& member : members) {
    const auto line = std::wstring(L"{\"capturedAt\":\"") + CurrentUtcTimestamp() +
                      L"\",\"accountName\":\"" + Utf8ToWide(EscapeJsonString(member.accountName)) +
                      L"\",\"sid\":\"" + Utf8ToWide(EscapeJsonString(member.sid)) + L"\"}\n";
    const auto utf8Line = WideToUtf8(line);
    output.write(utf8Line.data(), static_cast<std::streamsize>(utf8Line.size()));
  }

  output.flush();
  if (!output.good()) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir could not persist the local admin baseline snapshot.";
    }
    return false;
  }

  return true;
}

std::vector<LocalAdminMember> LoadLocalAdminBaselineSnapshot(const std::filesystem::path& baselinePath,
                                                             std::wstring* errorMessage) {
  std::vector<LocalAdminMember> members;

  std::ifstream input(baselinePath, std::ios::binary);
  if (!input.is_open()) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir could not open the local admin baseline snapshot.";
    }
    return members;
  }

  std::string utf8Line;
  while (std::getline(input, utf8Line)) {
    if (utf8Line.empty()) {
      continue;
    }

    const auto line = Utf8ToWide(utf8Line);
    LocalAdminMember member{};
    member.accountName = ExtractPayloadString(line, "accountName").value_or(L"");
    member.sid = ExtractPayloadString(line, "sid").value_or(L"");
    if (!member.accountName.empty() || !member.sid.empty()) {
      members.push_back(std::move(member));
    }
  }

  if (!input.good() && !input.eof()) {
    members.clear();
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir encountered an I/O error reading the local admin baseline snapshot.";
    }
  }

  return members;
}

bool RemoveLocalAdminMemberBySid(const std::wstring& sid, std::wstring* errorMessage) {
  if (sid.empty()) {
    return true;
  }

  PSID memberSid = nullptr;
  if (ConvertStringSidToSidW(sid.c_str(), &memberSid) == FALSE || memberSid == nullptr) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir could not parse local admin SID " + sid + L".";
    }
    return false;
  }

  LOCALGROUP_MEMBERS_INFO_0 memberInfo{};
  memberInfo.lgrmi0_sid = memberSid;
  const auto status = NetLocalGroupDelMembers(nullptr, L"Administrators", 0,
                                               reinterpret_cast<LPBYTE>(&memberInfo), 1);
  LocalFree(memberSid);

  if (status == NERR_Success || status == NERR_UserNotFound || status == ERROR_NO_SUCH_MEMBER) {
    return true;
  }

  if (errorMessage != nullptr) {
    *errorMessage = L"Fenrir could not remove SID " + sid + L" from local Administrators (status " +
                    std::to_wstring(status) + L").";
  }
  return false;
}

bool AddLocalAdminMemberBySid(const std::wstring& sid, std::wstring* errorMessage) {
  if (sid.empty()) {
    return true;
  }

  PSID memberSid = nullptr;
  if (ConvertStringSidToSidW(sid.c_str(), &memberSid) == FALSE || memberSid == nullptr) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir could not parse local admin SID " + sid + L" for restore.";
    }
    return false;
  }

  LOCALGROUP_MEMBERS_INFO_0 memberInfo{};
  memberInfo.lgrmi0_sid = memberSid;
  const auto status = NetLocalGroupAddMembers(nullptr, L"Administrators", 0,
                                               reinterpret_cast<LPBYTE>(&memberInfo), 1);
  LocalFree(memberSid);

  if (status == NERR_Success || status == ERROR_MEMBER_IN_ALIAS) {
    return true;
  }

  if (errorMessage != nullptr) {
    *errorMessage = L"Fenrir could not restore SID " + sid + L" to local Administrators (status " +
                    std::to_wstring(status) + L").";
  }
  return false;
}

bool IsLocalApprovalEligibleCommandType(const std::wstring& type) {
  static const std::array<const wchar_t*, 15> kEligibleTypes = {
      L"quarantine.restore",
      L"quarantine.delete",
      L"patch.scan",
      L"patch.software.install",
      L"patch.windows.install",
      L"patch.cycle.run",
      L"support.bundle.export",
      L"support.bundle.export.full",
      L"storage.maintenance.run",
      L"local.breakglass.enable",
      L"local.breakglass.disable",
      L"local.admin.audit",
      L"local.admin.reduction.plan",
      L"local.admin.reduction.apply",
      L"local.admin.reduction.rollback"};

  return std::any_of(kEligibleTypes.begin(), kEligibleTypes.end(),
                     [&type](const auto* candidate) { return type == candidate; });
}

bool TryLoadQueuedLocalApprovalRequest(const std::filesystem::path& queuePath, const std::wstring& approvalRequestId,
                                       QueuedLocalApprovalRequest* request, std::wstring* errorMessage) {
  if (request == nullptr) {
    return false;
  }

  std::ifstream input(queuePath, std::ios::binary);
  if (!input.is_open()) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir could not open the local approval request queue.";
    }
    return false;
  }

  std::string utf8Line;
  while (std::getline(input, utf8Line)) {
    if (utf8Line.empty()) {
      continue;
    }

    const auto line = Utf8ToWide(utf8Line);
    const auto lineRequestId = ExtractPayloadString(line, "requestId").value_or(L"");
    if (lineRequestId.empty() || _wcsicmp(lineRequestId.c_str(), approvalRequestId.c_str()) != 0) {
      continue;
    }

    const auto status = ToLowerCopy(ExtractPayloadString(line, "status").value_or(L"pending"));
    if (status != L"pending") {
      if (errorMessage != nullptr) {
        *errorMessage = L"This local approval request is no longer pending.";
      }
      return false;
    }

    request->requestId = lineRequestId;
    request->createdAt = ExtractPayloadString(line, "createdAt").value_or(L"");
    request->type = ExtractPayloadString(line, "type").value_or(L"");
    request->requester = ExtractPayloadString(line, "requester").value_or(L"");
    request->callerSid = ExtractPayloadString(line, "callerSid").value_or(L"");
    request->role = ExtractPayloadString(line, "role").value_or(L"");
    request->reason = ExtractPayloadString(line, "reason").value_or(L"");
    request->recordId = ExtractPayloadString(line, "recordId").value_or(L"");
    request->targetPath = ExtractPayloadString(line, "targetPath").value_or(L"");
    request->payloadJson = ExtractPayloadString(line, "payloadJson").value_or(L"{}");
    if (request->payloadJson.empty()) {
      request->payloadJson = L"{}";
    }

    if (request->type.empty()) {
      if (errorMessage != nullptr) {
        *errorMessage = L"Fenrir found the local approval request but it is missing command metadata.";
      }
      return false;
    }

    return true;
  }

  if (errorMessage != nullptr) {
    *errorMessage = L"Fenrir could not find a pending local approval request for the provided identifier.";
  }
  return false;
}

bool HasProcessedLocalApprovalRequest(const std::filesystem::path& ledgerPath, const std::wstring& approvalRequestId) {
  std::ifstream input(ledgerPath, std::ios::binary);
  if (!input.is_open()) {
    return false;
  }

  std::string utf8Line;
  while (std::getline(input, utf8Line)) {
    if (utf8Line.empty()) {
      continue;
    }

    const auto line = Utf8ToWide(utf8Line);
    const auto lineRequestId = ExtractPayloadString(line, "requestId").value_or(L"");
    if (!lineRequestId.empty() && _wcsicmp(lineRequestId.c_str(), approvalRequestId.c_str()) == 0) {
      return true;
    }
  }

  return false;
}

std::set<std::wstring> LoadProcessedLocalApprovalRequestIds(const std::filesystem::path& ledgerPath) {
  std::set<std::wstring> processed;

  std::ifstream input(ledgerPath, std::ios::binary);
  if (!input.is_open()) {
    return processed;
  }

  std::string utf8Line;
  while (std::getline(input, utf8Line)) {
    if (utf8Line.empty()) {
      continue;
    }

    const auto line = Utf8ToWide(utf8Line);
    auto requestId = ExtractPayloadString(line, "requestId").value_or(L"");
    if (requestId.empty()) {
      continue;
    }

    processed.insert(ToLowerCopy(std::move(requestId)));
  }

  return processed;
}

bool AppendLocalApprovalLedgerEntry(const std::filesystem::path& ledgerPath, const std::wstring& approvalRequestId,
                                    const std::wstring& approver, const std::wstring& decision,
                                    const std::wstring& detailMessage, const std::wstring& approvedType,
                                    const std::wstring& executedCommandId, const std::wstring& requester) {
  std::error_code createError;
  std::filesystem::create_directories(ledgerPath.parent_path(), createError);
  if (createError) {
    return false;
  }

  std::ofstream output(ledgerPath, std::ios::binary | std::ios::app);
  if (!output.is_open()) {
    return false;
  }

  const auto escapedRequestId = Utf8ToWide(EscapeJsonString(approvalRequestId));
  const auto escapedApprover = Utf8ToWide(EscapeJsonString(approver));
  const auto escapedDecision = Utf8ToWide(EscapeJsonString(decision));
  const auto escapedDetail = Utf8ToWide(EscapeJsonString(detailMessage));
  const auto escapedType = Utf8ToWide(EscapeJsonString(approvedType));
  const auto escapedExecutedCommandId = Utf8ToWide(EscapeJsonString(executedCommandId));
  const auto escapedRequester = Utf8ToWide(EscapeJsonString(requester));

  const std::wstring line =
      L"{\"timestamp\":\"" + CurrentUtcTimestamp() + L"\",\"requestId\":\"" + escapedRequestId +
      L"\",\"approver\":\"" + escapedApprover + L"\",\"decision\":\"" + escapedDecision +
      L"\",\"detail\":\"" + escapedDetail + L"\",\"type\":\"" + escapedType +
      L"\",\"executedCommandId\":\"" + escapedExecutedCommandId + L"\",\"requester\":\"" +
      escapedRequester + L"\"}\n";

  const auto utf8LineOut = WideToUtf8(line);
  output.write(utf8LineOut.data(), static_cast<std::streamsize>(utf8LineOut.size()));
  output.flush();
  return output.good();
}

bool IsHardeningReady(const HardeningStatus& status, const AgentConfig& config) {
  const auto protectedServiceExpected = status.elamDriverPresent || !config.elamDriverPath.empty();
  return status.registryConfigured && status.runtimePathsTrusted && status.runtimePathsProtected &&
         status.serviceControlProtected &&
         (!protectedServiceExpected || status.launchProtectedConfigured);
}

void EnsureDirectoryExists(const std::filesystem::path& path, const wchar_t* label) {
  if (path.empty()) {
    throw std::runtime_error("Runtime layout path is empty");
  }

  std::error_code error;
  std::filesystem::create_directories(path, error);
  if (error || !std::filesystem::exists(path, error)) {
    throw std::runtime_error("Could not prepare runtime layout path for " + WideToUtf8(std::wstring(label)));
  }
}

void EnsureRuntimeLayoutReady(const AgentConfig& config, const RuntimePathValidation& runtimeValidation) {
  const auto runtimeRoot = runtimeValidation.runtimeRootPath.empty() ? ResolveRuntimeRoot(config)
                                                                     : runtimeValidation.runtimeRootPath;
  EnsureDirectoryExists(runtimeRoot, L"runtime root");
  EnsureDirectoryExists(config.runtimeDatabasePath.parent_path(), L"runtime database root");
  EnsureDirectoryExists(config.stateFilePath.parent_path(), L"state root");
  EnsureDirectoryExists(config.telemetryQueuePath.parent_path(), L"telemetry queue root");
  EnsureDirectoryExists(config.updateRootPath, L"update root");
  EnsureDirectoryExists(config.journalRootPath, L"journal root");
  EnsureDirectoryExists(config.quarantineRootPath, L"quarantine root");
  EnsureDirectoryExists(config.evidenceRootPath, L"evidence root");
}

std::optional<int> QueryCpuLoadPercent() {
  FILETIME idleTime{};
  FILETIME kernelTime{};
  FILETIME userTime{};
  if (GetSystemTimes(&idleTime, &kernelTime, &userTime) == FALSE) {
    return std::nullopt;
  }

  const auto toUInt64 = [](const FILETIME& value) {
    ULARGE_INTEGER merged{};
    merged.LowPart = value.dwLowDateTime;
    merged.HighPart = value.dwHighDateTime;
    return merged.QuadPart;
  };

  const auto idle = toUInt64(idleTime);
  const auto kernel = toUInt64(kernelTime);
  const auto user = toUInt64(userTime);

  static std::mutex sampleLock;
  static ULONGLONG previousIdle = 0;
  static ULONGLONG previousKernel = 0;
  static ULONGLONG previousUser = 0;
  static bool hasPreviousSample = false;

  const std::lock_guard guard(sampleLock);
  if (!hasPreviousSample) {
    previousIdle = idle;
    previousKernel = kernel;
    previousUser = user;
    hasPreviousSample = true;
    return std::nullopt;
  }

  const auto idleDelta = idle - previousIdle;
  const auto kernelDelta = kernel - previousKernel;
  const auto userDelta = user - previousUser;

  previousIdle = idle;
  previousKernel = kernel;
  previousUser = user;

  const auto totalDelta = kernelDelta + userDelta;
  if (totalDelta == 0) {
    return std::nullopt;
  }

  const auto busyDelta = totalDelta > idleDelta ? totalDelta - idleDelta : 0;
  const auto cpuPercent = static_cast<int>((busyDelta * 100ull) / totalDelta);
  return std::clamp(cpuPercent, 0, 100);
}

std::optional<std::wstring> EvaluateHeavyOperationGate(const AgentConfig& config, const std::wstring& operationName) {
  if (!config.enforceOperationalGates) {
    return std::nullopt;
  }

  if (const auto cpuLoad = QueryCpuLoadPercent();
      cpuLoad.has_value() && *cpuLoad > config.maxCpuLoadPercent) {
    return std::wstring(L"Fenrir deferred ") + operationName +
           L" because CPU pressure exceeded policy budget (" + std::to_wstring(*cpuLoad) + L"% > " +
           std::to_wstring(config.maxCpuLoadPercent) + L"%).";
  }

  MEMORYSTATUSEX memoryStatus{};
  memoryStatus.dwLength = sizeof(memoryStatus);
  if (GlobalMemoryStatusEx(&memoryStatus) != FALSE &&
      static_cast<int>(memoryStatus.dwMemoryLoad) > config.maxMemoryLoadPercent) {
    return std::wstring(L"Fenrir deferred ") + operationName + L" because memory pressure exceeded policy budget (" +
           std::to_wstring(memoryStatus.dwMemoryLoad) + L"% > " + std::to_wstring(config.maxMemoryLoadPercent) + L"%).";
  }

  const auto runtimeRoot = ResolveRuntimeRoot(config);
  if (!runtimeRoot.empty()) {
    ULARGE_INTEGER freeBytesAvailable{};
    ULARGE_INTEGER totalBytes{};
    ULARGE_INTEGER totalFreeBytes{};
    if (GetDiskFreeSpaceExW(runtimeRoot.c_str(), &freeBytesAvailable, &totalBytes, &totalFreeBytes) != FALSE) {
      const auto freeMegabytes = freeBytesAvailable.QuadPart / (1024ull * 1024ull);
      if (freeMegabytes < static_cast<unsigned long long>(std::max(config.minFreeDiskMb, 1))) {
        return std::wstring(L"Fenrir deferred ") + operationName +
               L" because free disk is below the configured safety floor (" + std::to_wstring(freeMegabytes) +
               L" MB < " + std::to_wstring(config.minFreeDiskMb) + L" MB).";
      }
    }
  }

  if (config.deferHeavyActionsOnBattery) {
    SYSTEM_POWER_STATUS powerStatus{};
    if (GetSystemPowerStatus(&powerStatus) != FALSE && powerStatus.ACLineStatus == 0) {
      return std::wstring(L"Fenrir deferred ") + operationName +
             L" because the device is on battery power and heavy-operation gating is enabled.";
    }
  }

  return std::nullopt;
}

std::optional<EventEnvelope> BuildBehaviorEventFromProcessTelemetry(const TelemetryRecord& record,
                                                                    const std::wstring& deviceId) {
  if (record.eventType == L"process.started") {
    const auto imagePath = ExtractPayloadString(record.payloadJson, "imagePath").value_or(L"");
    const auto imageName = ExtractPayloadString(record.payloadJson, "imageName").value_or(L"");
    if (imagePath.empty() && imageName.empty()) {
      return std::nullopt;
    }

    EventEnvelope event{
        .kind = EventKind::ProcessStart,
        .deviceId = deviceId,
        .correlationId = record.eventId,
        .targetPath = imagePath.empty() ? imageName : imagePath,
        .sha256 = {},
        .process =
            ProcessContext{
                .imagePath = imagePath,
                .commandLine = ExtractPayloadString(record.payloadJson, "commandLine").value_or(L""),
                .parentImagePath = ExtractPayloadString(record.payloadJson, "parentImagePath").value_or(L""),
                .userSid = ExtractPayloadString(record.payloadJson, "userSid").value_or(L""),
                .signer = ExtractPayloadString(record.payloadJson, "signer").value_or(L"")},
        .occurredAt = std::chrono::system_clock::now()};
    return event;
  }

  if (record.eventType == L"image.loaded") {
    const auto modulePath = ExtractPayloadString(record.payloadJson, "imagePath").value_or(L"");
    if (modulePath.empty()) {
      return std::nullopt;
    }

    EventEnvelope event{
        .kind = EventKind::FileOpen,
        .deviceId = deviceId,
        .correlationId = record.eventId,
        .targetPath = modulePath,
        .sha256 = {},
        .process =
            ProcessContext{
                .imagePath = ExtractPayloadString(record.payloadJson, "processImagePath").value_or(L""),
                .commandLine = {},
                .parentImagePath = {},
                .userSid = {},
                .signer = ExtractPayloadString(record.payloadJson, "signer").value_or(L"")},
        .occurredAt = std::chrono::system_clock::now()};
    return event;
  }

  return std::nullopt;
}

std::optional<EventEnvelope> BuildBehaviorEventFromNetworkTelemetry(const TelemetryRecord& record,
                                                                    const std::wstring& deviceId) {
  if (record.eventType != L"network.connection.blocked" && record.eventType != L"network.connection.snapshot") {
    return std::nullopt;
  }

  const auto remoteAddress = ExtractPayloadString(record.payloadJson, "remoteAddress").value_or(L"");
  const auto remotePort = ExtractPayloadUInt32(record.payloadJson, "remotePort").value_or(0);
  if (remoteAddress.empty()) {
    return std::nullopt;
  }

  auto processImagePath = ExtractPayloadString(record.payloadJson, "processImagePath").value_or(L"");
  if (processImagePath.empty()) {
    processImagePath = ExtractPayloadString(record.payloadJson, "appId").value_or(L"");
  }

  std::wstring targetPath = remoteAddress;
  if (remotePort > 0) {
    targetPath += L":";
    targetPath += std::to_wstring(remotePort);
  }

  EventEnvelope event{
      .kind = EventKind::NetworkConnect,
      .deviceId = deviceId,
      .correlationId = record.eventId,
      .targetPath = std::move(targetPath),
      .sha256 = {},
      .process =
          ProcessContext{
              .imagePath = std::move(processImagePath),
              .commandLine = {},
              .parentImagePath = {},
              .userSid = ExtractPayloadString(record.payloadJson, "userSid").value_or(L""),
              .signer = {}},
      .occurredAt = std::chrono::system_clock::now()};
  return event;
}

bool TerminateProcessById(const DWORD pid) {
  if (pid == 0 || pid == GetCurrentProcessId()) {
    return false;
  }

  const HANDLE processHandle = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
  if (processHandle == nullptr) {
    return false;
  }

  const auto terminated = TerminateProcess(processHandle, 1) != FALSE;
  CloseHandle(processHandle);
  return terminated;
}

DWORD ExecuteHiddenProcess(const std::wstring& commandLine, const std::wstring& workingDirectory = {}) {
  std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
  mutableCommandLine.push_back(L'\0');

  STARTUPINFOW startupInfo{};
  startupInfo.cb = sizeof(startupInfo);
  startupInfo.dwFlags = STARTF_USESHOWWINDOW;
  startupInfo.wShowWindow = SW_HIDE;

  PROCESS_INFORMATION processInfo{};
  const auto created =
      CreateProcessW(nullptr, mutableCommandLine.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr,
                     workingDirectory.empty() ? nullptr : workingDirectory.c_str(), &startupInfo, &processInfo);
  if (!created) {
    throw std::runtime_error("CreateProcessW failed");
  }

  WaitForSingleObject(processInfo.hProcess, INFINITE);

  DWORD exitCode = 0;
  GetExitCodeProcess(processInfo.hProcess, &exitCode);
  CloseHandle(processInfo.hThread);
  CloseHandle(processInfo.hProcess);
  return exitCode;
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

std::filesystem::path WriteRuntimeScriptFile(const std::filesystem::path& jobsRoot, const std::wstring& extension,
                                             const std::wstring& content) {
  std::error_code error;
  std::filesystem::create_directories(jobsRoot, error);
  const auto scriptPath = jobsRoot / (GenerateGuidString() + extension);

  std::ofstream output(scriptPath, std::ios::binary | std::ios::trunc);
  if (!output.is_open()) {
    throw std::runtime_error("Unable to create the runtime script file");
  }

  const auto utf8Content = WideToUtf8(content);
  output.write(utf8Content.data(), static_cast<std::streamsize>(utf8Content.size()));
  output.close();

  return scriptPath;
}

std::wstring FormatWindowsError(const DWORD errorCode) {
  wchar_t* messageBuffer = nullptr;
  const auto flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
  const auto messageLength =
      FormatMessageW(flags, nullptr, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                     reinterpret_cast<LPWSTR>(&messageBuffer), 0, nullptr);
  if (messageLength == 0 || messageBuffer == nullptr) {
    return L"Windows error " + std::to_wstring(errorCode);
  }

  std::wstring message(messageBuffer, messageLength);
  LocalFree(messageBuffer);
  while (!message.empty() &&
         (message.back() == L'\r' || message.back() == L'\n' || message.back() == L' ' || message.back() == L'\t')) {
    message.pop_back();
  }
  return message;
}

std::wstring EscapePamJsonValue(const std::wstring& value) {
  std::wostringstream stream;
  for (const auto ch : value) {
    switch (ch) {
      case L'\\':
        stream << L"\\\\";
        break;
      case L'"':
        stream << L"\\\"";
        break;
      case L'\r':
        stream << L"\\r";
        break;
      case L'\n':
        stream << L"\\n";
        break;
      case L'\t':
        stream << L"\\t";
        break;
      default:
        stream << ch;
        break;
    }
  }
  return stream.str();
}

std::wstring QuoteCommandLineArgument(const std::wstring& argument) {
  if (argument.empty()) {
    return L"\"\"";
  }

  if (argument.find_first_of(L" \t\n\v\"") == std::wstring::npos) {
    return argument;
  }

  std::wstring quoted;
  quoted.push_back(L'"');

  int pendingBackslashes = 0;
  for (const auto ch : argument) {
    if (ch == L'\\') {
      ++pendingBackslashes;
      continue;
    }

    if (ch == L'"') {
      quoted.append(static_cast<std::size_t>((pendingBackslashes * 2) + 1), L'\\');
      quoted.push_back(L'"');
      pendingBackslashes = 0;
      continue;
    }

    if (pendingBackslashes != 0) {
      quoted.append(static_cast<std::size_t>(pendingBackslashes), L'\\');
      pendingBackslashes = 0;
    }
    quoted.push_back(ch);
  }

  if (pendingBackslashes != 0) {
    quoted.append(static_cast<std::size_t>(pendingBackslashes * 2), L'\\');
  }
  quoted.push_back(L'"');
  return quoted;
}

std::wstring BuildCreateProcessCommandLine(const std::wstring& executablePath, const std::wstring& arguments) {
  std::wstring commandLine = QuoteCommandLineArgument(executablePath);
  if (!arguments.empty()) {
    commandLine.push_back(L' ');
    commandLine += arguments;
  }
  return commandLine;
}

std::wstring GetSystemBinaryPath(const wchar_t* relativePath) {
  std::wstring buffer(MAX_PATH, L'\0');
  const auto written = GetSystemDirectoryW(buffer.data(), static_cast<UINT>(buffer.size()));
  if (written == 0) {
    return {};
  }

  buffer.resize(written);
  return (std::filesystem::path(buffer) / relativePath).wstring();
}

std::wstring TrimWhitespace(std::wstring value) {
  const auto first = value.find_first_not_of(L" \t\r\n");
  if (first == std::wstring::npos) {
    return {};
  }

  const auto last = value.find_last_not_of(L" \t\r\n");
  return value.substr(first, last - first + 1);
}

PamPolicySnapshot CreateDefaultPamPolicySnapshot() {
  PamPolicySnapshot policy;
  policy.allowedActions = {
      L"run_powershell",
      L"run_cmd",
      L"run_disk_cleanup",
      L"run_windows_update",
      L"run_network_reset",
      L"run_application",
      L"run_application_timed",
      L"elevate_2m",
  };
  policy.blockedPathPrefixes = {
      LR"(C:\Windows\System32\drivers)",
      LR"(C:\Windows\System32\config)",
  };
  return policy;
}

std::filesystem::path ResolvePamPolicyPath(const AgentConfig& config) {
  return ResolveRuntimeRoot(config) / kPamPolicyFileName;
}

bool IsPamRequesterAllowed(const PamPolicySnapshot& policy, const std::wstring& requester) {
  if (policy.allowedRequesters.empty()) {
    return true;
  }

  const auto requesterLower = ToLowerCopy(requester);
  for (const auto& allowedRequester : policy.allowedRequesters) {
    const auto allowedLower = ToLowerCopy(allowedRequester);
    if (allowedLower.empty()) {
      continue;
    }

    if (requesterLower == allowedLower) {
      return true;
    }

    const auto qualifiedSuffix = std::wstring(L"\\") + allowedLower;
    if (requesterLower.size() > qualifiedSuffix.size() && requesterLower.ends_with(qualifiedSuffix)) {
      return true;
    }
  }

  return false;
}

bool IsPamActionAllowed(const PamPolicySnapshot& policy, const std::wstring& actionLower) {
  if (policy.allowedActions.empty()) {
    return true;
  }

  return std::any_of(policy.allowedActions.begin(), policy.allowedActions.end(),
                     [&actionLower](const auto& allowedAction) {
                       return ToLowerCopy(allowedAction) == actionLower;
                     });
}

bool TryLoadPamPolicy(const AgentConfig& config, PamPolicySnapshot* policy, std::wstring* errorMessage) {
  if (policy == nullptr) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir PAM policy target was null.";
    }
    return false;
  }

  *policy = CreateDefaultPamPolicySnapshot();
  const auto policyPath = ResolvePamPolicyPath(config);
  std::error_code existsError;
  if (!std::filesystem::exists(policyPath, existsError) || existsError) {
    return true;
  }

  std::ifstream input(policyPath, std::ios::binary);
  if (!input.is_open()) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir PAM policy file could not be opened at " + policyPath.wstring() + L".";
    }
    policy->enabled = false;
    return false;
  }

  const std::string policyUtf8((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
  if (!input.good() && !input.eof()) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir PAM policy file could not be read cleanly from " + policyPath.wstring() + L".";
    }
    policy->enabled = false;
    return false;
  }

  const auto policyJson = Utf8ToWide(policyUtf8);
  if (const auto enabled = ExtractPayloadBool(policyJson, "enabled"); enabled.has_value()) {
    policy->enabled = *enabled;
  }
  if (const auto requireReason = ExtractPayloadBool(policyJson, "requireReason"); requireReason.has_value()) {
    policy->requireReason = *requireReason;
  }
  if (const auto allowBuiltIns = ExtractPayloadBool(policyJson, "allowBuiltInAdminTools"); allowBuiltIns.has_value()) {
    policy->allowBuiltInAdminTools = *allowBuiltIns;
  }
  if (const auto allowApplications = ExtractPayloadBool(policyJson, "allowArbitraryApplications");
      allowApplications.has_value()) {
    policy->allowArbitraryApplications = *allowApplications;
  }
  if (const auto maxRuntimeSeconds = ExtractPayloadUInt32(policyJson, "maxTimedRuntimeSeconds");
      maxRuntimeSeconds.has_value()) {
    policy->maxTimedRuntimeSeconds = std::clamp<std::uint32_t>(*maxRuntimeSeconds, 15, 900);
  }

  if (const auto actions = ExtractPayloadStringArray(policyJson, "allowedActions"); !actions.empty()) {
    policy->allowedActions = actions;
  }
  if (const auto requesters = ExtractPayloadStringArray(policyJson, "allowedRequesters"); !requesters.empty()) {
    policy->allowedRequesters = requesters;
  }
  if (const auto blockedPrefixes = ExtractPayloadStringArray(policyJson, "blockedPathPrefixes"); !blockedPrefixes.empty()) {
    policy->blockedPathPrefixes = blockedPrefixes;
  }
  if (const auto allowedPrefixes = ExtractPayloadStringArray(policyJson, "allowedPathPrefixes"); !allowedPrefixes.empty()) {
    policy->allowedPathPrefixes = allowedPrefixes;
  }

  return true;
}

bool EvaluatePamRequestPolicy(const PamPolicySnapshot& policy, const PamRequestPayload& request,
                              PamLaunchPlan* launchPlan, std::wstring* errorMessage) {
  if (launchPlan == nullptr) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir PAM policy evaluation did not receive a launch plan target.";
    }
    return false;
  }

  if (!policy.enabled) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir PAM policy is currently disabled for elevation requests.";
    }
    return false;
  }

  if (policy.requireReason && TrimWhitespace(request.reason).size() < 8) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir PAM policy requires a non-trivial justification before elevation is approved.";
    }
    return false;
  }

  if (!IsPamRequesterAllowed(policy, request.requester)) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir PAM policy denied this requester for elevation.";
    }
    return false;
  }

  const auto actionLower = ToLowerCopy(request.action);
  if (!IsPamActionAllowed(policy, actionLower)) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir PAM policy denied this action type for elevation.";
    }
    return false;
  }

  const auto builtInAction =
      actionLower == L"run_powershell" || actionLower == L"run_cmd" || actionLower == L"run_disk_cleanup" ||
      actionLower == L"run_windows_update" || actionLower == L"run_network_reset";
  const auto customAction =
      actionLower == L"run_application" || actionLower == L"run_application_timed" || actionLower == L"elevate_2m";

  if (builtInAction && !policy.allowBuiltInAdminTools) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir PAM policy denied built-in administrative tool elevation for this request.";
    }
    return false;
  }

  if (customAction && !policy.allowArbitraryApplications) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir PAM policy denied arbitrary application elevation for this request.";
    }
    return false;
  }

  const auto targetPath = launchPlan->targetPath.empty() ? request.targetPath : launchPlan->targetPath;
  if (!targetPath.empty()) {
    const auto blockedByPrefix = std::any_of(policy.blockedPathPrefixes.begin(), policy.blockedPathPrefixes.end(),
                                             [&targetPath](const auto& blockedPrefix) {
                                               return !blockedPrefix.empty() && PathStartsWith(targetPath, blockedPrefix);
                                             });
    if (blockedByPrefix) {
      if (errorMessage != nullptr) {
        *errorMessage = L"Fenrir PAM policy denied this target path because it matches a protected system prefix.";
      }
      return false;
    }

    if (customAction && !policy.allowedPathPrefixes.empty()) {
      const auto allowedByPrefix = std::any_of(policy.allowedPathPrefixes.begin(), policy.allowedPathPrefixes.end(),
                                               [&targetPath](const auto& allowedPrefix) {
                                                 return !allowedPrefix.empty() && PathStartsWith(targetPath, allowedPrefix);
                                               });
      if (!allowedByPrefix) {
        if (errorMessage != nullptr) {
          *errorMessage = L"Fenrir PAM policy denied this target path because it is outside approved application roots.";
        }
        return false;
      }
    }
  }

  const auto timedAction = actionLower == L"run_application_timed" || actionLower == L"elevate_2m";
  if (timedAction) {
    if (policy.maxTimedRuntimeSeconds == 0) {
      if (errorMessage != nullptr) {
        *errorMessage = L"Fenrir PAM policy denied timed elevation because timed windows are disabled.";
      }
      return false;
    }

    const auto requestedWindow = launchPlan->maxRuntimeSeconds.value_or(policy.maxTimedRuntimeSeconds);
    launchPlan->maxRuntimeSeconds = std::min<std::uint32_t>(requestedWindow, policy.maxTimedRuntimeSeconds);
  }

  return true;
}

bool ParsePamRequestPayload(const std::wstring& payload, PamRequestPayload* request, std::wstring* errorMessage) {
  if (request == nullptr) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir PAM request parser received a null request target.";
    }
    return false;
  }

  const auto action = ExtractPayloadString(payload, "action");
  if (!action.has_value() || action->empty()) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir PAM request payload is missing an action.";
    }
    return false;
  }

  const auto targetPath = ExtractPayloadString(payload, "targetPath");
  if (!targetPath.has_value() || targetPath->empty()) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir PAM request payload is missing a target path.";
    }
    return false;
  }

  request->action = *action;
  request->targetPath = *targetPath;
  request->arguments = ExtractPayloadString(payload, "arguments").value_or(L"");
  request->reason = ExtractPayloadString(payload, "reason").value_or(L"User approved a local Fenrir PAM request");
  request->requestedAt = ExtractPayloadString(payload, "requestedAt").value_or(CurrentUtcTimestamp());
  request->requester = ExtractPayloadString(payload, "requester").value_or(L"unknown");
  return true;
}

bool BuildPamLaunchPlan(const PamRequestPayload& request, PamLaunchPlan* launchPlan, std::wstring* errorMessage) {
  if (launchPlan == nullptr) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir PAM launch plan target was null.";
    }
    return false;
  }

  const auto action = ToLowerCopy(request.action);
  const auto timedScopedAction = action == L"run_application_timed" || action == L"elevate_2m";
  if (action == L"run_powershell") {
    launchPlan->executablePath = GetSystemBinaryPath(LR"(WindowsPowerShell\v1.0\powershell.exe)");
    launchPlan->arguments = L"-NoLogo";
    launchPlan->targetPath = launchPlan->executablePath;
    return !launchPlan->executablePath.empty();
  }

  if (action == L"run_cmd") {
    launchPlan->executablePath = GetSystemBinaryPath(L"cmd.exe");
    launchPlan->targetPath = launchPlan->executablePath;
    return !launchPlan->executablePath.empty();
  }

  if (action == L"run_disk_cleanup") {
    launchPlan->executablePath = GetSystemBinaryPath(L"cleanmgr.exe");
    launchPlan->targetPath = launchPlan->executablePath;
    return !launchPlan->executablePath.empty();
  }

  if (action == L"run_windows_update") {
    launchPlan->executablePath = GetSystemBinaryPath(L"control.exe");
    launchPlan->arguments = L"/name Microsoft.WindowsUpdate";
    launchPlan->targetPath = launchPlan->executablePath;
    return !launchPlan->executablePath.empty();
  }

  if (action == L"run_network_reset") {
    launchPlan->executablePath = GetSystemBinaryPath(L"cmd.exe");
    launchPlan->arguments = L"/c netsh winsock reset & netsh int ip reset";
    launchPlan->targetPath = launchPlan->executablePath;
    return !launchPlan->executablePath.empty();
  }

  if (action == L"run_application" || timedScopedAction) {
    const std::filesystem::path targetPath(request.targetPath);
    if (targetPath.empty()) {
      if (errorMessage != nullptr) {
        *errorMessage = L"Fenrir PAM did not receive an application path to elevate.";
      }
      return false;
    }

    std::error_code existsError;
    if (!std::filesystem::exists(targetPath, existsError) || existsError) {
      if (errorMessage != nullptr) {
        *errorMessage = L"Fenrir PAM could not find the selected application on disk.";
      }
      return false;
    }

    const auto extension = ToLowerCopy(targetPath.extension().wstring());
    if (extension == L".ps1") {
      launchPlan->executablePath = GetSystemBinaryPath(LR"(WindowsPowerShell\v1.0\powershell.exe)");
      if (launchPlan->executablePath.empty()) {
        if (errorMessage != nullptr) {
          *errorMessage = L"Fenrir PAM could not resolve PowerShell to launch the selected script.";
        }
        return false;
      }

      launchPlan->arguments = L"-NoLogo -NoProfile -ExecutionPolicy Bypass -File " +
                              QuoteCommandLineArgument(targetPath.wstring());
      if (!request.arguments.empty()) {
        launchPlan->arguments += L" ";
        launchPlan->arguments += request.arguments;
      }
    } else if (extension == L".cmd" || extension == L".bat") {
      launchPlan->executablePath = GetSystemBinaryPath(L"cmd.exe");
      if (launchPlan->executablePath.empty()) {
        if (errorMessage != nullptr) {
          *errorMessage = L"Fenrir PAM could not resolve Command Prompt to launch the selected script.";
        }
        return false;
      }

      launchPlan->arguments = L"/c " + QuoteCommandLineArgument(targetPath.wstring());
      if (!request.arguments.empty()) {
        launchPlan->arguments += L" ";
        launchPlan->arguments += request.arguments;
      }
    } else {
      launchPlan->executablePath = targetPath.wstring();
      launchPlan->arguments = request.arguments;
    }

    launchPlan->targetPath = targetPath.wstring();
    if (timedScopedAction) {
      launchPlan->maxRuntimeSeconds = 120;
    }
    return true;
  }

  if (errorMessage != nullptr) {
    *errorMessage = L"Fenrir PAM received an unsupported elevation action.";
  }
  return false;
}

std::wstring BuildPamRequestPayloadJson(const PamRequestPayload& request) {
  return L"{\"requestedAt\":\"" + EscapePamJsonValue(request.requestedAt) +
         L"\",\"requester\":\"" + EscapePamJsonValue(request.requester) +
         L"\",\"action\":\"" + EscapePamJsonValue(request.action) +
         L"\",\"targetPath\":\"" + EscapePamJsonValue(request.targetPath) +
         L"\",\"arguments\":\"" + EscapePamJsonValue(request.arguments) +
         L"\",\"reason\":\"" + EscapePamJsonValue(request.reason) + L"\"}";
}

bool QueuePamRequestPayload(const std::filesystem::path& requestPath, const PamRequestPayload& request,
                            std::wstring* errorMessage) {
  if (requestPath.empty()) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir PAM request path was empty.";
    }
    return false;
  }

  std::error_code directoryError;
  std::filesystem::create_directories(requestPath.parent_path(), directoryError);
  if (directoryError) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir could not create the PAM runtime directory at " +
                      requestPath.parent_path().wstring() + L".";
    }
    return false;
  }

  const auto tempPath = requestPath.wstring() + L".new";
  std::ofstream stream(std::filesystem::path(tempPath), std::ios::binary | std::ios::trunc);
  if (!stream.is_open()) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir could not open a temporary PAM request payload file.";
    }
    return false;
  }

  const auto payloadUtf8 = WideToUtf8(BuildPamRequestPayloadJson(request));
  stream.write(payloadUtf8.data(), static_cast<std::streamsize>(payloadUtf8.size()));
  stream.flush();
  if (!stream.good()) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir could not flush the PAM request payload.";
    }
    return false;
  }
  stream.close();

  if (MoveFileExW(tempPath.c_str(), requestPath.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == FALSE) {
    DeleteFileW(tempPath.c_str());
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir could not finalize the PAM request payload.";
    }
    return false;
  }

  return true;
}

bool TryReadPamRequestPayload(const std::filesystem::path& requestPath, std::wstring* payload, std::wstring* errorMessage) {
  std::ifstream input(requestPath, std::ios::binary);
  if (!input.is_open()) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir PAM could not open the pending request payload.";
    }
    return false;
  }

  const std::string utf8Payload((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
  if (!input.good() && !input.eof()) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir PAM encountered an I/O error while reading the request payload.";
    }
    return false;
  }

  if (utf8Payload.empty()) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir PAM received an empty request payload.";
    }
    return false;
  }

  if (payload != nullptr) {
    *payload = Utf8ToWide(utf8Payload);
  }
  return true;
}

bool AppendPamAuditEntry(const std::filesystem::path& journalPath, const PamRequestPayload& request,
                         const PamLaunchPlan& launchPlan, const std::wstring& decision,
                         const std::wstring& detailMessage, const std::wstring& approvalSource = L"policy",
                         const std::wstring& terminationOutcome = L"n/a") {
  std::error_code createError;
  std::filesystem::create_directories(journalPath.parent_path(), createError);
  if (createError) {
    return false;
  }

  std::ofstream output(journalPath, std::ios::binary | std::ios::app);
  if (!output.is_open()) {
    return false;
  }

  const auto durationSeconds = launchPlan.maxRuntimeSeconds.value_or(0);
  const std::wstring line = L"{\"timestamp\":\"" + EscapePamJsonValue(CurrentUtcTimestamp()) + L"\",\"requestedAt\":\"" +
                            EscapePamJsonValue(request.requestedAt) + L"\",\"requester\":\"" +
                            EscapePamJsonValue(request.requester) + L"\",\"action\":\"" +
                            EscapePamJsonValue(request.action) + L"\",\"target\":\"" +
                            EscapePamJsonValue(launchPlan.targetPath.empty() ? request.targetPath : launchPlan.targetPath) +
                            L"\",\"reason\":\"" + EscapePamJsonValue(request.reason) + L"\",\"decision\":\"" +
                            EscapePamJsonValue(decision) + L"\",\"detail\":\"" + EscapePamJsonValue(detailMessage) +
                            L"\",\"approvalSource\":\"" + EscapePamJsonValue(approvalSource) +
                            L"\",\"durationSeconds\":" + std::to_wstring(durationSeconds) +
                            L",\"terminationOutcome\":\"" + EscapePamJsonValue(terminationOutcome) + L"\"}\n";
  const auto utf8Line = WideToUtf8(line);
  output.write(utf8Line.data(), static_cast<std::streamsize>(utf8Line.size()));
  output.flush();
  return output.good();
}

DWORD ResolveInteractiveSessionId() {
  const auto consoleSessionId = WTSGetActiveConsoleSessionId();
  if (consoleSessionId != 0xFFFFFFFF) {
    return consoleSessionId;
  }

  PWTS_SESSION_INFOW sessions = nullptr;
  DWORD sessionCount = 0;
  if (WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &sessionCount) != FALSE) {
    DWORD activeSessionId = 0xFFFFFFFF;
    for (DWORD index = 0; index < sessionCount; ++index) {
      if (sessions[index].State == WTSActive) {
        activeSessionId = sessions[index].SessionId;
        break;
      }
    }
    WTSFreeMemory(sessions);
    return activeSessionId;
  }

  return 0xFFFFFFFF;
}

std::optional<std::filesystem::path> ResolveActiveUserPamRequestPath() {
  const auto sessionId = ResolveInteractiveSessionId();
  if (sessionId == 0xFFFFFFFF) {
    return std::nullopt;
  }

  HANDLE userToken = nullptr;
  if (WTSQueryUserToken(sessionId, &userToken) == FALSE) {
    return std::nullopt;
  }

  DWORD requiredLength = 0;
  GetUserProfileDirectoryW(userToken, nullptr, &requiredLength);
  if (requiredLength == 0) {
    CloseHandle(userToken);
    return std::nullopt;
  }

  std::wstring profileDirectory(requiredLength, L'\0');
  if (GetUserProfileDirectoryW(userToken, profileDirectory.data(), &requiredLength) == FALSE) {
    CloseHandle(userToken);
    return std::nullopt;
  }
  CloseHandle(userToken);

  while (!profileDirectory.empty() && profileDirectory.back() == L'\0') {
    profileDirectory.pop_back();
  }
  if (profileDirectory.empty()) {
    return std::nullopt;
  }

  return std::filesystem::path(profileDirectory) / L"AppData" / L"Local" / L"FenrirAgent" / L"runtime" /
         kPamRequestFileName;
}

std::vector<std::filesystem::path> ResolvePamRequestPathsFromUserProfiles() {
  std::vector<std::filesystem::path> requestPaths;

  const auto systemDrive = ReadEnvironmentVariable(L"SystemDrive");
  const auto usersRoot = std::filesystem::path(systemDrive.empty() ? L"C:\\" : systemDrive) / L"Users";
  std::error_code rootError;
  if (!std::filesystem::exists(usersRoot, rootError) || rootError) {
    return requestPaths;
  }

  for (const auto& entry : std::filesystem::directory_iterator(usersRoot, rootError)) {
    if (rootError) {
      break;
    }
    if (!entry.is_directory()) {
      continue;
    }

    const auto name = ToLowerCopy(entry.path().filename().wstring());
    if (name.empty() || name == L"default" || name == L"default user" || name == L"public" || name == L"all users") {
      continue;
    }

    requestPaths.push_back(entry.path() / L"AppData" / L"Local" / L"FenrirAgent" / L"runtime" / kPamRequestFileName);
  }

  return requestPaths;
}

bool LaunchPamProcessAsSystem(const PamLaunchPlan& launchPlan, DWORD* processId, std::wstring* errorMessage) {
  if (launchPlan.executablePath.empty()) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir PAM did not receive an executable to launch.";
    }
    return false;
  }

  const auto sessionId = ResolveInteractiveSessionId();
  if (sessionId == 0xFFFFFFFF) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir PAM could not identify an active interactive session.";
    }
    return false;
  }

  HANDLE serviceToken = nullptr;
  if (OpenProcessToken(GetCurrentProcess(),
                       TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT |
                           TOKEN_ADJUST_SESSIONID,
                       &serviceToken) == FALSE) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir PAM could not open the service security token: " +
                      FormatWindowsError(GetLastError());
    }
    return false;
  }

  HANDLE primaryToken = nullptr;
  if (DuplicateTokenEx(serviceToken, MAXIMUM_ALLOWED, nullptr, SecurityImpersonation, TokenPrimary, &primaryToken) ==
      FALSE) {
    const auto error = GetLastError();
    CloseHandle(serviceToken);
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir PAM could not duplicate a primary launch token: " + FormatWindowsError(error);
    }
    return false;
  }
  CloseHandle(serviceToken);

  DWORD mutableSessionId = sessionId;
  if (SetTokenInformation(primaryToken, TokenSessionId, &mutableSessionId, sizeof(mutableSessionId)) == FALSE) {
    const auto error = GetLastError();
    CloseHandle(primaryToken);
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir PAM could not bind the launch token to the active session: " +
                      FormatWindowsError(error);
    }
    return false;
  }

  LPVOID environmentBlock = nullptr;
  const auto environmentReady = CreateEnvironmentBlock(&environmentBlock, primaryToken, FALSE) != FALSE;
  const auto workingDirectory = std::filesystem::path(launchPlan.executablePath).parent_path();
  const auto commandLine = BuildCreateProcessCommandLine(launchPlan.executablePath, launchPlan.arguments);
  std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
  mutableCommandLine.push_back(L'\0');

  STARTUPINFOW startupInfo{};
  startupInfo.cb = sizeof(startupInfo);
  startupInfo.dwFlags = STARTF_USESHOWWINDOW;
  startupInfo.wShowWindow = SW_SHOWNORMAL;
  startupInfo.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");

  PROCESS_INFORMATION processInfo{};
  const auto creationFlags = CREATE_NEW_CONSOLE | (environmentReady ? CREATE_UNICODE_ENVIRONMENT : 0);
  const auto created = CreateProcessAsUserW(
      primaryToken, launchPlan.executablePath.c_str(), mutableCommandLine.data(), nullptr, nullptr, FALSE,
      creationFlags, environmentReady ? environmentBlock : nullptr,
      workingDirectory.empty() ? nullptr : workingDirectory.c_str(), &startupInfo, &processInfo);

  if (environmentReady && environmentBlock != nullptr) {
    DestroyEnvironmentBlock(environmentBlock);
  }
  CloseHandle(primaryToken);

  if (!created) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir PAM failed to launch the approved request: " + FormatWindowsError(GetLastError());
    }
    return false;
  }

  if (processId != nullptr) {
    *processId = processInfo.dwProcessId;
  }
  CloseHandle(processInfo.hThread);
  CloseHandle(processInfo.hProcess);
  return true;
}

void StartPamTimedProcessGuard(const std::filesystem::path& journalPath, const PamRequestPayload& request,
                               const PamLaunchPlan& launchPlan, const DWORD processId) {
  if (!launchPlan.maxRuntimeSeconds.has_value() || launchPlan.maxRuntimeSeconds.value_or(0) == 0 || processId == 0) {
    return;
  }

  const auto timeoutSeconds = *launchPlan.maxRuntimeSeconds;
  std::thread([journalPath, request, launchPlan, processId, timeoutSeconds]() {
    const HANDLE processHandle =
        OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (processHandle == nullptr) {
      AppendPamAuditEntry(journalPath, request, launchPlan, L"timed-guard-failed",
                          L"Fenrir could not monitor the timed elevation process: " +
                              FormatWindowsError(GetLastError()),
                          L"runtime-guard", L"guard-start-failed");
      return;
    }

    const auto waitResult = WaitForSingleObject(processHandle, timeoutSeconds * 1000);
    if (waitResult == WAIT_TIMEOUT) {
      if (TerminateProcess(processHandle, 0xF3) == FALSE) {
        AppendPamAuditEntry(journalPath, request, launchPlan, L"expired-termination-failed",
                            L"Fenrir timed elevation window expired after " + std::to_wstring(timeoutSeconds) +
                                L" seconds, but process termination failed: " +
                                FormatWindowsError(GetLastError()),
                            L"runtime-guard", L"termination-failed");
      } else {
        AppendPamAuditEntry(journalPath, request, launchPlan, L"expired",
                            L"Fenrir timed elevation window expired after " + std::to_wstring(timeoutSeconds) +
                                L" seconds and the process was terminated.",
                            L"runtime-guard", L"terminated");
      }
    } else if (waitResult == WAIT_OBJECT_0) {
      AppendPamAuditEntry(journalPath, request, launchPlan, L"completed",
                          L"Timed elevation process exited before the 2 minute cutoff.",
                          L"runtime-guard", L"completed");
    } else {
      AppendPamAuditEntry(journalPath, request, launchPlan, L"timed-guard-failed",
                          L"Fenrir timed elevation guard encountered a wait error: " +
                              FormatWindowsError(GetLastError()),
                          L"runtime-guard", L"wait-failed");
    }

    CloseHandle(processHandle);
  }).detach();
}

}  // namespace

AgentService::AgentService() = default;

AgentService::~AgentService() {
  if (pamRequestEvent_ != nullptr) {
    CloseHandle(pamRequestEvent_);
    pamRequestEvent_ = nullptr;
  }

  if (stopEvent_ != nullptr) {
    CloseHandle(stopEvent_);
    stopEvent_ = nullptr;
  }
}

int AgentService::Run(const AgentRunMode mode) {
  try {
    if (stopEvent_ == nullptr) {
      stopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
      if (stopEvent_ == nullptr) {
        throw std::runtime_error("Unable to create the agent stop event");
      }
    }
    if (pamRequestEvent_ == nullptr) {
      pamRequestEvent_ = CreateEventW(nullptr, FALSE, FALSE, kPamRequestEventName);
    }

    config_ = LoadAgentConfig();
    const auto runtimeValidation = ValidateRuntimePaths(config_);
    if (!runtimeValidation.trusted) {
      throw std::runtime_error("Runtime path boundary validation failed: " +
                               WideToUtf8(runtimeValidation.message.empty()
                                              ? L"Unknown runtime path boundary failure"
                                              : runtimeValidation.message));
    }

    EnsureRuntimeLayoutReady(config_, runtimeValidation);
    const auto installRoot = ResolveInstallRootForConfig(config_);
    if (mode == AgentRunMode::Service) {
      HardeningManager startupHardeningManager(config_, installRoot);
      const auto startupStatus = startupHardeningManager.QueryStatus(L"FenrirAgent");
      const auto hardeningReady = IsHardeningReady(startupStatus, config_);
      if (!hardeningReady) {
        std::wstring hardeningError;
        const auto hardeningApplied = startupHardeningManager.ApplyPostInstallHardening(
            ReadEnvironmentVariable(L"ANTIVIRUS_UNINSTALL_TOKEN"), &hardeningError);
        std::wstring serviceControlError;
        const auto serviceControlApplied =
            startupHardeningManager.ApplyServiceControlProtection(L"FenrirAgent", nullptr, &serviceControlError);
        const auto repairedStatus = startupHardeningManager.QueryStatus(L"FenrirAgent");
        if (!hardeningApplied || !serviceControlApplied || !IsHardeningReady(repairedStatus, config_)) {
          const auto reportedError = !hardeningError.empty()
                                         ? hardeningError
                                         : (!serviceControlError.empty() ? serviceControlError : repairedStatus.statusMessage);
          throw std::runtime_error(
              "Startup hardening repair is incomplete: " +
              WideToUtf8(reportedError.empty() ? L"Required hardening controls remain disabled." : reportedError));
        }
      }

      const auto runtimeTrust = ValidateRuntimeTrust(config_, installRoot);
      if (!runtimeTrust.trusted) {
        throw std::runtime_error(
            "Runtime trust validation failed: " +
            WideToUtf8(runtimeTrust.message.empty() ? L"Unknown runtime trust validation failure."
                                                    : runtimeTrust.message));
      }
    }

    stateStore_ = std::make_unique<LocalStateStore>(config_.runtimeDatabasePath, config_.stateFilePath);
    controlPlaneClient_ = std::make_unique<ControlPlaneClient>(config_.controlPlaneBaseUrl);
    commandJournalStore_ = std::make_unique<CommandJournalStore>(config_.runtimeDatabasePath);
    telemetryQueueStore_ = std::make_unique<TelemetryQueueStore>(config_.runtimeDatabasePath, config_.telemetryQueuePath);
    realtimeProtectionBroker_ = std::make_unique<RealtimeProtectionBroker>(config_);
    localControlChannel_ =
        std::make_unique<LocalControlChannel>([this](const RemoteCommand& command) { return ExecuteCommand(command); },
                                             [this]() { return ShouldStop(); });
    processEtwSensor_ = std::make_unique<ProcessEtwSensor>(config_);
    networkIsolationManager_ = std::make_unique<NetworkIsolationManager>(config_);

    LoadLocalPolicyCache();
    realtimeProtectionBroker_->SetPolicy(policy_);
    realtimeProtectionBroker_->SetDeviceId(state_.deviceId);
    processEtwSensor_->SetDeviceId(state_.deviceId);
    networkIsolationManager_->SetDeviceId(state_.deviceId);
    realtimeProtectionBroker_->Start();
    localControlChannel_->Start();
    processEtwSensor_->Start();
    networkIsolationManager_->Start();
    QueueEndpointStatusTelemetry();
    if (state_.isolated) {
      std::wstring isolationError;
      if (!networkIsolationManager_->ApplyIsolation(true, &isolationError)) {
        state_.isolated = false;
        QueueTelemetryEvent(L"network.isolation.resume.failed", L"network-wfp",
                            L"The endpoint could not restore WFP-backed isolation during startup.",
                            std::wstring(L"{\"errorMessage\":\"") +
                                Utf8ToWide(EscapeJsonString(isolationError.empty() ? L"Unknown startup isolation failure"
                                                                                  : isolationError)) +
                                L"\"}");
      }
    }
    StartTelemetrySpool();
    StartCommandLoop();
    QueueTelemetryEvent(L"service.started", L"agent-service", L"The endpoint agent boot sequence started.",
                        L"{\"phase\":\"bootstrap\"}");
    if (pamRequestEvent_ == nullptr) {
      QueueTelemetryEvent(L"privilege.elevation.event.unavailable", L"pam-broker",
                          L"The local PAM request signal could not be initialized; falling back to file polling.",
                          L"{\"eventName\":\"Global\\\\FenrirPamRequestReady\"}");
    }
    RunSyncLoop(mode);
    DrainProcessTelemetry();
    DrainRealtimeProtectionTelemetry();
    DrainNetworkTelemetry();
    localControlChannel_->Stop();
    networkIsolationManager_->Stop();
    processEtwSensor_->Stop();
    realtimeProtectionBroker_->Stop();
    PersistState();

    if (mode == AgentRunMode::Console) {
      std::wcout << L"Agent service skeleton is running." << std::endl;
      PrintStatus();
    }
    return 0;
  } catch (const std::exception& error) {
    std::wcerr << L"Agent service failed to initialize: " << Utf8ToWide(error.what()) << std::endl;
    return 1;
  }
}

void AgentService::RequestStop() {
  if (stopEvent_ != nullptr) {
    SetEvent(stopEvent_);
  }
}

std::wstring AgentService::BuildCyclePayload(const int cycle, const std::wstring& extraFields) {
  std::wstring payload = L"{\"cycle\":";
  payload += std::to_wstring(cycle);
  if (!extraFields.empty()) {
    payload += L",";
    payload += extraFields;
  }
  payload += L"}";
  return payload;
}

std::vector<std::filesystem::path> AgentService::BuildMonitoredRoots() const {
  std::vector<std::filesystem::path> roots;

  const auto userProfile = ReadEnvironmentVariable(L"USERPROFILE");
  if (!userProfile.empty()) {
    roots.emplace_back(std::filesystem::path(userProfile) / L"Downloads");
    roots.emplace_back(std::filesystem::path(userProfile) / L"Desktop");
  }

  roots.emplace_back(LR"(C:\Users\Public\Downloads)");
  return roots;
}

std::filesystem::path AgentService::GetPamRequestPath() const {
  auto runtimeRoot = config_.runtimeDatabasePath.parent_path();
  if (runtimeRoot.empty()) {
    runtimeRoot = config_.runtimeDatabasePath;
  }
  return runtimeRoot / kPamRequestFileName;
}

std::vector<std::filesystem::path> AgentService::GetPamRequestPaths() const {
  std::vector<std::filesystem::path> requestPaths;
  std::set<std::filesystem::path> seenPaths;

  const auto addRequestPath = [&requestPaths, &seenPaths](const std::filesystem::path& path) {
    if (path.empty()) {
      return;
    }
    if (seenPaths.insert(path).second) {
      requestPaths.push_back(path);
    }
  };

  addRequestPath(GetPamRequestPath());

  if (const auto activeUserRequestPath = ResolveActiveUserPamRequestPath();
      activeUserRequestPath.has_value() && !activeUserRequestPath->empty()) {
    addRequestPath(*activeUserRequestPath);
  }

  for (const auto& profileRequestPath : ResolvePamRequestPathsFromUserProfiles()) {
    addRequestPath(profileRequestPath);
  }

  return requestPaths;
}

std::filesystem::path AgentService::GetPamAuditJournalPath() const {
  auto journalRoot = config_.journalRootPath;
  if (journalRoot.empty()) {
    journalRoot = ResolveRuntimeRoot(config_);
  }
  return journalRoot / kPamAuditFileName;
}

void AgentService::ProcessPamRequests() {
  const auto journalPath = GetPamAuditJournalPath();
  PamPolicySnapshot pamPolicy{};
  std::wstring pamPolicyError;
  const auto pamPolicyLoaded = TryLoadPamPolicy(config_, &pamPolicy, &pamPolicyError);
  if (!pamPolicyLoaded) {
    QueueTelemetryEvent(
        L"privilege.elevation.policy.load.failed", L"pam-broker",
        L"Fenrir could not load PAM policy cleanly and is fail-closing elevation approvals.",
        std::wstring(L"{\"reason\":\"") + Utf8ToWide(EscapeJsonString(
            pamPolicyError.empty() ? L"Unknown PAM policy parsing failure" : pamPolicyError)) + L"\"}");
  }

  while (!ShouldStop()) {
    bool processedAnyRequests = false;

    for (const auto& requestPath : GetPamRequestPaths()) {
      std::error_code existsError;
      if (!std::filesystem::exists(requestPath, existsError) || existsError) {
        continue;
      }
      processedAnyRequests = true;

      std::wstring payload;
      std::wstring readError;
      if (!TryReadPamRequestPayload(requestPath, &payload, &readError)) {
        // The writer may still be finalizing the payload; keep the file for the next poll.
        continue;
      }

      PamRequestPayload request{};
      std::wstring parseError;
      if (!ParsePamRequestPayload(payload, &request, &parseError)) {
        PamLaunchPlan rejectedLaunch{
            .targetPath = request.targetPath.empty() ? L"<invalid-payload>" : request.targetPath};
        AppendPamAuditEntry(journalPath, request, rejectedLaunch, L"denied", parseError,
                  L"payload-validation", L"not-launched");
        QueueTelemetryEvent(
            L"privilege.elevation.request.rejected", L"pam-broker",
            L"Fenrir rejected a malformed local PAM request payload.",
            std::wstring(L"{\"reason\":\"") + Utf8ToWide(EscapeJsonString(parseError)) + L"\"}");
        std::error_code removeError;
        std::filesystem::remove(requestPath, removeError);
        continue;
      }

      PamLaunchPlan launchPlan{};
      std::wstring validationError;
      if (!BuildPamLaunchPlan(request, &launchPlan, &validationError)) {
        AppendPamAuditEntry(journalPath, request, launchPlan, L"denied", validationError,
                            L"action-validation", L"not-launched");
        QueueTelemetryEvent(
            L"privilege.elevation.request.denied", L"pam-broker",
            L"Fenrir denied a local PAM request during policy validation.",
            std::wstring(L"{\"requester\":\"") + Utf8ToWide(EscapeJsonString(request.requester)) +
                L"\",\"reason\":\"" + Utf8ToWide(EscapeJsonString(validationError)) + L"\"}");
        std::error_code removeError;
        std::filesystem::remove(requestPath, removeError);
        continue;
      }

      std::wstring policyError;
      if (!EvaluatePamRequestPolicy(pamPolicy, request, &launchPlan, &policyError)) {
        AppendPamAuditEntry(journalPath, request, launchPlan, L"denied", policyError,
                            L"policy", L"not-launched");
        QueueTelemetryEvent(
            L"privilege.elevation.request.denied", L"pam-broker",
            L"Fenrir denied a local PAM request due to PAM policy controls.",
            std::wstring(L"{\"requester\":\"") + Utf8ToWide(EscapeJsonString(request.requester)) +
                L"\",\"reason\":\"" + Utf8ToWide(EscapeJsonString(policyError)) +
                L"\",\"action\":\"" + Utf8ToWide(EscapeJsonString(request.action)) + L"\"}");
        std::error_code removeError;
        std::filesystem::remove(requestPath, removeError);
        continue;
      }

      std::wstring launchError;
      DWORD launchedProcessId = 0;
      const auto launched = LaunchPamProcessAsSystem(launchPlan, &launchedProcessId, &launchError);
      const auto decision = launched ? L"approved" : L"denied";
      const auto detail = launched ? (L"Launched process id " + std::to_wstring(launchedProcessId)) : launchError;
      AppendPamAuditEntry(journalPath, request, launchPlan, decision, detail,
                          launched ? L"policy-auto" : L"launch", launched ? L"pending" : L"not-launched");

      if (launched) {
        StartPamTimedProcessGuard(journalPath, request, launchPlan, launchedProcessId);
        QueueTelemetryEvent(
            L"privilege.elevation.request.approved", L"pam-broker",
            L"Fenrir approved and launched a local PAM elevation request.",
            std::wstring(L"{\"requester\":\"") + Utf8ToWide(EscapeJsonString(request.requester)) +
                L"\",\"targetPath\":\"" + Utf8ToWide(EscapeJsonString(launchPlan.targetPath)) +
                L"\",\"processId\":" + std::to_wstring(launchedProcessId) +
                L",\"timed\":"
                + (launchPlan.maxRuntimeSeconds.has_value() ? L"true" : L"false") + L"}");
      } else {
        QueueTelemetryEvent(
            L"privilege.elevation.request.denied", L"pam-broker",
            L"Fenrir denied a local PAM request because process launch failed.",
            std::wstring(L"{\"requester\":\"") + Utf8ToWide(EscapeJsonString(request.requester)) +
                L"\",\"targetPath\":\"" + Utf8ToWide(EscapeJsonString(launchPlan.targetPath)) +
                L"\",\"reason\":\"" + Utf8ToWide(EscapeJsonString(launchError)) + L"\"}");
      }

      std::error_code removeError;
      std::filesystem::remove(requestPath, removeError);
    }

    if (!processedAnyRequests) {
      return;
    }
  }
}

void AgentService::RunSyncLoop(const AgentRunMode mode) {
  const auto configuredIterations = std::max(config_.syncIterations, 1);
  int cycle = 1;

  while (!ShouldStop()) {
    ProcessPamRequests();
    QueueCycleTelemetry(cycle);
    QueueDeviceInventoryTelemetry(cycle);
    EnforceBlockedSoftware();
    ProcessPamRequests();
    DrainProcessTelemetry();
    DrainRealtimeProtectionTelemetry();
    DrainNetworkTelemetry();
    SyncWithControlPlane(cycle);
    ProcessPamRequests();
    DrainProcessTelemetry();
    DrainRealtimeProtectionTelemetry();
    DrainNetworkTelemetry();
    PollAndExecuteCommands(cycle);
    ProcessPamRequests();
    DrainProcessTelemetry();
    DrainRealtimeProtectionTelemetry();
    DrainNetworkTelemetry();
    FlushTelemetryQueue();
    PublishHeartbeat(cycle);
    DrainProcessTelemetry();
    DrainRealtimeProtectionTelemetry();
    DrainNetworkTelemetry();
    FlushTelemetryQueue();
    PersistState();

    const auto finishedConsoleRun = mode == AgentRunMode::Console && cycle >= configuredIterations;
    if (finishedConsoleRun) {
      break;
    }

    ++cycle;
    if (!WaitForNextCycle(mode, cycle)) {
      break;
    }
  }
}

bool AgentService::WaitForNextCycle(const AgentRunMode mode, const int nextCycle) {
  if (ShouldStop()) {
    return false;
  }

  if (mode == AgentRunMode::Console) {
    std::wcout << L"Sleeping " << config_.syncIntervalSeconds << L" seconds before sync cycle " << nextCycle
               << std::endl;
  }

  const auto waitMilliseconds = static_cast<DWORD>(std::max(config_.syncIntervalSeconds, 1) * 1000);
  const auto waitDeadline = GetTickCount64() + waitMilliseconds;

  while (!ShouldStop()) {
    const auto now = GetTickCount64();
    if (now >= waitDeadline) {
      ProcessPamRequests();
      return !ShouldStop();
    }

    const auto remaining = static_cast<DWORD>(waitDeadline - now);
    const auto waitChunk = std::min<DWORD>(remaining, 1000);

    if (pamRequestEvent_ != nullptr) {
      HANDLE waitHandles[] = {stopEvent_, pamRequestEvent_};
      const auto waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, waitChunk);
      if (waitResult == WAIT_OBJECT_0) {
        return false;
      }
      if (waitResult == WAIT_OBJECT_0 + 1) {
        ProcessPamRequests();
        continue;
      }
      if (waitResult == WAIT_FAILED) {
        return !ShouldStop();
      }
    } else {
      if (WaitForSingleObject(stopEvent_, waitChunk) == WAIT_OBJECT_0) {
        return false;
      }
    }

    ProcessPamRequests();
  }

  return false;
}

bool AgentService::ShouldStop() const {
  return stopEvent_ != nullptr && WaitForSingleObject(stopEvent_, 0) == WAIT_OBJECT_0;
}

void AgentService::SyncWithControlPlane(const int cycle) {
  bool attemptedRecovery = false;

  for (;;) {
    try {
      EnsureEnrollment();
      RefreshPolicy(cycle);
      lastControlPlaneSyncFailed_ = false;
      return;
    } catch (const std::exception& error) {
      if (!attemptedRecovery && RecoverDeviceIdentity(error, L"control-plane sync")) {
        attemptedRecovery = true;
        continue;
      }

      lastControlPlaneSyncFailed_ = true;
      QueueTelemetryEvent(L"control-plane.sync.failed", L"control-plane-client",
                          L"The agent could not complete a control-plane sync and is using cached state.",
                          BuildCyclePayload(cycle));
      std::wcerr << L"Control-plane sync failed, continuing with cached state: " << Utf8ToWide(error.what())
                 << std::endl;
      return;
    }
  }
}

void AgentService::EnsureEnrollment() {
  if (!state_.deviceId.empty()) {
    return;
  }

  const auto enrollment = controlPlaneClient_->Enroll(state_);
  state_.deviceId = enrollment.deviceId;
  state_.commandChannelUrl = enrollment.commandChannelUrl;
  state_.lastEnrollmentAt = enrollment.issuedAt;
  state_.policy = enrollment.policy;
  policy_ = enrollment.policy;
  realtimeProtectionBroker_->SetDeviceId(state_.deviceId);
  realtimeProtectionBroker_->SetPolicy(policy_);
  processEtwSensor_->SetDeviceId(state_.deviceId);
  networkIsolationManager_->SetDeviceId(state_.deviceId);
  QueueTelemetryEvent(L"device.enrolled", L"control-plane-client",
                      L"The endpoint enrolled with the control plane.",
                      std::wstring(L"{\"deviceId\":\"") + state_.deviceId + L"\"}");
}

void AgentService::ResetEnrollmentState() {
  state_.deviceId.clear();
  state_.commandChannelUrl.clear();
  state_.lastEnrollmentAt.clear();
  state_.lastHeartbeatAt.clear();
  state_.lastPolicySyncAt.clear();
  realtimeProtectionBroker_->SetDeviceId(L"");
  processEtwSensor_->SetDeviceId(L"");
  networkIsolationManager_->SetDeviceId(L"");
}

bool AgentService::RecoverDeviceIdentity(const std::exception& error, const std::wstring& operationName) {
  const auto* rejectedError = dynamic_cast<const DeviceIdentityRejectedError*>(&error);
  if (rejectedError == nullptr) {
    return false;
  }

  const auto previousDeviceId = state_.deviceId;
  QueueTelemetryEvent(L"device.identity.rejected", L"control-plane-client",
                      L"The control plane rejected the cached device identity and the agent is re-enrolling.",
                      std::wstring(L"{\"previousDeviceId\":\"") + previousDeviceId + L"\",\"operation\":\"" +
                          Utf8ToWide(EscapeJsonString(operationName)) + L"\"}");

  std::wcerr << L"Cached device identity was rejected during " << operationName
             << L"; clearing the cached registration and re-enrolling." << std::endl;

  ResetEnrollmentState();

  try {
    EnsureEnrollment();
    PersistState();
    std::wcout << L"Recovered control-plane identity. New device ID: " << state_.deviceId << std::endl;
    return true;
  } catch (const std::exception& recoveryError) {
    std::wcerr << L"Re-enrollment after identity rejection failed: " << Utf8ToWide(recoveryError.what()) << std::endl;
    return false;
  }
}

void AgentService::RefreshPolicy(const int cycle) {
  if (state_.deviceId.empty()) {
    return;
  }

  const auto policyCheckIn = controlPlaneClient_->CheckInPolicy(state_);
  state_.lastPolicySyncAt = policyCheckIn.retrievedAt;
  state_.policy = policyCheckIn.policy;
  policy_ = policyCheckIn.policy;
  realtimeProtectionBroker_->SetPolicy(policy_);
  QueueTelemetryEvent(L"policy.checked-in", L"control-plane-client",
                      policyCheckIn.changed ? L"The endpoint retrieved a newer effective policy."
                                            : L"The endpoint confirmed that policy is already current.",
                      BuildCyclePayload(cycle, std::wstring(L"\"revision\":\"") + policy_.revision + L"\""));
}

void AgentService::PollAndExecuteCommands(const int cycle) {
  if (state_.deviceId.empty()) {
    return;
  }

  bool attemptedRecovery = false;

  for (;;) {
    try {
      const auto pollResult = controlPlaneClient_->PollPendingCommands(state_);
      if (pollResult.items.empty()) {
        return;
      }

      QueueTelemetryEvent(L"commands.polled", L"command-executor",
                          L"The endpoint pulled pending response actions from the control plane.",
                          BuildCyclePayload(cycle, std::wstring(L"\"count\":") + std::to_wstring(pollResult.items.size())));

      for (const auto& command : pollResult.items) {
        if (commandJournalStore_) {
          commandJournalStore_->RecordPolled(command);
        }
        try {
          const auto resultJson = ExecuteCommand(command);
          controlPlaneClient_->CompleteCommand(state_, command.commandId, L"completed", resultJson);
          if (commandJournalStore_) {
            commandJournalStore_->RecordCompleted(command, resultJson);
          }
          QueueTelemetryEvent(L"command.completed", L"command-executor",
                              std::wstring(L"Completed remote command ") + command.type + L".",
                              std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"type\":\"" + command.type +
                                  L"\"}");
        } catch (const std::exception& error) {
          const auto errorMessage = Utf8ToWide(error.what());
          const auto failureJson = std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"error\":\"" +
                                   Utf8ToWide(EscapeJsonString(errorMessage)) + L"\"}";

          try {
            controlPlaneClient_->CompleteCommand(state_, command.commandId, L"failed", failureJson);
          } catch (const std::exception& completionError) {
            std::wcerr << L"Completing failed command state also failed: " << Utf8ToWide(completionError.what())
                       << std::endl;
          }

          if (commandJournalStore_) {
            commandJournalStore_->RecordFailed(command, failureJson, errorMessage);
          }

          QueueTelemetryEvent(L"command.failed", L"command-executor",
                              std::wstring(L"Remote command failed: ") + command.type + L".", failureJson);
        }
      }

      return;
    } catch (const std::exception& error) {
      if (!attemptedRecovery && RecoverDeviceIdentity(error, L"command polling")) {
        attemptedRecovery = true;
        continue;
      }

      QueueTelemetryEvent(L"command.poll.failed", L"command-executor",
                          L"The endpoint could not retrieve pending commands from the control plane.",
                          BuildCyclePayload(cycle));
      std::wcerr << L"Command polling failed: " << Utf8ToWide(error.what()) << std::endl;
      return;
    }
  }
}

std::wstring AgentService::ExecuteCommand(const RemoteCommand& command) {
  if (command.type == L"device.isolate") {
    return ExecuteIsolationCommand(command, true);
  }

  if (command.type == L"device.release") {
    return ExecuteIsolationCommand(command, false);
  }

  if (command.type == L"scan.targeted") {
    return ExecuteTargetedScan(command);
  }

  if (command.type == L"quarantine.restore") {
    return ExecuteQuarantineMutation(command, true);
  }

  if (command.type == L"quarantine.delete") {
    return ExecuteQuarantineMutation(command, false);
  }

  if (command.type == L"update.apply") {
    return ExecuteUpdateCommand(command, false);
  }

  if (command.type == L"update.rollback") {
    return ExecuteUpdateCommand(command, true);
  }

  if (command.type == L"agent.repair") {
    return ExecuteRepairCommand(command);
  }

  if (command.type == L"process.terminate") {
    return ExecuteProcessTerminationCommand(command, false);
  }

  if (command.type == L"process.tree.terminate") {
    return ExecuteProcessTerminationCommand(command, true);
  }

  if (command.type == L"persistence.cleanup") {
    return ExecutePersistenceCleanupCommand(command);
  }

  if (command.type == L"remediate.path") {
    return ExecutePathRemediationCommand(command);
  }

  if (command.type == L"script.run") {
    return ExecuteScriptCommand(command);
  }

  if (command.type == L"software.uninstall") {
    return ExecuteSoftwareCommand(command, true, false);
  }

  if (command.type == L"software.update") {
    return ExecuteSoftwareCommand(command, false, false);
  }

  if (command.type == L"software.update.search") {
    return ExecuteSoftwareCommand(command, false, true);
  }

  if (command.type == L"patch.scan") {
    return ExecutePatchCommand(command, false, false, false);
  }

  if (command.type == L"patch.windows.install") {
    return ExecutePatchCommand(command, true, false, false);
  }

  if (command.type == L"patch.software.install") {
    return ExecutePatchCommand(command, false, true, false);
  }

  if (command.type == L"patch.cycle.run") {
    return ExecutePatchCommand(command, true, true, true);
  }

  if (command.type == L"support.bundle.export") {
    return ExecuteSupportBundleCommand(command, true);
  }

  if (command.type == L"support.bundle.export.full") {
    return ExecuteSupportBundleCommand(command, false);
  }

  if (command.type == L"storage.maintenance.run") {
    return ExecuteStorageMaintenanceCommand(command);
  }

  if (command.type == L"local.breakglass.enable") {
    return ExecuteBreakGlassCommand(command, true);
  }

  if (command.type == L"local.breakglass.disable") {
    return ExecuteBreakGlassCommand(command, false);
  }

  if (command.type == L"local.approval.execute") {
    return ExecuteLocalApprovalCommand(command);
  }

  if (command.type == L"local.approval.list") {
    return ExecuteLocalApprovalListCommand(command);
  }

  if (command.type == L"local.admin.audit") {
    return ExecuteLocalAdminAuditCommand(command);
  }

  if (command.type == L"local.admin.reduction.plan") {
    return ExecuteLocalAdminReductionCommand(command, false);
  }

  if (command.type == L"local.admin.reduction.apply") {
    return ExecuteLocalAdminReductionCommand(command, true);
  }

  if (command.type == L"local.admin.reduction.rollback") {
    return ExecuteLocalAdminRollbackCommand(command);
  }

  if (command.type == L"software.block") {
    return ExecuteSoftwareBlockCommand(command);
  }

  throw std::runtime_error("Unsupported remote command type");
}

std::wstring AgentService::ExecuteTargetedScan(const RemoteCommand& command) {
  if (command.targetPath.empty()) {
    throw std::runtime_error("scan.targeted command is missing targetPath");
  }

  const std::filesystem::path targetPath(command.targetPath);
  std::error_code error;
  if (!std::filesystem::exists(targetPath, error)) {
    throw std::runtime_error("Targeted scan path does not exist");
  }

  if (const auto gate = EvaluateHeavyOperationGate(config_, L"targeted scan"); gate.has_value()) {
    throw std::runtime_error(WideToUtf8(*gate));
  }

  auto findings = ScanTargets({targetPath}, policy_, ScanProgressCallback{}, config_.scanExcludedPaths);
  QuarantineStore quarantineStore(config_.quarantineRootPath, config_.runtimeDatabasePath);
  EvidenceRecorder evidenceRecorder(config_.evidenceRootPath, config_.runtimeDatabasePath);

  for (auto& finding : findings) {
    if (finding.verdict.disposition != VerdictDisposition::Allow) {
      const auto quarantineResult = quarantineStore.QuarantineFile(finding);
      if (quarantineResult.success) {
        finding.remediationStatus = RemediationStatus::Quarantined;
        finding.quarantineRecordId = quarantineResult.recordId;
        finding.quarantinedPath = quarantineResult.quarantinedPath;
        finding.verdict.reasons.push_back(
            {L"QUARANTINE_APPLIED", L"Fenrir moved this artifact into local quarantine."});
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
            quarantineResult.errorMessage.empty() ? L"Unable to move the file into quarantine" : quarantineResult.errorMessage;
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

    const auto evidenceResult = evidenceRecorder.RecordScanFinding(finding, policy_, L"agent-service");
    finding.evidenceRecordId = evidenceResult.recordId;
  }

  QueueTelemetryEvent(BuildScanSummaryTelemetry(1, findings.size(), policy_, L"agent-service").eventType,
                      L"agent-service", BuildScanSummaryTelemetry(1, findings.size(), policy_, L"agent-service").summary,
                      BuildScanSummaryTelemetry(1, findings.size(), policy_, L"agent-service").payloadJson);
  for (const auto& finding : findings) {
    const auto record = BuildScanFindingTelemetry(finding, L"agent-service");
    QueueTelemetryEvent(record.eventType, record.source, record.summary, record.payloadJson);
  }

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"targetPath\":\"" +
         Utf8ToWide(EscapeJsonString(command.targetPath)) + L"\",\"findingCount\":" + std::to_wstring(findings.size()) +
         L"}";
}

std::wstring AgentService::ExecuteIsolationCommand(const RemoteCommand& command, const bool isolate) {
  if (!networkIsolationManager_) {
    throw std::runtime_error("The WFP isolation manager is not available");
  }

  std::wstring errorMessage;
  if (!networkIsolationManager_->ApplyIsolation(isolate, &errorMessage)) {
    throw std::runtime_error(WideToUtf8(errorMessage.empty() ? L"The WFP isolation manager rejected the requested state"
                                                            : errorMessage));
  }

  state_.isolated = networkIsolationManager_->IsolationActive();

  const auto eventType = isolate ? L"device.isolated" : L"device.released";
  const auto summary = isolate ? L"The endpoint entered WFP-backed host isolation after a remote action."
                               : L"The endpoint left WFP-backed host isolation after a remote action.";
  QueueTelemetryEvent(eventType, L"command-executor", summary,
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"wfpApplied\":true}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"isolated\":" +
         (state_.isolated ? L"true" : L"false") + L",\"wfpApplied\":true}";
}

std::wstring AgentService::ExecuteQuarantineMutation(const RemoteCommand& command, const bool restore) {
  if (command.recordId.empty()) {
    throw std::runtime_error("Quarantine command is missing recordId");
  }

  QuarantineStore quarantineStore(config_.quarantineRootPath, config_.runtimeDatabasePath);
  const auto result = restore ? quarantineStore.RestoreFile(command.recordId) : quarantineStore.DeleteRecord(command.recordId);

  if (!result.success) {
    throw std::runtime_error(WideToUtf8(result.errorMessage.empty() ? L"Quarantine operation failed" : result.errorMessage));
  }

  const auto eventType = restore ? L"quarantine.restored" : L"quarantine.deleted";
  const auto summary = restore ? L"A quarantined item was restored after a remote action."
                               : L"A quarantined item was deleted after a remote action.";
  QueueTelemetryEvent(eventType, L"command-executor", summary,
                      std::wstring(L"{\"recordId\":\"") + result.recordId + L"\",\"originalPath\":\"" +
                          Utf8ToWide(EscapeJsonString(result.originalPath.wstring())) + L"\",\"quarantinedPath\":\"" +
                          Utf8ToWide(EscapeJsonString(result.quarantinedPath.wstring())) + L"\"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"recordId\":\"" + result.recordId +
         L"\",\"action\":\"" + (restore ? std::wstring(L"restore") : std::wstring(L"delete")) + L"\"}";
}

std::wstring AgentService::ExecuteUpdateCommand(const RemoteCommand& command, const bool rollback) {
  if (const auto gate = EvaluateHeavyOperationGate(config_, rollback ? L"update rollback" : L"update apply");
      gate.has_value()) {
    throw std::runtime_error(WideToUtf8(*gate));
  }

  const auto installRoot = ResolveInstallRootForConfig(config_);
  UpdaterService updater(config_, installRoot);
  const auto result =
      rollback ? updater.RollbackTransaction(command.recordId)
               : updater.ApplyPackage(command.targetPath, UpdateApplyMode::InService);

  if (!result.success) {
    throw std::runtime_error(WideToUtf8(result.errorMessage.empty() ? L"Update operation failed" : result.errorMessage));
  }

  const auto eventType = rollback ? L"update.rolled_back" : L"update.applied";
  const auto summary = rollback ? L"The endpoint rolled back a staged platform update."
                                : L"The endpoint applied a staged platform or engine update.";
  QueueTelemetryEvent(eventType, L"command-executor", summary,
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"transactionId\":\"" +
                          result.transactionId + L"\",\"packageId\":\"" + result.packageId + L"\",\"status\":\"" +
                          result.status + L"\",\"restartRequired\":" +
                          (result.restartRequired ? std::wstring(L"true") : std::wstring(L"false")) + L"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"transactionId\":\"" + result.transactionId +
         L"\",\"packageId\":\"" + result.packageId + L"\",\"status\":\"" + result.status + L"\",\"restartRequired\":" +
         (result.restartRequired ? std::wstring(L"true") : std::wstring(L"false")) + L"}";
}

std::wstring AgentService::ExecutePatchCommand(const RemoteCommand& command, const bool installWindows,
                                               const bool installSoftware, const bool runCycle) {
  const auto routeThroughPam = installWindows && ExtractPayloadBool(command.payloadJson, "routeThroughPam").value_or(false);
  if (routeThroughPam) {
    PamRequestPayload pamRequest{};
    pamRequest.requestedAt = CurrentUtcTimestamp();
    pamRequest.requester = command.issuedBy.empty() ? L"remote-control-plane" : command.issuedBy;
    pamRequest.action = L"run_windows_update";
    pamRequest.targetPath = GetSystemBinaryPath(L"control.exe");
    pamRequest.arguments.clear();
    pamRequest.reason = TrimWhitespace(ExtractPayloadString(command.payloadJson, "reason").value_or(L""));
    if (pamRequest.reason.empty()) {
      pamRequest.reason = L"Remote patch.windows.install command routed through PAM policy controls.";
    }

    if (pamRequest.targetPath.empty()) {
      throw std::runtime_error("Unable to resolve Windows Update control path for PAM routing");
    }

    std::wstring queueError;
    if (!QueuePamRequestPayload(GetPamRequestPath(), pamRequest, &queueError)) {
      throw std::runtime_error(
          WideToUtf8(queueError.empty() ? L"Unable to stage PAM request for patch.windows.install" : queueError));
    }

    if (pamRequestEvent_ != nullptr) {
      SetEvent(pamRequestEvent_);
    }

    QueueTelemetryEvent(
        L"patch.windows.install.pam.routed", L"patch-orchestrator",
        L"Fenrir routed a Windows patch install command through PAM policy controls.",
        std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"action\":\"run_windows_update\",\"requester\":\"" +
            Utf8ToWide(EscapeJsonString(pamRequest.requester)) + L"\",\"reason\":\"" +
            Utf8ToWide(EscapeJsonString(pamRequest.reason)) + L"\",\"queued\":true}");

    return std::wstring(L"{\"commandId\":\"") + command.commandId +
           L"\",\"action\":\"run_windows_update\",\"status\":\"queued_for_pam\",\"queued\":true}";
  }

  if ((installWindows || installSoftware || runCycle)) {
    if (const auto gate = EvaluateHeavyOperationGate(config_, L"patch orchestration action"); gate.has_value()) {
      throw std::runtime_error(WideToUtf8(*gate));
    }
  }

  PatchOrchestrator orchestrator(config_);
  PatchExecutionResult result{};

  if (runCycle) {
    result = orchestrator.RunPatchCycle();
  } else if (installWindows) {
    const auto securityOnly = ExtractPayloadUInt32(command.payloadJson, "securityOnly").value_or(1) != 0;
    result = orchestrator.InstallWindowsUpdates(securityOnly);
  } else if (installSoftware) {
    const auto softwareId = ExtractPayloadString(command.payloadJson, "softwareId").value_or(L"");
    if (softwareId.empty()) {
      throw std::runtime_error("patch.software.install command is missing softwareId");
    }
    result = orchestrator.UpdateSoftware(softwareId, false);
  } else {
    const auto summary = orchestrator.RefreshPatchState();
    QueueTelemetryEvent(L"patch.scan.completed", L"patch-orchestrator",
                        L"Fenrir refreshed Windows and third-party patch inventory.",
                        std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"windowsUpdateCount\":" +
                            std::to_wstring(summary.windowsUpdateCount) + L",\"softwareCount\":" +
                            std::to_wstring(summary.softwareCount) + L",\"recipeCount\":" +
                            std::to_wstring(summary.recipeCount) + L",\"rebootPending\":" +
                            (summary.rebootPending ? std::wstring(L"true") : std::wstring(L"false")) + L"}");
    return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"windowsUpdateCount\":" +
           std::to_wstring(summary.windowsUpdateCount) + L",\"softwareCount\":" +
           std::to_wstring(summary.softwareCount) + L",\"recipeCount\":" + std::to_wstring(summary.recipeCount) +
           L",\"rebootPending\":" + (summary.rebootPending ? std::wstring(L"true") : std::wstring(L"false")) + L"}";
  }

  const auto eventType = runCycle ? L"patch.cycle.completed"
                                  : (installWindows ? L"patch.windows.install.completed" : L"patch.software.install.completed");
  const auto summary = result.success ? L"Fenrir completed a patch orchestration action."
                                      : L"Fenrir attempted a patch orchestration action but it did not fully succeed.";
  QueueTelemetryEvent(result.success ? eventType : eventType + std::wstring(L".failed"), L"patch-orchestrator", summary,
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"action\":\"" + result.action +
                          L"\",\"targetId\":\"" + result.targetId + L"\",\"provider\":\"" + result.provider +
                          L"\",\"status\":\"" + result.status + L"\",\"rebootRequired\":" +
                          (result.rebootRequired ? std::wstring(L"true") : std::wstring(L"false")) +
                          L",\"errorCode\":\"" + result.errorCode + L"\",\"detailJson\":" + result.detailJson + L"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"action\":\"" + result.action +
         L"\",\"targetId\":\"" + result.targetId + L"\",\"provider\":\"" + result.provider + L"\",\"status\":\"" +
         result.status + L"\",\"rebootRequired\":" +
         (result.rebootRequired ? std::wstring(L"true") : std::wstring(L"false")) + L",\"errorCode\":\"" +
         result.errorCode + L"\",\"detailJson\":" + result.detailJson + L"}";
}

std::wstring AgentService::ExecuteSupportBundleCommand(const RemoteCommand& command, const bool sanitized) {
  if (!sanitized) {
    if (const auto gate = EvaluateHeavyOperationGate(config_, L"full support bundle export"); gate.has_value()) {
      throw std::runtime_error(WideToUtf8(*gate));
    }
  }

  const auto result = ExportSupportBundle(config_, state_, policy_, sanitized);
  if (!result.success) {
    throw std::runtime_error(WideToUtf8(result.errorMessage.empty() ? L"Support bundle export failed" : result.errorMessage));
  }

  QueueTelemetryEvent(L"support.bundle.exported", L"support-bundle",
                      sanitized ? L"Fenrir exported a sanitized local support bundle."
                                : L"Fenrir exported a full local support bundle.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"sanitized\":" +
                          (sanitized ? std::wstring(L"true") : std::wstring(L"false")) + L",\"bundleRoot\":\"" +
                          Utf8ToWide(EscapeJsonString(result.bundleRoot.wstring())) + L"\",\"manifestPath\":\"" +
                          Utf8ToWide(EscapeJsonString(result.manifestPath.wstring())) + L"\",\"copiedFileCount\":" +
                          std::to_wstring(result.copiedFileCount) + L"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"sanitized\":" +
         (sanitized ? std::wstring(L"true") : std::wstring(L"false")) + L",\"bundleRoot\":\"" +
         Utf8ToWide(EscapeJsonString(result.bundleRoot.wstring())) + L"\",\"manifestPath\":\"" +
         Utf8ToWide(EscapeJsonString(result.manifestPath.wstring())) + L"\",\"copiedFileCount\":" +
         std::to_wstring(result.copiedFileCount) + L"}";
}

std::wstring AgentService::ExecuteStorageMaintenanceCommand(const RemoteCommand& command) {
  const auto result = RunStorageMaintenance(config_);
  if (!result.success) {
    throw std::runtime_error(WideToUtf8(result.errorMessage.empty() ? L"Storage maintenance failed" : result.errorMessage));
  }

  QueueTelemetryEvent(L"storage.maintenance.completed", L"support-bundle", result.summary,
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"deletedEntries\":" +
                          std::to_wstring(result.deletedEntries) + L",\"reclaimedBytes\":" +
                          std::to_wstring(result.reclaimedBytes) + L"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"deletedEntries\":" +
         std::to_wstring(result.deletedEntries) + L",\"reclaimedBytes\":" +
         std::to_wstring(result.reclaimedBytes) + L",\"summary\":\"" +
         Utf8ToWide(EscapeJsonString(result.summary)) + L"\"}";
}

std::wstring AgentService::ExecuteBreakGlassCommand(const RemoteCommand& command, const bool enable) {
  const auto reason = TrimWhitespace(ExtractPayloadString(command.payloadJson, "reason").value_or(L""));

  std::wstring persistError;
  if (!SetBreakGlassModeEnabled(enable, &persistError)) {
    throw std::runtime_error(WideToUtf8(persistError.empty()
                                            ? L"Fenrir could not persist break-glass mode state."
                                            : persistError));
  }

  const auto queuePamRecovery = enable && ExtractPayloadBool(command.payloadJson, "queuePamRecovery").value_or(true);
  bool pamRecoveryQueued = false;
  std::wstring pamQueueError;
  if (queuePamRecovery) {
    PamRequestPayload pamRequest{};
    pamRequest.requestedAt = CurrentUtcTimestamp();
    pamRequest.requester = command.issuedBy.empty() ? L"local-breakglass" : command.issuedBy;
    pamRequest.action = L"launch_application";
    const auto defaultRecoveryTarget = GetSystemBinaryPath(L"cmd.exe");
    pamRequest.targetPath =
        TrimWhitespace(ExtractPayloadString(command.payloadJson, "recoveryTargetPath").value_or(defaultRecoveryTarget));
    pamRequest.arguments = ExtractPayloadString(command.payloadJson, "recoveryArguments").value_or(L"");
    pamRequest.reason = reason.empty() ? L"Break-glass recovery session requested from local control channel." : reason;

    if (pamRequest.targetPath.empty()) {
      pamQueueError = L"Fenrir could not resolve a safe recovery target path for break-glass mode.";
    } else {
      pamRecoveryQueued = QueuePamRequestPayload(GetPamRequestPath(), pamRequest, &pamQueueError);
      if (pamRecoveryQueued && pamRequestEvent_ != nullptr) {
        SetEvent(pamRequestEvent_);
      }
    }
  }

  const auto breakGlassEnabled = QueryBreakGlassModeEnabled();
  const auto eventType = enable ? L"local.breakglass.enabled" : L"local.breakglass.disabled";
  QueueTelemetryEvent(eventType, L"local-control",
                      enable ? L"Fenrir enabled break-glass administrator mode for emergency local recovery."
                             : L"Fenrir disabled break-glass administrator mode and restored normal owner controls.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"breakGlassEnabled\":" +
                          (breakGlassEnabled ? std::wstring(L"true") : std::wstring(L"false")) +
                          L",\"pamRecoveryQueued\":" +
                          (pamRecoveryQueued ? std::wstring(L"true") : std::wstring(L"false")) +
                          L",\"reason\":\"" + Utf8ToWide(EscapeJsonString(reason)) + L"\"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"breakGlassEnabled\":" +
         (breakGlassEnabled ? std::wstring(L"true") : std::wstring(L"false")) + L",\"pamRecoveryQueued\":" +
         (pamRecoveryQueued ? std::wstring(L"true") : std::wstring(L"false")) + L",\"reason\":\"" +
         Utf8ToWide(EscapeJsonString(reason)) + L"\",\"pamRecoveryError\":\"" +
         Utf8ToWide(EscapeJsonString(pamQueueError)) + L"\"}";
}

std::wstring AgentService::ExecuteLocalApprovalCommand(const RemoteCommand& command) {
  const auto approvalRequestId = ExtractPayloadString(command.payloadJson, "approvalRequestId").value_or(L"");
  if (approvalRequestId.empty()) {
    throw std::runtime_error("local.approval.execute command is missing approvalRequestId");
  }

  const auto queuePath = ResolveLocalApprovalQueuePath();
  const auto ledgerPath = ResolveLocalApprovalLedgerPath();
  if (HasProcessedLocalApprovalRequest(ledgerPath, approvalRequestId)) {
    throw std::runtime_error("The local approval request has already been processed");
  }

  QueuedLocalApprovalRequest queuedRequest{};
  std::wstring loadError;
  if (!TryLoadQueuedLocalApprovalRequest(queuePath, approvalRequestId, &queuedRequest, &loadError)) {
    throw std::runtime_error(WideToUtf8(loadError.empty()
                                            ? L"Fenrir could not find the local approval request to execute."
                                            : loadError));
  }

  if (!IsLocalApprovalEligibleCommandType(queuedRequest.type)) {
    AppendLocalApprovalLedgerEntry(
        ledgerPath, approvalRequestId, command.issuedBy, L"rejected",
        L"Fenrir rejected this approval request because the queued command type is not eligible for local approval.",
        queuedRequest.type, L"", queuedRequest.requester);
    throw std::runtime_error("The queued local approval request references an unsupported command type");
  }

  RemoteCommand approvedCommand{};
  approvedCommand.commandId = L"local-approved-" + GenerateGuidString();
  approvedCommand.type = queuedRequest.type;
  approvedCommand.issuedBy = command.issuedBy.empty() ? L"local-approval" : command.issuedBy;
  approvedCommand.createdAt = CurrentUtcTimestamp();
  approvedCommand.updatedAt = approvedCommand.createdAt;
  approvedCommand.recordId = queuedRequest.recordId;
  approvedCommand.targetPath = queuedRequest.targetPath;
  approvedCommand.payloadJson = queuedRequest.payloadJson;

  std::wstring executionResult;
  try {
    executionResult = ExecuteCommand(approvedCommand);
  } catch (const std::exception& error) {
    const auto detail = Utf8ToWide(error.what());
    AppendLocalApprovalLedgerEntry(ledgerPath, approvalRequestId, command.issuedBy, L"approved-failed", detail,
                                   queuedRequest.type, approvedCommand.commandId, queuedRequest.requester);
    QueueTelemetryEvent(L"local.approval.failed", L"local-control",
                        L"Fenrir could not execute an approved local request.",
                        std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"approvalRequestId\":\"" +
                            Utf8ToWide(EscapeJsonString(approvalRequestId)) + L"\",\"approvedType\":\"" +
                            Utf8ToWide(EscapeJsonString(queuedRequest.type)) + L"\",\"error\":\"" +
                            Utf8ToWide(EscapeJsonString(detail)) + L"\"}");
    throw;
  }

  if (!AppendLocalApprovalLedgerEntry(
          ledgerPath, approvalRequestId, command.issuedBy, L"approved-executed",
          L"Fenrir executed the approved local request with administrator authorization.", queuedRequest.type,
          approvedCommand.commandId, queuedRequest.requester)) {
    throw std::runtime_error("Fenrir executed the local approval request but could not persist the approval ledger entry");
  }

  QueueTelemetryEvent(L"local.approval.executed", L"local-control",
                      L"Fenrir executed a queued local action after administrator approval.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"approvalRequestId\":\"" +
                          Utf8ToWide(EscapeJsonString(approvalRequestId)) + L"\",\"approvedType\":\"" +
                          Utf8ToWide(EscapeJsonString(queuedRequest.type)) + L"\",\"executedCommandId\":\"" +
                          Utf8ToWide(EscapeJsonString(approvedCommand.commandId)) + L"\"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"approvalRequestId\":\"" +
         Utf8ToWide(EscapeJsonString(approvalRequestId)) + L"\",\"approvedType\":\"" +
         Utf8ToWide(EscapeJsonString(queuedRequest.type)) + L"\",\"queuedRequester\":\"" +
         Utf8ToWide(EscapeJsonString(queuedRequest.requester)) + L"\",\"executedCommandId\":\"" +
         Utf8ToWide(EscapeJsonString(approvedCommand.commandId)) + L"\",\"executionResult\":" + executionResult + L"}";
}

std::wstring AgentService::ExecuteLocalApprovalListCommand(const RemoteCommand& command) {
  const auto queuePath = ResolveLocalApprovalQueuePath();
  const auto ledgerPath = ResolveLocalApprovalLedgerPath();
  const auto requestedLimit = ExtractPayloadUInt32(command.payloadJson, "limit").value_or(50);
  const auto limit = static_cast<std::size_t>(std::clamp<std::uint32_t>(requestedLimit, 1, 200));

  const auto processedRequestIds = LoadProcessedLocalApprovalRequestIds(ledgerPath);
  std::vector<QueuedLocalApprovalRequest> pendingRequests;
  pendingRequests.reserve(limit);

  std::size_t totalPending = 0;
  std::ifstream input(queuePath, std::ios::binary);
  if (input.is_open()) {
    std::string utf8Line;
    while (std::getline(input, utf8Line)) {
      if (utf8Line.empty()) {
        continue;
      }

      const auto line = Utf8ToWide(utf8Line);
      auto requestId = ExtractPayloadString(line, "requestId").value_or(L"");
      if (requestId.empty()) {
        continue;
      }

      const auto status = ToLowerCopy(ExtractPayloadString(line, "status").value_or(L"pending"));
      if (status != L"pending") {
        continue;
      }

      if (processedRequestIds.find(ToLowerCopy(requestId)) != processedRequestIds.end()) {
        continue;
      }

      ++totalPending;
      if (pendingRequests.size() >= limit) {
        continue;
      }

      pendingRequests.push_back(QueuedLocalApprovalRequest{
          .requestId = std::move(requestId),
          .createdAt = ExtractPayloadString(line, "createdAt").value_or(L""),
          .type = ExtractPayloadString(line, "type").value_or(L""),
          .requester = ExtractPayloadString(line, "requester").value_or(L""),
          .callerSid = ExtractPayloadString(line, "callerSid").value_or(L""),
          .role = ExtractPayloadString(line, "role").value_or(L""),
          .reason = ExtractPayloadString(line, "reason").value_or(L""),
          .recordId = ExtractPayloadString(line, "recordId").value_or(L""),
          .targetPath = ExtractPayloadString(line, "targetPath").value_or(L""),
          .payloadJson = ExtractPayloadString(line, "payloadJson").value_or(L"{}")});
    }
  }

  std::wstring requestsJson = L"[";
  for (std::size_t index = 0; index < pendingRequests.size(); ++index) {
    const auto& request = pendingRequests[index];
    if (index != 0) {
      requestsJson += L",";
    }

    requestsJson += L"{\"requestId\":\"" + Utf8ToWide(EscapeJsonString(request.requestId)) +
                    L"\",\"createdAt\":\"" + Utf8ToWide(EscapeJsonString(request.createdAt)) +
                    L"\",\"type\":\"" + Utf8ToWide(EscapeJsonString(request.type)) +
                    L"\",\"requester\":\"" + Utf8ToWide(EscapeJsonString(request.requester)) +
                    L"\",\"callerSid\":\"" + Utf8ToWide(EscapeJsonString(request.callerSid)) +
                    L"\",\"role\":\"" + Utf8ToWide(EscapeJsonString(request.role)) +
                    L"\",\"reason\":\"" + Utf8ToWide(EscapeJsonString(request.reason)) +
                    L"\",\"recordId\":\"" + Utf8ToWide(EscapeJsonString(request.recordId)) +
                    L"\",\"targetPath\":\"" + Utf8ToWide(EscapeJsonString(request.targetPath)) + L"\"}";
  }
  requestsJson += L"]";

  QueueTelemetryEvent(L"local.approval.listed", L"local-control",
                      L"Fenrir returned pending local approval requests for administrator review.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"pendingCount\":" +
                          std::to_wstring(totalPending) + L",\"returnedCount\":" +
                          std::to_wstring(pendingRequests.size()) + L"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"pendingCount\":" +
         std::to_wstring(totalPending) + L",\"returnedCount\":" +
         std::to_wstring(pendingRequests.size()) + L",\"requests\":" + requestsJson + L"}";
}

std::wstring AgentService::ExecuteLocalAdminAuditCommand(const RemoteCommand& command) {
  std::wstring enumerateError;
  const auto members = EnumerateLocalAdminMembers(&enumerateError);
  if (!enumerateError.empty()) {
    throw std::runtime_error(WideToUtf8(enumerateError));
  }

  const auto ownerSid = QueryConfiguredDeviceOwnerSid();
  const auto keepSids = ExtractPayloadStringArray(command.payloadJson, "keepSids");
  const auto reducibleMembers = BuildReducibleLocalAdminMembers(members, ownerSid, keepSids);

  QueueTelemetryEvent(L"local.admin.audit.completed", L"local-control",
                      L"Fenrir audited local Administrators group membership for PAM admin-reduction planning.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"memberCount\":" +
                          std::to_wstring(members.size()) + L",\"reducibleCount\":" +
                          std::to_wstring(reducibleMembers.size()) + L",\"ownerSid\":\"" +
                          Utf8ToWide(EscapeJsonString(ownerSid)) + L"\"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"ownerSid\":\"" +
         Utf8ToWide(EscapeJsonString(ownerSid)) + L"\",\"memberCount\":" +
         std::to_wstring(members.size()) + L",\"reducibleCount\":" +
         std::to_wstring(reducibleMembers.size()) + L",\"members\":" + BuildLocalAdminMembersJson(members) +
         L",\"reducibleMembers\":" + BuildLocalAdminMembersJson(reducibleMembers) + L"}";
}

std::wstring AgentService::ExecuteLocalAdminReductionCommand(const RemoteCommand& command, const bool applyChanges) {
  std::wstring enumerateError;
  const auto members = EnumerateLocalAdminMembers(&enumerateError);
  if (!enumerateError.empty()) {
    throw std::runtime_error(WideToUtf8(enumerateError));
  }

  const auto ownerSid = QueryConfiguredDeviceOwnerSid();
  const auto keepSids = ExtractPayloadStringArray(command.payloadJson, "keepSids");
  const auto reducibleMembers = BuildReducibleLocalAdminMembers(members, ownerSid, keepSids);
  const auto dryRun = ExtractPayloadBool(command.payloadJson, "dryRun").value_or(!applyChanges);

  if (!applyChanges || dryRun) {
    QueueTelemetryEvent(L"local.admin.reduction.planned", L"local-control",
                        L"Fenrir generated a local admin reduction plan without applying membership changes.",
                        std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"plannedCount\":" +
                            std::to_wstring(reducibleMembers.size()) + L",\"memberCount\":" +
                            std::to_wstring(members.size()) + L"}");

    return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"applied\":false,\"dryRun\":true,\"ownerSid\":\"" +
           Utf8ToWide(EscapeJsonString(ownerSid)) + L"\",\"memberCount\":" +
           std::to_wstring(members.size()) + L",\"plannedReductionCount\":" +
           std::to_wstring(reducibleMembers.size()) + L",\"plannedRemovals\":" +
           BuildLocalAdminMembersJson(reducibleMembers) + L"}";
  }

  const auto baselinePath = ResolveLocalAdminBaselinePath(config_);
  std::wstring baselineError;
  if (!SaveLocalAdminBaselineSnapshot(baselinePath, members, &baselineError)) {
    throw std::runtime_error(WideToUtf8(baselineError.empty()
                                            ? L"Fenrir could not create a baseline snapshot before admin reduction."
                                            : baselineError));
  }

  std::vector<std::wstring> removedSids;
  std::vector<std::wstring> failedChanges;
  for (const auto& member : reducibleMembers) {
    std::wstring removeError;
    if (RemoveLocalAdminMemberBySid(member.sid, &removeError)) {
      removedSids.push_back(member.sid);
      continue;
    }

    failedChanges.push_back(member.sid + L": " + removeError);
  }

  const auto eventType = failedChanges.empty() ? L"local.admin.reduction.applied" : L"local.admin.reduction.partial";
  QueueTelemetryEvent(eventType, L"local-control",
                      failedChanges.empty()
                          ? L"Fenrir applied local admin reduction according to PAM governance policy."
                          : L"Fenrir applied local admin reduction with partial failures.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"plannedCount\":" +
                          std::to_wstring(reducibleMembers.size()) + L",\"removedCount\":" +
                          std::to_wstring(removedSids.size()) + L",\"failedCount\":" +
                          std::to_wstring(failedChanges.size()) + L",\"baselinePath\":\"" +
                          Utf8ToWide(EscapeJsonString(baselinePath.wstring())) + L"\"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"applied\":true,\"ownerSid\":\"" +
         Utf8ToWide(EscapeJsonString(ownerSid)) + L"\",\"baselinePath\":\"" +
         Utf8ToWide(EscapeJsonString(baselinePath.wstring())) + L"\",\"plannedReductionCount\":" +
         std::to_wstring(reducibleMembers.size()) + L",\"removedCount\":" + std::to_wstring(removedSids.size()) +
         L",\"failedCount\":" + std::to_wstring(failedChanges.size()) + L",\"removedSids\":" +
         BuildJsonStringArray(removedSids) + L",\"failedChanges\":" + BuildJsonStringArray(failedChanges) + L"}";
}

std::wstring AgentService::ExecuteLocalAdminRollbackCommand(const RemoteCommand& command) {
  const auto baselinePath = ResolveLocalAdminBaselinePath(config_);
  std::wstring baselineError;
  const auto baselineMembers = LoadLocalAdminBaselineSnapshot(baselinePath, &baselineError);
  if (!baselineError.empty()) {
    throw std::runtime_error(WideToUtf8(baselineError));
  }
  if (baselineMembers.empty()) {
    throw std::runtime_error("Fenrir local admin rollback baseline is empty or missing");
  }

  std::wstring enumerateError;
  const auto currentMembers = EnumerateLocalAdminMembers(&enumerateError);
  if (!enumerateError.empty()) {
    throw std::runtime_error(WideToUtf8(enumerateError));
  }

  std::vector<std::wstring> currentSids;
  currentSids.reserve(currentMembers.size());
  for (const auto& member : currentMembers) {
    if (!member.sid.empty()) {
      currentSids.push_back(member.sid);
    }
  }
  auto currentSidSet = NormalizeSidList(currentSids);

  std::vector<std::wstring> restoredSids;
  std::vector<std::wstring> failedRestores;
  for (const auto& baselineMember : baselineMembers) {
    if (baselineMember.sid.empty()) {
      continue;
    }

    const auto sidLower = ToLowerCopy(baselineMember.sid);
    if (std::find(currentSidSet.begin(), currentSidSet.end(), sidLower) != currentSidSet.end()) {
      continue;
    }

    std::wstring restoreError;
    if (AddLocalAdminMemberBySid(baselineMember.sid, &restoreError)) {
      restoredSids.push_back(baselineMember.sid);
      currentSidSet.push_back(sidLower);
      continue;
    }

    failedRestores.push_back(baselineMember.sid + L": " + restoreError);
  }

  const auto eventType = failedRestores.empty() ? L"local.admin.reduction.rollback.completed"
                                                 : L"local.admin.reduction.rollback.partial";
  QueueTelemetryEvent(eventType, L"local-control",
                      failedRestores.empty()
                          ? L"Fenrir restored local admin membership from the last baseline snapshot."
                          : L"Fenrir attempted local admin rollback but some principals could not be restored.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"restoredCount\":" +
                          std::to_wstring(restoredSids.size()) + L",\"failedCount\":" +
                          std::to_wstring(failedRestores.size()) + L",\"baselinePath\":\"" +
                          Utf8ToWide(EscapeJsonString(baselinePath.wstring())) + L"\"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"baselinePath\":\"" +
         Utf8ToWide(EscapeJsonString(baselinePath.wstring())) + L"\",\"restoredCount\":" +
         std::to_wstring(restoredSids.size()) + L",\"failedCount\":" +
         std::to_wstring(failedRestores.size()) + L",\"restoredSids\":" + BuildJsonStringArray(restoredSids) +
         L",\"failedRestores\":" + BuildJsonStringArray(failedRestores) + L"}";
}

std::wstring AgentService::ExecuteRepairCommand(const RemoteCommand& command) {
  const auto installRoot = ResolveInstallRootForConfig(config_);
  HardeningManager hardeningManager(config_, installRoot);
  std::wstring hardeningError;
  const auto hardeningApplied =
      hardeningManager.ApplyPostInstallHardening(ReadEnvironmentVariable(L"ANTIVIRUS_UNINSTALL_TOKEN"),
                                                 &hardeningError);
  std::wstring serviceControlError;
  const auto serviceControlApplied =
      hardeningManager.ApplyServiceControlProtection(L"FenrirAgent", nullptr, &serviceControlError);
  const auto repairedStatus = hardeningManager.QueryStatus(L"FenrirAgent");
  const auto runtimeTrust = ValidateRuntimeTrust(config_, installRoot);
  const auto repairSucceeded = hardeningApplied && serviceControlApplied && IsHardeningReady(repairedStatus, config_) &&
                               runtimeTrust.trusted;
  lastHardeningCheckFailed_ = !repairSucceeded;

  const WscCoexistenceManager wscManager;
  const auto wscSnapshot = wscManager.CaptureSnapshot();
  QueueTelemetryEvent(repairSucceeded ? L"agent.repaired" : L"agent.repair.failed", L"command-executor",
                      repairSucceeded ? L"The endpoint reapplied hardening and runtime trust controls."
                                      : L"The endpoint could not fully reapply hardening or runtime trust controls.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId +
                          L"\",\"hardeningApplied\":" +
                          (hardeningApplied ? std::wstring(L"true") : std::wstring(L"false")) +
                          L",\"serviceControlApplied\":" +
                          (serviceControlApplied ? std::wstring(L"true") : std::wstring(L"false")) +
                          L",\"runtimeTrustValidated\":" +
                          (runtimeTrust.trusted ? std::wstring(L"true") : std::wstring(L"false")) +
                          L",\"wscAvailable\":" +
                          (wscSnapshot.available ? std::wstring(L"true") : std::wstring(L"false")) + L"}");

  if (!repairSucceeded) {
    const auto reportedError = !hardeningError.empty()
                                   ? hardeningError
                                   : (!serviceControlError.empty() ? serviceControlError
                                                                   : (!runtimeTrust.message.empty()
                                                                          ? runtimeTrust.message
                                                                          : repairedStatus.statusMessage));
    throw std::runtime_error(
        WideToUtf8(reportedError.empty() ? L"Endpoint repair failed" : reportedError));
  }

  return std::wstring(L"{\"commandId\":\"") + command.commandId +
         L"\",\"hardeningApplied\":true,\"serviceControlApplied\":true,\"runtimeTrustValidated\":true,\"wscAvailable\":" +
         (wscSnapshot.available ? std::wstring(L"true") : std::wstring(L"false")) + L"}";
}

std::wstring AgentService::ExecuteProcessTerminationCommand(const RemoteCommand& command, const bool includeChildren) {
  if (command.targetPath.empty()) {
    throw std::runtime_error("Process termination command is missing targetPath");
  }

  RemediationEngine remediationEngine(config_);
  const auto result = remediationEngine.TerminateProcessesForPath(command.targetPath, includeChildren);
  QueueTelemetryEvent(includeChildren ? L"process.tree.terminated" : L"process.terminated", L"command-executor",
                      includeChildren ? L"The endpoint terminated a malicious process tree."
                                      : L"The endpoint terminated a malicious process.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"targetPath\":\"" +
                          Utf8ToWide(EscapeJsonString(command.targetPath)) + L"\",\"terminatedCount\":" +
                          std::to_wstring(result.processesTerminated) + L"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"targetPath\":\"" +
         Utf8ToWide(EscapeJsonString(command.targetPath)) + L"\",\"terminatedCount\":" +
         std::to_wstring(result.processesTerminated) + L"}";
}

std::wstring AgentService::ExecutePersistenceCleanupCommand(const RemoteCommand& command) {
  if (command.targetPath.empty()) {
    throw std::runtime_error("Persistence cleanup command is missing targetPath");
  }

  RemediationEngine remediationEngine(config_);
  const auto result = remediationEngine.CleanupPersistenceForPath(command.targetPath);
  QueueTelemetryEvent(L"persistence.cleaned", L"command-executor",
                      L"The endpoint removed startup persistence tied to a malicious artifact.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"targetPath\":\"" +
                          Utf8ToWide(EscapeJsonString(command.targetPath)) + L"\",\"registryValuesRemoved\":" +
                          std::to_wstring(result.registryValuesRemoved) + L",\"startupArtifactsRemoved\":" +
                          std::to_wstring(result.startupArtifactsRemoved) + L"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"targetPath\":\"" +
         Utf8ToWide(EscapeJsonString(command.targetPath)) + L"\",\"registryValuesRemoved\":" +
         std::to_wstring(result.registryValuesRemoved) + L",\"startupArtifactsRemoved\":" +
         std::to_wstring(result.startupArtifactsRemoved) + L"}";
}

std::wstring AgentService::ExecutePathRemediationCommand(const RemoteCommand& command) {
  if (command.targetPath.empty()) {
    throw std::runtime_error("remediate.path command is missing targetPath");
  }

  RemediationEngine remediationEngine(config_);
  const auto result = remediationEngine.RemediatePath(command.targetPath, policy_);
  QueueTelemetryEvent(L"remediation.completed", L"command-executor",
                      L"The endpoint executed a full remediation workflow for a malicious artifact.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"targetPath\":\"" +
                          Utf8ToWide(EscapeJsonString(command.targetPath)) + L"\",\"terminatedCount\":" +
                          std::to_wstring(result.processesTerminated) + L",\"registryValuesRemoved\":" +
                          std::to_wstring(result.registryValuesRemoved) + L",\"startupArtifactsRemoved\":" +
                          std::to_wstring(result.startupArtifactsRemoved) + L",\"quarantineApplied\":" +
                          (result.quarantineApplied ? std::wstring(L"true") : std::wstring(L"false")) + L"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"targetPath\":\"" +
         Utf8ToWide(EscapeJsonString(command.targetPath)) + L"\",\"terminatedCount\":" +
         std::to_wstring(result.processesTerminated) + L",\"registryValuesRemoved\":" +
         std::to_wstring(result.registryValuesRemoved) + L",\"startupArtifactsRemoved\":" +
         std::to_wstring(result.startupArtifactsRemoved) + L",\"quarantineApplied\":" +
         (result.quarantineApplied ? std::wstring(L"true") : std::wstring(L"false")) + L",\"quarantineRecordId\":\"" +
         result.quarantineRecordId + L"\",\"evidenceRecordId\":\"" + result.evidenceRecordId + L"\"}";
}

std::wstring AgentService::ExecuteScriptCommand(const RemoteCommand& command) {
  const auto scriptId = ExtractPayloadString(command.payloadJson, "scriptId").value_or(L"");
  const auto scriptName = ExtractPayloadString(command.payloadJson, "scriptName").value_or(L"remote-script");
  const auto language = ExtractPayloadString(command.payloadJson, "language").value_or(L"powershell");
  const auto content = ExtractPayloadString(command.payloadJson, "content").value_or(L"");

  if (content.empty()) {
    throw std::runtime_error("script.run command is missing content");
  }

  const auto jobsRoot = config_.evidenceRootPath.parent_path() / L"jobs";
  const auto scriptPath = WriteRuntimeScriptFile(jobsRoot, language == L"cmd" ? L".cmd" : L".ps1", content);
  const auto commandLine = language == L"cmd"
                               ? std::wstring(L"cmd.exe /c \"") + scriptPath.wstring() + L"\""
                               : std::wstring(L"powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"") +
                                     scriptPath.wstring() + L"\"";
  const auto exitCode = ExecuteHiddenProcess(commandLine, jobsRoot.wstring());

  QueueTelemetryEvent(exitCode == 0 ? L"script.executed" : L"script.failed", L"command-executor",
                      exitCode == 0 ? L"The endpoint executed a remote script successfully."
                                    : L"The endpoint executed a remote script but it returned a non-zero exit code.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"scriptId\":\"" + scriptId +
                          L"\",\"scriptName\":\"" + Utf8ToWide(EscapeJsonString(scriptName)) + L"\",\"language\":\"" +
                          language + L"\",\"path\":\"" + Utf8ToWide(EscapeJsonString(scriptPath.wstring())) +
                          L"\",\"exitCode\":" + std::to_wstring(exitCode) + L"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"scriptId\":\"" + scriptId +
         L"\",\"scriptName\":\"" + Utf8ToWide(EscapeJsonString(scriptName)) + L"\",\"language\":\"" + language +
         L"\",\"path\":\"" + Utf8ToWide(EscapeJsonString(scriptPath.wstring())) + L"\",\"exitCode\":" +
         std::to_wstring(exitCode) + L"}";
}

std::wstring AgentService::ExecuteSoftwareCommand(const RemoteCommand& command, const bool uninstall,
                                                  const bool searchOnly) {
  const auto softwareId = ExtractPayloadString(command.payloadJson, "softwareId").value_or(L"");
  const auto displayName = ExtractPayloadString(command.payloadJson, "displayName").value_or(L"software-package");
  const auto installLocation = ExtractPayloadString(command.payloadJson, "installLocation").value_or(L"");
  const auto uninstallCommand = ExtractPayloadString(command.payloadJson, "uninstallCommand").value_or(L"");
  const auto quietUninstallCommand = ExtractPayloadString(command.payloadJson, "quietUninstallCommand").value_or(L"");
  const auto commandLineOverride = ExtractPayloadString(command.payloadJson, "commandLine").value_or(L"");
  const auto workingDirectory = ExtractPayloadString(command.payloadJson, "workingDirectory").value_or(installLocation);

  if (!uninstall && !softwareId.empty()) {
    PatchOrchestrator orchestrator(config_);
    const auto patchResult = orchestrator.UpdateSoftware(softwareId, searchOnly);
    const auto summary = searchOnly
                             ? (patchResult.status == L"available"
                                    ? L"Fenrir checked software update availability through the patch orchestrator and found an update."
                                    : L"Fenrir checked software update availability through the patch orchestrator.")
                             : (patchResult.success ? L"Fenrir completed a software update through the patch orchestrator."
                                                    : L"Fenrir attempted a software update through the patch orchestrator.");

    QueueTelemetryEvent(searchOnly ? L"software.update.search.completed"
                                   : (patchResult.success ? L"software.updated" : L"software.update.failed"),
                        L"patch-orchestrator", summary,
                        std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"softwareId\":\"" + softwareId +
                            L"\",\"displayName\":\"" + Utf8ToWide(EscapeJsonString(displayName)) +
                            L"\",\"provider\":\"" + patchResult.provider + L"\",\"status\":\"" + patchResult.status +
                            L"\",\"detailJson\":" + patchResult.detailJson + L"}");

    return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"softwareId\":\"" + softwareId +
           L"\",\"displayName\":\"" + Utf8ToWide(EscapeJsonString(displayName)) + L"\",\"provider\":\"" +
           patchResult.provider + L"\",\"status\":\"" + patchResult.status + L"\",\"detailJson\":" +
           patchResult.detailJson + L"}";
  }

  if (searchOnly) {
    const auto searchCommand = std::wstring(L"cmd.exe /c winget upgrade --name \"") + displayName +
                               L"\" --accept-source-agreements --disable-interactivity";
    const auto result = ExecuteHiddenProcessCapture(searchCommand, workingDirectory);
    const auto normalizedOutput = ToLowerCopy(result.output);
    const auto updateAvailable =
        result.exitCode == 0 && normalizedOutput.find(L"no available upgrade found") == std::wstring::npos &&
        normalizedOutput.find(L"no installed package found") == std::wstring::npos;
    const auto summary = updateAvailable ? L"Fenrir found a newer software package version for this application."
                                         : L"Fenrir did not find a newer software package version for this application.";

    QueueTelemetryEvent(result.exitCode == 0 ? L"software.update.search.completed" : L"software.update.search.failed",
                        L"command-executor", summary,
                        std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"softwareId\":\"" + softwareId +
                            L"\",\"displayName\":\"" + Utf8ToWide(EscapeJsonString(displayName)) +
                            L"\",\"updateAvailable\":" + (updateAvailable ? std::wstring(L"true") : std::wstring(L"false")) +
                            L",\"exitCode\":" + std::to_wstring(result.exitCode) + L",\"summary\":\"" +
                            Utf8ToWide(EscapeJsonString(summary)) + L"\",\"output\":\"" +
                            Utf8ToWide(EscapeJsonString(result.output)) + L"\"}");

    return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"softwareId\":\"" + softwareId +
           L"\",\"displayName\":\"" + Utf8ToWide(EscapeJsonString(displayName)) + L"\",\"updateAvailable\":" +
           (updateAvailable ? std::wstring(L"true") : std::wstring(L"false")) + L",\"exitCode\":" +
           std::to_wstring(result.exitCode) + L",\"output\":\"" + Utf8ToWide(EscapeJsonString(result.output)) + L"\"}";
  }

  std::wstring commandLine = commandLineOverride;
  if (commandLine.empty()) {
    if (uninstall) {
      commandLine = !quietUninstallCommand.empty() ? quietUninstallCommand : uninstallCommand;
    } else {
      commandLine = std::wstring(L"cmd.exe /c winget upgrade --name \"") + displayName +
                    L"\" --accept-package-agreements --accept-source-agreements --silent --disable-interactivity";
    }
  }

  if (commandLine.empty()) {
    throw std::runtime_error("Software command is missing commandLine");
  }

  const auto result = ExecuteHiddenProcessCapture(commandLine, workingDirectory);
  const auto eventType = uninstall ? (result.exitCode == 0 ? L"software.uninstalled" : L"software.uninstall.failed")
                                   : (result.exitCode == 0 ? L"software.updated" : L"software.update.failed");
  const auto summary = uninstall ? (result.exitCode == 0 ? L"The endpoint completed a remote software uninstall."
                                                          : L"The endpoint attempted a remote software uninstall but it failed.")
                                 : (result.exitCode == 0 ? L"The endpoint completed a remote software update."
                                                         : L"The endpoint attempted a remote software update but it failed.");

  QueueTelemetryEvent(eventType, L"command-executor", summary,
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"softwareId\":\"" + softwareId +
                          L"\",\"displayName\":\"" + Utf8ToWide(EscapeJsonString(displayName)) +
                          L"\",\"installLocation\":\"" + Utf8ToWide(EscapeJsonString(installLocation)) +
                          L"\",\"exitCode\":" + std::to_wstring(result.exitCode) + L",\"output\":\"" +
                          Utf8ToWide(EscapeJsonString(result.output)) + L"\"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"softwareId\":\"" + softwareId +
         L"\",\"displayName\":\"" + Utf8ToWide(EscapeJsonString(displayName)) + L"\",\"exitCode\":" +
         std::to_wstring(result.exitCode) + L",\"output\":\"" + Utf8ToWide(EscapeJsonString(result.output)) + L"\"}";
}

std::wstring AgentService::ExecuteSoftwareBlockCommand(const RemoteCommand& command) {
  RuntimeDatabase database(config_.runtimeDatabasePath);
  const auto softwareId = ExtractPayloadString(command.payloadJson, "softwareId").value_or(GenerateGuidString());
  const auto displayName = ExtractPayloadString(command.payloadJson, "displayName").value_or(L"blocked-software");
  const auto installLocation = ExtractPayloadString(command.payloadJson, "installLocation").value_or(L"");
  auto executableNames = ExtractPayloadStringArray(command.payloadJson, "executableNames");
  std::transform(executableNames.begin(), executableNames.end(), executableNames.begin(), ToLowerCopy);

  database.UpsertBlockedSoftwareRule(BlockedSoftwareRule{
      .softwareId = softwareId,
      .displayName = displayName,
      .installLocation = installLocation,
      .executableNames = executableNames,
      .blockedAt = CurrentUtcTimestamp()});

  EnforceBlockedSoftware();

  QueueTelemetryEvent(L"software.blocked", L"command-executor",
                      L"Fenrir blocked the selected software on this endpoint.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"softwareId\":\"" + softwareId +
                          L"\",\"displayName\":\"" + Utf8ToWide(EscapeJsonString(displayName)) +
                          L"\",\"installLocation\":\"" + Utf8ToWide(EscapeJsonString(installLocation)) + L"\"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"softwareId\":\"" + softwareId +
         L"\",\"displayName\":\"" + Utf8ToWide(EscapeJsonString(displayName)) + L"\"}";
}

void AgentService::PublishHeartbeat(const int cycle) {
  if (state_.deviceId.empty()) {
    return;
  }

  const auto wfpIsolationActive = networkIsolationManager_ && networkIsolationManager_->IsolationActive();
  const auto wfpUnavailable =
      policy_.networkContainmentEnabled && (!networkIsolationManager_ || !networkIsolationManager_->EngineReady());
  const auto realtimeUnavailable = policy_.realtimeProtectionEnabled &&
                                   (!realtimeProtectionBroker_ || !realtimeProtectionBroker_->IsRealtimeCoverageHealthy());

  state_.isolated = wfpIsolationActive;
  state_.healthState = wfpIsolationActive
                           ? L"isolated"
                           : ((wfpUnavailable || realtimeUnavailable || lastControlPlaneSyncFailed_ || lastTelemetryFlushFailed_ ||
                               lastHardeningCheckFailed_)
                                  ? L"degraded"
                                  : L"healthy");

  bool attemptedRecovery = false;
  for (;;) {
    try {
      const auto heartbeat = controlPlaneClient_->SendHeartbeat(state_);
      state_.lastHeartbeatAt = heartbeat.receivedAt;
      lastControlPlaneSyncFailed_ = false;
      QueueTelemetryEvent(L"device.heartbeat", L"control-plane-client",
                          L"The endpoint heartbeat was acknowledged by the control plane.",
                          BuildCyclePayload(cycle, std::wstring(L"\"commandsPending\":") +
                                                       std::to_wstring(heartbeat.commandsPending)));
      return;
    } catch (const std::exception& error) {
      if (!attemptedRecovery && RecoverDeviceIdentity(error, L"heartbeat")) {
        attemptedRecovery = true;
        continue;
      }

      lastControlPlaneSyncFailed_ = true;
      QueueTelemetryEvent(L"device.heartbeat.failed", L"control-plane-client",
                          L"The endpoint heartbeat could not be delivered to the control plane.",
                          BuildCyclePayload(cycle));
      std::wcerr << L"Heartbeat failed, keeping the previous health state cached: " << Utf8ToWide(error.what())
                 << std::endl;
      return;
    }
  }
}

void AgentService::PersistState() {
  if (!stateStore_) {
    return;
  }

  stateStore_->Save(state_);
  telemetryQueueStore_->SavePending(pendingTelemetry_);
}

void AgentService::LoadLocalPolicyCache() {
  state_ = stateStore_->LoadOrCreate();
  state_.agentVersion = config_.agentVersion;
  state_.platformVersion = config_.platformVersion;
  policy_ = state_.policy;
  pendingTelemetry_ = telemetryQueueStore_->LoadPending();
}

void AgentService::StartTelemetrySpool() const {
  const auto deviceLabel = state_.deviceId.empty() ? std::wstring(L"(not yet enrolled)") : state_.deviceId;
  std::wcout << L"Telemetry spool ready for device " << deviceLabel << L" with " << pendingTelemetry_.size()
             << L" queued event(s)." << std::endl;
}

void AgentService::StartCommandLoop() const {
  if (!state_.commandChannelUrl.empty()) {
    std::wcout << L"Command polling configured at " << state_.commandChannelUrl << std::endl;
  } else {
    std::wcout << L"Command polling has not been assigned yet." << std::endl;
  }

  std::wcout << L"Real-time protection broker targeting port " << config_.realtimeProtectionPortName << std::endl;
  std::wcout << L"ETW process telemetry sensor " << (processEtwSensor_ && processEtwSensor_->IsActive() ? L"active"
                                                                                                          : L"fallback")
             << std::endl;
  std::wcout << L"WFP isolation manager "
             << (networkIsolationManager_ ? (networkIsolationManager_->EngineReady() ? L"ready" : L"unavailable")
                                          : L"not configured")
             << std::endl;
}

void AgentService::PrintStatus() const {
  const auto deviceLabel = state_.deviceId.empty() ? std::wstring(L"(pending)") : state_.deviceId;
  const auto lastPolicySync = state_.lastPolicySyncAt.empty() ? std::wstring(L"(never)") : state_.lastPolicySyncAt;
  const auto lastHeartbeat = state_.lastHeartbeatAt.empty() ? std::wstring(L"(never)") : state_.lastHeartbeatAt;

  std::wcout << L"Hostname: " << state_.hostname << std::endl;
  std::wcout << L"Device ID: " << deviceLabel << std::endl;
  std::wcout << L"Policy: " << policy_.policyName << L" (" << policy_.revision << L")" << std::endl;
  std::wcout << L"Health state: " << state_.healthState << std::endl;
  std::wcout << L"Last policy sync: " << lastPolicySync << std::endl;
  std::wcout << L"Last heartbeat: " << lastHeartbeat << std::endl;
  std::wcout << L"Real-time protection port: " << config_.realtimeProtectionPortName << std::endl;
  std::wcout << L"ETW process telemetry: "
             << (processEtwSensor_ && processEtwSensor_->IsActive() ? L"active" : L"fallback polling") << std::endl;
  std::wcout << L"WFP host isolation: "
             << (networkIsolationManager_ ? (networkIsolationManager_->IsolationActive()
                                                 ? L"active"
                                                 : (networkIsolationManager_->EngineReady() ? L"ready" : L"unavailable"))
                                          : L"not configured")
             << std::endl;
  std::wcout << L"Tamper protection: " << (lastHardeningCheckFailed_ ? L"degraded" : L"configured") << std::endl;
  std::wcout << L"Pending telemetry events: " << pendingTelemetry_.size() << std::endl;
}

void AgentService::QueueEndpointStatusTelemetry() {
  const auto installRoot = ResolveInstallRootForConfig(config_);
  HardeningManager hardeningManager(config_, installRoot);
  const auto hardeningStatus = hardeningManager.QueryStatus();
  const auto runtimeTrust = ValidateRuntimeTrust(config_, installRoot);
  lastHardeningCheckFailed_ = !(IsHardeningReady(hardeningStatus, config_) && runtimeTrust.trusted);
  QueueTelemetryEvent(lastHardeningCheckFailed_ ? L"tamper.protection.degraded" : L"tamper.protection.ready",
                      L"hardening-manager", hardeningStatus.statusMessage,
                      std::wstring(L"{\"registryConfigured\":") +
                          (hardeningStatus.registryConfigured ? std::wstring(L"true") : std::wstring(L"false")) +
                          L",\"runtimePathsTrusted\":" +
                          (hardeningStatus.runtimePathsTrusted ? std::wstring(L"true") : std::wstring(L"false")) +
                          L",\"runtimePathsProtected\":" +
                          (hardeningStatus.runtimePathsProtected ? std::wstring(L"true") : std::wstring(L"false")) +
                          L",\"serviceControlProtected\":" +
                          (hardeningStatus.serviceControlProtected ? std::wstring(L"true")
                                                                   : std::wstring(L"false")) +
                          L",\"uninstallProtectionEnabled\":" +
                          (hardeningStatus.uninstallProtectionEnabled ? std::wstring(L"true")
                                                                      : std::wstring(L"false")) +
                          L",\"elamDriverPresent\":" +
                          (hardeningStatus.elamDriverPresent ? std::wstring(L"true") : std::wstring(L"false")) +
                          L",\"elamCertificateInstalled\":" +
                          (hardeningStatus.elamCertificateInstalled ? std::wstring(L"true")
                                                                    : std::wstring(L"false")) +
                          L",\"launchProtectedConfigured\":" +
                          (hardeningStatus.launchProtectedConfigured ? std::wstring(L"true")
                                                                     : std::wstring(L"false")) +
                          L",\"runtimeTrustValidated\":" +
                          (runtimeTrust.trusted ? std::wstring(L"true") : std::wstring(L"false")) +
                          L",\"runtimeTrustMarkerPresent\":" +
                          (runtimeTrust.registryRuntimeMarkerPresent ? std::wstring(L"true") : std::wstring(L"false")) +
                          L",\"runtimeTrustMarkerMatch\":" +
                          (runtimeTrust.registryRuntimeMatches ? std::wstring(L"true") : std::wstring(L"false")) +
                          L",\"runtimeTrustInstallMatch\":" +
                          (runtimeTrust.registryInstallMatches ? std::wstring(L"true") : std::wstring(L"false")) +
                          L",\"runtimeTrustRequireSigned\":" +
                          (runtimeTrust.requireSignedBinaries ? std::wstring(L"true") : std::wstring(L"false")) +
                          L",\"runtimeTrustSignatureWarning\":" +
                          (runtimeTrust.signatureWarning ? std::wstring(L"true") : std::wstring(L"false")) +
                          L",\"runtimeTrustMessage\":\"" +
                          Utf8ToWide(EscapeJsonString(runtimeTrust.message)) +
                          L"\"" +
                          L"}");

  const WscCoexistenceManager wscManager;
  const auto wscSnapshot = wscManager.CaptureSnapshot();
  QueueTelemetryEvent(wscSnapshot.available ? L"wsc.coexistence.ready" : L"wsc.coexistence.degraded",
                      L"wsc-coexistence", wscSnapshot.available
                                              ? L"Windows Security Center coexistence data was collected."
                                              : L"Windows Security Center coexistence data is unavailable on this host.",
                      WscCoexistenceManager::ToJson(wscSnapshot));
}

void AgentService::QueueDeviceInventoryTelemetry(const int cycle) {
  if (cycle != 1 && (cycle % 10) != 0) {
    return;
  }

  RuntimeDatabase database(config_.runtimeDatabasePath);
  auto snapshot = CollectDeviceInventorySnapshot();
  const auto blockedRules = database.ListBlockedSoftwareRules();
  const auto patchInventory = database.ListSoftwarePatchRecords(500);

  for (auto& software : snapshot.installedSoftware) {
    const auto blockedRule =
        std::find_if(blockedRules.begin(), blockedRules.end(), [&](const BlockedSoftwareRule& rule) {
          return (!rule.softwareId.empty() && rule.softwareId == software.softwareId) ||
                 (!rule.displayName.empty() && _wcsicmp(rule.displayName.c_str(), software.displayName.c_str()) == 0);
        });
    if (blockedRule != blockedRules.end()) {
      software.blocked = true;
      if (software.updateSummary.empty()) {
        software.updateSummary = L"Execution is blocked on this endpoint.";
      }
    }

    const auto patchRecord = std::find_if(patchInventory.begin(), patchInventory.end(),
                                          [&](const SoftwarePatchRecord& record) { return record.softwareId == software.softwareId; });
    if (patchRecord != patchInventory.end()) {
      software.updateState = patchRecord->updateState;
      software.lastUpdateCheckAt = patchRecord->lastCheckedAt;
      software.updateSummary = patchRecord->updateSummary;
      software.supportedPatchSource = patchRecord->supportedSource;
      software.manualPatchOnly = patchRecord->manualOnly;
      software.patchUnsupported = !patchRecord->supported;
    }
  }

  QueueTelemetryEvent(L"device.inventory.snapshot", L"device-inventory",
                      L"The endpoint refreshed its local user, network, and installed software inventory.",
                      BuildDeviceInventoryPayload(snapshot));
}

void AgentService::QueuePatchTelemetry(const int cycle) {
  if (cycle != 1 && (cycle % 30) != 0) {
    return;
  }

  PatchOrchestrator orchestrator(config_);
  const auto refresh = orchestrator.RefreshPatchState();
  const auto snapshot = orchestrator.LoadSnapshot(50, 100, 20, 50);

  QueueTelemetryEvent(L"patch.inventory.snapshot", L"patch-orchestrator",
                      L"The endpoint refreshed Windows and third-party patch inventory.",
                          std::wstring(L"{\"windowsUpdateCount\":") + std::to_wstring(refresh.windowsUpdateCount) +
                          L",\"softwareCount\":" + std::to_wstring(refresh.softwareCount) +
                          L",\"recipeCount\":" + std::to_wstring(refresh.recipeCount) + L",\"rebootPending\":" +
                          (snapshot.rebootState.rebootRequired ? std::wstring(L"true") : std::wstring(L"false")) +
                          L",\"windowsUpdates\":" + std::to_wstring(snapshot.windowsUpdates.size()) +
                          L",\"softwarePatches\":" + std::to_wstring(snapshot.software.size()) + L"}");
}

void AgentService::DrainProcessTelemetry() {
  if (!processEtwSensor_) {
    return;
  }

  const auto telemetry = processEtwSensor_->DrainTelemetry();
  if (telemetry.empty()) {
    return;
  }

  for (const auto& record : telemetry) {
    if (realtimeProtectionBroker_) {
      if (const auto behaviorEvent = BuildBehaviorEventFromProcessTelemetry(record, state_.deviceId);
          behaviorEvent.has_value()) {
        realtimeProtectionBroker_->ObserveBehaviorEvent(*behaviorEvent);
      }
    }

    if (record.eventType == L"process.started") {
      const auto pid = ExtractPayloadUInt32(record.payloadJson, "pid");
      const auto imageName = ExtractPayloadString(record.payloadJson, "imageName").value_or(L"");
      const auto imagePath = ExtractPayloadString(record.payloadJson, "imagePath").value_or(L"");

      RuntimeDatabase database(config_.runtimeDatabasePath);
      for (const auto& rule : database.ListBlockedSoftwareRules()) {
        const auto matchedName = std::any_of(rule.executableNames.begin(), rule.executableNames.end(),
                                             [&](const std::wstring& executableName) {
                                               return !imageName.empty() &&
                                                      _wcsicmp(executableName.c_str(), imageName.c_str()) == 0;
                                             });
        const auto matchedPath = !rule.installLocation.empty() && !imagePath.empty() &&
                                 PathStartsWith(imagePath, rule.installLocation);

        if ((matchedName || matchedPath) && pid && TerminateProcessById(*pid)) {
          QueueTelemetryEvent(L"software.block.enforced", L"command-executor",
                              L"Fenrir terminated a blocked software process after it launched.",
                              std::wstring(L"{\"softwareId\":\"") + rule.softwareId + L"\",\"displayName\":\"" +
                                  Utf8ToWide(EscapeJsonString(rule.displayName)) + L"\",\"pid\":" +
                                  std::to_wstring(*pid) + L",\"imageName\":\"" +
                                  Utf8ToWide(EscapeJsonString(imageName)) + L"\"}");
        }
      }
    }
  }

  QueueTelemetryRecords(telemetry);
}

void AgentService::EnforceBlockedSoftware() {
  RuntimeDatabase database(config_.runtimeDatabasePath);
  const auto rules = database.ListBlockedSoftwareRules();
  if (rules.empty()) {
    return;
  }

  const auto processes = CollectProcessInventory();
  for (const auto& process : processes) {
    for (const auto& rule : rules) {
      const auto matchedName = std::any_of(rule.executableNames.begin(), rule.executableNames.end(),
                                           [&](const std::wstring& executableName) {
                                             return !process.imageName.empty() &&
                                                    _wcsicmp(executableName.c_str(), process.imageName.c_str()) == 0;
                                           });
      const auto matchedPath = !rule.installLocation.empty() && !process.imagePath.empty() &&
                               PathStartsWith(process.imagePath, rule.installLocation);

      if ((matchedName || matchedPath) && TerminateProcessById(process.pid)) {
        QueueTelemetryEvent(L"software.block.enforced", L"command-executor",
                            L"Fenrir terminated a blocked software process during policy enforcement.",
                            std::wstring(L"{\"softwareId\":\"") + rule.softwareId + L"\",\"displayName\":\"" +
                                Utf8ToWide(EscapeJsonString(rule.displayName)) + L"\",\"pid\":" +
                                std::to_wstring(process.pid) + L",\"imageName\":\"" +
                                Utf8ToWide(EscapeJsonString(process.imageName)) + L"\"}");
      }
    }
  }
}

void AgentService::DrainRealtimeProtectionTelemetry() {
  if (!realtimeProtectionBroker_) {
    return;
  }

  const auto telemetry = realtimeProtectionBroker_->DrainTelemetry();
  if (!telemetry.empty()) {
    QueueTelemetryRecords(telemetry);
  }
}

void AgentService::DrainNetworkTelemetry() {
  if (!networkIsolationManager_) {
    return;
  }

  const auto telemetry = networkIsolationManager_->DrainTelemetry();
  if (telemetry.empty()) {
    return;
  }

  if (realtimeProtectionBroker_) {
    for (const auto& record : telemetry) {
      if (const auto behaviorEvent = BuildBehaviorEventFromNetworkTelemetry(record, state_.deviceId);
          behaviorEvent.has_value()) {
        realtimeProtectionBroker_->ObserveBehaviorEvent(*behaviorEvent);
      }
    }
  }

  QueueTelemetryRecords(telemetry);
}

void AgentService::QueueCycleTelemetry(const int cycle) {
  QueueTelemetryEvent(L"service.sync.cycle", L"agent-service",
                      L"The endpoint is starting a scheduled sync cycle.",
                      BuildCyclePayload(cycle, std::wstring(L"\"hostname\":\"") + state_.hostname + L"\""));

  DrainProcessTelemetry();
  DrainNetworkTelemetry();
  if (!processEtwSensor_ || !processEtwSensor_->IsActive()) {
    const auto processInventory = CollectProcessInventory();
    const auto processSnapshotRecords = BuildProcessSnapshotTelemetry(processInventory, 4);
    if (processSnapshotRecords.empty()) {
      QueueTelemetryEvent(L"process.snapshot.empty", L"process-snapshot",
                          L"No process snapshot records were collected during this cycle.", BuildCyclePayload(cycle));
    } else {
      QueueTelemetryRecords(processSnapshotRecords);
    }
    QueueTelemetryRecords(processDeltaTracker_.CollectDeltaTelemetry(processInventory));
  }

  const auto serviceSnapshotRecords = CollectServiceSnapshotTelemetry(4);
  if (serviceSnapshotRecords.empty()) {
    QueueTelemetryEvent(L"service.snapshot.empty", L"service-snapshot",
                        L"No service snapshot records were collected during this cycle.", BuildCyclePayload(cycle));
  } else {
    QueueTelemetryRecords(serviceSnapshotRecords);
  }

  const auto fileInventory = CollectFileInventory(BuildMonitoredRoots());
  const auto fileSnapshotRecords = BuildRecentFileTelemetry(fileInventory, 4);
  if (fileSnapshotRecords.empty()) {
    QueueTelemetryEvent(L"file.snapshot.empty", L"file-snapshot",
                        L"No recent files were found in the monitored folders during this cycle.",
                        BuildCyclePayload(cycle));
  } else {
    QueueTelemetryRecords(fileSnapshotRecords);
  }
  QueueTelemetryRecords(fileDeltaTracker_.CollectDeltaTelemetry(fileInventory));

  if (networkIsolationManager_ && networkIsolationManager_->EngineReady()) {
    QueueTelemetryRecords(networkIsolationManager_->CollectConnectionSnapshotTelemetry(6));
  }

  QueuePatchTelemetry(cycle);
}

void AgentService::QueueTelemetryEvent(const std::wstring& eventType, const std::wstring& source,
                                       const std::wstring& summary, const std::wstring& payloadJson) {
  pendingTelemetry_.push_back(TelemetryRecord{
      .eventId = GenerateGuidString(),
      .eventType = eventType,
      .source = source,
      .summary = summary,
      .occurredAt = CurrentUtcTimestamp(),
      .payloadJson = payloadJson});

  telemetryQueueStore_->SavePending(pendingTelemetry_);
}

void AgentService::QueueTelemetryRecords(const std::vector<TelemetryRecord>& records) {
  pendingTelemetry_.insert(pendingTelemetry_.end(), records.begin(), records.end());
  telemetryQueueStore_->SavePending(pendingTelemetry_);
}

void AgentService::FlushTelemetryQueue() {
  if (state_.deviceId.empty() || pendingTelemetry_.empty()) {
    lastTelemetryFlushFailed_ = false;
    return;
  }

  lastTelemetryFlushFailed_ = false;
  bool attemptedRecovery = false;
  while (!pendingTelemetry_.empty() && !ShouldStop()) {
    const auto batchSize =
        std::min<std::size_t>(pendingTelemetry_.size(), static_cast<std::size_t>(config_.telemetryBatchSize));
    const std::vector<TelemetryRecord> batch(pendingTelemetry_.begin(), pendingTelemetry_.begin() + batchSize);

    try {
      const auto result = controlPlaneClient_->SendTelemetryBatch(state_, batch);
      pendingTelemetry_.erase(pendingTelemetry_.begin(), pendingTelemetry_.begin() + batchSize);
      telemetryQueueStore_->SavePending(pendingTelemetry_);
      std::wcout << L"Uploaded " << result.accepted << L" telemetry event(s) at " << result.receivedAt
                 << L". Backend now stores " << result.totalStored << L" event(s)." << std::endl;
    } catch (const std::exception& error) {
      if (!attemptedRecovery && RecoverDeviceIdentity(error, L"telemetry upload")) {
        attemptedRecovery = true;
        continue;
      }

      lastTelemetryFlushFailed_ = true;
      std::wcerr << L"Telemetry upload failed, leaving " << pendingTelemetry_.size()
                 << L" event(s) queued locally: " << Utf8ToWide(error.what()) << std::endl;
      break;
    }
  }
}

ScanVerdict AgentService::EvaluateEvent(const EventEnvelope& event) const {
  if (realtimeProtectionBroker_) {
    return realtimeProtectionBroker_->EvaluateEvent(event);
  }

  return ScanVerdict{};
}

}  // namespace antivirus::agent
