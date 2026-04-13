#include "QuarantineStore.h"

#include <Windows.h>
#include <aclapi.h>

#include <array>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "RuntimeDatabase.h"
#include "StringUtils.h"

namespace antivirus::agent {
namespace {

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

std::optional<std::string> ExtractJsonString(const std::string& json, const std::string& key) {
  const std::regex pattern("\"" + EscapeRegex(key) + "\"\\s*:\\s*\"((?:\\\\.|[^\"])*)\"");
  std::smatch match;
  if (std::regex_search(json, match, pattern)) {
    return UnescapeJsonString(match[1].str());
  }

  return std::nullopt;
}

std::optional<std::uintmax_t> ExtractJsonNumber(const std::string& json, const std::string& key) {
  const std::regex pattern("\"" + EscapeRegex(key) + "\"\\s*:\\s*(\\d+)");
  std::smatch match;
  if (std::regex_search(json, match, pattern)) {
    return static_cast<std::uintmax_t>(std::stoull(match[1].str()));
  }

  return std::nullopt;
}

std::filesystem::path BuildQuarantineFilePath(const std::filesystem::path& rootPath, const std::wstring& recordId,
                                              const std::filesystem::path& originalPath) {
  const auto extension = originalPath.extension().wstring();
  const auto fileName = extension.empty() ? recordId + L".quarantine" : recordId + extension + L".quarantine";
  return rootPath / L"files" / fileName;
}

void WriteMetadata(const std::filesystem::path& rootPath, const std::wstring& recordId, const ScanFinding& finding,
                   const std::filesystem::path& quarantinedPath, const std::wstring& localStatus) {
  const auto metadataDirectory = rootPath / L"records";
  std::filesystem::create_directories(metadataDirectory);

  const auto metadataPath = metadataDirectory / (recordId + L".json");
  std::ofstream output(metadataPath, std::ios::trunc);
  if (!output.is_open()) {
    throw std::runtime_error("Unable to write quarantine metadata");
  }

  output << "{\n";
  output << "  \"recordId\": \"" << EscapeJsonString(recordId) << "\",\n";
  output << "  \"capturedAt\": \"" << EscapeJsonString(CurrentUtcTimestamp()) << "\",\n";
  output << "  \"originalPath\": \"" << EscapeJsonString(finding.path.wstring()) << "\",\n";
  output << "  \"quarantinedPath\": \"" << EscapeJsonString(quarantinedPath.wstring()) << "\",\n";
  output << "  \"sha256\": \"" << EscapeJsonString(finding.sha256) << "\",\n";
  output << "  \"sizeBytes\": " << finding.sizeBytes << ",\n";
  output << "  \"disposition\": \"" << EscapeJsonString(VerdictDispositionToString(finding.verdict.disposition))
         << "\",\n";
  output << "  \"techniqueId\": \"" << EscapeJsonString(finding.verdict.techniqueId) << "\",\n";
  output << "  \"localStatus\": \"" << EscapeJsonString(localStatus) << "\"\n";
  output << "}\n";
}

void WriteMetadata(const std::filesystem::path& rootPath, const QuarantineEntry& entry) {
  const auto metadataDirectory = rootPath / L"records";
  std::filesystem::create_directories(metadataDirectory);

  const auto metadataPath = metadataDirectory / (entry.recordId + L".json");
  std::ofstream output(metadataPath, std::ios::trunc);
  if (!output.is_open()) {
    throw std::runtime_error("Unable to write quarantine metadata");
  }

  output << "{\n";
  output << "  \"recordId\": \"" << EscapeJsonString(entry.recordId) << "\",\n";
  output << "  \"capturedAt\": \"" << EscapeJsonString(CurrentUtcTimestamp()) << "\",\n";
  output << "  \"originalPath\": \"" << EscapeJsonString(entry.originalPath.wstring()) << "\",\n";
  output << "  \"quarantinedPath\": \"" << EscapeJsonString(entry.quarantinedPath.wstring()) << "\",\n";
  output << "  \"sha256\": \"" << EscapeJsonString(entry.sha256) << "\",\n";
  output << "  \"sizeBytes\": " << entry.sizeBytes << ",\n";
  output << "  \"techniqueId\": \"" << EscapeJsonString(entry.techniqueId) << "\",\n";
  output << "  \"localStatus\": \"" << EscapeJsonString(entry.localStatus) << "\"\n";
  output << "}\n";
}

std::string ReadMetadataFile(const std::filesystem::path& metadataPath) {
  std::ifstream input(metadataPath);
  if (!input.is_open()) {
    throw std::runtime_error("Unable to open quarantine metadata");
  }

  std::ostringstream buffer;
  buffer << input.rdbuf();
  return buffer.str();
}

std::filesystem::path ResolveDatabasePath(const std::filesystem::path& rootPath, const std::filesystem::path& databasePath) {
  if (!databasePath.empty()) {
    return databasePath;
  }

  return rootPath.parent_path() / L"agent-runtime.db";
}

bool ScheduleDeleteOnReboot(const std::filesystem::path& path) {
  return MoveFileExW(path.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT) != FALSE;
}

bool CreateKnownSid(const WELL_KNOWN_SID_TYPE type, std::array<BYTE, SECURITY_MAX_SID_SIZE>& buffer, PSID* sid) {
  DWORD size = static_cast<DWORD>(buffer.size());
  if (CreateWellKnownSid(type, nullptr, buffer.data(), &size) == FALSE) {
    return false;
  }

  *sid = buffer.data();
  return true;
}

bool LockDownPathForSystemOnly(const std::filesystem::path& path) {
  std::array<BYTE, SECURITY_MAX_SID_SIZE> systemBuffer{};
  PSID systemSid = nullptr;
  if (!CreateKnownSid(WinLocalSystemSid, systemBuffer, &systemSid)) {
    return false;
  }

  EXPLICIT_ACCESSW systemAccess{};
  systemAccess.grfAccessPermissions = GENERIC_ALL;
  systemAccess.grfAccessMode = SET_ACCESS;
  systemAccess.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
  systemAccess.Trustee.TrusteeForm = TRUSTEE_IS_SID;
  systemAccess.Trustee.TrusteeType = TRUSTEE_IS_USER;
  systemAccess.Trustee.ptstrName = static_cast<LPWSTR>(systemSid);

  PACL acl = nullptr;
  const auto aclStatus = SetEntriesInAclW(1, &systemAccess, nullptr, &acl);
  if (aclStatus != ERROR_SUCCESS) {
    return false;
  }

  const auto securityStatus = SetNamedSecurityInfoW(
      const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT,
      DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, acl, nullptr);
  LocalFree(acl);
  return securityStatus == ERROR_SUCCESS;
}

struct NeutralizationVerification {
  bool neutralized{false};
  bool originalPresent{false};
  std::wstring localStatus;
  std::wstring detail;
};

std::mutex gQuarantineJournalMutex;

bool CanOpenForExecution(const std::filesystem::path& path) {
  const HANDLE handle =
      CreateFileW(path.c_str(), FILE_EXECUTE | FILE_READ_ATTRIBUTES,
                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                  FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    return false;
  }

  CloseHandle(handle);
  return true;
}

NeutralizationVerification VerifyNeutralizationState(const std::filesystem::path& originalPath,
                                                     const std::wstring& currentStatus) {
  std::error_code existsError;
  const bool originalPresent = std::filesystem::exists(originalPath, existsError);
  if (existsError) {
    return NeutralizationVerification{
        .neutralized = false,
        .originalPresent = true,
        .localStatus = L"quarantined-verification-error",
        .detail = L"Fenrir could not verify the original path after quarantine."};
  }

  if (!originalPresent) {
    return NeutralizationVerification{
        .neutralized = true,
        .originalPresent = false,
        .localStatus = L"quarantined-verified-removed",
        .detail = L"Original artifact removed from the source path."};
  }

  if (_wcsicmp(currentStatus.c_str(), L"quarantined-pending-delete") == 0) {
    return NeutralizationVerification{
        .neutralized = true,
        .originalPresent = true,
        .localStatus = L"quarantined-pending-delete",
        .detail = L"Original artifact remains on disk until the scheduled reboot deletion executes."};
  }

  if (_wcsicmp(currentStatus.c_str(), L"quarantined-locked") == 0) {
    if (!CanOpenForExecution(originalPath)) {
      return NeutralizationVerification{
          .neutralized = true,
          .originalPresent = true,
          .localStatus = L"quarantined-verified-locked",
          .detail = L"Original artifact path remains but execution access is blocked by lockdown."};
    }

    return NeutralizationVerification{
        .neutralized = false,
        .originalPresent = true,
        .localStatus = L"quarantined-locked-unverified",
        .detail = L"Original artifact is still executable after lockdown and requires additional remediation."};
  }

  if (ScheduleDeleteOnReboot(originalPath)) {
    return NeutralizationVerification{
        .neutralized = true,
        .originalPresent = true,
        .localStatus = L"quarantined-pending-delete",
        .detail = L"Original artifact was still present; Fenrir scheduled delete-on-reboot."};
  }

  return NeutralizationVerification{
      .neutralized = false,
      .originalPresent = true,
      .localStatus = L"quarantined-original-still-present",
      .detail = L"Original artifact is still present after quarantine and no delete-on-reboot fallback was applied."};
}

void AppendQuarantineJournalEntry(const std::filesystem::path& rootPath, const std::wstring& action,
                                  const std::wstring& recordId, const std::filesystem::path& originalPath,
                                  const std::filesystem::path& quarantinedPath, const std::wstring& localStatus,
                                  const bool success, const std::wstring& detail) {
  const std::scoped_lock lock(gQuarantineJournalMutex);

  std::error_code createError;
  const auto recordsDirectory = rootPath / L"records";
  std::filesystem::create_directories(recordsDirectory, createError);
  if (createError) {
    return;
  }

  std::ofstream output(recordsDirectory / L"quarantine-journal.jsonl", std::ios::binary | std::ios::app);
  if (!output.is_open()) {
    return;
  }

  const std::wstring line = L"{\"recordedAt\":\"" + CurrentUtcTimestamp() + L"\",\"action\":\"" +
                            Utf8ToWide(EscapeJsonString(action)) + L"\",\"recordId\":\"" +
                            Utf8ToWide(EscapeJsonString(recordId)) + L"\",\"originalPath\":\"" +
                            Utf8ToWide(EscapeJsonString(originalPath.wstring())) + L"\",\"quarantinedPath\":\"" +
                            Utf8ToWide(EscapeJsonString(quarantinedPath.wstring())) + L"\",\"localStatus\":\"" +
                            Utf8ToWide(EscapeJsonString(localStatus)) + L"\",\"success\":" +
                            (success ? L"true" : L"false") + L",\"detail\":\"" +
                            Utf8ToWide(EscapeJsonString(detail)) + L"\"}\n";
  const auto utf8Line = WideToUtf8(line);
  output.write(utf8Line.data(), static_cast<std::streamsize>(utf8Line.size()));
}

}  // namespace

QuarantineStore::QuarantineStore(std::filesystem::path rootPath, std::filesystem::path databasePath)
    : rootPath_(std::move(rootPath)), databasePath_(ResolveDatabasePath(rootPath_, databasePath)) {}

QuarantineResult QuarantineStore::QuarantineFile(const ScanFinding& finding) const {
  QuarantineResult result{
      .attempted = true,
      .success = false,
      .neutralized = false,
      .originalArtifactPresent = false,
      .recordId = GenerateGuidString(),
      .quarantinedPath = {},
      .localStatus = L"quarantine-failed",
      .verificationDetail = {},
      .errorMessage = {}};

  try {
    std::filesystem::create_directories(rootPath_ / L"files");
    const auto destinationPath = BuildQuarantineFilePath(rootPath_, result.recordId, finding.path);
    auto localStatus = L"quarantined";

    std::error_code error;
    std::filesystem::rename(finding.path, destinationPath, error);
    if (error) {
      error.clear();
      std::filesystem::copy_file(finding.path, destinationPath, std::filesystem::copy_options::overwrite_existing,
                                 error);
      if (error) {
        throw std::runtime_error("Copy to quarantine failed");
      }

      error.clear();
      std::filesystem::remove(finding.path, error);
      if (error) {
        const auto locked = LockDownPathForSystemOnly(finding.path);
        const auto scheduled = ScheduleDeleteOnReboot(finding.path);
        localStatus = scheduled ? L"quarantined-pending-delete" : L"quarantined-locked";
        if (!locked && !scheduled) {
          throw std::runtime_error("Original file could not be removed or locked after quarantine copy");
        }
      }
    }

    const auto verification = VerifyNeutralizationState(finding.path, localStatus);
    result.localStatus = verification.localStatus;
    result.neutralized = verification.neutralized;
    result.originalArtifactPresent = verification.originalPresent;
    result.verificationDetail = verification.detail;

    WriteMetadata(rootPath_, result.recordId, finding, destinationPath, result.localStatus);
    RuntimeDatabase(databasePath_).UpsertQuarantineRecord(QuarantineIndexRecord{
        .recordId = result.recordId,
        .capturedAt = CurrentUtcTimestamp(),
        .originalPath = finding.path,
        .quarantinedPath = destinationPath,
        .sha256 = finding.sha256,
        .sizeBytes = finding.sizeBytes,
        .techniqueId = finding.verdict.techniqueId,
        .localStatus = result.localStatus});
    result.success = result.neutralized;
    result.quarantinedPath = destinationPath;
    if (!result.success) {
      result.errorMessage = result.verificationDetail.empty()
                                ? L"Fenrir could not verify original artifact neutralization after quarantine."
                                : result.verificationDetail;
    }
    AppendQuarantineJournalEntry(
        rootPath_, L"quarantine", result.recordId, finding.path, destinationPath, result.localStatus, result.success,
        result.success ? L"Fenrir quarantined and verified the artifact." : result.errorMessage);
    return result;
  } catch (const std::exception& error) {
    result.errorMessage = Utf8ToWide(error.what());
    AppendQuarantineJournalEntry(rootPath_, L"quarantine", result.recordId, finding.path, result.quarantinedPath,
                                 result.localStatus, false, result.errorMessage);
    return result;
  }
}

QuarantineEntry QuarantineStore::LoadEntry(const std::wstring& recordId) const {
  QuarantineIndexRecord indexedRecord;
  if (RuntimeDatabase(databasePath_).LoadQuarantineRecord(recordId, indexedRecord)) {
    return QuarantineEntry{
        .recordId = indexedRecord.recordId,
        .originalPath = indexedRecord.originalPath,
        .quarantinedPath = indexedRecord.quarantinedPath,
        .sha256 = indexedRecord.sha256,
        .sizeBytes = indexedRecord.sizeBytes,
        .techniqueId = indexedRecord.techniqueId,
        .localStatus = indexedRecord.localStatus};
  }

  const auto metadataPath = rootPath_ / L"records" / (recordId + L".json");
  const auto rawJson = ReadMetadataFile(metadataPath);

  QuarantineEntry entry{
      .recordId = recordId,
      .originalPath = Utf8ToWide(ExtractJsonString(rawJson, "originalPath").value_or("")),
      .quarantinedPath = Utf8ToWide(ExtractJsonString(rawJson, "quarantinedPath").value_or("")),
      .sha256 = Utf8ToWide(ExtractJsonString(rawJson, "sha256").value_or("")),
      .sizeBytes = ExtractJsonNumber(rawJson, "sizeBytes").value_or(0),
      .techniqueId = Utf8ToWide(ExtractJsonString(rawJson, "techniqueId").value_or("")),
      .localStatus = Utf8ToWide(ExtractJsonString(rawJson, "localStatus").value_or("quarantined"))};

  if (entry.originalPath.empty() || entry.quarantinedPath.empty()) {
    throw std::runtime_error("Quarantine metadata is missing required file paths");
  }

  RuntimeDatabase(databasePath_).UpsertQuarantineRecord(QuarantineIndexRecord{
      .recordId = entry.recordId,
      .capturedAt = CurrentUtcTimestamp(),
      .originalPath = entry.originalPath,
      .quarantinedPath = entry.quarantinedPath,
      .sha256 = entry.sha256,
      .sizeBytes = entry.sizeBytes,
      .techniqueId = entry.techniqueId,
      .localStatus = entry.localStatus});

  return entry;
}

QuarantineActionResult QuarantineStore::RestoreFile(const std::wstring& recordId) const {
  QuarantineActionResult result{
      .success = false,
      .recordId = recordId,
      .originalPath = {},
      .quarantinedPath = {},
      .errorMessage = {}};

  try {
    auto entry = LoadEntry(recordId);
    result.originalPath = entry.originalPath;
    result.quarantinedPath = entry.quarantinedPath;

    auto restorePolicy = CreateDefaultPolicySnapshot();
    restorePolicy.cloudLookupEnabled = false;
    const auto finding = ScanFile(entry.quarantinedPath, restorePolicy);
    if (finding.has_value() &&
        (finding->verdict.disposition == VerdictDisposition::Block ||
         finding->verdict.disposition == VerdictDisposition::Quarantine)) {
      throw std::runtime_error("Restore blocked because the quarantined artifact still scores as malicious");
    }

    std::filesystem::create_directories(entry.originalPath.parent_path());
    std::error_code error;
    std::filesystem::rename(entry.quarantinedPath, entry.originalPath, error);
    if (error) {
      error.clear();
      std::filesystem::copy_file(entry.quarantinedPath, entry.originalPath,
                                 std::filesystem::copy_options::overwrite_existing, error);
      if (error) {
        throw std::runtime_error("Unable to restore the quarantined file");
      }

      error.clear();
      std::filesystem::remove(entry.quarantinedPath, error);
      if (error) {
        throw std::runtime_error("Unable to remove the quarantined copy after restore");
      }
    }

    entry.localStatus = L"restored";
    WriteMetadata(rootPath_, entry);
    RuntimeDatabase(databasePath_).UpsertQuarantineRecord(QuarantineIndexRecord{
        .recordId = entry.recordId,
        .capturedAt = CurrentUtcTimestamp(),
        .originalPath = entry.originalPath,
        .quarantinedPath = entry.quarantinedPath,
        .sha256 = entry.sha256,
        .sizeBytes = entry.sizeBytes,
        .techniqueId = entry.techniqueId,
        .localStatus = entry.localStatus});
    result.success = true;
    result.quarantinedPath = entry.quarantinedPath;
    AppendQuarantineJournalEntry(rootPath_, L"restore", entry.recordId, entry.originalPath, entry.quarantinedPath,
                                 entry.localStatus, true, L"Fenrir restored the quarantined artifact.");
    return result;
  } catch (const std::exception& error) {
    result.errorMessage = Utf8ToWide(error.what());
    AppendQuarantineJournalEntry(rootPath_, L"restore", result.recordId, result.originalPath, result.quarantinedPath,
                                 L"restore-failed", false, result.errorMessage);
    return result;
  }
}

QuarantineActionResult QuarantineStore::DeleteRecord(const std::wstring& recordId) const {
  QuarantineActionResult result{
      .success = false,
      .recordId = recordId,
      .originalPath = {},
      .quarantinedPath = {},
      .errorMessage = {}};

  try {
    auto entry = LoadEntry(recordId);
    result.originalPath = entry.originalPath;
    result.quarantinedPath = entry.quarantinedPath;

    std::error_code error;
    std::filesystem::remove(entry.quarantinedPath, error);
    if (error) {
      throw std::runtime_error("Unable to delete the quarantined file");
    }

    entry.localStatus = L"deleted";
    entry.quarantinedPath.clear();
    WriteMetadata(rootPath_, entry);
    RuntimeDatabase(databasePath_).UpsertQuarantineRecord(QuarantineIndexRecord{
        .recordId = entry.recordId,
        .capturedAt = CurrentUtcTimestamp(),
        .originalPath = entry.originalPath,
        .quarantinedPath = entry.quarantinedPath,
        .sha256 = entry.sha256,
        .sizeBytes = entry.sizeBytes,
        .techniqueId = entry.techniqueId,
        .localStatus = entry.localStatus});
    result.success = true;
    result.quarantinedPath = std::filesystem::path();
    AppendQuarantineJournalEntry(rootPath_, L"delete", entry.recordId, entry.originalPath, result.quarantinedPath,
                                 entry.localStatus, true, L"Fenrir deleted the quarantined artifact record.");
    return result;
  } catch (const std::exception& error) {
    result.errorMessage = Utf8ToWide(error.what());
    AppendQuarantineJournalEntry(rootPath_, L"delete", result.recordId, result.originalPath, result.quarantinedPath,
                                 L"delete-failed", false, result.errorMessage);
    return result;
  }
}

}  // namespace antivirus::agent
