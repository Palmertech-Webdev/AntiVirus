#include "UpdaterService.h"

#include <Windows.h>

#include <algorithm>
#include <cwctype>
#include <fstream>
#include <optional>
#include <stdexcept>
#include <system_error>

#include "CryptoUtils.h"
#include "RuntimeDatabase.h"
#include "StringUtils.h"

namespace antivirus::agent {
namespace {

std::wstring ToLowerCopy(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return value;
}

std::wstring TrimWide(std::wstring value) {
  const auto first = value.find_first_not_of(L" \t\r\n");
  if (first == std::wstring::npos) {
    return {};
  }

  const auto last = value.find_last_not_of(L" \t\r\n");
  return value.substr(first, last - first + 1);
}

std::vector<std::wstring> SplitWide(const std::wstring& value, const wchar_t separator) {
  std::vector<std::wstring> parts;
  std::wstring current;
  for (const auto ch : value) {
    if (ch == separator) {
      parts.push_back(TrimWide(current));
      current.clear();
      continue;
    }

    current.push_back(ch);
  }

  parts.push_back(TrimWide(current));
  return parts;
}

bool ParseBoolText(const std::wstring& value) {
  const auto lower = ToLowerCopy(TrimWide(value));
  return lower == L"1" || lower == L"true" || lower == L"yes";
}

std::vector<std::wstring> SplitVersionTokens(const std::wstring& value) {
  std::vector<std::wstring> tokens;
  std::wstring current;
  for (const auto ch : value) {
    if ((ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'z') || (ch >= L'A' && ch <= L'Z')) {
      current.push_back(static_cast<wchar_t>(std::towlower(ch)));
      continue;
    }

    if (!current.empty()) {
      tokens.push_back(current);
      current.clear();
    }
  }

  if (!current.empty()) {
    tokens.push_back(current);
  }
  return tokens;
}

int CompareVersionStrings(const std::wstring& left, const std::wstring& right) {
  const auto leftTokens = SplitVersionTokens(left);
  const auto rightTokens = SplitVersionTokens(right);
  const auto limit = std::max(leftTokens.size(), rightTokens.size());

  for (std::size_t index = 0; index < limit; ++index) {
    const auto leftToken = index < leftTokens.size() ? leftTokens[index] : std::wstring(L"0");
    const auto rightToken = index < rightTokens.size() ? rightTokens[index] : std::wstring(L"0");

    const auto leftNumeric = std::all_of(leftToken.begin(), leftToken.end(), [](const wchar_t ch) { return iswdigit(ch) != 0; });
    const auto rightNumeric =
        std::all_of(rightToken.begin(), rightToken.end(), [](const wchar_t ch) { return iswdigit(ch) != 0; });
    if (leftNumeric && rightNumeric) {
      const auto leftValue = std::stoll(leftToken);
      const auto rightValue = std::stoll(rightToken);
      if (leftValue < rightValue) {
        return -1;
      }
      if (leftValue > rightValue) {
        return 1;
      }
      continue;
    }

    if (leftToken < rightToken) {
      return -1;
    }
    if (leftToken > rightToken) {
      return 1;
    }
  }

  return 0;
}

std::vector<std::wstring> LoadKeyList(const std::filesystem::path& path) {
  std::vector<std::wstring> values;
  std::wifstream input(path);
  if (!input.is_open()) {
    return values;
  }

  std::wstring line;
  while (std::getline(input, line)) {
    const auto trimmed = TrimWide(line);
    if (!trimmed.empty() && !trimmed.starts_with(L"#") && !trimmed.starts_with(L";")) {
      values.push_back(trimmed);
    }
  }
  return values;
}

std::vector<std::wstring> TrustedKeyIdsForPackageType(const AgentConfig& config, const std::wstring& packageType) {
  const auto lowerType = ToLowerCopy(packageType);
  const auto trustRoot = config.updateRootPath / L"trust";
  auto trusted = LoadKeyList((lowerType == L"rules" || lowerType == L"signatures")
                                 ? (trustRoot / L"content-trusted-key-ids.txt")
                                 : (trustRoot / L"platform-trusted-key-ids.txt"));
  if (!trusted.empty()) {
    return trusted;
  }

  if (lowerType == L"rules" || lowerType == L"signatures") {
    return {L"fenrir-content-prod-2026"};
  }
  return {L"fenrir-platform-prod-2026"};
}

bool SigningKeyRevoked(const AgentConfig& config, const std::wstring& signingKeyId) {
  const auto revoked = LoadKeyList(config.updateRootPath / L"trust" / L"revoked-key-ids.txt");
  return std::find(revoked.begin(), revoked.end(), signingKeyId) != revoked.end();
}

std::optional<std::wstring> LatestKnownPackageVersion(const RuntimeDatabase& database, const std::wstring& packageId) {
  const auto journal = database.ListUpdateJournal(100);
  std::optional<std::wstring> latest;
  for (const auto& record : journal) {
    if (record.packageId != packageId || record.targetVersion.empty()) {
      continue;
    }
    if (!latest.has_value() || CompareVersionStrings(record.targetVersion, *latest) > 0) {
      latest = record.targetVersion;
    }
  }
  return latest;
}

std::wstring NormalizePathForCompare(const std::filesystem::path& path) {
  auto normalized = std::filesystem::absolute(path).lexically_normal().wstring();
  normalized = ToLowerCopy(normalized);
  if (!normalized.empty() && normalized.back() != L'\\' && normalized.back() != L'/') {
    normalized.push_back(L'\\');
  }
  return normalized;
}

bool IsPathWithinRoot(const std::filesystem::path& candidate, const std::filesystem::path& root) {
  const auto normalizedCandidate = NormalizePathForCompare(candidate);
  const auto normalizedRoot = NormalizePathForCompare(root);
  return normalizedCandidate.starts_with(normalizedRoot);
}

std::filesystem::path ResolveTargetPath(const std::filesystem::path& targetPath, const std::filesystem::path& installRoot) {
  const auto resolved = targetPath.is_absolute() ? targetPath : (installRoot / targetPath);
  const auto normalized = std::filesystem::absolute(resolved).lexically_normal();
  if (!IsPathWithinRoot(normalized, installRoot)) {
    throw std::runtime_error("Update target path escaped the install root");
  }
  return normalized;
}

UpdateManifest LoadManifestFile(const std::filesystem::path& manifestPath, const std::filesystem::path& installRoot) {
  std::wifstream input(manifestPath);
  if (!input.is_open()) {
    throw std::runtime_error("Could not open the update manifest");
  }

  UpdateManifest manifest;
  manifest.manifestPath = std::filesystem::absolute(manifestPath);
  const auto manifestDirectory = manifest.manifestPath.parent_path();
  std::wstring line;
  while (std::getline(input, line)) {
    const auto trimmed = TrimWide(line);
    if (trimmed.empty() || trimmed.starts_with(L"#") || trimmed.starts_with(L";")) {
      continue;
    }

    const auto separator = trimmed.find(L'=');
    if (separator == std::wstring::npos) {
      continue;
    }

    const auto key = ToLowerCopy(TrimWide(trimmed.substr(0, separator)));
    const auto value = TrimWide(trimmed.substr(separator + 1));
    if (key == L"package_id") {
      manifest.packageId = value;
      continue;
    }

    if (key == L"package_type") {
      manifest.packageType = value;
      continue;
    }

    if (key == L"target_version") {
      manifest.targetVersion = value;
      continue;
    }

    if (key == L"channel") {
      manifest.channel = value;
      continue;
    }

    if (key == L"package_signer") {
      manifest.packageSigner = value;
      continue;
    }

    if (key == L"signing_key_id") {
      manifest.signingKeyId = value;
      continue;
    }

    if (key == L"allow_downgrade") {
      manifest.allowDowngrade = ParseBoolText(value);
      continue;
    }

    if (key == L"file") {
      const auto parts = SplitWide(value, L'|');
      if (parts.size() < 3) {
        throw std::runtime_error("Update manifest file entries require source|target|sha256");
      }

      UpdateFilePlan filePlan;
      filePlan.sourcePath = std::filesystem::absolute(manifestDirectory / parts[0]).lexically_normal();
      filePlan.targetPath = ResolveTargetPath(parts[1], installRoot);
      filePlan.sha256 = ToLowerCopy(parts[2]);
      filePlan.requiredSigner = parts.size() >= 4 ? parts[3] : manifest.packageSigner;
      filePlan.requireSignature =
          (parts.size() >= 5 && (ToLowerCopy(parts[4]) == L"1" || ToLowerCopy(parts[4]) == L"true")) ||
          !filePlan.requiredSigner.empty();
      manifest.files.push_back(std::move(filePlan));
    }
  }

  if (manifest.packageId.empty()) {
    manifest.packageId = manifest.manifestPath.stem().wstring();
  }
  if (manifest.packageType.empty()) {
    manifest.packageType = L"platform";
  }
  if (manifest.targetVersion.empty()) {
    manifest.targetVersion = L"unknown";
  }
  if (manifest.files.empty()) {
    throw std::runtime_error("Update manifest does not define any files");
  }

  return manifest;
}

void VerifyManifestPolicy(const UpdateManifest& manifest, const AgentConfig& config, const RuntimeDatabase& database) {
  static const std::vector<std::wstring> allowedPackageTypes = {L"platform", L"driver", L"rules", L"signatures"};
  static const std::vector<std::wstring> allowedChannels = {L"stable", L"beta", L"alpha", L"dev", L"lab"};

  const auto lowerType = ToLowerCopy(manifest.packageType);
  const auto lowerChannel = ToLowerCopy(manifest.channel);
  if (std::find(allowedPackageTypes.begin(), allowedPackageTypes.end(), lowerType) == allowedPackageTypes.end()) {
    throw std::runtime_error("Update manifest package type is not allowed");
  }
  if (manifest.channel.empty() ||
      std::find(allowedChannels.begin(), allowedChannels.end(), lowerChannel) == allowedChannels.end()) {
    throw std::runtime_error("Update manifest channel is not allowed");
  }
  if (manifest.packageSigner.empty()) {
    throw std::runtime_error("Update manifest must declare a package signer");
  }
  if (manifest.signingKeyId.empty()) {
    throw std::runtime_error("Update manifest must declare a signing key id");
  }
  if (SigningKeyRevoked(config, manifest.signingKeyId)) {
    throw std::runtime_error("Update manifest signing key has been revoked");
  }

  const auto trustedKeyIds = TrustedKeyIdsForPackageType(config, manifest.packageType);
  if (std::find(trustedKeyIds.begin(), trustedKeyIds.end(), manifest.signingKeyId) == trustedKeyIds.end()) {
    throw std::runtime_error("Update manifest signing key id is not trusted for this package type");
  }

  if (!manifest.allowDowngrade) {
    const auto baselineVersion =
        (lowerType == L"platform" || lowerType == L"driver")
            ? std::optional<std::wstring>(config.platformVersion)
            : LatestKnownPackageVersion(database, manifest.packageId);

    if (baselineVersion.has_value() && CompareVersionStrings(manifest.targetVersion, *baselineVersion) < 0) {
      throw std::runtime_error("Update manifest target version is lower than the current trusted baseline");
    }
  }
}

void VerifyPlan(const UpdateManifest& manifest) {
  for (const auto& file : manifest.files) {
    if (!std::filesystem::exists(file.sourcePath)) {
      throw std::runtime_error("Update source file is missing");
    }

    if (ToLowerCopy(ComputeFileSha256(file.sourcePath)) != ToLowerCopy(file.sha256)) {
      throw std::runtime_error("Update package hash verification failed");
    }

    if (file.requireSignature && !VerifyFileAuthenticodeSignature(file.sourcePath)) {
      throw std::runtime_error("Update package signature verification failed");
    }

    if (!file.requiredSigner.empty()) {
      const auto signer = ToLowerCopy(QueryFileSignerSubject(file.sourcePath));
      if (signer.find(ToLowerCopy(file.requiredSigner)) == std::wstring::npos) {
        throw std::runtime_error("Update package signer did not match the manifest requirement");
      }
    }
  }
}

std::filesystem::path RelativeTargetPath(const std::filesystem::path& targetPath, const std::filesystem::path& installRoot) {
  const auto relative = targetPath.lexically_relative(installRoot);
  return relative.empty() ? targetPath.filename() : relative;
}

bool CopyFileWithParents(const std::filesystem::path& sourcePath, const std::filesystem::path& targetPath) {
  std::error_code error;
  std::filesystem::create_directories(targetPath.parent_path(), error);
  error.clear();
  return std::filesystem::copy_file(sourcePath, targetPath, std::filesystem::copy_options::overwrite_existing, error) &&
         !error;
}

bool ApplySingleFile(const std::filesystem::path& stagedPath, const std::filesystem::path& targetPath,
                     const UpdateApplyMode mode, bool* restartRequired) {
  std::error_code error;
  std::filesystem::create_directories(targetPath.parent_path(), error);
  if (CopyFileW(stagedPath.c_str(), targetPath.c_str(), FALSE) != FALSE) {
    return true;
  }

  const auto lastError = GetLastError();
  if (mode == UpdateApplyMode::InService &&
      (lastError == ERROR_SHARING_VIOLATION || lastError == ERROR_ACCESS_DENIED || lastError == ERROR_USER_MAPPED_FILE)) {
    if (MoveFileExW(stagedPath.c_str(), targetPath.c_str(), MOVEFILE_DELAY_UNTIL_REBOOT | MOVEFILE_REPLACE_EXISTING) !=
        FALSE) {
      *restartRequired = true;
      return true;
    }
  }

  return false;
}

void RestoreBackupTree(const UpdateManifest& manifest, const std::filesystem::path& installRoot,
                       const std::filesystem::path& backupRoot, bool* restartRequired) {
  std::error_code error;
  for (const auto& file : manifest.files) {
    const auto relativeTarget = RelativeTargetPath(file.targetPath, installRoot);
    const auto backupPath = backupRoot / relativeTarget;
    if (std::filesystem::exists(backupPath)) {
      std::filesystem::create_directories(file.targetPath.parent_path(), error);
      error.clear();
      if (!std::filesystem::copy_file(backupPath, file.targetPath, std::filesystem::copy_options::overwrite_existing,
                                      error) &&
          error) {
        if (MoveFileExW(backupPath.c_str(), file.targetPath.c_str(),
                        MOVEFILE_DELAY_UNTIL_REBOOT | MOVEFILE_REPLACE_EXISTING) != FALSE) {
          *restartRequired = true;
          continue;
        }

        throw std::runtime_error("Rollback could not restore a protected file");
      }

      continue;
    }

    std::filesystem::remove(file.targetPath, error);
  }
}

}  // namespace

UpdaterService::UpdaterService(const AgentConfig& config, std::filesystem::path installRoot)
    : config_(config), installRoot_(std::filesystem::absolute(std::move(installRoot)).lexically_normal()) {}

UpdateResult UpdaterService::ApplyPackage(const std::filesystem::path& manifestPath, const UpdateApplyMode mode) const {
  RuntimeDatabase database(config_.runtimeDatabasePath);
  UpdateJournalRecord journal;
  journal.transactionId = GenerateGuidString();
  journal.startedAt = CurrentUtcTimestamp();
  journal.manifestPath = std::filesystem::absolute(manifestPath).lexically_normal();
  journal.backupRoot = config_.updateRootPath / L"backups" / journal.transactionId;
  journal.stagedRoot = config_.updateRootPath / L"staged" / journal.transactionId;
  journal.status = L"verifying";

  UpdateResult result;
  result.transactionId = journal.transactionId;

  try {
    const auto manifest = LoadManifestFile(manifestPath, installRoot_);
    VerifyManifestPolicy(manifest, config_, database);
    VerifyPlan(manifest);

    result.packageId = manifest.packageId;
    result.packageType = manifest.packageType;
    result.targetVersion = manifest.targetVersion;
    journal.packageId = manifest.packageId;
    journal.packageType = manifest.packageType;
    journal.targetVersion = manifest.targetVersion;
    database.UpsertUpdateJournal(journal);

    std::error_code error;
    std::filesystem::create_directories(journal.backupRoot, error);
    std::filesystem::create_directories(journal.stagedRoot, error);

    std::vector<std::filesystem::path> stagedFiles;
    stagedFiles.reserve(manifest.files.size());
    for (const auto& file : manifest.files) {
      const auto relativeTarget = RelativeTargetPath(file.targetPath, installRoot_);
      const auto stagedPath = journal.stagedRoot / relativeTarget;
      std::filesystem::create_directories(stagedPath.parent_path(), error);
      if (!CopyFileWithParents(file.sourcePath, stagedPath)) {
        throw std::runtime_error("Could not stage a verified update file");
      }
      stagedFiles.push_back(stagedPath);
    }

    journal.status = L"applying";
    database.UpsertUpdateJournal(journal);

    bool restartRequired = false;
    for (std::size_t index = 0; index < manifest.files.size(); ++index) {
      const auto& file = manifest.files[index];
      const auto relativeTarget = RelativeTargetPath(file.targetPath, installRoot_);
      const auto backupPath = journal.backupRoot / relativeTarget;

      if (std::filesystem::exists(file.targetPath)) {
        std::filesystem::create_directories(backupPath.parent_path(), error);
        if (!CopyFileWithParents(file.targetPath, backupPath)) {
          throw std::runtime_error("Could not back up an existing endpoint binary before update");
        }
      }

      if (!ApplySingleFile(stagedFiles[index], file.targetPath, mode, &restartRequired)) {
        result.rollbackAttempted = true;
        RestoreBackupTree(manifest, installRoot_, journal.backupRoot, &restartRequired);
        result.rollbackPerformed = true;
        throw std::runtime_error("Could not apply an update payload to the installation root");
      }
    }

    journal.completedAt = CurrentUtcTimestamp();
    journal.requiresRestart = restartRequired;
    journal.status = restartRequired ? L"pending_restart" : L"completed";
    journal.resultJson = std::wstring(L"{\"packageId\":\"") + manifest.packageId + L"\",\"targetVersion\":\"" +
                         manifest.targetVersion + L"\",\"restartRequired\":" +
                         (restartRequired ? std::wstring(L"true") : std::wstring(L"false")) + L"}";
    database.UpsertUpdateJournal(journal);

    result.success = true;
    result.restartRequired = restartRequired;
    result.status = journal.status;
    return result;
  } catch (const std::exception& error) {
    journal.completedAt = CurrentUtcTimestamp();
    journal.status = L"failed";
    journal.resultJson =
        std::wstring(L"{\"error\":\"") + Utf8ToWide(EscapeJsonString(Utf8ToWide(error.what()))) + L"\"}";
    database.UpsertUpdateJournal(journal);

    result.status = journal.status;
    result.errorMessage = Utf8ToWide(error.what());
    return result;
  }
}

UpdateResult UpdaterService::RollbackTransaction(const std::wstring& transactionId) const {
  RuntimeDatabase database(config_.runtimeDatabasePath);
  UpdateJournalRecord journal;
  if (!database.LoadUpdateJournal(transactionId, journal)) {
    return UpdateResult{
        .success = false,
        .transactionId = transactionId,
        .status = L"missing",
        .errorMessage = L"The requested update transaction could not be found."};
  }

  try {
    const auto manifest = LoadManifestFile(journal.manifestPath, installRoot_);
    bool restartRequired = false;
    RestoreBackupTree(manifest, installRoot_, journal.backupRoot, &restartRequired);

    journal.completedAt = CurrentUtcTimestamp();
    journal.status = restartRequired ? L"rolled_back_pending_restart" : L"rolled_back";
    journal.requiresRestart = restartRequired;
    journal.resultJson = std::wstring(L"{\"rolledBack\":true,\"restartRequired\":") +
                         (restartRequired ? std::wstring(L"true") : std::wstring(L"false")) + L"}";
    database.UpsertUpdateJournal(journal);

    return UpdateResult{
        .success = true,
        .restartRequired = restartRequired,
        .rollbackPerformed = true,
        .transactionId = journal.transactionId,
        .packageId = journal.packageId,
        .packageType = journal.packageType,
        .targetVersion = journal.targetVersion,
        .status = journal.status};
  } catch (const std::exception& error) {
    journal.completedAt = CurrentUtcTimestamp();
    journal.status = L"rollback_failed";
    journal.resultJson =
        std::wstring(L"{\"error\":\"") + Utf8ToWide(EscapeJsonString(Utf8ToWide(error.what()))) + L"\"}";
    database.UpsertUpdateJournal(journal);

    return UpdateResult{
        .success = false,
        .transactionId = journal.transactionId,
        .packageId = journal.packageId,
        .packageType = journal.packageType,
        .targetVersion = journal.targetVersion,
        .status = journal.status,
        .errorMessage = Utf8ToWide(error.what())};
  }
}

}  // namespace antivirus::agent
