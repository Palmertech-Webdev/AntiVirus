#include "QuarantineStore.h"

#include <filesystem>
#include <fstream>
#include <optional>
#include <regex>
#include <sstream>
#include <stdexcept>

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

}  // namespace

QuarantineStore::QuarantineStore(std::filesystem::path rootPath, std::filesystem::path databasePath)
    : rootPath_(std::move(rootPath)), databasePath_(ResolveDatabasePath(rootPath_, databasePath)) {}

QuarantineResult QuarantineStore::QuarantineFile(const ScanFinding& finding) const {
  QuarantineResult result{
      .attempted = true,
      .success = false,
      .recordId = GenerateGuidString(),
      .quarantinedPath = {},
      .errorMessage = {}};

  try {
    std::filesystem::create_directories(rootPath_ / L"files");
    const auto destinationPath = BuildQuarantineFilePath(rootPath_, result.recordId, finding.path);

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
        std::filesystem::remove(destinationPath, error);
        throw std::runtime_error("Removing the original file after quarantine copy failed");
      }
    }

    WriteMetadata(rootPath_, result.recordId, finding, destinationPath, L"quarantined");
    RuntimeDatabase(databasePath_).UpsertQuarantineRecord(QuarantineIndexRecord{
        .recordId = result.recordId,
        .capturedAt = CurrentUtcTimestamp(),
        .originalPath = finding.path,
        .quarantinedPath = destinationPath,
        .sha256 = finding.sha256,
        .sizeBytes = finding.sizeBytes,
        .techniqueId = finding.verdict.techniqueId,
        .localStatus = L"quarantined"});
    result.success = true;
    result.quarantinedPath = destinationPath;
    return result;
  } catch (const std::exception& error) {
    result.errorMessage = Utf8ToWide(error.what());
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
    return result;
  } catch (const std::exception& error) {
    result.errorMessage = Utf8ToWide(error.what());
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
    return result;
  } catch (const std::exception& error) {
    result.errorMessage = Utf8ToWide(error.what());
    return result;
  }
}

}  // namespace antivirus::agent
