#include "EvidenceRecorder.h"

#include <algorithm>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <set>
#include <system_error>
#include <vector>

#include "RuntimeDatabase.h"
#include "StringUtils.h"

namespace antivirus::agent {

namespace {

std::filesystem::path ResolveDatabasePath(const std::filesystem::path& rootPath, const std::filesystem::path& databasePath) {
  if (!databasePath.empty()) {
    return databasePath;
  }

  return rootPath.parent_path() / L"agent-runtime.db";
}

std::wstring NormalizePathKey(const std::filesystem::path& value) {
  if (value.empty()) {
    return {};
  }

  std::error_code error;
  auto normalized = std::filesystem::absolute(value, error);
  if (error) {
    normalized = value;
  }
  auto key = normalized.lexically_normal().wstring();
  std::transform(key.begin(), key.end(), key.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  std::replace(key.begin(), key.end(), L'/', L'\\');
  return key;
}

std::vector<std::filesystem::path> ResolveEvidenceRoots(const std::filesystem::path& preferredRoot) {
  std::vector<std::filesystem::path> roots;
  std::set<std::wstring> seen;

  const auto addRoot = [&](const std::filesystem::path& root) {
    if (root.empty()) {
      return;
    }

    const auto key = NormalizePathKey(root);
    if (key.empty() || !seen.insert(key).second) {
      return;
    }

    std::error_code error;
    auto normalized = std::filesystem::absolute(root, error);
    if (error) {
      normalized = root;
    }
    roots.push_back(normalized.lexically_normal());
  };

  addRoot(preferredRoot);

  const auto programData = ReadEnvironmentVariable(L"PROGRAMDATA");
  if (!programData.empty()) {
    addRoot(std::filesystem::path(programData) / L"FenrirAgent" / L"runtime" / L"evidence");
  }

  const auto localAppData = ReadEnvironmentVariable(L"LOCALAPPDATA");
  if (!localAppData.empty()) {
    addRoot(std::filesystem::path(localAppData) / L"FenrirAgent" / L"runtime" / L"evidence");
  }

  return roots;
}

bool TryWriteEvidenceRecord(const std::filesystem::path& recordPath, const ScanFinding& finding, const PolicySnapshot& policy,
                            const std::wstring& source, const std::wstring& recordId) {
  std::ofstream output(recordPath, std::ios::trunc);
  if (!output.is_open()) {
    return false;
  }

  output << "{\n";
  output << "  \"evidenceId\": \"" << EscapeJsonString(recordId) << "\",\n";
  output << "  \"recordedAt\": \"" << EscapeJsonString(CurrentUtcTimestamp()) << "\",\n";
  output << "  \"source\": \"" << EscapeJsonString(source) << "\",\n";
  output << "  \"policyRevision\": \"" << EscapeJsonString(policy.revision) << "\",\n";
  output << "  \"path\": \"" << EscapeJsonString(finding.path.wstring()) << "\",\n";
  output << "  \"sizeBytes\": " << finding.sizeBytes << ",\n";
  output << "  \"sha256\": \"" << EscapeJsonString(finding.sha256) << "\",\n";
  output << "  \"contentType\": \"" << EscapeJsonString(finding.contentType) << "\",\n";
  output << "  \"reputation\": \"" << EscapeJsonString(finding.reputation) << "\",\n";
  output << "  \"signer\": \"" << EscapeJsonString(finding.signer) << "\",\n";
  output << "  \"heuristicScore\": " << finding.heuristicScore << ",\n";
  output << "  \"archiveEntryCount\": " << finding.archiveEntryCount << ",\n";
  output << "  \"disposition\": \"" << EscapeJsonString(VerdictDispositionToString(finding.verdict.disposition)) << "\",\n";
  output << "  \"tacticId\": \"" << EscapeJsonString(finding.verdict.tacticId) << "\",\n";
  output << "  \"techniqueId\": \"" << EscapeJsonString(finding.verdict.techniqueId) << "\",\n";
  output << "  \"remediationStatus\": \"" << EscapeJsonString(RemediationStatusToString(finding.remediationStatus)) << "\",\n";
  output << "  \"quarantineRecordId\": \"" << EscapeJsonString(finding.quarantineRecordId) << "\",\n";
  output << "  \"quarantinedPath\": \"" << EscapeJsonString(finding.quarantinedPath.wstring()) << "\",\n";
  output << "  \"remediationError\": \"" << EscapeJsonString(finding.remediationError) << "\",\n";
  output << "  \"alertTitle\": \"" << EscapeJsonString(finding.alertTitle) << "\",\n";
  output << "  \"alertSummary\": \"" << EscapeJsonString(finding.alertSummary) << "\",\n";
  output << "  \"originContext\": " << WideToUtf8(SerializeContentOriginContext(finding.originContext)) << ",\n";
  output << "  \"reasons\": [\n";
  for (std::size_t index = 0; index < finding.verdict.reasons.size(); ++index) {
    const auto& reason = finding.verdict.reasons[index];
    output << "    {\"code\": \"" << EscapeJsonString(reason.code) << "\", \"message\": \""
           << EscapeJsonString(reason.message) << "\"}";
    if (index + 1 != finding.verdict.reasons.size()) {
      output << ",";
    }
    output << "\n";
  }
  output << "  ],\n";
  output << "  \"timeline\": [\n";
  output << "    {\"phase\": \"detection\", \"recordedAt\": \"" << EscapeJsonString(CurrentUtcTimestamp())
         << "\", \"summary\": \"" << EscapeJsonString(VerdictDispositionToString(finding.verdict.disposition)) << "\"},\n";
  output << "    {\"phase\": \"remediation\", \"recordedAt\": \"" << EscapeJsonString(CurrentUtcTimestamp())
         << "\", \"summary\": \"" << EscapeJsonString(RemediationStatusToString(finding.remediationStatus)) << "\"}\n";
  output << "  ]\n";
  output << "}\n";
  output.flush();
  return output.good();
}

}  // namespace

EvidenceRecorder::EvidenceRecorder(std::filesystem::path rootPath, std::filesystem::path databasePath)
    : rootPath_(std::move(rootPath)), databasePath_(ResolveDatabasePath(rootPath_, databasePath)) {}

EvidenceRecordResult EvidenceRecorder::RecordScanFinding(const ScanFinding& finding, const PolicySnapshot& policy,
                                                         const std::wstring& source) const {
  EvidenceRecordResult result{
      .recordId = GenerateGuidString(),
      .recordPath = {}};

  for (const auto& root : ResolveEvidenceRoots(rootPath_)) {
    std::error_code error;
    std::filesystem::create_directories(root, error);
    if (error) {
      continue;
    }

    const auto candidatePath = root / (result.recordId + L".json");
    if (TryWriteEvidenceRecord(candidatePath, finding, policy, source, result.recordId)) {
      result.recordPath = candidatePath;
      break;
    }
  }

  RuntimeDatabase database(databasePath_);
  if (!result.recordPath.empty()) {
    database.UpsertEvidenceRecord(EvidenceIndexRecord{
        .recordId = result.recordId,
        .recordedAt = CurrentUtcTimestamp(),
        .source = source,
        .recordPath = result.recordPath,
        .subjectPath = finding.path,
        .sha256 = finding.sha256,
        .disposition = VerdictDispositionToString(finding.verdict.disposition),
        .tacticId = finding.verdict.tacticId,
        .techniqueId = finding.verdict.techniqueId,
        .appName = L"",
        .contentName = L"",
        .alertTitle = finding.alertTitle,
        .contextType = finding.originContext.channel,
        .sourceApplication = finding.originContext.sourceApplication,
        .originReference = !finding.originContext.sourceDomain.empty() ? finding.originContext.sourceDomain
                                                                       : finding.originContext.navigationType,
        .contextJson = SerializeContentOriginContext(finding.originContext)});
  }

  const auto evidenceRecordId = result.recordPath.empty() ? std::wstring{} : result.recordId;

  RuntimeDatabase(databasePath_).RecordScanHistory(ScanHistoryRecord{
      .recordedAt = CurrentUtcTimestamp(),
      .source = source,
      .subjectPath = finding.path,
      .sha256 = finding.sha256,
      .contentType = finding.contentType,
      .reputation = finding.reputation,
      .disposition = VerdictDispositionToString(finding.verdict.disposition),
      .confidence = finding.verdict.confidence,
      .tacticId = finding.verdict.tacticId,
      .techniqueId = finding.verdict.techniqueId,
      .remediationStatus = RemediationStatusToString(finding.remediationStatus),
      .evidenceRecordId = evidenceRecordId,
      .quarantineRecordId = finding.quarantineRecordId,
      .alertTitle = finding.alertTitle,
      .contextType = finding.originContext.channel,
      .sourceApplication = finding.originContext.sourceApplication,
      .originReference = !finding.originContext.sourceDomain.empty() ? finding.originContext.sourceDomain
                                                                     : finding.originContext.navigationType,
      .contextJson = SerializeContentOriginContext(finding.originContext)});

  if (result.recordPath.empty()) {
    result.recordId.clear();
  }

  return result;
}

}  // namespace antivirus::agent
