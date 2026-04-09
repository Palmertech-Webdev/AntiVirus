#include "EvidenceRecorder.h"

#include <filesystem>
#include <fstream>
#include <stdexcept>

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

}  // namespace

EvidenceRecorder::EvidenceRecorder(std::filesystem::path rootPath, std::filesystem::path databasePath)
    : rootPath_(std::move(rootPath)), databasePath_(ResolveDatabasePath(rootPath_, databasePath)) {}

EvidenceRecordResult EvidenceRecorder::RecordScanFinding(const ScanFinding& finding, const PolicySnapshot& policy,
                                                         const std::wstring& source) const {
  std::filesystem::create_directories(rootPath_);

  EvidenceRecordResult result{
      .recordId = GenerateGuidString(),
      .recordPath = rootPath_ / (GenerateGuidString() + L".json")};

  result.recordPath = rootPath_ / (result.recordId + L".json");

  std::ofstream output(result.recordPath, std::ios::trunc);
  if (!output.is_open()) {
    throw std::runtime_error("Unable to write a local evidence record");
  }

  output << "{\n";
  output << "  \"evidenceId\": \"" << EscapeJsonString(result.recordId) << "\",\n";
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
  output << "  \"disposition\": \"" << EscapeJsonString(VerdictDispositionToString(finding.verdict.disposition))
         << "\",\n";
  output << "  \"tacticId\": \"" << EscapeJsonString(finding.verdict.tacticId) << "\",\n";
  output << "  \"techniqueId\": \"" << EscapeJsonString(finding.verdict.techniqueId) << "\",\n";
  output << "  \"remediationStatus\": \"" << EscapeJsonString(RemediationStatusToString(finding.remediationStatus))
         << "\",\n";
  output << "  \"quarantineRecordId\": \"" << EscapeJsonString(finding.quarantineRecordId) << "\",\n";
  output << "  \"quarantinedPath\": \"" << EscapeJsonString(finding.quarantinedPath.wstring()) << "\",\n";
  output << "  \"remediationError\": \"" << EscapeJsonString(finding.remediationError) << "\"\n";
  output << "}\n";

  RuntimeDatabase(databasePath_).UpsertEvidenceRecord(EvidenceIndexRecord{
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
      .contentName = L""});
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
      .evidenceRecordId = result.recordId,
      .quarantineRecordId = finding.quarantineRecordId});

  return result;
}

}  // namespace antivirus::agent
