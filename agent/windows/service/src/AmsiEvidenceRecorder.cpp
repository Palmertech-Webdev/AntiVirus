#include "AmsiEvidenceRecorder.h"

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

AmsiEvidenceRecorder::AmsiEvidenceRecorder(std::filesystem::path rootPath, std::filesystem::path databasePath)
    : rootPath_(std::move(rootPath)), databasePath_(ResolveDatabasePath(rootPath_, databasePath)) {}

AmsiEvidenceRecordResult AmsiEvidenceRecorder::RecordInspection(const AmsiContentRequest& request,
                                                                const AmsiInspectionOutcome& outcome,
                                                                const PolicySnapshot& policy,
                                                                const std::wstring& source) const {
  std::filesystem::create_directories(rootPath_);

  AmsiEvidenceRecordResult result{
      .recordId = GenerateGuidString(),
      .recordPath = rootPath_ / (GenerateGuidString() + L".json")};

  result.recordPath = rootPath_ / (result.recordId + L".json");

  std::ofstream output(result.recordPath, std::ios::trunc);
  if (!output.is_open()) {
    throw std::runtime_error("Unable to write an AMSI evidence record");
  }

  output << "{\n";
  output << "  \"evidenceId\": \"" << EscapeJsonString(result.recordId) << "\",\n";
  output << "  \"recordedAt\": \"" << EscapeJsonString(CurrentUtcTimestamp()) << "\",\n";
  output << "  \"source\": \"" << EscapeJsonString(source) << "\",\n";
  output << "  \"policyRevision\": \"" << EscapeJsonString(policy.revision) << "\",\n";
  output << "  \"appName\": \"" << EscapeJsonString(outcome.appName) << "\",\n";
  output << "  \"contentName\": \"" << EscapeJsonString(outcome.contentName) << "\",\n";
  output << "  \"sessionId\": " << outcome.sessionId << ",\n";
  output << "  \"quiet\": " << (request.quiet ? "true" : "false") << ",\n";
  output << "  \"sourceType\": \"" << (request.source == AmsiContentSource::Notify ? "notify" : "stream") << "\",\n";
  output << "  \"contentLength\": " << request.content.size() << ",\n";
  output << "  \"preview\": \"" << EscapeJsonString(outcome.preview) << "\",\n";
  output << "  \"sha256\": \"" << EscapeJsonString(outcome.finding.sha256) << "\",\n";
  output << "  \"disposition\": \"" << EscapeJsonString(VerdictDispositionToString(outcome.finding.verdict.disposition))
         << "\",\n";
  output << "  \"tacticId\": \"" << EscapeJsonString(outcome.finding.verdict.tacticId) << "\",\n";
  output << "  \"techniqueId\": \"" << EscapeJsonString(outcome.finding.verdict.techniqueId) << "\",\n";
  output << "  \"remediationStatus\": \"" << EscapeJsonString(RemediationStatusToString(outcome.finding.remediationStatus))
         << "\",\n";
  output << "  \"quarantineRecordId\": \"" << EscapeJsonString(outcome.finding.quarantineRecordId) << "\",\n";
  output << "  \"quarantinedPath\": \"" << EscapeJsonString(outcome.finding.quarantinedPath.wstring()) << "\",\n";
  output << "  \"remediationError\": \"" << EscapeJsonString(outcome.finding.remediationError) << "\"\n";
  output << "}\n";

  RuntimeDatabase(databasePath_).UpsertEvidenceRecord(EvidenceIndexRecord{
      .recordId = result.recordId,
      .recordedAt = CurrentUtcTimestamp(),
      .source = source,
      .recordPath = result.recordPath,
      .subjectPath = outcome.finding.path,
      .sha256 = outcome.finding.sha256,
      .disposition = VerdictDispositionToString(outcome.finding.verdict.disposition),
      .tacticId = outcome.finding.verdict.tacticId,
      .techniqueId = outcome.finding.verdict.techniqueId,
      .appName = outcome.appName,
      .contentName = outcome.contentName});
  RuntimeDatabase(databasePath_).RecordScanHistory(ScanHistoryRecord{
      .recordedAt = CurrentUtcTimestamp(),
      .source = source,
      .subjectPath = outcome.finding.path,
      .sha256 = outcome.finding.sha256,
      .contentType = L"amsi",
      .reputation = outcome.finding.reputation,
      .disposition = VerdictDispositionToString(outcome.finding.verdict.disposition),
      .confidence = outcome.finding.verdict.confidence,
      .tacticId = outcome.finding.verdict.tacticId,
      .techniqueId = outcome.finding.verdict.techniqueId,
      .remediationStatus = RemediationStatusToString(outcome.finding.remediationStatus),
      .evidenceRecordId = result.recordId,
      .quarantineRecordId = outcome.finding.quarantineRecordId});

  return result;
}

}  // namespace antivirus::agent
