#pragma once

#include <filesystem>
#include <string>
#include <vector>

#include "AgentState.h"
#include "ControlPlaneClient.h"
#include "TelemetryRecord.h"

namespace antivirus::agent {

struct QuarantineIndexRecord {
  std::wstring recordId;
  std::wstring capturedAt;
  std::filesystem::path originalPath;
  std::filesystem::path quarantinedPath;
  std::wstring sha256;
  std::uintmax_t sizeBytes{0};
  std::wstring techniqueId;
  std::wstring localStatus;
};

struct EvidenceIndexRecord {
  std::wstring recordId;
  std::wstring recordedAt;
  std::wstring source;
  std::filesystem::path recordPath;
  std::filesystem::path subjectPath;
  std::wstring sha256;
  std::wstring disposition;
  std::wstring tacticId;
  std::wstring techniqueId;
  std::wstring appName;
  std::wstring contentName;
};

struct ScanHistoryRecord {
  std::wstring recordedAt;
  std::wstring source;
  std::filesystem::path subjectPath;
  std::wstring sha256;
  std::wstring contentType;
  std::wstring reputation;
  std::wstring disposition;
  std::uint32_t confidence{0};
  std::wstring tacticId;
  std::wstring techniqueId;
  std::wstring remediationStatus;
  std::wstring evidenceRecordId;
  std::wstring quarantineRecordId;
};

struct UpdateJournalRecord {
  std::wstring transactionId;
  std::wstring packageId;
  std::wstring packageType;
  std::wstring targetVersion;
  std::filesystem::path manifestPath;
  std::filesystem::path backupRoot;
  std::filesystem::path stagedRoot;
  std::wstring startedAt;
  std::wstring completedAt;
  std::wstring status;
  std::wstring resultJson;
  bool requiresRestart{false};
};

class RuntimeDatabase {
 public:
  explicit RuntimeDatabase(std::filesystem::path databasePath);

  bool LoadAgentState(AgentState& state) const;
  void SaveAgentState(const AgentState& state) const;

  std::vector<TelemetryRecord> LoadTelemetryQueue() const;
  void ReplaceTelemetryQueue(const std::vector<TelemetryRecord>& records) const;
  std::size_t CountTelemetryQueue() const;

  void UpsertCommandJournal(const RemoteCommand& command, const std::wstring& status, const std::wstring& resultJson,
                            const std::wstring& lastError) const;
  void UpdateCommandJournalStatus(const std::wstring& commandId, const std::wstring& status,
                                  const std::wstring& resultJson, const std::wstring& lastError) const;

  bool LoadQuarantineRecord(const std::wstring& recordId, QuarantineIndexRecord& record) const;
  void UpsertQuarantineRecord(const QuarantineIndexRecord& record) const;
  std::vector<QuarantineIndexRecord> ListQuarantineRecords(std::size_t limit = 100) const;

  void UpsertEvidenceRecord(const EvidenceIndexRecord& record) const;
  std::vector<EvidenceIndexRecord> ListEvidenceRecords(std::size_t limit = 100) const;
  void RecordScanHistory(const ScanHistoryRecord& record) const;
  std::vector<ScanHistoryRecord> ListScanHistory(std::size_t limit = 100) const;

  void UpsertUpdateJournal(const UpdateJournalRecord& record) const;
  bool LoadUpdateJournal(const std::wstring& transactionId, UpdateJournalRecord& record) const;
  std::vector<UpdateJournalRecord> ListUpdateJournal(std::size_t limit = 20) const;

 private:
  std::filesystem::path databasePath_;
};

}  // namespace antivirus::agent
