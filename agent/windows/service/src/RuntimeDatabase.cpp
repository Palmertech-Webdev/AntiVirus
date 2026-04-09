#include "RuntimeDatabase.h"

#include <sqlite3.h>

#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>

#include "StringUtils.h"

namespace antivirus::agent {
namespace {

using ConnectionHandle = std::unique_ptr<sqlite3, decltype(&sqlite3_close)>;
using StatementHandle = std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)>;

constexpr int kSingletonKey = 1;

std::string WidePathToUtf8(const std::filesystem::path& path) { return WideToUtf8(path.wstring()); }

[[noreturn]] void ThrowSqliteError(sqlite3* db, const char* message) {
  throw std::runtime_error(std::string(message) + ": " + (db == nullptr ? "sqlite unavailable" : sqlite3_errmsg(db)));
}

void Exec(sqlite3* db, const char* sql) {
  char* errorMessage = nullptr;
  if (sqlite3_exec(db, sql, nullptr, nullptr, &errorMessage) != SQLITE_OK) {
    const auto combined = std::string("sqlite exec failed: ") + (errorMessage == nullptr ? sql : errorMessage);
    if (errorMessage != nullptr) {
      sqlite3_free(errorMessage);
    }
    throw std::runtime_error(combined);
  }
}

ConnectionHandle OpenConnection(const std::filesystem::path& databasePath) {
  if (databasePath.has_parent_path()) {
    std::filesystem::create_directories(databasePath.parent_path());
  }

  sqlite3* raw = nullptr;
  if (sqlite3_open_v2(WidePathToUtf8(databasePath).c_str(), &raw,
                      SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr) != SQLITE_OK) {
    ThrowSqliteError(raw, "sqlite3_open_v2 failed");
  }

  ConnectionHandle connection(raw, sqlite3_close);
  Exec(connection.get(), "PRAGMA journal_mode=WAL;");
  Exec(connection.get(), "PRAGMA synchronous=FULL;");
  Exec(connection.get(), "PRAGMA foreign_keys=ON;");
  Exec(connection.get(), "PRAGMA busy_timeout=5000;");
  Exec(connection.get(),
       "CREATE TABLE IF NOT EXISTS agent_state ("
       " singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
       " device_id TEXT, hostname TEXT, os_version TEXT, serial_number TEXT,"
       " agent_version TEXT, platform_version TEXT, command_channel_url TEXT,"
       " last_enrollment_at TEXT, last_heartbeat_at TEXT, last_policy_sync_at TEXT,"
       " health_state TEXT, isolated INTEGER NOT NULL DEFAULT 0"
       ");"
       "CREATE TABLE IF NOT EXISTS policy_cache ("
       " singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
       " policy_id TEXT, policy_name TEXT, revision TEXT,"
       " realtime_protection_enabled INTEGER NOT NULL,"
       " cloud_lookup_enabled INTEGER NOT NULL,"
       " script_inspection_enabled INTEGER NOT NULL,"
       " network_containment_enabled INTEGER NOT NULL,"
       " quarantine_on_malicious INTEGER NOT NULL"
       ");"
       "CREATE TABLE IF NOT EXISTS telemetry_queue ("
       " queue_id INTEGER PRIMARY KEY AUTOINCREMENT,"
       " event_id TEXT NOT NULL, event_type TEXT NOT NULL, source TEXT NOT NULL,"
       " summary TEXT NOT NULL, occurred_at TEXT NOT NULL, payload_json TEXT NOT NULL"
       ");"
       "CREATE TABLE IF NOT EXISTS command_journal ("
       " command_id TEXT PRIMARY KEY,"
       " type TEXT NOT NULL, issued_by TEXT, created_at TEXT, updated_at TEXT,"
       " target_path TEXT, record_id TEXT, status TEXT NOT NULL, result_json TEXT, last_error TEXT"
       ");"
       "CREATE TABLE IF NOT EXISTS quarantine_index ("
       " record_id TEXT PRIMARY KEY, captured_at TEXT, original_path TEXT NOT NULL,"
       " quarantined_path TEXT, sha256 TEXT, size_bytes INTEGER NOT NULL DEFAULT 0,"
       " technique_id TEXT, local_status TEXT NOT NULL"
       ");"
       "CREATE TABLE IF NOT EXISTS evidence_index ("
       " record_id TEXT PRIMARY KEY, recorded_at TEXT, source TEXT NOT NULL,"
       " record_path TEXT NOT NULL, subject_path TEXT, sha256 TEXT, disposition TEXT,"
       " tactic_id TEXT, technique_id TEXT, app_name TEXT, content_name TEXT"
       ");"
       "CREATE TABLE IF NOT EXISTS scan_history ("
       " scan_id INTEGER PRIMARY KEY AUTOINCREMENT, recorded_at TEXT NOT NULL,"
       " source TEXT NOT NULL, subject_path TEXT, sha256 TEXT, content_type TEXT,"
       " reputation TEXT, disposition TEXT NOT NULL, confidence INTEGER NOT NULL,"
       " tactic_id TEXT, technique_id TEXT, remediation_status TEXT,"
       " evidence_record_id TEXT, quarantine_record_id TEXT"
       ");"
       "CREATE TABLE IF NOT EXISTS update_journal ("
       " transaction_id TEXT PRIMARY KEY, package_id TEXT NOT NULL, package_type TEXT NOT NULL,"
       " target_version TEXT, manifest_path TEXT NOT NULL, backup_root TEXT NOT NULL,"
       " staged_root TEXT NOT NULL, started_at TEXT NOT NULL, completed_at TEXT,"
       " status TEXT NOT NULL, result_json TEXT, requires_restart INTEGER NOT NULL DEFAULT 0"
       ");"
       "CREATE INDEX IF NOT EXISTS idx_telemetry_queue_queue_id ON telemetry_queue(queue_id);"
       "CREATE INDEX IF NOT EXISTS idx_command_journal_status ON command_journal(status, updated_at);"
       "CREATE INDEX IF NOT EXISTS idx_quarantine_index_status ON quarantine_index(local_status);"
       "CREATE INDEX IF NOT EXISTS idx_evidence_index_source ON evidence_index(source, recorded_at);"
       "CREATE INDEX IF NOT EXISTS idx_scan_history_recorded_at ON scan_history(recorded_at DESC);"
       "CREATE INDEX IF NOT EXISTS idx_update_journal_status ON update_journal(status, started_at DESC);");
  return connection;
}

StatementHandle Prepare(sqlite3* db, const char* sql) {
  sqlite3_stmt* raw = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &raw, nullptr) != SQLITE_OK) {
    ThrowSqliteError(db, "sqlite3_prepare_v2 failed");
  }
  return StatementHandle(raw, sqlite3_finalize);
}

void StepDone(sqlite3* db, sqlite3_stmt* statement) {
  if (sqlite3_step(statement) != SQLITE_DONE) {
    ThrowSqliteError(db, "sqlite3_step did not finish");
  }
}

void Begin(sqlite3* db) { Exec(db, "BEGIN IMMEDIATE TRANSACTION;"); }
void Commit(sqlite3* db) { Exec(db, "COMMIT;"); }
void Rollback(sqlite3* db) noexcept { sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr); }

void BindText(sqlite3_stmt* statement, const int index, const std::wstring& value) {
  const auto utf8 = WideToUtf8(value);
  sqlite3_bind_text(statement, index, utf8.c_str(), -1, SQLITE_TRANSIENT);
}

void BindPath(sqlite3_stmt* statement, const int index, const std::filesystem::path& value) {
  BindText(statement, index, value.wstring());
}

std::wstring ColumnText(sqlite3_stmt* statement, const int column) {
  const auto* text = reinterpret_cast<const char*>(sqlite3_column_text(statement, column));
  return text == nullptr ? std::wstring{} : Utf8ToWide(reinterpret_cast<const char*>(text));
}

}  // namespace

RuntimeDatabase::RuntimeDatabase(std::filesystem::path databasePath) : databasePath_(std::move(databasePath)) {}

bool RuntimeDatabase::LoadAgentState(AgentState& state) const {
  const auto db = OpenConnection(databasePath_);
  auto stateStatement = Prepare(db.get(),
                                "SELECT device_id, hostname, os_version, serial_number, agent_version,"
                                " platform_version, command_channel_url, last_enrollment_at, last_heartbeat_at,"
                                " last_policy_sync_at, health_state, isolated FROM agent_state WHERE singleton=1;");
  const auto stateStep = sqlite3_step(stateStatement.get());
  if (stateStep == SQLITE_DONE) {
    return false;
  }
  if (stateStep != SQLITE_ROW) {
    ThrowSqliteError(db.get(), "loading agent_state failed");
  }

  state.deviceId = ColumnText(stateStatement.get(), 0);
  state.hostname = ColumnText(stateStatement.get(), 1);
  state.osVersion = ColumnText(stateStatement.get(), 2);
  state.serialNumber = ColumnText(stateStatement.get(), 3);
  state.agentVersion = ColumnText(stateStatement.get(), 4);
  state.platformVersion = ColumnText(stateStatement.get(), 5);
  state.commandChannelUrl = ColumnText(stateStatement.get(), 6);
  state.lastEnrollmentAt = ColumnText(stateStatement.get(), 7);
  state.lastHeartbeatAt = ColumnText(stateStatement.get(), 8);
  state.lastPolicySyncAt = ColumnText(stateStatement.get(), 9);
  state.healthState = ColumnText(stateStatement.get(), 10);
  state.isolated = sqlite3_column_int(stateStatement.get(), 11) != 0;

  auto policyStatement = Prepare(db.get(),
                                 "SELECT policy_id, policy_name, revision, realtime_protection_enabled,"
                                 " cloud_lookup_enabled, script_inspection_enabled, network_containment_enabled,"
                                 " quarantine_on_malicious FROM policy_cache WHERE singleton=1;");
  const auto policyStep = sqlite3_step(policyStatement.get());
  if (policyStep == SQLITE_ROW) {
    state.policy.policyId = ColumnText(policyStatement.get(), 0);
    state.policy.policyName = ColumnText(policyStatement.get(), 1);
    state.policy.revision = ColumnText(policyStatement.get(), 2);
    state.policy.realtimeProtectionEnabled = sqlite3_column_int(policyStatement.get(), 3) != 0;
    state.policy.cloudLookupEnabled = sqlite3_column_int(policyStatement.get(), 4) != 0;
    state.policy.scriptInspectionEnabled = sqlite3_column_int(policyStatement.get(), 5) != 0;
    state.policy.networkContainmentEnabled = sqlite3_column_int(policyStatement.get(), 6) != 0;
    state.policy.quarantineOnMalicious = sqlite3_column_int(policyStatement.get(), 7) != 0;
  }

  return true;
}

void RuntimeDatabase::SaveAgentState(const AgentState& state) const {
  const auto db = OpenConnection(databasePath_);
  try {
    Begin(db.get());

    auto stateStatement = Prepare(db.get(),
                                  "INSERT INTO agent_state("
                                  " singleton, device_id, hostname, os_version, serial_number, agent_version,"
                                  " platform_version, command_channel_url, last_enrollment_at, last_heartbeat_at,"
                                  " last_policy_sync_at, health_state, isolated)"
                                  " VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                                  " ON CONFLICT(singleton) DO UPDATE SET"
                                  " device_id=excluded.device_id, hostname=excluded.hostname,"
                                  " os_version=excluded.os_version, serial_number=excluded.serial_number,"
                                  " agent_version=excluded.agent_version, platform_version=excluded.platform_version,"
                                  " command_channel_url=excluded.command_channel_url,"
                                  " last_enrollment_at=excluded.last_enrollment_at,"
                                  " last_heartbeat_at=excluded.last_heartbeat_at,"
                                  " last_policy_sync_at=excluded.last_policy_sync_at,"
                                  " health_state=excluded.health_state, isolated=excluded.isolated;");
    sqlite3_bind_int(stateStatement.get(), 1, kSingletonKey);
    BindText(stateStatement.get(), 2, state.deviceId);
    BindText(stateStatement.get(), 3, state.hostname);
    BindText(stateStatement.get(), 4, state.osVersion);
    BindText(stateStatement.get(), 5, state.serialNumber);
    BindText(stateStatement.get(), 6, state.agentVersion);
    BindText(stateStatement.get(), 7, state.platformVersion);
    BindText(stateStatement.get(), 8, state.commandChannelUrl);
    BindText(stateStatement.get(), 9, state.lastEnrollmentAt);
    BindText(stateStatement.get(), 10, state.lastHeartbeatAt);
    BindText(stateStatement.get(), 11, state.lastPolicySyncAt);
    BindText(stateStatement.get(), 12, state.healthState);
    sqlite3_bind_int(stateStatement.get(), 13, state.isolated ? 1 : 0);
    StepDone(db.get(), stateStatement.get());

    auto policyStatement = Prepare(db.get(),
                                   "INSERT INTO policy_cache("
                                   " singleton, policy_id, policy_name, revision, realtime_protection_enabled,"
                                   " cloud_lookup_enabled, script_inspection_enabled, network_containment_enabled,"
                                   " quarantine_on_malicious)"
                                   " VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)"
                                   " ON CONFLICT(singleton) DO UPDATE SET"
                                   " policy_id=excluded.policy_id, policy_name=excluded.policy_name,"
                                   " revision=excluded.revision,"
                                   " realtime_protection_enabled=excluded.realtime_protection_enabled,"
                                   " cloud_lookup_enabled=excluded.cloud_lookup_enabled,"
                                   " script_inspection_enabled=excluded.script_inspection_enabled,"
                                   " network_containment_enabled=excluded.network_containment_enabled,"
                                   " quarantine_on_malicious=excluded.quarantine_on_malicious;");
    sqlite3_bind_int(policyStatement.get(), 1, kSingletonKey);
    BindText(policyStatement.get(), 2, state.policy.policyId);
    BindText(policyStatement.get(), 3, state.policy.policyName);
    BindText(policyStatement.get(), 4, state.policy.revision);
    sqlite3_bind_int(policyStatement.get(), 5, state.policy.realtimeProtectionEnabled ? 1 : 0);
    sqlite3_bind_int(policyStatement.get(), 6, state.policy.cloudLookupEnabled ? 1 : 0);
    sqlite3_bind_int(policyStatement.get(), 7, state.policy.scriptInspectionEnabled ? 1 : 0);
    sqlite3_bind_int(policyStatement.get(), 8, state.policy.networkContainmentEnabled ? 1 : 0);
    sqlite3_bind_int(policyStatement.get(), 9, state.policy.quarantineOnMalicious ? 1 : 0);
    StepDone(db.get(), policyStatement.get());

    Commit(db.get());
  } catch (...) {
    Rollback(db.get());
    throw;
  }
}

std::vector<TelemetryRecord> RuntimeDatabase::LoadTelemetryQueue() const {
  const auto db = OpenConnection(databasePath_);
  auto statement = Prepare(db.get(),
                           "SELECT event_id, event_type, source, summary, occurred_at, payload_json"
                           " FROM telemetry_queue ORDER BY queue_id ASC;");
  std::vector<TelemetryRecord> records;
  for (;;) {
    const auto step = sqlite3_step(statement.get());
    if (step == SQLITE_DONE) {
      break;
    }
    if (step != SQLITE_ROW) {
      ThrowSqliteError(db.get(), "loading telemetry queue failed");
    }
    records.push_back(TelemetryRecord{
        .eventId = ColumnText(statement.get(), 0),
        .eventType = ColumnText(statement.get(), 1),
        .source = ColumnText(statement.get(), 2),
        .summary = ColumnText(statement.get(), 3),
        .occurredAt = ColumnText(statement.get(), 4),
        .payloadJson = ColumnText(statement.get(), 5)});
  }
  return records;
}

void RuntimeDatabase::ReplaceTelemetryQueue(const std::vector<TelemetryRecord>& records) const {
  const auto db = OpenConnection(databasePath_);
  try {
    Begin(db.get());
    Exec(db.get(), "DELETE FROM telemetry_queue;");
    auto statement = Prepare(db.get(),
                             "INSERT INTO telemetry_queue(event_id, event_type, source, summary, occurred_at, payload_json)"
                             " VALUES(?, ?, ?, ?, ?, ?);");
    for (const auto& record : records) {
      sqlite3_reset(statement.get());
      sqlite3_clear_bindings(statement.get());
      BindText(statement.get(), 1, record.eventId);
      BindText(statement.get(), 2, record.eventType);
      BindText(statement.get(), 3, record.source);
      BindText(statement.get(), 4, record.summary);
      BindText(statement.get(), 5, record.occurredAt);
      BindText(statement.get(), 6, record.payloadJson);
      StepDone(db.get(), statement.get());
    }
    Commit(db.get());
  } catch (...) {
    Rollback(db.get());
    throw;
  }
}

std::size_t RuntimeDatabase::CountTelemetryQueue() const {
  const auto db = OpenConnection(databasePath_);
  auto statement = Prepare(db.get(), "SELECT COUNT(*) FROM telemetry_queue;");
  const auto step = sqlite3_step(statement.get());
  if (step != SQLITE_ROW) {
    ThrowSqliteError(db.get(), "counting telemetry queue failed");
  }

  return static_cast<std::size_t>(sqlite3_column_int64(statement.get(), 0));
}

void RuntimeDatabase::UpsertCommandJournal(const RemoteCommand& command, const std::wstring& status,
                                           const std::wstring& resultJson, const std::wstring& lastError) const {
  const auto db = OpenConnection(databasePath_);
  auto statement = Prepare(db.get(),
                           "INSERT INTO command_journal("
                           " command_id, type, issued_by, created_at, updated_at, target_path, record_id, status, result_json, last_error)"
                           " VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                           " ON CONFLICT(command_id) DO UPDATE SET"
                           " type=excluded.type, issued_by=excluded.issued_by, created_at=excluded.created_at,"
                           " updated_at=excluded.updated_at, target_path=excluded.target_path, record_id=excluded.record_id,"
                           " status=excluded.status, result_json=excluded.result_json, last_error=excluded.last_error;");
  BindText(statement.get(), 1, command.commandId);
  BindText(statement.get(), 2, command.type);
  BindText(statement.get(), 3, command.issuedBy);
  BindText(statement.get(), 4, command.createdAt);
  BindText(statement.get(), 5, command.updatedAt);
  BindText(statement.get(), 6, command.targetPath);
  BindText(statement.get(), 7, command.recordId);
  BindText(statement.get(), 8, status);
  BindText(statement.get(), 9, resultJson);
  BindText(statement.get(), 10, lastError);
  StepDone(db.get(), statement.get());
}

void RuntimeDatabase::UpdateCommandJournalStatus(const std::wstring& commandId, const std::wstring& status,
                                                 const std::wstring& resultJson, const std::wstring& lastError) const {
  const auto db = OpenConnection(databasePath_);
  auto statement = Prepare(db.get(),
                           "UPDATE command_journal SET status=?, result_json=?, last_error=?, updated_at=?"
                           " WHERE command_id=?;");
  BindText(statement.get(), 1, status);
  BindText(statement.get(), 2, resultJson);
  BindText(statement.get(), 3, lastError);
  BindText(statement.get(), 4, CurrentUtcTimestamp());
  BindText(statement.get(), 5, commandId);
  StepDone(db.get(), statement.get());
}

bool RuntimeDatabase::LoadQuarantineRecord(const std::wstring& recordId, QuarantineIndexRecord& record) const {
  const auto db = OpenConnection(databasePath_);
  auto statement = Prepare(db.get(),
                           "SELECT record_id, captured_at, original_path, quarantined_path, sha256, size_bytes,"
                           " technique_id, local_status FROM quarantine_index WHERE record_id=?;");
  BindText(statement.get(), 1, recordId);
  const auto step = sqlite3_step(statement.get());
  if (step == SQLITE_DONE) {
    return false;
  }
  if (step != SQLITE_ROW) {
    ThrowSqliteError(db.get(), "loading quarantine record failed");
  }
  record.recordId = ColumnText(statement.get(), 0);
  record.capturedAt = ColumnText(statement.get(), 1);
  record.originalPath = ColumnText(statement.get(), 2);
  record.quarantinedPath = ColumnText(statement.get(), 3);
  record.sha256 = ColumnText(statement.get(), 4);
  record.sizeBytes = static_cast<std::uintmax_t>(sqlite3_column_int64(statement.get(), 5));
  record.techniqueId = ColumnText(statement.get(), 6);
  record.localStatus = ColumnText(statement.get(), 7);
  return true;
}

void RuntimeDatabase::UpsertQuarantineRecord(const QuarantineIndexRecord& record) const {
  const auto db = OpenConnection(databasePath_);
  auto statement = Prepare(db.get(),
                           "INSERT INTO quarantine_index("
                           " record_id, captured_at, original_path, quarantined_path, sha256, size_bytes, technique_id, local_status)"
                           " VALUES(?, ?, ?, ?, ?, ?, ?, ?)"
                           " ON CONFLICT(record_id) DO UPDATE SET"
                           " captured_at=excluded.captured_at, original_path=excluded.original_path,"
                           " quarantined_path=excluded.quarantined_path, sha256=excluded.sha256,"
                           " size_bytes=excluded.size_bytes, technique_id=excluded.technique_id,"
                           " local_status=excluded.local_status;");
  BindText(statement.get(), 1, record.recordId);
  BindText(statement.get(), 2, record.capturedAt);
  BindPath(statement.get(), 3, record.originalPath);
  BindPath(statement.get(), 4, record.quarantinedPath);
  BindText(statement.get(), 5, record.sha256);
  sqlite3_bind_int64(statement.get(), 6, static_cast<sqlite3_int64>(record.sizeBytes));
  BindText(statement.get(), 7, record.techniqueId);
  BindText(statement.get(), 8, record.localStatus);
  StepDone(db.get(), statement.get());
}

std::vector<QuarantineIndexRecord> RuntimeDatabase::ListQuarantineRecords(const std::size_t limit) const {
  const auto db = OpenConnection(databasePath_);
  auto statement = Prepare(db.get(),
                           "SELECT record_id, captured_at, original_path, quarantined_path, sha256, size_bytes,"
                           " technique_id, local_status FROM quarantine_index"
                           " ORDER BY captured_at DESC, record_id DESC LIMIT ?;");
  sqlite3_bind_int64(statement.get(), 1, static_cast<sqlite3_int64>(limit));

  std::vector<QuarantineIndexRecord> records;
  for (;;) {
    const auto step = sqlite3_step(statement.get());
    if (step == SQLITE_DONE) {
      break;
    }
    if (step != SQLITE_ROW) {
      ThrowSqliteError(db.get(), "listing quarantine records failed");
    }

    records.push_back(QuarantineIndexRecord{
        .recordId = ColumnText(statement.get(), 0),
        .capturedAt = ColumnText(statement.get(), 1),
        .originalPath = ColumnText(statement.get(), 2),
        .quarantinedPath = ColumnText(statement.get(), 3),
        .sha256 = ColumnText(statement.get(), 4),
        .sizeBytes = static_cast<std::uintmax_t>(sqlite3_column_int64(statement.get(), 5)),
        .techniqueId = ColumnText(statement.get(), 6),
        .localStatus = ColumnText(statement.get(), 7)});
  }

  return records;
}

void RuntimeDatabase::UpsertEvidenceRecord(const EvidenceIndexRecord& record) const {
  const auto db = OpenConnection(databasePath_);
  auto statement = Prepare(db.get(),
                           "INSERT INTO evidence_index("
                           " record_id, recorded_at, source, record_path, subject_path, sha256, disposition,"
                           " tactic_id, technique_id, app_name, content_name)"
                           " VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                           " ON CONFLICT(record_id) DO UPDATE SET"
                           " recorded_at=excluded.recorded_at, source=excluded.source, record_path=excluded.record_path,"
                           " subject_path=excluded.subject_path, sha256=excluded.sha256, disposition=excluded.disposition,"
                           " tactic_id=excluded.tactic_id, technique_id=excluded.technique_id,"
                           " app_name=excluded.app_name, content_name=excluded.content_name;");
  BindText(statement.get(), 1, record.recordId);
  BindText(statement.get(), 2, record.recordedAt);
  BindText(statement.get(), 3, record.source);
  BindPath(statement.get(), 4, record.recordPath);
  BindPath(statement.get(), 5, record.subjectPath);
  BindText(statement.get(), 6, record.sha256);
  BindText(statement.get(), 7, record.disposition);
  BindText(statement.get(), 8, record.tacticId);
  BindText(statement.get(), 9, record.techniqueId);
  BindText(statement.get(), 10, record.appName);
  BindText(statement.get(), 11, record.contentName);
  StepDone(db.get(), statement.get());
}

std::vector<EvidenceIndexRecord> RuntimeDatabase::ListEvidenceRecords(const std::size_t limit) const {
  const auto db = OpenConnection(databasePath_);
  auto statement = Prepare(db.get(),
                           "SELECT record_id, recorded_at, source, record_path, subject_path, sha256, disposition,"
                           " tactic_id, technique_id, app_name, content_name FROM evidence_index"
                           " ORDER BY recorded_at DESC, record_id DESC LIMIT ?;");
  sqlite3_bind_int64(statement.get(), 1, static_cast<sqlite3_int64>(limit));

  std::vector<EvidenceIndexRecord> records;
  for (;;) {
    const auto step = sqlite3_step(statement.get());
    if (step == SQLITE_DONE) {
      break;
    }
    if (step != SQLITE_ROW) {
      ThrowSqliteError(db.get(), "listing evidence records failed");
    }

    records.push_back(EvidenceIndexRecord{
        .recordId = ColumnText(statement.get(), 0),
        .recordedAt = ColumnText(statement.get(), 1),
        .source = ColumnText(statement.get(), 2),
        .recordPath = ColumnText(statement.get(), 3),
        .subjectPath = ColumnText(statement.get(), 4),
        .sha256 = ColumnText(statement.get(), 5),
        .disposition = ColumnText(statement.get(), 6),
        .tacticId = ColumnText(statement.get(), 7),
        .techniqueId = ColumnText(statement.get(), 8),
        .appName = ColumnText(statement.get(), 9),
        .contentName = ColumnText(statement.get(), 10)});
  }

  return records;
}

void RuntimeDatabase::RecordScanHistory(const ScanHistoryRecord& record) const {
  const auto db = OpenConnection(databasePath_);
  auto statement = Prepare(db.get(),
                           "INSERT INTO scan_history("
                           " recorded_at, source, subject_path, sha256, content_type, reputation, disposition,"
                           " confidence, tactic_id, technique_id, remediation_status, evidence_record_id, quarantine_record_id)"
                           " VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);");
  BindText(statement.get(), 1, record.recordedAt);
  BindText(statement.get(), 2, record.source);
  BindPath(statement.get(), 3, record.subjectPath);
  BindText(statement.get(), 4, record.sha256);
  BindText(statement.get(), 5, record.contentType);
  BindText(statement.get(), 6, record.reputation);
  BindText(statement.get(), 7, record.disposition);
  sqlite3_bind_int(statement.get(), 8, static_cast<int>(record.confidence));
  BindText(statement.get(), 9, record.tacticId);
  BindText(statement.get(), 10, record.techniqueId);
  BindText(statement.get(), 11, record.remediationStatus);
  BindText(statement.get(), 12, record.evidenceRecordId);
  BindText(statement.get(), 13, record.quarantineRecordId);
  StepDone(db.get(), statement.get());
}

std::vector<ScanHistoryRecord> RuntimeDatabase::ListScanHistory(const std::size_t limit) const {
  const auto db = OpenConnection(databasePath_);
  auto statement = Prepare(db.get(),
                           "SELECT recorded_at, source, subject_path, sha256, content_type, reputation,"
                           " disposition, confidence, tactic_id, technique_id, remediation_status,"
                           " evidence_record_id, quarantine_record_id FROM scan_history"
                           " ORDER BY recorded_at DESC, scan_id DESC LIMIT ?;");
  sqlite3_bind_int64(statement.get(), 1, static_cast<sqlite3_int64>(limit));

  std::vector<ScanHistoryRecord> records;
  for (;;) {
    const auto step = sqlite3_step(statement.get());
    if (step == SQLITE_DONE) {
      break;
    }
    if (step != SQLITE_ROW) {
      ThrowSqliteError(db.get(), "listing scan history failed");
    }

    records.push_back(ScanHistoryRecord{
        .recordedAt = ColumnText(statement.get(), 0),
        .source = ColumnText(statement.get(), 1),
        .subjectPath = ColumnText(statement.get(), 2),
        .sha256 = ColumnText(statement.get(), 3),
        .contentType = ColumnText(statement.get(), 4),
        .reputation = ColumnText(statement.get(), 5),
        .disposition = ColumnText(statement.get(), 6),
        .confidence = static_cast<std::uint32_t>(sqlite3_column_int(statement.get(), 7)),
        .tacticId = ColumnText(statement.get(), 8),
        .techniqueId = ColumnText(statement.get(), 9),
        .remediationStatus = ColumnText(statement.get(), 10),
        .evidenceRecordId = ColumnText(statement.get(), 11),
        .quarantineRecordId = ColumnText(statement.get(), 12)});
  }

  return records;
}

void RuntimeDatabase::UpsertUpdateJournal(const UpdateJournalRecord& record) const {
  const auto db = OpenConnection(databasePath_);
  auto statement = Prepare(db.get(),
                           "INSERT INTO update_journal("
                           " transaction_id, package_id, package_type, target_version, manifest_path, backup_root,"
                           " staged_root, started_at, completed_at, status, result_json, requires_restart)"
                           " VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                           " ON CONFLICT(transaction_id) DO UPDATE SET"
                           " package_id=excluded.package_id, package_type=excluded.package_type,"
                           " target_version=excluded.target_version, manifest_path=excluded.manifest_path,"
                           " backup_root=excluded.backup_root, staged_root=excluded.staged_root,"
                           " started_at=excluded.started_at, completed_at=excluded.completed_at,"
                           " status=excluded.status, result_json=excluded.result_json,"
                           " requires_restart=excluded.requires_restart;");
  BindText(statement.get(), 1, record.transactionId);
  BindText(statement.get(), 2, record.packageId);
  BindText(statement.get(), 3, record.packageType);
  BindText(statement.get(), 4, record.targetVersion);
  BindPath(statement.get(), 5, record.manifestPath);
  BindPath(statement.get(), 6, record.backupRoot);
  BindPath(statement.get(), 7, record.stagedRoot);
  BindText(statement.get(), 8, record.startedAt);
  BindText(statement.get(), 9, record.completedAt);
  BindText(statement.get(), 10, record.status);
  BindText(statement.get(), 11, record.resultJson);
  sqlite3_bind_int(statement.get(), 12, record.requiresRestart ? 1 : 0);
  StepDone(db.get(), statement.get());
}

bool RuntimeDatabase::LoadUpdateJournal(const std::wstring& transactionId, UpdateJournalRecord& record) const {
  const auto db = OpenConnection(databasePath_);
  auto statement = Prepare(db.get(),
                           "SELECT transaction_id, package_id, package_type, target_version, manifest_path,"
                           " backup_root, staged_root, started_at, completed_at, status, result_json,"
                           " requires_restart FROM update_journal WHERE transaction_id=?;");
  BindText(statement.get(), 1, transactionId);
  const auto step = sqlite3_step(statement.get());
  if (step == SQLITE_DONE) {
    return false;
  }
  if (step != SQLITE_ROW) {
    ThrowSqliteError(db.get(), "loading update journal failed");
  }

  record.transactionId = ColumnText(statement.get(), 0);
  record.packageId = ColumnText(statement.get(), 1);
  record.packageType = ColumnText(statement.get(), 2);
  record.targetVersion = ColumnText(statement.get(), 3);
  record.manifestPath = ColumnText(statement.get(), 4);
  record.backupRoot = ColumnText(statement.get(), 5);
  record.stagedRoot = ColumnText(statement.get(), 6);
  record.startedAt = ColumnText(statement.get(), 7);
  record.completedAt = ColumnText(statement.get(), 8);
  record.status = ColumnText(statement.get(), 9);
  record.resultJson = ColumnText(statement.get(), 10);
  record.requiresRestart = sqlite3_column_int(statement.get(), 11) != 0;
  return true;
}

std::vector<UpdateJournalRecord> RuntimeDatabase::ListUpdateJournal(const std::size_t limit) const {
  const auto db = OpenConnection(databasePath_);
  auto statement = Prepare(db.get(),
                           "SELECT transaction_id, package_id, package_type, target_version, manifest_path,"
                           " backup_root, staged_root, started_at, completed_at, status, result_json,"
                           " requires_restart FROM update_journal"
                           " ORDER BY started_at DESC, transaction_id DESC LIMIT ?;");
  sqlite3_bind_int64(statement.get(), 1, static_cast<sqlite3_int64>(limit));

  std::vector<UpdateJournalRecord> records;
  for (;;) {
    const auto step = sqlite3_step(statement.get());
    if (step == SQLITE_DONE) {
      break;
    }
    if (step != SQLITE_ROW) {
      ThrowSqliteError(db.get(), "listing update journal failed");
    }

    records.push_back(UpdateJournalRecord{
        .transactionId = ColumnText(statement.get(), 0),
        .packageId = ColumnText(statement.get(), 1),
        .packageType = ColumnText(statement.get(), 2),
        .targetVersion = ColumnText(statement.get(), 3),
        .manifestPath = ColumnText(statement.get(), 4),
        .backupRoot = ColumnText(statement.get(), 5),
        .stagedRoot = ColumnText(statement.get(), 6),
        .startedAt = ColumnText(statement.get(), 7),
        .completedAt = ColumnText(statement.get(), 8),
        .status = ColumnText(statement.get(), 9),
        .resultJson = ColumnText(statement.get(), 10),
        .requiresRestart = sqlite3_column_int(statement.get(), 11) != 0});
  }

  return records;
}

}  // namespace antivirus::agent
