#include "RuntimeDatabase.h"

#include <sqlite3.h>

#include <filesystem>
#include <memory>
#include <stdexcept>
#include <sstream>
#include <string>

#include "StringUtils.h"

namespace antivirus::agent {
namespace {

using ConnectionHandle = std::unique_ptr<sqlite3, decltype(&sqlite3_close)>;
using StatementHandle = std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)>;

constexpr int kSingletonKey = 1;
constexpr int kRuntimeDatabaseSchemaVersion = 6;

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

void ExecIgnoreDuplicateColumn(sqlite3* db, const char* sql) {
  char* errorMessage = nullptr;
  if (sqlite3_exec(db, sql, nullptr, nullptr, &errorMessage) != SQLITE_OK) {
    const auto message = std::string(errorMessage == nullptr ? "sqlite exec failed" : errorMessage);
    if (errorMessage != nullptr) {
      sqlite3_free(errorMessage);
    }

    if (message.find("duplicate column name") == std::string::npos) {
      throw std::runtime_error(message);
    }
  }
}

void Begin(sqlite3* db) { Exec(db, "BEGIN IMMEDIATE TRANSACTION;"); }
void Commit(sqlite3* db) { Exec(db, "COMMIT;"); }
void Rollback(sqlite3* db) noexcept { sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr); }

int GetUserVersion(sqlite3* db) {
  sqlite3_stmt* raw = nullptr;
  if (sqlite3_prepare_v2(db, "PRAGMA user_version;", -1, &raw, nullptr) != SQLITE_OK) {
    ThrowSqliteError(db, "sqlite3_prepare_v2 failed for PRAGMA user_version");
  }

  StatementHandle statement(raw, sqlite3_finalize);
  const auto step = sqlite3_step(statement.get());
  if (step != SQLITE_ROW) {
    ThrowSqliteError(db, "sqlite3_step failed for PRAGMA user_version");
  }

  return sqlite3_column_int(statement.get(), 0);
}

void SetUserVersion(sqlite3* db, const int version) {
  Exec(db, ("PRAGMA user_version=" + std::to_string(version) + ";").c_str());
}

void EnsureBaseSchema(sqlite3* db) {
  Exec(db,
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
       " quarantine_on_malicious INTEGER NOT NULL,"
       " suppression_path_roots TEXT NOT NULL DEFAULT '',"
       " suppression_sha256 TEXT NOT NULL DEFAULT '',"
       " suppression_signer_names TEXT NOT NULL DEFAULT ''"
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
       "CREATE TABLE IF NOT EXISTS blocked_software ("
       " software_id TEXT PRIMARY KEY, display_name TEXT NOT NULL, install_location TEXT,"
       " executable_names TEXT NOT NULL, blocked_at TEXT NOT NULL"
       ");"
       "CREATE TABLE IF NOT EXISTS patch_policy ("
       " singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
       " policy_id TEXT NOT NULL, auto_install_windows_security INTEGER NOT NULL DEFAULT 1,"
       " auto_install_windows_quality INTEGER NOT NULL DEFAULT 1,"
       " defer_feature_updates INTEGER NOT NULL DEFAULT 1,"
       " include_driver_updates INTEGER NOT NULL DEFAULT 0,"
       " include_optional_updates INTEGER NOT NULL DEFAULT 0,"
       " auto_update_high_risk_apps_only INTEGER NOT NULL DEFAULT 1,"
       " auto_update_all_supported_apps INTEGER NOT NULL DEFAULT 0,"
       " notify_before_update INTEGER NOT NULL DEFAULT 0,"
       " silent_only INTEGER NOT NULL DEFAULT 1,"
       " skip_interactive_updates INTEGER NOT NULL DEFAULT 1,"
       " paused INTEGER NOT NULL DEFAULT 0,"
       " respect_metered_connections INTEGER NOT NULL DEFAULT 1,"
       " battery_aware INTEGER NOT NULL DEFAULT 1,"
       " allow_native_updaters INTEGER NOT NULL DEFAULT 1,"
       " allow_winget INTEGER NOT NULL DEFAULT 1,"
       " allow_recipes INTEGER NOT NULL DEFAULT 1,"
       " maintenance_window_start TEXT, maintenance_window_end TEXT,"
       " reboot_grace_period_minutes INTEGER NOT NULL DEFAULT 240,"
       " feature_update_deferral_days INTEGER NOT NULL DEFAULT 30,"
       " active_hours_start TEXT, active_hours_end TEXT, updated_at TEXT"
       ");"
       "CREATE TABLE IF NOT EXISTS windows_update_inventory ("
       " update_id TEXT PRIMARY KEY, revision TEXT, title TEXT NOT NULL,"
       " kb_articles TEXT, categories TEXT, classification TEXT, severity TEXT,"
       " update_type TEXT, deployment_action TEXT, discovered_at TEXT NOT NULL,"
       " last_attempt_at TEXT, last_succeeded_at TEXT, status TEXT NOT NULL,"
       " failure_code TEXT, detail_json TEXT, installed INTEGER NOT NULL DEFAULT 0,"
       " hidden INTEGER NOT NULL DEFAULT 0, downloaded INTEGER NOT NULL DEFAULT 0,"
       " mandatory INTEGER NOT NULL DEFAULT 0, browse_only INTEGER NOT NULL DEFAULT 0,"
       " reboot_required INTEGER NOT NULL DEFAULT 0, driver INTEGER NOT NULL DEFAULT 0,"
       " feature_update INTEGER NOT NULL DEFAULT 0, optional INTEGER NOT NULL DEFAULT 0"
       ");"
       "CREATE TABLE IF NOT EXISTS software_patch_inventory ("
       " software_id TEXT PRIMARY KEY, display_name TEXT NOT NULL, display_version TEXT,"
       " available_version TEXT, publisher TEXT, install_location TEXT,"
       " uninstall_command TEXT, quiet_uninstall_command TEXT,"
       " executable_names TEXT, executable_paths TEXT, provider TEXT, provider_id TEXT,"
       " supported_source TEXT, update_state TEXT NOT NULL, update_summary TEXT,"
       " last_checked_at TEXT, last_attempted_at TEXT, last_updated_at TEXT,"
       " failure_code TEXT, detail_json TEXT, blocked INTEGER NOT NULL DEFAULT 0,"
       " supported INTEGER NOT NULL DEFAULT 0, manual_only INTEGER NOT NULL DEFAULT 0,"
       " user_interaction_required INTEGER NOT NULL DEFAULT 0,"
       " reboot_required INTEGER NOT NULL DEFAULT 0, high_risk INTEGER NOT NULL DEFAULT 0"
       ");"
       "CREATE TABLE IF NOT EXISTS patch_history ("
       " record_id TEXT PRIMARY KEY, target_type TEXT NOT NULL, target_id TEXT NOT NULL,"
       " title TEXT, provider TEXT, action TEXT NOT NULL, status TEXT NOT NULL,"
       " started_at TEXT NOT NULL, completed_at TEXT, error_code TEXT, detail_json TEXT,"
       " reboot_required INTEGER NOT NULL DEFAULT 0"
       ");"
       "CREATE TABLE IF NOT EXISTS patch_recipes ("
       " recipe_id TEXT PRIMARY KEY, display_name TEXT NOT NULL, publisher TEXT,"
       " match_pattern TEXT, winget_id TEXT, source_url TEXT, installer_sha256 TEXT,"
       " required_signer TEXT, silent_args TEXT, reboot_behavior TEXT,"
       " detect_hints_json TEXT, updated_at TEXT, priority INTEGER NOT NULL DEFAULT 300,"
       " manual_only INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1"
       ");"
       "CREATE TABLE IF NOT EXISTS reboot_coordinator ("
       " singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
       " reboot_required INTEGER NOT NULL DEFAULT 0,"
       " pending_windows_update INTEGER NOT NULL DEFAULT 0,"
       " pending_file_rename INTEGER NOT NULL DEFAULT 0,"
       " pending_computer_rename INTEGER NOT NULL DEFAULT 0,"
       " pending_component_servicing INTEGER NOT NULL DEFAULT 0,"
       " reboot_reasons TEXT, detected_at TEXT, deferred_until TEXT,"
       " grace_period_minutes INTEGER NOT NULL DEFAULT 0, status TEXT"
       ");"
       "CREATE TABLE IF NOT EXISTS threat_intelligence_cache ("
       " indicator_type TEXT NOT NULL, indicator_key TEXT NOT NULL,"
       " provider TEXT NOT NULL, source TEXT, verdict TEXT NOT NULL,"
       " trust_score INTEGER NOT NULL DEFAULT 0, provider_weight INTEGER NOT NULL DEFAULT 0,"
       " summary TEXT, details TEXT, metadata_json TEXT,"
       " first_seen_at TEXT, last_seen_at TEXT, expires_at TEXT,"
       " signed_pack INTEGER NOT NULL DEFAULT 0, local_only INTEGER NOT NULL DEFAULT 0,"
       " PRIMARY KEY(indicator_type, indicator_key, provider)"
       ");"
       "CREATE TABLE IF NOT EXISTS exclusion_policy ("
       " rule_id TEXT PRIMARY KEY, path TEXT NOT NULL, scope TEXT,"
       " created_by TEXT, reason TEXT, created_at TEXT NOT NULL, expires_at TEXT,"
       " warning_state TEXT, risk_level TEXT, state TEXT NOT NULL,"
       " dangerous INTEGER NOT NULL DEFAULT 0, approved INTEGER NOT NULL DEFAULT 0"
       ");"
       "CREATE TABLE IF NOT EXISTS quarantine_approvals ("
       " record_id TEXT NOT NULL, action TEXT NOT NULL, requested_by TEXT, approved_by TEXT,"
       " restore_path TEXT, requested_at TEXT NOT NULL, decided_at TEXT, decision TEXT NOT NULL, reason TEXT,"
       " PRIMARY KEY(record_id, action, requested_at)"
       ");"
      "CREATE TABLE IF NOT EXISTS local_admin_baseline ("
      " entry_id INTEGER PRIMARY KEY AUTOINCREMENT,"
      " baseline_id TEXT NOT NULL, captured_at TEXT NOT NULL, captured_by TEXT,"
      " account_name TEXT NOT NULL, sid TEXT, member_class TEXT NOT NULL,"
      " protected_member INTEGER NOT NULL DEFAULT 0, managed_candidate INTEGER NOT NULL DEFAULT 0"
      ");"
       "CREATE INDEX IF NOT EXISTS idx_telemetry_queue_queue_id ON telemetry_queue(queue_id);"
       "CREATE INDEX IF NOT EXISTS idx_command_journal_status ON command_journal(status, updated_at);"
       "CREATE INDEX IF NOT EXISTS idx_quarantine_index_status ON quarantine_index(local_status);"
       "CREATE INDEX IF NOT EXISTS idx_evidence_index_source ON evidence_index(source, recorded_at);"
       "CREATE INDEX IF NOT EXISTS idx_scan_history_recorded_at ON scan_history(recorded_at DESC);"
       "CREATE INDEX IF NOT EXISTS idx_update_journal_status ON update_journal(status, started_at DESC);"
       "CREATE INDEX IF NOT EXISTS idx_blocked_software_name ON blocked_software(display_name);"
       "CREATE INDEX IF NOT EXISTS idx_windows_update_status ON windows_update_inventory(status, classification);"
       "CREATE INDEX IF NOT EXISTS idx_software_patch_state ON software_patch_inventory(update_state, provider);"
       "CREATE INDEX IF NOT EXISTS idx_patch_history_started_at ON patch_history(started_at DESC);"
       "CREATE INDEX IF NOT EXISTS idx_patch_recipes_name ON patch_recipes(display_name, priority);"
       "CREATE INDEX IF NOT EXISTS idx_threat_intel_lookup ON threat_intelligence_cache(indicator_type, indicator_key, expires_at);"
       "CREATE INDEX IF NOT EXISTS idx_exclusion_policy_state ON exclusion_policy(state, expires_at);"
      "CREATE INDEX IF NOT EXISTS idx_quarantine_approvals_decision ON quarantine_approvals(decision, requested_at DESC);"
      "CREATE INDEX IF NOT EXISTS idx_local_admin_baseline_group ON local_admin_baseline(baseline_id, captured_at DESC);"
      "CREATE INDEX IF NOT EXISTS idx_local_admin_baseline_sid ON local_admin_baseline(sid, baseline_id);");
}

void RunSchemaMigrations(sqlite3* db) {
  const auto currentVersion = GetUserVersion(db);
  if (currentVersion >= kRuntimeDatabaseSchemaVersion) {
    return;
  }

  try {
    Begin(db);

    if (currentVersion < 2) {
      ExecIgnoreDuplicateColumn(db, "ALTER TABLE policy_cache ADD COLUMN suppression_path_roots TEXT NOT NULL DEFAULT '';");
      ExecIgnoreDuplicateColumn(db, "ALTER TABLE policy_cache ADD COLUMN suppression_sha256 TEXT NOT NULL DEFAULT '';");
      ExecIgnoreDuplicateColumn(db, "ALTER TABLE policy_cache ADD COLUMN suppression_signer_names TEXT NOT NULL DEFAULT '';");
    }

    if (currentVersion < 3) {
      EnsureBaseSchema(db);
    }

    if (currentVersion < 4) {
      EnsureBaseSchema(db);
    }

    if (currentVersion < 5) {
      EnsureBaseSchema(db);
    }

    if (currentVersion < 6) {
      EnsureBaseSchema(db);
    }

    SetUserVersion(db, kRuntimeDatabaseSchemaVersion);
    Commit(db);
  } catch (...) {
    Rollback(db);
    throw;
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
  EnsureBaseSchema(connection.get());
  RunSchemaMigrations(connection.get());
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

std::wstring JoinStrings(const std::vector<std::wstring>& values) {
  std::wstringstream stream;
  for (std::size_t index = 0; index < values.size(); ++index) {
    if (index > 0) {
      stream << L";";
    }
    stream << values[index];
  }
  return stream.str();
}

std::vector<std::wstring> SplitStrings(const std::wstring& value) {
  std::vector<std::wstring> results;
  std::wstringstream stream(value);
  std::wstring item;
  while (std::getline(stream, item, L';')) {
    if (!item.empty()) {
      results.push_back(item);
    }
  }
  return results;
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
                                 " quarantine_on_malicious, suppression_path_roots, suppression_sha256,"
                                 " suppression_signer_names FROM policy_cache WHERE singleton=1;");
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
    state.policy.suppressionPathRoots = SplitStrings(ColumnText(policyStatement.get(), 8));
    state.policy.suppressionSha256 = SplitStrings(ColumnText(policyStatement.get(), 9));
    state.policy.suppressionSignerNames = SplitStrings(ColumnText(policyStatement.get(), 10));
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
                                   " quarantine_on_malicious, suppression_path_roots, suppression_sha256,"
                                   " suppression_signer_names)"
                                   " VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                                   " ON CONFLICT(singleton) DO UPDATE SET"
                                   " policy_id=excluded.policy_id, policy_name=excluded.policy_name,"
                                   " revision=excluded.revision,"
                                   " realtime_protection_enabled=excluded.realtime_protection_enabled,"
                                   " cloud_lookup_enabled=excluded.cloud_lookup_enabled,"
                                   " script_inspection_enabled=excluded.script_inspection_enabled,"
                                   " network_containment_enabled=excluded.network_containment_enabled,"
                                   " quarantine_on_malicious=excluded.quarantine_on_malicious,"
                                   " suppression_path_roots=excluded.suppression_path_roots,"
                                   " suppression_sha256=excluded.suppression_sha256,"
                                   " suppression_signer_names=excluded.suppression_signer_names;");
    sqlite3_bind_int(policyStatement.get(), 1, kSingletonKey);
    BindText(policyStatement.get(), 2, state.policy.policyId);
    BindText(policyStatement.get(), 3, state.policy.policyName);
    BindText(policyStatement.get(), 4, state.policy.revision);
    sqlite3_bind_int(policyStatement.get(), 5, state.policy.realtimeProtectionEnabled ? 1 : 0);
    sqlite3_bind_int(policyStatement.get(), 6, state.policy.cloudLookupEnabled ? 1 : 0);
    sqlite3_bind_int(policyStatement.get(), 7, state.policy.scriptInspectionEnabled ? 1 : 0);
    sqlite3_bind_int(policyStatement.get(), 8, state.policy.networkContainmentEnabled ? 1 : 0);
    sqlite3_bind_int(policyStatement.get(), 9, state.policy.quarantineOnMalicious ? 1 : 0);
    BindText(policyStatement.get(), 10, JoinStrings(state.policy.suppressionPathRoots));
    BindText(policyStatement.get(), 11, JoinStrings(state.policy.suppressionSha256));
    BindText(policyStatement.get(), 12, JoinStrings(state.policy.suppressionSignerNames));
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

void RuntimeDatabase::UpsertBlockedSoftwareRule(const BlockedSoftwareRule& record) const {
  const auto db = OpenConnection(databasePath_);
  auto statement = Prepare(db.get(),
                           "INSERT INTO blocked_software("
                           " software_id, display_name, install_location, executable_names, blocked_at)"
                           " VALUES(?, ?, ?, ?, ?)"
                           " ON CONFLICT(software_id) DO UPDATE SET"
                           " display_name=excluded.display_name, install_location=excluded.install_location,"
                           " executable_names=excluded.executable_names, blocked_at=excluded.blocked_at;");
  BindText(statement.get(), 1, record.softwareId);
  BindText(statement.get(), 2, record.displayName);
  BindText(statement.get(), 3, record.installLocation);
  BindText(statement.get(), 4, JoinStrings(record.executableNames));
  BindText(statement.get(), 5, record.blockedAt);
  StepDone(db.get(), statement.get());
}

std::vector<BlockedSoftwareRule> RuntimeDatabase::ListBlockedSoftwareRules(const std::size_t limit) const {
  const auto db = OpenConnection(databasePath_);
  auto statement = Prepare(db.get(),
                           "SELECT software_id, display_name, install_location, executable_names, blocked_at"
                           " FROM blocked_software ORDER BY blocked_at DESC, software_id DESC LIMIT ?;");
  sqlite3_bind_int64(statement.get(), 1, static_cast<sqlite3_int64>(limit));

  std::vector<BlockedSoftwareRule> records;
  for (;;) {
    const auto step = sqlite3_step(statement.get());
    if (step == SQLITE_DONE) {
      break;
    }
    if (step != SQLITE_ROW) {
      ThrowSqliteError(db.get(), "listing blocked software rules failed");
    }

    records.push_back(BlockedSoftwareRule{
        .softwareId = ColumnText(statement.get(), 0),
        .displayName = ColumnText(statement.get(), 1),
        .installLocation = ColumnText(statement.get(), 2),
        .executableNames = SplitStrings(ColumnText(statement.get(), 3)),
        .blockedAt = ColumnText(statement.get(), 4)});
  }

  return records;
}

void RuntimeDatabase::SavePatchPolicy(const PatchPolicyRecord& record) const {
  const auto db = OpenConnection(databasePath_);
  auto statement = Prepare(db.get(),
                           "INSERT INTO patch_policy("
                           " singleton, policy_id, auto_install_windows_security, auto_install_windows_quality,"
                           " defer_feature_updates, include_driver_updates, include_optional_updates,"
                           " auto_update_high_risk_apps_only, auto_update_all_supported_apps,"
                           " notify_before_update, silent_only, skip_interactive_updates, paused,"
                           " respect_metered_connections, battery_aware, allow_native_updaters,"
                           " allow_winget, allow_recipes, maintenance_window_start, maintenance_window_end,"
                           " reboot_grace_period_minutes, feature_update_deferral_days,"
                           " active_hours_start, active_hours_end, updated_at)"
                           " VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                           " ON CONFLICT(singleton) DO UPDATE SET"
                           " policy_id=excluded.policy_id,"
                           " auto_install_windows_security=excluded.auto_install_windows_security,"
                           " auto_install_windows_quality=excluded.auto_install_windows_quality,"
                           " defer_feature_updates=excluded.defer_feature_updates,"
                           " include_driver_updates=excluded.include_driver_updates,"
                           " include_optional_updates=excluded.include_optional_updates,"
                           " auto_update_high_risk_apps_only=excluded.auto_update_high_risk_apps_only,"
                           " auto_update_all_supported_apps=excluded.auto_update_all_supported_apps,"
                           " notify_before_update=excluded.notify_before_update,"
                           " silent_only=excluded.silent_only,"
                           " skip_interactive_updates=excluded.skip_interactive_updates,"
                           " paused=excluded.paused,"
                           " respect_metered_connections=excluded.respect_metered_connections,"
                           " battery_aware=excluded.battery_aware,"
                           " allow_native_updaters=excluded.allow_native_updaters,"
                           " allow_winget=excluded.allow_winget,"
                           " allow_recipes=excluded.allow_recipes,"
                           " maintenance_window_start=excluded.maintenance_window_start,"
                           " maintenance_window_end=excluded.maintenance_window_end,"
                           " reboot_grace_period_minutes=excluded.reboot_grace_period_minutes,"
                           " feature_update_deferral_days=excluded.feature_update_deferral_days,"
                           " active_hours_start=excluded.active_hours_start,"
                           " active_hours_end=excluded.active_hours_end,"
                           " updated_at=excluded.updated_at;");
  sqlite3_bind_int(statement.get(), 1, kSingletonKey);
  BindText(statement.get(), 2, record.policyId);
  sqlite3_bind_int(statement.get(), 3, record.autoInstallWindowsSecurity ? 1 : 0);
  sqlite3_bind_int(statement.get(), 4, record.autoInstallWindowsQuality ? 1 : 0);
  sqlite3_bind_int(statement.get(), 5, record.deferFeatureUpdates ? 1 : 0);
  sqlite3_bind_int(statement.get(), 6, record.includeDriverUpdates ? 1 : 0);
  sqlite3_bind_int(statement.get(), 7, record.includeOptionalUpdates ? 1 : 0);
  sqlite3_bind_int(statement.get(), 8, record.autoUpdateHighRiskAppsOnly ? 1 : 0);
  sqlite3_bind_int(statement.get(), 9, record.autoUpdateAllSupportedApps ? 1 : 0);
  sqlite3_bind_int(statement.get(), 10, record.notifyBeforeUpdate ? 1 : 0);
  sqlite3_bind_int(statement.get(), 11, record.silentOnly ? 1 : 0);
  sqlite3_bind_int(statement.get(), 12, record.skipInteractiveUpdates ? 1 : 0);
  sqlite3_bind_int(statement.get(), 13, record.paused ? 1 : 0);
  sqlite3_bind_int(statement.get(), 14, record.respectMeteredConnections ? 1 : 0);
  sqlite3_bind_int(statement.get(), 15, record.batteryAware ? 1 : 0);
  sqlite3_bind_int(statement.get(), 16, record.allowNativeUpdaters ? 1 : 0);
  sqlite3_bind_int(statement.get(), 17, record.allowWinget ? 1 : 0);
  sqlite3_bind_int(statement.get(), 18, record.allowRecipes ? 1 : 0);
  BindText(statement.get(), 19, record.maintenanceWindowStart);
  BindText(statement.get(), 20, record.maintenanceWindowEnd);
  sqlite3_bind_int(statement.get(), 21, record.rebootGracePeriodMinutes);
  sqlite3_bind_int(statement.get(), 22, record.featureUpdateDeferralDays);
  BindText(statement.get(), 23, record.activeHoursStart);
  BindText(statement.get(), 24, record.activeHoursEnd);
  BindText(statement.get(), 25, record.updatedAt);
  StepDone(db.get(), statement.get());
}

bool RuntimeDatabase::LoadPatchPolicy(PatchPolicyRecord& record) const {
  const auto db = OpenConnection(databasePath_);
  auto statement = Prepare(db.get(),
                           "SELECT policy_id, auto_install_windows_security, auto_install_windows_quality,"
                           " defer_feature_updates, include_driver_updates, include_optional_updates,"
                           " auto_update_high_risk_apps_only, auto_update_all_supported_apps,"
                           " notify_before_update, silent_only, skip_interactive_updates, paused,"
                           " respect_metered_connections, battery_aware, allow_native_updaters,"
                           " allow_winget, allow_recipes, maintenance_window_start, maintenance_window_end,"
                           " reboot_grace_period_minutes, feature_update_deferral_days,"
                           " active_hours_start, active_hours_end, updated_at"
                           " FROM patch_policy WHERE singleton=1;");
  const auto step = sqlite3_step(statement.get());
  if (step == SQLITE_DONE) {
    return false;
  }
  if (step != SQLITE_ROW) {
    ThrowSqliteError(db.get(), "loading patch policy failed");
  }

  record.policyId = ColumnText(statement.get(), 0);
  record.autoInstallWindowsSecurity = sqlite3_column_int(statement.get(), 1) != 0;
  record.autoInstallWindowsQuality = sqlite3_column_int(statement.get(), 2) != 0;
  record.deferFeatureUpdates = sqlite3_column_int(statement.get(), 3) != 0;
  record.includeDriverUpdates = sqlite3_column_int(statement.get(), 4) != 0;
  record.includeOptionalUpdates = sqlite3_column_int(statement.get(), 5) != 0;
  record.autoUpdateHighRiskAppsOnly = sqlite3_column_int(statement.get(), 6) != 0;
  record.autoUpdateAllSupportedApps = sqlite3_column_int(statement.get(), 7) != 0;
  record.notifyBeforeUpdate = sqlite3_column_int(statement.get(), 8) != 0;
  record.silentOnly = sqlite3_column_int(statement.get(), 9) != 0;
  record.skipInteractiveUpdates = sqlite3_column_int(statement.get(), 10) != 0;
  record.paused = sqlite3_column_int(statement.get(), 11) != 0;
  record.respectMeteredConnections = sqlite3_column_int(statement.get(), 12) != 0;
  record.batteryAware = sqlite3_column_int(statement.get(), 13) != 0;
  record.allowNativeUpdaters = sqlite3_column_int(statement.get(), 14) != 0;
  record.allowWinget = sqlite3_column_int(statement.get(), 15) != 0;
  record.allowRecipes = sqlite3_column_int(statement.get(), 16) != 0;
  record.maintenanceWindowStart = ColumnText(statement.get(), 17);
  record.maintenanceWindowEnd = ColumnText(statement.get(), 18);
  record.rebootGracePeriodMinutes = sqlite3_column_int(statement.get(), 19);
  record.featureUpdateDeferralDays = sqlite3_column_int(statement.get(), 20);
  record.activeHoursStart = ColumnText(statement.get(), 21);
  record.activeHoursEnd = ColumnText(statement.get(), 22);
  record.updatedAt = ColumnText(statement.get(), 23);
  return true;
}

void RuntimeDatabase::ReplaceWindowsUpdateRecords(const std::vector<WindowsUpdateRecord>& records) const {
  const auto db = OpenConnection(databasePath_);
  try {
    Begin(db.get());
    Exec(db.get(), "DELETE FROM windows_update_inventory;");
    auto statement = Prepare(db.get(),
                             "INSERT INTO windows_update_inventory("
                             " update_id, revision, title, kb_articles, categories, classification, severity,"
                             " update_type, deployment_action, discovered_at, last_attempt_at, last_succeeded_at,"
                             " status, failure_code, detail_json, installed, hidden, downloaded, mandatory,"
                             " browse_only, reboot_required, driver, feature_update, optional)"
                             " VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);");
    for (const auto& record : records) {
      sqlite3_reset(statement.get());
      sqlite3_clear_bindings(statement.get());
      BindText(statement.get(), 1, record.updateId);
      BindText(statement.get(), 2, record.revision);
      BindText(statement.get(), 3, record.title);
      BindText(statement.get(), 4, record.kbArticles);
      BindText(statement.get(), 5, record.categories);
      BindText(statement.get(), 6, record.classification);
      BindText(statement.get(), 7, record.severity);
      BindText(statement.get(), 8, record.updateType);
      BindText(statement.get(), 9, record.deploymentAction);
      BindText(statement.get(), 10, record.discoveredAt);
      BindText(statement.get(), 11, record.lastAttemptAt);
      BindText(statement.get(), 12, record.lastSucceededAt);
      BindText(statement.get(), 13, record.status);
      BindText(statement.get(), 14, record.failureCode);
      BindText(statement.get(), 15, record.detailJson);
      sqlite3_bind_int(statement.get(), 16, record.installed ? 1 : 0);
      sqlite3_bind_int(statement.get(), 17, record.hidden ? 1 : 0);
      sqlite3_bind_int(statement.get(), 18, record.downloaded ? 1 : 0);
      sqlite3_bind_int(statement.get(), 19, record.mandatory ? 1 : 0);
      sqlite3_bind_int(statement.get(), 20, record.browseOnly ? 1 : 0);
      sqlite3_bind_int(statement.get(), 21, record.rebootRequired ? 1 : 0);
      sqlite3_bind_int(statement.get(), 22, record.driver ? 1 : 0);
      sqlite3_bind_int(statement.get(), 23, record.featureUpdate ? 1 : 0);
      sqlite3_bind_int(statement.get(), 24, record.optional ? 1 : 0);
      StepDone(db.get(), statement.get());
    }
    Commit(db.get());
  } catch (...) {
    Rollback(db.get());
    throw;
  }
}

std::vector<WindowsUpdateRecord> RuntimeDatabase::ListWindowsUpdateRecords(const std::size_t limit) const {
  const auto db = OpenConnection(databasePath_);
  auto statement = Prepare(db.get(),
                           "SELECT update_id, revision, title, kb_articles, categories, classification, severity,"
                           " update_type, deployment_action, discovered_at, last_attempt_at, last_succeeded_at,"
                           " status, failure_code, detail_json, installed, hidden, downloaded, mandatory,"
                           " browse_only, reboot_required, driver, feature_update, optional"
                           " FROM windows_update_inventory"
                           " ORDER BY discovered_at DESC, title ASC LIMIT ?;");
  sqlite3_bind_int64(statement.get(), 1, static_cast<sqlite3_int64>(limit));
  std::vector<WindowsUpdateRecord> records;
  for (;;) {
    const auto step = sqlite3_step(statement.get());
    if (step == SQLITE_DONE) {
      break;
    }
    if (step != SQLITE_ROW) {
      ThrowSqliteError(db.get(), "listing windows update inventory failed");
    }

    records.push_back(WindowsUpdateRecord{
        .updateId = ColumnText(statement.get(), 0),
        .revision = ColumnText(statement.get(), 1),
        .title = ColumnText(statement.get(), 2),
        .kbArticles = ColumnText(statement.get(), 3),
        .categories = ColumnText(statement.get(), 4),
        .classification = ColumnText(statement.get(), 5),
        .severity = ColumnText(statement.get(), 6),
        .updateType = ColumnText(statement.get(), 7),
        .deploymentAction = ColumnText(statement.get(), 8),
        .discoveredAt = ColumnText(statement.get(), 9),
        .lastAttemptAt = ColumnText(statement.get(), 10),
        .lastSucceededAt = ColumnText(statement.get(), 11),
        .status = ColumnText(statement.get(), 12),
        .failureCode = ColumnText(statement.get(), 13),
        .detailJson = ColumnText(statement.get(), 14),
        .installed = sqlite3_column_int(statement.get(), 15) != 0,
        .hidden = sqlite3_column_int(statement.get(), 16) != 0,
        .downloaded = sqlite3_column_int(statement.get(), 17) != 0,
        .mandatory = sqlite3_column_int(statement.get(), 18) != 0,
        .browseOnly = sqlite3_column_int(statement.get(), 19) != 0,
        .rebootRequired = sqlite3_column_int(statement.get(), 20) != 0,
        .driver = sqlite3_column_int(statement.get(), 21) != 0,
        .featureUpdate = sqlite3_column_int(statement.get(), 22) != 0,
        .optional = sqlite3_column_int(statement.get(), 23) != 0});
  }
  return records;
}

void RuntimeDatabase::ReplaceSoftwarePatchRecords(const std::vector<SoftwarePatchRecord>& records) const {
  const auto db = OpenConnection(databasePath_);
  try {
    Begin(db.get());
    Exec(db.get(), "DELETE FROM software_patch_inventory;");
    auto statement = Prepare(db.get(),
                             "INSERT INTO software_patch_inventory("
                             " software_id, display_name, display_version, available_version, publisher,"
                             " install_location, uninstall_command, quiet_uninstall_command, executable_names,"
                             " executable_paths, provider, provider_id, supported_source, update_state,"
                             " update_summary, last_checked_at, last_attempted_at, last_updated_at, failure_code,"
                             " detail_json, blocked, supported, manual_only, user_interaction_required,"
                             " reboot_required, high_risk)"
                             " VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);");
    for (const auto& record : records) {
      sqlite3_reset(statement.get());
      sqlite3_clear_bindings(statement.get());
      BindText(statement.get(), 1, record.softwareId);
      BindText(statement.get(), 2, record.displayName);
      BindText(statement.get(), 3, record.displayVersion);
      BindText(statement.get(), 4, record.availableVersion);
      BindText(statement.get(), 5, record.publisher);
      BindText(statement.get(), 6, record.installLocation);
      BindText(statement.get(), 7, record.uninstallCommand);
      BindText(statement.get(), 8, record.quietUninstallCommand);
      BindText(statement.get(), 9, record.executableNames);
      BindText(statement.get(), 10, record.executablePaths);
      BindText(statement.get(), 11, record.provider);
      BindText(statement.get(), 12, record.providerId);
      BindText(statement.get(), 13, record.supportedSource);
      BindText(statement.get(), 14, record.updateState);
      BindText(statement.get(), 15, record.updateSummary);
      BindText(statement.get(), 16, record.lastCheckedAt);
      BindText(statement.get(), 17, record.lastAttemptedAt);
      BindText(statement.get(), 18, record.lastUpdatedAt);
      BindText(statement.get(), 19, record.failureCode);
      BindText(statement.get(), 20, record.detailJson);
      sqlite3_bind_int(statement.get(), 21, record.blocked ? 1 : 0);
      sqlite3_bind_int(statement.get(), 22, record.supported ? 1 : 0);
      sqlite3_bind_int(statement.get(), 23, record.manualOnly ? 1 : 0);
      sqlite3_bind_int(statement.get(), 24, record.userInteractionRequired ? 1 : 0);
      sqlite3_bind_int(statement.get(), 25, record.rebootRequired ? 1 : 0);
      sqlite3_bind_int(statement.get(), 26, record.highRisk ? 1 : 0);
      StepDone(db.get(), statement.get());
    }
    Commit(db.get());
  } catch (...) {
    Rollback(db.get());
    throw;
  }
}

std::vector<SoftwarePatchRecord> RuntimeDatabase::ListSoftwarePatchRecords(const std::size_t limit) const {
  const auto db = OpenConnection(databasePath_);
  auto statement = Prepare(db.get(),
                           "SELECT software_id, display_name, display_version, available_version, publisher,"
                           " install_location, uninstall_command, quiet_uninstall_command, executable_names,"
                           " executable_paths, provider, provider_id, supported_source, update_state,"
                           " update_summary, last_checked_at, last_attempted_at, last_updated_at, failure_code,"
                           " detail_json, blocked, supported, manual_only, user_interaction_required,"
                           " reboot_required, high_risk FROM software_patch_inventory"
                           " ORDER BY high_risk DESC, display_name ASC LIMIT ?;");
  sqlite3_bind_int64(statement.get(), 1, static_cast<sqlite3_int64>(limit));
  std::vector<SoftwarePatchRecord> records;
  for (;;) {
    const auto step = sqlite3_step(statement.get());
    if (step == SQLITE_DONE) {
      break;
    }
    if (step != SQLITE_ROW) {
      ThrowSqliteError(db.get(), "listing software patch inventory failed");
    }

    records.push_back(SoftwarePatchRecord{
        .softwareId = ColumnText(statement.get(), 0),
        .displayName = ColumnText(statement.get(), 1),
        .displayVersion = ColumnText(statement.get(), 2),
        .availableVersion = ColumnText(statement.get(), 3),
        .publisher = ColumnText(statement.get(), 4),
        .installLocation = ColumnText(statement.get(), 5),
        .uninstallCommand = ColumnText(statement.get(), 6),
        .quietUninstallCommand = ColumnText(statement.get(), 7),
        .executableNames = ColumnText(statement.get(), 8),
        .executablePaths = ColumnText(statement.get(), 9),
        .provider = ColumnText(statement.get(), 10),
        .providerId = ColumnText(statement.get(), 11),
        .supportedSource = ColumnText(statement.get(), 12),
        .updateState = ColumnText(statement.get(), 13),
        .updateSummary = ColumnText(statement.get(), 14),
        .lastCheckedAt = ColumnText(statement.get(), 15),
        .lastAttemptedAt = ColumnText(statement.get(), 16),
        .lastUpdatedAt = ColumnText(statement.get(), 17),
        .failureCode = ColumnText(statement.get(), 18),
        .detailJson = ColumnText(statement.get(), 19),
        .blocked = sqlite3_column_int(statement.get(), 20) != 0,
        .supported = sqlite3_column_int(statement.get(), 21) != 0,
        .manualOnly = sqlite3_column_int(statement.get(), 22) != 0,
        .userInteractionRequired = sqlite3_column_int(statement.get(), 23) != 0,
        .rebootRequired = sqlite3_column_int(statement.get(), 24) != 0,
        .highRisk = sqlite3_column_int(statement.get(), 25) != 0});
  }
  return records;
}

void RuntimeDatabase::UpsertPatchHistoryRecord(const PatchHistoryRecord& record) const {
  const auto db = OpenConnection(databasePath_);
  auto statement = Prepare(db.get(),
                           "INSERT INTO patch_history("
                           " record_id, target_type, target_id, title, provider, action, status,"
                           " started_at, completed_at, error_code, detail_json, reboot_required)"
                           " VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                           " ON CONFLICT(record_id) DO UPDATE SET"
                           " target_type=excluded.target_type, target_id=excluded.target_id,"
                           " title=excluded.title, provider=excluded.provider, action=excluded.action,"
                           " status=excluded.status, started_at=excluded.started_at,"
                           " completed_at=excluded.completed_at, error_code=excluded.error_code,"
                           " detail_json=excluded.detail_json, reboot_required=excluded.reboot_required;");
  BindText(statement.get(), 1, record.recordId);
  BindText(statement.get(), 2, record.targetType);
  BindText(statement.get(), 3, record.targetId);
  BindText(statement.get(), 4, record.title);
  BindText(statement.get(), 5, record.provider);
  BindText(statement.get(), 6, record.action);
  BindText(statement.get(), 7, record.status);
  BindText(statement.get(), 8, record.startedAt);
  BindText(statement.get(), 9, record.completedAt);
  BindText(statement.get(), 10, record.errorCode);
  BindText(statement.get(), 11, record.detailJson);
  sqlite3_bind_int(statement.get(), 12, record.rebootRequired ? 1 : 0);
  StepDone(db.get(), statement.get());
}

std::vector<PatchHistoryRecord> RuntimeDatabase::ListPatchHistoryRecords(const std::size_t limit) const {
  const auto db = OpenConnection(databasePath_);
  auto statement = Prepare(db.get(),
                           "SELECT record_id, target_type, target_id, title, provider, action, status,"
                           " started_at, completed_at, error_code, detail_json, reboot_required"
                           " FROM patch_history ORDER BY started_at DESC, record_id DESC LIMIT ?;");
  sqlite3_bind_int64(statement.get(), 1, static_cast<sqlite3_int64>(limit));
  std::vector<PatchHistoryRecord> records;
  for (;;) {
    const auto step = sqlite3_step(statement.get());
    if (step == SQLITE_DONE) {
      break;
    }
    if (step != SQLITE_ROW) {
      ThrowSqliteError(db.get(), "listing patch history failed");
    }

    records.push_back(PatchHistoryRecord{
        .recordId = ColumnText(statement.get(), 0),
        .targetType = ColumnText(statement.get(), 1),
        .targetId = ColumnText(statement.get(), 2),
        .title = ColumnText(statement.get(), 3),
        .provider = ColumnText(statement.get(), 4),
        .action = ColumnText(statement.get(), 5),
        .status = ColumnText(statement.get(), 6),
        .startedAt = ColumnText(statement.get(), 7),
        .completedAt = ColumnText(statement.get(), 8),
        .errorCode = ColumnText(statement.get(), 9),
        .detailJson = ColumnText(statement.get(), 10),
        .rebootRequired = sqlite3_column_int(statement.get(), 11) != 0});
  }
  return records;
}

void RuntimeDatabase::ReplacePackageRecipes(const std::vector<PackageRecipeRecord>& records) const {
  const auto db = OpenConnection(databasePath_);
  try {
    Begin(db.get());
    Exec(db.get(), "DELETE FROM patch_recipes;");
    auto statement = Prepare(db.get(),
                             "INSERT INTO patch_recipes("
                             " recipe_id, display_name, publisher, match_pattern, winget_id, source_url,"
                             " installer_sha256, required_signer, silent_args, reboot_behavior, detect_hints_json,"
                             " updated_at, priority, manual_only, enabled)"
                             " VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);");
    for (const auto& record : records) {
      sqlite3_reset(statement.get());
      sqlite3_clear_bindings(statement.get());
      BindText(statement.get(), 1, record.recipeId);
      BindText(statement.get(), 2, record.displayName);
      BindText(statement.get(), 3, record.publisher);
      BindText(statement.get(), 4, record.matchPattern);
      BindText(statement.get(), 5, record.wingetId);
      BindText(statement.get(), 6, record.sourceUrl);
      BindText(statement.get(), 7, record.installerSha256);
      BindText(statement.get(), 8, record.requiredSigner);
      BindText(statement.get(), 9, record.silentArgs);
      BindText(statement.get(), 10, record.rebootBehavior);
      BindText(statement.get(), 11, record.detectHintsJson);
      BindText(statement.get(), 12, record.updatedAt);
      sqlite3_bind_int(statement.get(), 13, record.priority);
      sqlite3_bind_int(statement.get(), 14, record.manualOnly ? 1 : 0);
      sqlite3_bind_int(statement.get(), 15, record.enabled ? 1 : 0);
      StepDone(db.get(), statement.get());
    }
    Commit(db.get());
  } catch (...) {
    Rollback(db.get());
    throw;
  }
}

std::vector<PackageRecipeRecord> RuntimeDatabase::ListPackageRecipes(const std::size_t limit) const {
  const auto db = OpenConnection(databasePath_);
  auto statement = Prepare(db.get(),
                           "SELECT recipe_id, display_name, publisher, match_pattern, winget_id, source_url,"
                           " installer_sha256, required_signer, silent_args, reboot_behavior, detect_hints_json,"
                           " updated_at, priority, manual_only, enabled FROM patch_recipes"
                           " ORDER BY priority ASC, display_name ASC LIMIT ?;");
  sqlite3_bind_int64(statement.get(), 1, static_cast<sqlite3_int64>(limit));
  std::vector<PackageRecipeRecord> records;
  for (;;) {
    const auto step = sqlite3_step(statement.get());
    if (step == SQLITE_DONE) {
      break;
    }
    if (step != SQLITE_ROW) {
      ThrowSqliteError(db.get(), "listing patch recipes failed");
    }

    records.push_back(PackageRecipeRecord{
        .recipeId = ColumnText(statement.get(), 0),
        .displayName = ColumnText(statement.get(), 1),
        .publisher = ColumnText(statement.get(), 2),
        .matchPattern = ColumnText(statement.get(), 3),
        .wingetId = ColumnText(statement.get(), 4),
        .sourceUrl = ColumnText(statement.get(), 5),
        .installerSha256 = ColumnText(statement.get(), 6),
        .requiredSigner = ColumnText(statement.get(), 7),
        .silentArgs = ColumnText(statement.get(), 8),
        .rebootBehavior = ColumnText(statement.get(), 9),
        .detectHintsJson = ColumnText(statement.get(), 10),
        .updatedAt = ColumnText(statement.get(), 11),
        .priority = sqlite3_column_int(statement.get(), 12),
        .manualOnly = sqlite3_column_int(statement.get(), 13) != 0,
        .enabled = sqlite3_column_int(statement.get(), 14) != 0});
  }
  return records;
}

void RuntimeDatabase::SaveRebootCoordinator(const RebootCoordinatorRecord& record) const {
  const auto db = OpenConnection(databasePath_);
  auto statement = Prepare(db.get(),
                           "INSERT INTO reboot_coordinator("
                           " singleton, reboot_required, pending_windows_update, pending_file_rename,"
                           " pending_computer_rename, pending_component_servicing, reboot_reasons, detected_at,"
                           " deferred_until, grace_period_minutes, status)"
                           " VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                           " ON CONFLICT(singleton) DO UPDATE SET"
                           " reboot_required=excluded.reboot_required,"
                           " pending_windows_update=excluded.pending_windows_update,"
                           " pending_file_rename=excluded.pending_file_rename,"
                           " pending_computer_rename=excluded.pending_computer_rename,"
                           " pending_component_servicing=excluded.pending_component_servicing,"
                           " reboot_reasons=excluded.reboot_reasons, detected_at=excluded.detected_at,"
                           " deferred_until=excluded.deferred_until,"
                           " grace_period_minutes=excluded.grace_period_minutes, status=excluded.status;");
  sqlite3_bind_int(statement.get(), 1, kSingletonKey);
  sqlite3_bind_int(statement.get(), 2, record.rebootRequired ? 1 : 0);
  sqlite3_bind_int(statement.get(), 3, record.pendingWindowsUpdate ? 1 : 0);
  sqlite3_bind_int(statement.get(), 4, record.pendingFileRename ? 1 : 0);
  sqlite3_bind_int(statement.get(), 5, record.pendingComputerRename ? 1 : 0);
  sqlite3_bind_int(statement.get(), 6, record.pendingComponentServicing ? 1 : 0);
  BindText(statement.get(), 7, record.rebootReasons);
  BindText(statement.get(), 8, record.detectedAt);
  BindText(statement.get(), 9, record.deferredUntil);
  sqlite3_bind_int(statement.get(), 10, record.gracePeriodMinutes);
  BindText(statement.get(), 11, record.status);
  StepDone(db.get(), statement.get());
}

bool RuntimeDatabase::LoadRebootCoordinator(RebootCoordinatorRecord& record) const {
  const auto db = OpenConnection(databasePath_);
  auto statement = Prepare(db.get(),
                           "SELECT reboot_required, pending_windows_update, pending_file_rename,"
                           " pending_computer_rename, pending_component_servicing, reboot_reasons,"
                           " detected_at, deferred_until, grace_period_minutes, status"
                           " FROM reboot_coordinator WHERE singleton=1;");
  const auto step = sqlite3_step(statement.get());
  if (step == SQLITE_DONE) {
    return false;
  }
  if (step != SQLITE_ROW) {
    ThrowSqliteError(db.get(), "loading reboot coordinator failed");
  }

  record.rebootRequired = sqlite3_column_int(statement.get(), 0) != 0;
  record.pendingWindowsUpdate = sqlite3_column_int(statement.get(), 1) != 0;
  record.pendingFileRename = sqlite3_column_int(statement.get(), 2) != 0;
  record.pendingComputerRename = sqlite3_column_int(statement.get(), 3) != 0;
  record.pendingComponentServicing = sqlite3_column_int(statement.get(), 4) != 0;
  record.rebootReasons = ColumnText(statement.get(), 5);
  record.detectedAt = ColumnText(statement.get(), 6);
  record.deferredUntil = ColumnText(statement.get(), 7);
  record.gracePeriodMinutes = sqlite3_column_int(statement.get(), 8);
  record.status = ColumnText(statement.get(), 9);
  return true;
}

void RuntimeDatabase::UpsertThreatIntelRecord(const ThreatIntelRecord& record) const {
  const auto db = OpenConnection(databasePath_);
  auto statement = Prepare(
      db.get(),
      "INSERT INTO threat_intelligence_cache("
      " indicator_type, indicator_key, provider, source, verdict, trust_score, provider_weight, summary, details,"
      " metadata_json, first_seen_at, last_seen_at, expires_at, signed_pack, local_only)"
      " VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
      " ON CONFLICT(indicator_type, indicator_key, provider) DO UPDATE SET"
      " source=excluded.source, verdict=excluded.verdict, trust_score=excluded.trust_score,"
      " provider_weight=excluded.provider_weight, summary=excluded.summary, details=excluded.details,"
      " metadata_json=excluded.metadata_json, first_seen_at=COALESCE(threat_intelligence_cache.first_seen_at, excluded.first_seen_at),"
      " last_seen_at=excluded.last_seen_at, expires_at=excluded.expires_at,"
      " signed_pack=excluded.signed_pack, local_only=excluded.local_only;");
  BindText(statement.get(), 1, ThreatIndicatorTypeToString(record.indicatorType));
  BindText(statement.get(), 2, record.indicatorKey);
  BindText(statement.get(), 3, record.provider);
  BindText(statement.get(), 4, record.source);
  BindText(statement.get(), 5, record.verdict);
  sqlite3_bind_int(statement.get(), 6, static_cast<int>(record.trustScore));
  sqlite3_bind_int(statement.get(), 7, static_cast<int>(record.providerWeight));
  BindText(statement.get(), 8, record.summary);
  BindText(statement.get(), 9, record.details);
  BindText(statement.get(), 10, record.metadataJson);
  BindText(statement.get(), 11, record.firstSeenAt);
  BindText(statement.get(), 12, record.lastSeenAt);
  BindText(statement.get(), 13, record.expiresAt);
  sqlite3_bind_int(statement.get(), 14, record.signedPack ? 1 : 0);
  sqlite3_bind_int(statement.get(), 15, record.localOnly ? 1 : 0);
  StepDone(db.get(), statement.get());
}

bool RuntimeDatabase::TryGetThreatIntelRecord(const ThreatIndicatorType indicatorType, const std::wstring& indicatorKey,
                                              ThreatIntelRecord& record) const {
  const auto db = OpenConnection(databasePath_);
  auto statement = Prepare(
      db.get(),
      "SELECT indicator_type, indicator_key, provider, source, verdict, trust_score, provider_weight, summary, details,"
      " metadata_json, first_seen_at, last_seen_at, expires_at, signed_pack, local_only"
      " FROM threat_intelligence_cache WHERE indicator_type=? AND indicator_key=?"
      " ORDER BY provider_weight DESC, trust_score DESC, last_seen_at DESC LIMIT 1;");
  BindText(statement.get(), 1, ThreatIndicatorTypeToString(indicatorType));
  BindText(statement.get(), 2, indicatorKey);
  const auto step = sqlite3_step(statement.get());
  if (step == SQLITE_DONE) {
    return false;
  }
  if (step != SQLITE_ROW) {
    ThrowSqliteError(db.get(), "loading threat intelligence cache failed");
  }

  record.indicatorType = ThreatIndicatorTypeFromString(ColumnText(statement.get(), 0));
  record.indicatorKey = ColumnText(statement.get(), 1);
  record.provider = ColumnText(statement.get(), 2);
  record.source = ColumnText(statement.get(), 3);
  record.verdict = ColumnText(statement.get(), 4);
  record.trustScore = static_cast<std::uint32_t>(sqlite3_column_int(statement.get(), 5));
  record.providerWeight = static_cast<std::uint32_t>(sqlite3_column_int(statement.get(), 6));
  record.summary = ColumnText(statement.get(), 7);
  record.details = ColumnText(statement.get(), 8);
  record.metadataJson = ColumnText(statement.get(), 9);
  record.firstSeenAt = ColumnText(statement.get(), 10);
  record.lastSeenAt = ColumnText(statement.get(), 11);
  record.expiresAt = ColumnText(statement.get(), 12);
  record.signedPack = sqlite3_column_int(statement.get(), 13) != 0;
  record.localOnly = sqlite3_column_int(statement.get(), 14) != 0;
  return true;
}

std::vector<ThreatIntelRecord> RuntimeDatabase::ListThreatIntelRecords(const std::size_t limit) const {
  const auto db = OpenConnection(databasePath_);
  auto statement = Prepare(
      db.get(),
      "SELECT indicator_type, indicator_key, provider, source, verdict, trust_score, provider_weight, summary, details,"
      " metadata_json, first_seen_at, last_seen_at, expires_at, signed_pack, local_only"
      " FROM threat_intelligence_cache ORDER BY last_seen_at DESC, provider_weight DESC LIMIT ?;");
  sqlite3_bind_int64(statement.get(), 1, static_cast<sqlite3_int64>(limit));

  std::vector<ThreatIntelRecord> records;
  for (;;) {
    const auto step = sqlite3_step(statement.get());
    if (step == SQLITE_DONE) {
      break;
    }
    if (step != SQLITE_ROW) {
      ThrowSqliteError(db.get(), "listing threat intelligence cache failed");
    }
    records.push_back(ThreatIntelRecord{
        .indicatorType = ThreatIndicatorTypeFromString(ColumnText(statement.get(), 0)),
        .indicatorKey = ColumnText(statement.get(), 1),
        .provider = ColumnText(statement.get(), 2),
        .source = ColumnText(statement.get(), 3),
        .verdict = ColumnText(statement.get(), 4),
        .trustScore = static_cast<std::uint32_t>(sqlite3_column_int(statement.get(), 5)),
        .providerWeight = static_cast<std::uint32_t>(sqlite3_column_int(statement.get(), 6)),
        .summary = ColumnText(statement.get(), 7),
        .details = ColumnText(statement.get(), 8),
        .metadataJson = ColumnText(statement.get(), 9),
        .firstSeenAt = ColumnText(statement.get(), 10),
        .lastSeenAt = ColumnText(statement.get(), 11),
        .expiresAt = ColumnText(statement.get(), 12),
        .signedPack = sqlite3_column_int(statement.get(), 13) != 0,
        .localOnly = sqlite3_column_int(statement.get(), 14) != 0});
  }
  return records;
}

void RuntimeDatabase::PurgeExpiredThreatIntelRecords(const std::wstring& referenceTimestamp) const {
  const auto db = OpenConnection(databasePath_);
  auto statement = Prepare(db.get(),
                           "DELETE FROM threat_intelligence_cache WHERE expires_at <> '' AND expires_at <= ?;");
  BindText(statement.get(), 1, referenceTimestamp);
  StepDone(db.get(), statement.get());
}

void RuntimeDatabase::UpsertExclusionPolicyRecord(const ExclusionPolicyRecord& record) const {
  const auto db = OpenConnection(databasePath_);
  auto statement = Prepare(
      db.get(),
      "INSERT INTO exclusion_policy("
      " rule_id, path, scope, created_by, reason, created_at, expires_at, warning_state, risk_level, state, dangerous, approved)"
      " VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
      " ON CONFLICT(rule_id) DO UPDATE SET"
      " path=excluded.path, scope=excluded.scope, created_by=excluded.created_by, reason=excluded.reason,"
      " created_at=excluded.created_at, expires_at=excluded.expires_at, warning_state=excluded.warning_state,"
      " risk_level=excluded.risk_level, state=excluded.state, dangerous=excluded.dangerous, approved=excluded.approved;");
  BindText(statement.get(), 1, record.ruleId);
  BindText(statement.get(), 2, record.path);
  BindText(statement.get(), 3, record.scope);
  BindText(statement.get(), 4, record.createdBy);
  BindText(statement.get(), 5, record.reason);
  BindText(statement.get(), 6, record.createdAt);
  BindText(statement.get(), 7, record.expiresAt);
  BindText(statement.get(), 8, record.warningState);
  BindText(statement.get(), 9, record.riskLevel);
  BindText(statement.get(), 10, record.state);
  sqlite3_bind_int(statement.get(), 11, record.dangerous ? 1 : 0);
  sqlite3_bind_int(statement.get(), 12, record.approved ? 1 : 0);
  StepDone(db.get(), statement.get());
}

std::vector<ExclusionPolicyRecord> RuntimeDatabase::ListExclusionPolicyRecords(const std::size_t limit) const {
  const auto db = OpenConnection(databasePath_);
  auto statement = Prepare(
      db.get(),
      "SELECT rule_id, path, scope, created_by, reason, created_at, expires_at, warning_state, risk_level, state,"
      " dangerous, approved FROM exclusion_policy ORDER BY created_at DESC LIMIT ?;");
  sqlite3_bind_int64(statement.get(), 1, static_cast<sqlite3_int64>(limit));

  std::vector<ExclusionPolicyRecord> records;
  for (;;) {
    const auto step = sqlite3_step(statement.get());
    if (step == SQLITE_DONE) {
      break;
    }
    if (step != SQLITE_ROW) {
      ThrowSqliteError(db.get(), "listing exclusion policy records failed");
    }
    records.push_back(ExclusionPolicyRecord{
        .ruleId = ColumnText(statement.get(), 0),
        .path = ColumnText(statement.get(), 1),
        .scope = ColumnText(statement.get(), 2),
        .createdBy = ColumnText(statement.get(), 3),
        .reason = ColumnText(statement.get(), 4),
        .createdAt = ColumnText(statement.get(), 5),
        .expiresAt = ColumnText(statement.get(), 6),
        .warningState = ColumnText(statement.get(), 7),
        .riskLevel = ColumnText(statement.get(), 8),
        .state = ColumnText(statement.get(), 9),
        .dangerous = sqlite3_column_int(statement.get(), 10) != 0,
        .approved = sqlite3_column_int(statement.get(), 11) != 0});
  }
  return records;
}

void RuntimeDatabase::UpsertQuarantineApprovalRecord(const QuarantineApprovalRecord& record) const {
  const auto db = OpenConnection(databasePath_);
  auto statement = Prepare(
      db.get(),
      "INSERT INTO quarantine_approvals("
      " record_id, action, requested_by, approved_by, restore_path, requested_at, decided_at, decision, reason)"
      " VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)"
      " ON CONFLICT(record_id, action, requested_at) DO UPDATE SET"
      " requested_by=excluded.requested_by, approved_by=excluded.approved_by, restore_path=excluded.restore_path,"
      " decided_at=excluded.decided_at, decision=excluded.decision, reason=excluded.reason;");
  BindText(statement.get(), 1, record.recordId);
  BindText(statement.get(), 2, record.action);
  BindText(statement.get(), 3, record.requestedBy);
  BindText(statement.get(), 4, record.approvedBy);
  BindText(statement.get(), 5, record.restorePath);
  BindText(statement.get(), 6, record.requestedAt);
  BindText(statement.get(), 7, record.decidedAt);
  BindText(statement.get(), 8, record.decision);
  BindText(statement.get(), 9, record.reason);
  StepDone(db.get(), statement.get());
}

std::vector<QuarantineApprovalRecord> RuntimeDatabase::ListQuarantineApprovalRecords(const std::size_t limit) const {
  const auto db = OpenConnection(databasePath_);
  auto statement = Prepare(
      db.get(),
      "SELECT record_id, action, requested_by, approved_by, restore_path, requested_at, decided_at, decision, reason"
      " FROM quarantine_approvals ORDER BY requested_at DESC LIMIT ?;");
  sqlite3_bind_int64(statement.get(), 1, static_cast<sqlite3_int64>(limit));

  std::vector<QuarantineApprovalRecord> records;
  for (;;) {
    const auto step = sqlite3_step(statement.get());
    if (step == SQLITE_DONE) {
      break;
    }
    if (step != SQLITE_ROW) {
      ThrowSqliteError(db.get(), "listing quarantine approvals failed");
    }
    records.push_back(QuarantineApprovalRecord{
        .recordId = ColumnText(statement.get(), 0),
        .action = ColumnText(statement.get(), 1),
        .requestedBy = ColumnText(statement.get(), 2),
        .approvedBy = ColumnText(statement.get(), 3),
        .restorePath = ColumnText(statement.get(), 4),
        .requestedAt = ColumnText(statement.get(), 5),
        .decidedAt = ColumnText(statement.get(), 6),
        .decision = ColumnText(statement.get(), 7),
        .reason = ColumnText(statement.get(), 8)});
  }
  return records;
}

void RuntimeDatabase::ReplaceLocalAdminBaselineSnapshot(const std::wstring& baselineId,
                                                        const std::wstring& capturedAt,
                                                        const std::wstring& capturedBy,
                                                        const std::vector<LocalAdminBaselineMemberRecord>& members) const {
  if (baselineId.empty()) {
    throw std::runtime_error("local admin baseline id cannot be empty");
  }

  const auto db = OpenConnection(databasePath_);
  try {
    Begin(db.get());

    auto deleteStatement = Prepare(db.get(),
                                   "DELETE FROM local_admin_baseline WHERE baseline_id=?;");
    BindText(deleteStatement.get(), 1, baselineId);
    StepDone(db.get(), deleteStatement.get());

    auto insertStatement = Prepare(
        db.get(),
        "INSERT INTO local_admin_baseline("
        " baseline_id, captured_at, captured_by, account_name, sid, member_class, protected_member, managed_candidate)"
        " VALUES(?, ?, ?, ?, ?, ?, ?, ?);");

    for (const auto& member : members) {
      sqlite3_reset(insertStatement.get());
      sqlite3_clear_bindings(insertStatement.get());
      BindText(insertStatement.get(), 1, baselineId);
      BindText(insertStatement.get(), 2, capturedAt.empty() ? member.capturedAt : capturedAt);
      BindText(insertStatement.get(), 3, capturedBy.empty() ? member.capturedBy : capturedBy);
      BindText(insertStatement.get(), 4, member.accountName);
      BindText(insertStatement.get(), 5, member.sid);
      BindText(insertStatement.get(), 6, member.memberClass);
      sqlite3_bind_int(insertStatement.get(), 7, member.protectedMember ? 1 : 0);
      sqlite3_bind_int(insertStatement.get(), 8, member.managedCandidate ? 1 : 0);
      StepDone(db.get(), insertStatement.get());
    }

    Commit(db.get());
  } catch (...) {
    Rollback(db.get());
    throw;
  }
}

std::vector<LocalAdminBaselineMemberRecord> RuntimeDatabase::ListLocalAdminBaselineSnapshot(
    const std::wstring& baselineId, const std::size_t limit) const {
  if (baselineId.empty()) {
    return {};
  }

  const auto db = OpenConnection(databasePath_);
  auto statement = Prepare(
      db.get(),
      "SELECT baseline_id, captured_at, captured_by, account_name, sid, member_class, protected_member, managed_candidate"
      " FROM local_admin_baseline WHERE baseline_id=?"
      " ORDER BY account_name COLLATE NOCASE ASC, sid COLLATE NOCASE ASC LIMIT ?;");
  BindText(statement.get(), 1, baselineId);
  sqlite3_bind_int64(statement.get(), 2, static_cast<sqlite3_int64>(limit));

  std::vector<LocalAdminBaselineMemberRecord> records;
  for (;;) {
    const auto step = sqlite3_step(statement.get());
    if (step == SQLITE_DONE) {
      break;
    }
    if (step != SQLITE_ROW) {
      ThrowSqliteError(db.get(), "listing local admin baseline snapshot failed");
    }

    records.push_back(LocalAdminBaselineMemberRecord{
        .baselineId = ColumnText(statement.get(), 0),
        .capturedAt = ColumnText(statement.get(), 1),
        .capturedBy = ColumnText(statement.get(), 2),
        .accountName = ColumnText(statement.get(), 3),
        .sid = ColumnText(statement.get(), 4),
        .memberClass = ColumnText(statement.get(), 5),
        .protectedMember = sqlite3_column_int(statement.get(), 6) != 0,
        .managedCandidate = sqlite3_column_int(statement.get(), 7) != 0,
    });
  }

  return records;
}

std::vector<LocalAdminBaselineMemberRecord> RuntimeDatabase::ListLatestLocalAdminBaselineSnapshot(
    const std::size_t limit) const {
  const auto db = OpenConnection(databasePath_);
  auto statement = Prepare(
      db.get(),
      "SELECT baseline_id, captured_at, captured_by, account_name, sid, member_class, protected_member, managed_candidate"
      " FROM local_admin_baseline"
      " WHERE baseline_id=("
      "   SELECT baseline_id FROM local_admin_baseline"
      "   ORDER BY captured_at DESC, baseline_id DESC, entry_id DESC LIMIT 1"
      " )"
      " ORDER BY account_name COLLATE NOCASE ASC, sid COLLATE NOCASE ASC LIMIT ?;");
  sqlite3_bind_int64(statement.get(), 1, static_cast<sqlite3_int64>(limit));

  std::vector<LocalAdminBaselineMemberRecord> records;
  for (;;) {
    const auto step = sqlite3_step(statement.get());
    if (step == SQLITE_DONE) {
      break;
    }
    if (step != SQLITE_ROW) {
      ThrowSqliteError(db.get(), "listing latest local admin baseline snapshot failed");
    }

    records.push_back(LocalAdminBaselineMemberRecord{
        .baselineId = ColumnText(statement.get(), 0),
        .capturedAt = ColumnText(statement.get(), 1),
        .capturedBy = ColumnText(statement.get(), 2),
        .accountName = ColumnText(statement.get(), 3),
        .sid = ColumnText(statement.get(), 4),
        .memberClass = ColumnText(statement.get(), 5),
        .protectedMember = sqlite3_column_int(statement.get(), 6) != 0,
        .managedCandidate = sqlite3_column_int(statement.get(), 7) != 0,
    });
  }

  return records;
}

}  // namespace antivirus::agent
