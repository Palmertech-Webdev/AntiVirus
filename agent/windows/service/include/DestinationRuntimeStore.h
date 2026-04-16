#pragma once

#include <sqlite3.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "DestinationProtection.h"
#include "PolicySnapshot.h"
#include "StringUtils.h"

namespace antivirus::agent {

class DestinationRuntimeStore {
 public:
  explicit DestinationRuntimeStore(std::filesystem::path databasePath) : databasePath_(std::move(databasePath)) {}

  bool LoadPolicy(DestinationPolicySnapshot& policy) const {
    const auto db = OpenConnection();
    auto statement = Prepare(db.get(),
                             "SELECT destination_protection_enabled, anti_phishing_enabled, web_protection_enabled,"
                             " email_link_protection_enabled, evaluate_domains, evaluate_urls,"
                             " block_known_malicious_destinations, block_known_phishing_destinations,"
                             " block_known_scam_destinations, warn_on_suspicious_destinations,"
                             " warn_on_newly_registered_domains, allow_degraded_mode_when_offline,"
                             " browser_context_required_for_warn_only, suspicious_warn_threshold,"
                             " phishing_warn_threshold, phishing_block_threshold, destination_cache_ttl_minutes"
                             " FROM destination_policy_cache WHERE singleton=1;");
    const auto step = sqlite3_step(statement.get());
    if (step == SQLITE_DONE) {
      return false;
    }
    if (step != SQLITE_ROW) {
      ThrowSqliteError(db.get(), "loading destination policy failed");
    }

    policy.destinationProtectionEnabled = sqlite3_column_int(statement.get(), 0) != 0;
    policy.antiPhishingEnabled = sqlite3_column_int(statement.get(), 1) != 0;
    policy.webProtectionEnabled = sqlite3_column_int(statement.get(), 2) != 0;
    policy.emailLinkProtectionEnabled = sqlite3_column_int(statement.get(), 3) != 0;
    policy.evaluateDomains = sqlite3_column_int(statement.get(), 4) != 0;
    policy.evaluateUrls = sqlite3_column_int(statement.get(), 5) != 0;
    policy.blockKnownMaliciousDestinations = sqlite3_column_int(statement.get(), 6) != 0;
    policy.blockKnownPhishingDestinations = sqlite3_column_int(statement.get(), 7) != 0;
    policy.blockKnownScamDestinations = sqlite3_column_int(statement.get(), 8) != 0;
    policy.warnOnSuspiciousDestinations = sqlite3_column_int(statement.get(), 9) != 0;
    policy.warnOnNewlyRegisteredDomains = sqlite3_column_int(statement.get(), 10) != 0;
    policy.allowDegradedModeWhenOffline = sqlite3_column_int(statement.get(), 11) != 0;
    policy.browserContextRequiredForWarnOnly = sqlite3_column_int(statement.get(), 12) != 0;
    policy.suspiciousWarnThreshold = static_cast<std::uint32_t>(std::clamp(sqlite3_column_int(statement.get(), 13), 1, 99));
    policy.phishingWarnThreshold = static_cast<std::uint32_t>(std::clamp(sqlite3_column_int(statement.get(), 14), 1, 99));
    policy.phishingBlockThreshold = static_cast<std::uint32_t>(std::clamp(sqlite3_column_int(statement.get(), 15), 1, 99));
    policy.destinationCacheTtlMinutes = static_cast<std::uint32_t>(std::clamp(sqlite3_column_int(statement.get(), 16), 1, 1440 * 30));
    return true;
  }

  void SavePolicy(const DestinationPolicySnapshot& policy) const {
    const auto db = OpenConnection();
    auto statement = Prepare(db.get(),
                             "INSERT INTO destination_policy_cache("
                             " singleton, destination_protection_enabled, anti_phishing_enabled, web_protection_enabled,"
                             " email_link_protection_enabled, evaluate_domains, evaluate_urls,"
                             " block_known_malicious_destinations, block_known_phishing_destinations,"
                             " block_known_scam_destinations, warn_on_suspicious_destinations,"
                             " warn_on_newly_registered_domains, allow_degraded_mode_when_offline,"
                             " browser_context_required_for_warn_only, suspicious_warn_threshold,"
                             " phishing_warn_threshold, phishing_block_threshold, destination_cache_ttl_minutes, updated_at)"
                             " VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                             " ON CONFLICT(singleton) DO UPDATE SET"
                             " destination_protection_enabled=excluded.destination_protection_enabled,"
                             " anti_phishing_enabled=excluded.anti_phishing_enabled,"
                             " web_protection_enabled=excluded.web_protection_enabled,"
                             " email_link_protection_enabled=excluded.email_link_protection_enabled,"
                             " evaluate_domains=excluded.evaluate_domains,"
                             " evaluate_urls=excluded.evaluate_urls,"
                             " block_known_malicious_destinations=excluded.block_known_malicious_destinations,"
                             " block_known_phishing_destinations=excluded.block_known_phishing_destinations,"
                             " block_known_scam_destinations=excluded.block_known_scam_destinations,"
                             " warn_on_suspicious_destinations=excluded.warn_on_suspicious_destinations,"
                             " warn_on_newly_registered_domains=excluded.warn_on_newly_registered_domains,"
                             " allow_degraded_mode_when_offline=excluded.allow_degraded_mode_when_offline,"
                             " browser_context_required_for_warn_only=excluded.browser_context_required_for_warn_only,"
                             " suspicious_warn_threshold=excluded.suspicious_warn_threshold,"
                             " phishing_warn_threshold=excluded.phishing_warn_threshold,"
                             " phishing_block_threshold=excluded.phishing_block_threshold,"
                             " destination_cache_ttl_minutes=excluded.destination_cache_ttl_minutes,"
                             " updated_at=excluded.updated_at;");
    sqlite3_bind_int(statement.get(), 1, 1);
    sqlite3_bind_int(statement.get(), 2, policy.destinationProtectionEnabled ? 1 : 0);
    sqlite3_bind_int(statement.get(), 3, policy.antiPhishingEnabled ? 1 : 0);
    sqlite3_bind_int(statement.get(), 4, policy.webProtectionEnabled ? 1 : 0);
    sqlite3_bind_int(statement.get(), 5, policy.emailLinkProtectionEnabled ? 1 : 0);
    sqlite3_bind_int(statement.get(), 6, policy.evaluateDomains ? 1 : 0);
    sqlite3_bind_int(statement.get(), 7, policy.evaluateUrls ? 1 : 0);
    sqlite3_bind_int(statement.get(), 8, policy.blockKnownMaliciousDestinations ? 1 : 0);
    sqlite3_bind_int(statement.get(), 9, policy.blockKnownPhishingDestinations ? 1 : 0);
    sqlite3_bind_int(statement.get(), 10, policy.blockKnownScamDestinations ? 1 : 0);
    sqlite3_bind_int(statement.get(), 11, policy.warnOnSuspiciousDestinations ? 1 : 0);
    sqlite3_bind_int(statement.get(), 12, policy.warnOnNewlyRegisteredDomains ? 1 : 0);
    sqlite3_bind_int(statement.get(), 13, policy.allowDegradedModeWhenOffline ? 1 : 0);
    sqlite3_bind_int(statement.get(), 14, policy.browserContextRequiredForWarnOnly ? 1 : 0);
    sqlite3_bind_int(statement.get(), 15, static_cast<int>(policy.suspiciousWarnThreshold));
    sqlite3_bind_int(statement.get(), 16, static_cast<int>(policy.phishingWarnThreshold));
    sqlite3_bind_int(statement.get(), 17, static_cast<int>(policy.phishingBlockThreshold));
    sqlite3_bind_int(statement.get(), 18, static_cast<int>(policy.destinationCacheTtlMinutes));
    BindText(statement.get(), 19, CurrentUtcTimestamp());
    StepDone(db.get(), statement.get());
  }

  void SavePolicy(const PolicySnapshot& policy) const {
    DestinationPolicySnapshot projected{};
    projected.destinationProtectionEnabled = policy.destinationProtectionEnabled;
    projected.antiPhishingEnabled = policy.antiPhishingEnabled;
    projected.webProtectionEnabled = policy.webProtectionEnabled;
    projected.emailLinkProtectionEnabled = policy.emailLinkProtectionEnabled;
    projected.evaluateDomains = policy.evaluateDomains;
    projected.evaluateUrls = policy.evaluateUrls;
    projected.blockKnownMaliciousDestinations = policy.blockKnownMaliciousDestinations;
    projected.blockKnownPhishingDestinations = policy.blockKnownPhishingDestinations;
    projected.blockKnownScamDestinations = policy.blockKnownScamDestinations;
    projected.warnOnSuspiciousDestinations = policy.warnOnSuspiciousDestinations;
    projected.warnOnNewlyRegisteredDomains = policy.warnOnNewlyRegisteredDomains;
    projected.allowDegradedModeWhenOffline = policy.allowDegradedDestinationModeWhenOffline;
    projected.browserContextRequiredForWarnOnly = policy.browserContextRequiredForWarnOnly;
    projected.suspiciousWarnThreshold = policy.suspiciousDestinationWarnThreshold;
    projected.phishingWarnThreshold = policy.phishingWarnThreshold;
    projected.phishingBlockThreshold = policy.phishingBlockThreshold;
    projected.destinationCacheTtlMinutes = policy.destinationCacheTtlMinutes;
    SavePolicy(projected);
  }

  void UpsertIntelligenceRecord(const DestinationIntelligenceRecord& record) const {
    const auto db = OpenConnection();
    auto statement = Prepare(db.get(),
                             "INSERT INTO destination_intelligence_cache("
                             " indicator_type, normalized_indicator, canonical_url, host, source, provider, verdict, action,"
                             " category, confidence, reason_codes, metadata_json, first_seen_at, last_seen_at, expires_at,"
                             " suspicious, known_bad, from_cloud)"
                             " VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                             " ON CONFLICT(indicator_type, normalized_indicator) DO UPDATE SET"
                             " canonical_url=excluded.canonical_url, host=excluded.host, source=excluded.source,"
                             " provider=excluded.provider, verdict=excluded.verdict, action=excluded.action,"
                             " category=excluded.category, confidence=excluded.confidence, reason_codes=excluded.reason_codes,"
                             " metadata_json=excluded.metadata_json, first_seen_at=COALESCE(destination_intelligence_cache.first_seen_at, excluded.first_seen_at),"
                             " last_seen_at=excluded.last_seen_at, expires_at=excluded.expires_at, suspicious=excluded.suspicious,"
                             " known_bad=excluded.known_bad, from_cloud=excluded.from_cloud;");
    BindText(statement.get(), 1, ThreatIndicatorTypeToString(record.indicatorType));
    BindText(statement.get(), 2, record.normalizedIndicator);
    BindText(statement.get(), 3, record.canonicalUrl);
    BindText(statement.get(), 4, record.host);
    BindText(statement.get(), 5, record.source);
    BindText(statement.get(), 6, record.provider);
    BindText(statement.get(), 7, record.verdict);
    BindText(statement.get(), 8, DestinationActionToString(record.action));
    BindText(statement.get(), 9, DestinationThreatCategoryToString(record.category));
    sqlite3_bind_int(statement.get(), 10, static_cast<int>(record.confidence));
    BindText(statement.get(), 11, JoinDestinationReasonCodes(record.reasonCodes));
    BindText(statement.get(), 12, record.metadataJson);
    BindText(statement.get(), 13, record.firstSeenAt);
    BindText(statement.get(), 14, record.lastSeenAt);
    BindText(statement.get(), 15, record.expiresAt);
    sqlite3_bind_int(statement.get(), 16, record.suspicious ? 1 : 0);
    sqlite3_bind_int(statement.get(), 17, record.knownBad ? 1 : 0);
    sqlite3_bind_int(statement.get(), 18, record.fromCloud ? 1 : 0);
    StepDone(db.get(), statement.get());
  }

  bool TryGetIntelligenceRecord(ThreatIndicatorType indicatorType, const std::wstring& indicator,
                                DestinationIntelligenceRecord& record) const {
    const auto db = OpenConnection();
    auto statement = Prepare(db.get(),
                             "SELECT indicator_type, normalized_indicator, canonical_url, host, source, provider, verdict, action,"
                             " category, confidence, reason_codes, metadata_json, first_seen_at, last_seen_at, expires_at,"
                             " suspicious, known_bad, from_cloud"
                             " FROM destination_intelligence_cache WHERE indicator_type=? AND normalized_indicator=? LIMIT 1;");
    BindText(statement.get(), 1, ThreatIndicatorTypeToString(indicatorType));
    BindText(statement.get(), 2, indicator);
    const auto step = sqlite3_step(statement.get());
    if (step == SQLITE_DONE) {
      return false;
    }
    if (step != SQLITE_ROW) {
      ThrowSqliteError(db.get(), "loading destination intelligence cache failed");
    }

    record.indicatorType = ThreatIndicatorTypeFromString(ColumnText(statement.get(), 0));
    record.normalizedIndicator = ColumnText(statement.get(), 1);
    record.canonicalUrl = ColumnText(statement.get(), 2);
    record.host = ColumnText(statement.get(), 3);
    record.source = ColumnText(statement.get(), 4);
    record.provider = ColumnText(statement.get(), 5);
    record.verdict = ColumnText(statement.get(), 6);
    record.action = DestinationActionFromString(ColumnText(statement.get(), 7));
    record.category = DestinationThreatCategoryFromString(ColumnText(statement.get(), 8));
    record.confidence = static_cast<std::uint32_t>(sqlite3_column_int(statement.get(), 9));
    record.reasonCodes = SplitDestinationReasonCodes(ColumnText(statement.get(), 10));
    record.metadataJson = ColumnText(statement.get(), 11);
    record.firstSeenAt = ColumnText(statement.get(), 12);
    record.lastSeenAt = ColumnText(statement.get(), 13);
    record.expiresAt = ColumnText(statement.get(), 14);
    record.suspicious = sqlite3_column_int(statement.get(), 15) != 0;
    record.knownBad = sqlite3_column_int(statement.get(), 16) != 0;
    record.fromCloud = sqlite3_column_int(statement.get(), 17) != 0;
    return true;
  }

  std::vector<DestinationIntelligenceRecord> ListActiveBlockingRecords(const std::size_t maxRecords = 512) const {
    const auto db = OpenConnection();
    auto statement = Prepare(db.get(),
                             "SELECT indicator_type, normalized_indicator, canonical_url, host, source, provider, verdict, action,"
                             " category, confidence, reason_codes, metadata_json, first_seen_at, last_seen_at, expires_at,"
                             " suspicious, known_bad, from_cloud"
                             " FROM destination_intelligence_cache"
                             " WHERE action=? AND (expires_at IS NULL OR expires_at='' OR expires_at >= ?)"
                             " ORDER BY confidence DESC, last_seen_at DESC LIMIT ?;");
    BindText(statement.get(), 1, DestinationActionToString(DestinationAction::Block));
    BindText(statement.get(), 2, CurrentUtcTimestamp());
    sqlite3_bind_int(statement.get(), 3, static_cast<int>(std::clamp<std::size_t>(maxRecords, 1, 4096)));

    std::vector<DestinationIntelligenceRecord> records;
    for (;;) {
      const auto step = sqlite3_step(statement.get());
      if (step == SQLITE_DONE) {
        break;
      }
      if (step != SQLITE_ROW) {
        ThrowSqliteError(db.get(), "listing destination intelligence cache failed");
      }

      DestinationIntelligenceRecord record{};
      record.indicatorType = ThreatIndicatorTypeFromString(ColumnText(statement.get(), 0));
      record.normalizedIndicator = ColumnText(statement.get(), 1);
      record.canonicalUrl = ColumnText(statement.get(), 2);
      record.host = ColumnText(statement.get(), 3);
      record.source = ColumnText(statement.get(), 4);
      record.provider = ColumnText(statement.get(), 5);
      record.verdict = ColumnText(statement.get(), 6);
      record.action = DestinationActionFromString(ColumnText(statement.get(), 7));
      record.category = DestinationThreatCategoryFromString(ColumnText(statement.get(), 8));
      record.confidence = static_cast<std::uint32_t>(sqlite3_column_int(statement.get(), 9));
      record.reasonCodes = SplitDestinationReasonCodes(ColumnText(statement.get(), 10));
      record.metadataJson = ColumnText(statement.get(), 11);
      record.firstSeenAt = ColumnText(statement.get(), 12);
      record.lastSeenAt = ColumnText(statement.get(), 13);
      record.expiresAt = ColumnText(statement.get(), 14);
      record.suspicious = sqlite3_column_int(statement.get(), 15) != 0;
      record.knownBad = sqlite3_column_int(statement.get(), 16) != 0;
      record.fromCloud = sqlite3_column_int(statement.get(), 17) != 0;
      records.push_back(std::move(record));
    }

    return records;
  }

 private:
  using ConnectionHandle = std::unique_ptr<sqlite3, decltype(&sqlite3_close)>;
  using StatementHandle = std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)>;

  std::filesystem::path databasePath_;

  [[noreturn]] static void ThrowSqliteError(sqlite3* db, const char* message) {
    throw std::runtime_error(std::string(message) + ": " + (db == nullptr ? "sqlite unavailable" : sqlite3_errmsg(db)));
  }

  static void Exec(sqlite3* db, const char* sql) {
    char* errorMessage = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &errorMessage) != SQLITE_OK) {
      const auto combined = std::string("sqlite exec failed: ") + (errorMessage == nullptr ? sql : errorMessage);
      if (errorMessage != nullptr) {
        sqlite3_free(errorMessage);
      }
      throw std::runtime_error(combined);
    }
  }

  ConnectionHandle OpenConnection() const {
    if (databasePath_.has_parent_path()) {
      std::filesystem::create_directories(databasePath_.parent_path());
    }

    sqlite3* raw = nullptr;
    if (sqlite3_open_v2(WideToUtf8(databasePath_.wstring()).c_str(), &raw,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr) != SQLITE_OK) {
      ThrowSqliteError(raw, "sqlite3_open_v2 failed");
    }

    ConnectionHandle connection(raw, sqlite3_close);
    Exec(connection.get(), "PRAGMA journal_mode=WAL;");
    Exec(connection.get(), "PRAGMA synchronous=FULL;");
    Exec(connection.get(), "PRAGMA foreign_keys=ON;");
    EnsureSchema(connection.get());
    return connection;
  }

  static StatementHandle Prepare(sqlite3* db, const char* sql) {
    sqlite3_stmt* raw = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &raw, nullptr) != SQLITE_OK) {
      ThrowSqliteError(db, "sqlite3_prepare_v2 failed");
    }
    return StatementHandle(raw, sqlite3_finalize);
  }

  static void StepDone(sqlite3* db, sqlite3_stmt* statement) {
    if (sqlite3_step(statement) != SQLITE_DONE) {
      ThrowSqliteError(db, "sqlite3_step did not finish");
    }
  }

  static void BindText(sqlite3_stmt* statement, int index, const std::wstring& value) {
    const auto utf8 = WideToUtf8(value);
    sqlite3_bind_text(statement, index, utf8.c_str(), -1, SQLITE_TRANSIENT);
  }

  static std::wstring ColumnText(sqlite3_stmt* statement, int column) {
    const auto* text = reinterpret_cast<const char*>(sqlite3_column_text(statement, column));
    return text == nullptr ? std::wstring{} : Utf8ToWide(reinterpret_cast<const char*>(text));
  }

  static void EnsureSchema(sqlite3* db) {
    Exec(db,
         "CREATE TABLE IF NOT EXISTS destination_policy_cache ("
         " singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
         " destination_protection_enabled INTEGER NOT NULL DEFAULT 1,"
         " anti_phishing_enabled INTEGER NOT NULL DEFAULT 1,"
         " web_protection_enabled INTEGER NOT NULL DEFAULT 1,"
         " email_link_protection_enabled INTEGER NOT NULL DEFAULT 1,"
         " evaluate_domains INTEGER NOT NULL DEFAULT 1,"
         " evaluate_urls INTEGER NOT NULL DEFAULT 1,"
         " block_known_malicious_destinations INTEGER NOT NULL DEFAULT 1,"
         " block_known_phishing_destinations INTEGER NOT NULL DEFAULT 1,"
         " block_known_scam_destinations INTEGER NOT NULL DEFAULT 0,"
         " warn_on_suspicious_destinations INTEGER NOT NULL DEFAULT 1,"
         " warn_on_newly_registered_domains INTEGER NOT NULL DEFAULT 1,"
         " allow_degraded_mode_when_offline INTEGER NOT NULL DEFAULT 1,"
         " browser_context_required_for_warn_only INTEGER NOT NULL DEFAULT 0,"
         " suspicious_warn_threshold INTEGER NOT NULL DEFAULT 45,"
         " phishing_warn_threshold INTEGER NOT NULL DEFAULT 55,"
         " phishing_block_threshold INTEGER NOT NULL DEFAULT 80,"
         " destination_cache_ttl_minutes INTEGER NOT NULL DEFAULT 240,"
         " updated_at TEXT"
         ");"
         "CREATE TABLE IF NOT EXISTS destination_intelligence_cache ("
         " indicator_type TEXT NOT NULL,"
         " normalized_indicator TEXT NOT NULL,"
         " canonical_url TEXT,"
         " host TEXT,"
         " source TEXT,"
         " provider TEXT,"
         " verdict TEXT,"
         " action TEXT,"
         " category TEXT,"
         " confidence INTEGER NOT NULL DEFAULT 0,"
         " reason_codes TEXT,"
         " metadata_json TEXT,"
         " first_seen_at TEXT,"
         " last_seen_at TEXT,"
         " expires_at TEXT,"
         " suspicious INTEGER NOT NULL DEFAULT 0,"
         " known_bad INTEGER NOT NULL DEFAULT 0,"
         " from_cloud INTEGER NOT NULL DEFAULT 0,"
         " PRIMARY KEY(indicator_type, normalized_indicator)"
         ");"
         "CREATE INDEX IF NOT EXISTS idx_destination_cache_last_seen ON destination_intelligence_cache(last_seen_at DESC);"
         "CREATE INDEX IF NOT EXISTS idx_destination_cache_category ON destination_intelligence_cache(category, confidence DESC);"
         "CREATE INDEX IF NOT EXISTS idx_destination_cache_action ON destination_intelligence_cache(action, expires_at);");
  }
};

}  // namespace antivirus::agent
