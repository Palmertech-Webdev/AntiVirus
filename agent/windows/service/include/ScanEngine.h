#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <vector>

#include "ContextAwareness.h"
#include "PolicySnapshot.h"
#include "ScanVerdict.h"
#include "TelemetryRecord.h"

namespace antivirus::agent {

enum class RemediationStatus {
  None,
  Quarantined,
  Failed
};

struct ScanFinding {
  std::filesystem::path path;
  std::uintmax_t sizeBytes{0};
  std::wstring sha256;
  std::wstring contentType;
  std::wstring reputation;
  std::wstring signer;
  std::uint32_t heuristicScore{0};
  std::uint32_t archiveEntryCount{0};
  ScanVerdict verdict;
  RemediationStatus remediationStatus{RemediationStatus::None};
  std::filesystem::path quarantinedPath;
  std::wstring quarantineRecordId;
  std::wstring evidenceRecordId;
  std::wstring remediationError;
  std::wstring alertTitle;
  std::wstring alertSummary;
  ContentOriginContext originContext;
};

struct ScanProgressUpdate {
  std::size_t completedTargets{0};
  std::size_t totalTargets{0};
  std::size_t findingCount{0};
  std::filesystem::path currentPath;
};

using ScanProgressCallback = std::function<void(const ScanProgressUpdate&)>;

std::optional<ScanFinding> ScanFile(const std::filesystem::path& path, const PolicySnapshot& policy);
std::optional<ScanFinding> ScanFile(const std::filesystem::path& path, const PolicySnapshot& policy,
                                    const std::vector<std::filesystem::path>& excludedPaths);
std::optional<ScanFinding> ScanFile(const std::filesystem::path& path, const PolicySnapshot& policy,
                                    const std::vector<std::filesystem::path>& excludedPaths,
                                    const ContentOriginContext& originContext);
std::optional<ScanFinding> BuildAllowOverrideFinding(const std::filesystem::path& path, const PolicySnapshot& policy);
std::optional<ScanFinding> BuildAllowOverrideFinding(const std::filesystem::path& path, const PolicySnapshot& policy,
                                                     const std::vector<std::filesystem::path>& excludedPaths);
std::vector<ScanFinding> ScanTargets(const std::vector<std::filesystem::path>& targets, const PolicySnapshot& policy);
std::vector<ScanFinding> ScanTargets(const std::vector<std::filesystem::path>& targets, const PolicySnapshot& policy,
                                     const ScanProgressCallback& progressCallback);
std::vector<ScanFinding> ScanTargets(const std::vector<std::filesystem::path>& targets, const PolicySnapshot& policy,
                                     const ScanProgressCallback& progressCallback,
                                     const std::vector<std::filesystem::path>& excludedPaths);
std::wstring VerdictDispositionToString(VerdictDisposition disposition);
std::wstring RemediationStatusToString(RemediationStatus status);
TelemetryRecord BuildScanFindingTelemetry(const ScanFinding& finding, const std::wstring& source);
TelemetryRecord BuildScanSummaryTelemetry(std::size_t targetCount, std::size_t findingCount,
                                          const PolicySnapshot& policy, const std::wstring& source);

}  // namespace antivirus::agent
