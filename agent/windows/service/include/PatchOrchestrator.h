#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "AgentConfig.h"
#include "DeviceInventoryCollector.h"

namespace antivirus::agent {

enum class PatchProviderKind {
  NativeUpdater,
  Winget,
  Recipe,
  Manual
};

std::wstring PatchProviderKindToString(PatchProviderKind provider);
PatchProviderKind PatchProviderKindFromString(const std::wstring& value);

struct PatchPolicyRecord {
  std::wstring policyId{L"local-default"};
  bool autoInstallWindowsSecurity{true};
  bool autoInstallWindowsQuality{true};
  bool deferFeatureUpdates{true};
  bool includeDriverUpdates{false};
  bool includeOptionalUpdates{false};
  bool autoUpdateHighRiskAppsOnly{true};
  bool autoUpdateAllSupportedApps{false};
  bool notifyBeforeUpdate{false};
  bool silentOnly{true};
  bool skipInteractiveUpdates{true};
  bool paused{false};
  bool respectMeteredConnections{true};
  bool batteryAware{true};
  bool allowNativeUpdaters{true};
  bool allowWinget{true};
  bool allowRecipes{true};
  std::wstring maintenanceWindowStart{L"02:00"};
  std::wstring maintenanceWindowEnd{L"05:00"};
  int rebootGracePeriodMinutes{240};
  int featureUpdateDeferralDays{30};
  std::wstring activeHoursStart{L"08:00"};
  std::wstring activeHoursEnd{L"20:00"};
  std::wstring updatedAt;
};

struct WindowsUpdateRecord {
  std::wstring updateId;
  std::wstring revision;
  std::wstring title;
  std::wstring kbArticles;
  std::wstring categories;
  std::wstring classification;
  std::wstring severity;
  std::wstring updateType;
  std::wstring deploymentAction;
  std::wstring discoveredAt;
  std::wstring lastAttemptAt;
  std::wstring lastSucceededAt;
  std::wstring status;
  std::wstring failureCode;
  std::wstring detailJson;
  bool installed{false};
  bool hidden{false};
  bool downloaded{false};
  bool mandatory{false};
  bool browseOnly{false};
  bool rebootRequired{false};
  bool driver{false};
  bool featureUpdate{false};
  bool optional{false};
};

struct SoftwarePatchRecord {
  std::wstring softwareId;
  std::wstring displayName;
  std::wstring displayVersion;
  std::wstring availableVersion;
  std::wstring publisher;
  std::wstring installLocation;
  std::wstring uninstallCommand;
  std::wstring quietUninstallCommand;
  std::wstring executableNames;
  std::wstring executablePaths;
  std::wstring provider;
  std::wstring providerId;
  std::wstring supportedSource;
  std::wstring updateState;
  std::wstring updateSummary;
  std::wstring lastCheckedAt;
  std::wstring lastAttemptedAt;
  std::wstring lastUpdatedAt;
  std::wstring failureCode;
  std::wstring detailJson;
  bool blocked{false};
  bool supported{false};
  bool manualOnly{false};
  bool userInteractionRequired{false};
  bool rebootRequired{false};
  bool highRisk{false};
};

struct PatchHistoryRecord {
  std::wstring recordId;
  std::wstring targetType;
  std::wstring targetId;
  std::wstring title;
  std::wstring provider;
  std::wstring action;
  std::wstring status;
  std::wstring startedAt;
  std::wstring completedAt;
  std::wstring errorCode;
  std::wstring detailJson;
  bool rebootRequired{false};
};

struct PackageRecipeRecord {
  std::wstring recipeId;
  std::wstring displayName;
  std::wstring publisher;
  std::wstring matchPattern;
  std::wstring wingetId;
  std::wstring sourceUrl;
  std::wstring installerSha256;
  std::wstring requiredSigner;
  std::wstring silentArgs;
  std::wstring rebootBehavior;
  std::wstring detectHintsJson;
  std::wstring updatedAt;
  int priority{300};
  bool manualOnly{false};
  bool enabled{true};
};

struct RebootCoordinatorRecord {
  bool rebootRequired{false};
  bool pendingWindowsUpdate{false};
  bool pendingFileRename{false};
  bool pendingComputerRename{false};
  bool pendingComponentServicing{false};
  std::wstring rebootReasons;
  std::wstring detectedAt;
  std::wstring deferredUntil;
  int gracePeriodMinutes{0};
  std::wstring status;
};

struct PatchRefreshSummary {
  std::size_t windowsUpdateCount{0};
  std::size_t softwareCount{0};
  std::size_t recipeCount{0};
  bool rebootPending{false};
};

struct PatchExecutionResult {
  bool success{false};
  bool rebootRequired{false};
  std::wstring action;
  std::wstring targetId;
  std::wstring provider;
  std::wstring status;
  std::wstring errorCode;
  std::wstring detailJson;
};

struct PatchSnapshot {
  PatchPolicyRecord policy;
  RebootCoordinatorRecord rebootState;
  std::vector<WindowsUpdateRecord> windowsUpdates;
  std::vector<SoftwarePatchRecord> software;
  std::vector<PackageRecipeRecord> recipes;
  std::vector<PatchHistoryRecord> history;
};

class PatchOrchestrator {
 public:
  explicit PatchOrchestrator(const AgentConfig& config);

  PatchRefreshSummary RefreshPatchState() const;
  PatchSnapshot LoadSnapshot(std::size_t windowsLimit = 100, std::size_t softwareLimit = 200,
                             std::size_t historyLimit = 100, std::size_t recipeLimit = 200) const;
  PatchExecutionResult InstallWindowsUpdates(bool securityOnly) const;
  PatchExecutionResult UpdateSoftware(const std::wstring& softwareId, bool searchOnly) const;
  PatchExecutionResult RunPatchCycle() const;
  void SavePolicy(const PatchPolicyRecord& policy) const;
  PatchPolicyRecord LoadPolicy() const;

 private:
  AgentConfig config_;
};

}  // namespace antivirus::agent
