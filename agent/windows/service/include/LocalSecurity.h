#pragma once

#include <string>
#include <vector>

namespace antivirus::agent {

enum class LocalUserRole {
  Unknown,
  DeviceOwnerAdmin,
  BreakGlassAdmin,
  LocalAdmin,
  HouseholdTrustedUser,
  HouseholdRestrictedUser,
  StandardUser
};

enum class LocalAction {
  ViewStatus,
  IssueSessionApproval,
  StartServiceAction,
  PatchRefresh,
  PatchInstall,
  EditExclusions,
  QuarantineMutate,
  ExportSupportBundle
};

struct LocalActionAuthorization {
  LocalUserRole role{LocalUserRole::Unknown};
  bool allowed{false};
  bool requestOnly{false};
  std::wstring reason;
};

struct HouseholdRolePolicySnapshot {
  std::wstring ownerSid;
  std::vector<std::wstring> trustedHouseholdSids;
  std::vector<std::wstring> restrictedHouseholdSids;
};

LocalUserRole QueryCurrentLocalUserRole();
bool IsCurrentUserElevatedAdmin();
bool IsCurrentTokenElevated();
std::wstring QueryCurrentUserSid();
std::wstring QueryConfiguredDeviceOwnerSid();
HouseholdRolePolicySnapshot QueryHouseholdRolePolicySnapshot();
bool ValidateHouseholdRolePolicySnapshot(const HouseholdRolePolicySnapshot& snapshot,
                                         std::wstring* errorMessage = nullptr);
bool SetHouseholdRolePolicySnapshot(const HouseholdRolePolicySnapshot& snapshot, bool persistOwnerSid,
                                    std::wstring* errorMessage = nullptr);
std::wstring LocalUserRoleToString(LocalUserRole role);
LocalActionAuthorization AuthorizeCurrentUser(LocalAction action);
bool QueryBreakGlassModeEnabled();
bool SetBreakGlassModeEnabled(bool enabled, std::wstring* errorMessage = nullptr);

}  // namespace antivirus::agent
