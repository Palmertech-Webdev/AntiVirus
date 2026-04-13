#pragma once

#include <string>

namespace antivirus::agent {

enum class LocalUserRole {
  Unknown,
  DeviceOwnerAdmin,
  LocalAdmin,
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

LocalUserRole QueryCurrentLocalUserRole();
bool IsCurrentUserElevatedAdmin();
bool IsCurrentTokenElevated();
std::wstring QueryCurrentUserSid();
std::wstring LocalUserRoleToString(LocalUserRole role);
LocalActionAuthorization AuthorizeCurrentUser(LocalAction action);

}  // namespace antivirus::agent
