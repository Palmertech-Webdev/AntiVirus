#include "LocalSecurity.h"

#include <Windows.h>
namespace antivirus::agent {

LocalUserRole QueryCurrentLocalUserRole() {
  SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
  PSID administratorsGroup = nullptr;
  BOOL isMember = FALSE;
  if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0,
                               0, &administratorsGroup) == FALSE) {
    return LocalUserRole::Unknown;
  }

  const auto membershipChecked = CheckTokenMembership(nullptr, administratorsGroup, &isMember) != FALSE;
  FreeSid(administratorsGroup);
  if (!membershipChecked) {
    return LocalUserRole::Unknown;
  }

  return isMember != FALSE ? LocalUserRole::LocalAdmin : LocalUserRole::StandardUser;
}

bool IsCurrentUserElevatedAdmin() {
  return QueryCurrentLocalUserRole() == LocalUserRole::LocalAdmin;
}

std::wstring LocalUserRoleToString(const LocalUserRole role) {
  switch (role) {
    case LocalUserRole::LocalAdmin:
      return L"local_admin";
    case LocalUserRole::StandardUser:
      return L"standard_user";
    default:
      return L"unknown";
  }
}

LocalActionAuthorization AuthorizeCurrentUser(const LocalAction action) {
  const auto role = QueryCurrentLocalUserRole();
  switch (action) {
    case LocalAction::ViewStatus:
    case LocalAction::PatchRefresh:
      return LocalActionAuthorization{
          .role = role,
          .allowed = true,
          .requestOnly = false,
          .reason = L"Local status and update posture inspection are available to all local users."};
    case LocalAction::PatchInstall:
      if (role == LocalUserRole::LocalAdmin) {
        return LocalActionAuthorization{
            .role = role,
            .allowed = true,
            .requestOnly = false,
            .reason = L"Administrators can install software updates directly from the local client."};
      }
      return LocalActionAuthorization{
          .role = role,
          .allowed = false,
          .requestOnly = true,
          .reason = L"Standard users can inspect update posture, but patch installation requires administrator approval."};
    case LocalAction::StartServiceAction:
      if (role == LocalUserRole::LocalAdmin) {
        return LocalActionAuthorization{
            .role = role,
            .allowed = true,
            .requestOnly = false,
            .reason = L"Administrators can start or repair the Fenrir protection service."};
      }
      return LocalActionAuthorization{
          .role = role,
          .allowed = false,
          .requestOnly = true,
          .reason = L"Starting the protection service is an administrator-only action."};
    case LocalAction::EditExclusions:
      if (role == LocalUserRole::LocalAdmin) {
        return LocalActionAuthorization{
            .role = role,
            .allowed = true,
            .requestOnly = false,
            .reason = L"Administrators can edit system-wide exclusions."};
      }
      return LocalActionAuthorization{
          .role = role,
          .allowed = false,
          .requestOnly = true,
          .reason = L"System-wide exclusions require administrator approval because they weaken device protection."};
    case LocalAction::QuarantineMutate:
      if (role == LocalUserRole::LocalAdmin) {
        return LocalActionAuthorization{
            .role = role,
            .allowed = true,
            .requestOnly = false,
            .reason = L"Administrators can restore or purge quarantined content."};
      }
      return LocalActionAuthorization{
          .role = role,
          .allowed = false,
          .requestOnly = true,
          .reason = L"Quarantine restore and delete actions require administrator approval."};
    case LocalAction::ExportSupportBundle:
      return LocalActionAuthorization{
          .role = role,
          .allowed = true,
          .requestOnly = false,
          .reason = L"Local support bundle export is available to help diagnose endpoint issues."};
    default:
      return LocalActionAuthorization{
          .role = role,
          .allowed = false,
          .requestOnly = false,
          .reason = L"Fenrir could not determine whether this local action is safe to allow."};
  }
}

}  // namespace antivirus::agent
