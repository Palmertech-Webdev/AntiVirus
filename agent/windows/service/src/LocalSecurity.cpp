#include "LocalSecurity.h"

#include <Windows.h>
#include <sddl.h>

#include <optional>
#include <vector>

namespace antivirus::agent {

namespace {

constexpr wchar_t kRegistryRoot[] = L"SOFTWARE\\FenrirAgent";
constexpr wchar_t kLegacyRegistryRoot[] = L"SOFTWARE\\AntiVirusAgent";
constexpr wchar_t kOwnerSidValueName[] = L"DeviceOwnerSid";

bool OpenEffectiveToken(const DWORD accessMask, HANDLE* token) {
  if (token == nullptr) {
    return false;
  }

  *token = nullptr;
  if (OpenThreadToken(GetCurrentThread(), accessMask, TRUE, token) != FALSE) {
    return true;
  }

  if (GetLastError() != ERROR_NO_TOKEN) {
    return false;
  }

  return OpenProcessToken(GetCurrentProcess(), accessMask, token) != FALSE;
}

std::optional<bool> IsCurrentTokenInAdministratorsGroup() {
  SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
  PSID administratorsGroup = nullptr;
  BOOL isMember = FALSE;
  if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0,
                               0, &administratorsGroup) == FALSE) {
    return std::nullopt;
  }

  const auto membershipChecked = CheckTokenMembership(nullptr, administratorsGroup, &isMember) != FALSE;
  FreeSid(administratorsGroup);
  if (!membershipChecked) {
    return std::nullopt;
  }

  return isMember != FALSE;
}

std::wstring ReadRegistryStringFromRoot(const HKEY hive, const wchar_t* rootPath, const wchar_t* valueName) {
  HKEY key = nullptr;
  if (RegOpenKeyExW(hive, rootPath, 0, KEY_READ, &key) != ERROR_SUCCESS) {
    return {};
  }

  DWORD type = 0;
  DWORD bytes = 0;
  if (RegQueryValueExW(key, valueName, nullptr, &type, nullptr, &bytes) != ERROR_SUCCESS || type != REG_SZ ||
      bytes == 0) {
    RegCloseKey(key);
    return {};
  }

  std::wstring value(bytes / sizeof(wchar_t), L'\0');
  if (RegQueryValueExW(key, valueName, nullptr, &type, reinterpret_cast<LPBYTE>(value.data()), &bytes) !=
      ERROR_SUCCESS) {
    RegCloseKey(key);
    return {};
  }

  RegCloseKey(key);
  while (!value.empty() && value.back() == L'\0') {
    value.pop_back();
  }

  return value;
}

bool WriteRegistryStringToRoot(const HKEY hive, const wchar_t* rootPath, const wchar_t* valueName,
                               const std::wstring& value) {
  HKEY key = nullptr;
  if (RegCreateKeyExW(hive, rootPath, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_READ | KEY_WRITE, nullptr, &key,
                      nullptr) != ERROR_SUCCESS) {
    return false;
  }

  const auto status = RegSetValueExW(key, valueName, 0, REG_SZ, reinterpret_cast<const BYTE*>(value.c_str()),
                                     static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t)));
  RegCloseKey(key);
  return status == ERROR_SUCCESS;
}

std::wstring ReadDeviceOwnerSid() {
  for (const auto hive : {HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER}) {
    const auto sid = ReadRegistryStringFromRoot(hive, kRegistryRoot, kOwnerSidValueName);
    if (!sid.empty()) {
      return sid;
    }

    const auto legacySid = ReadRegistryStringFromRoot(hive, kLegacyRegistryRoot, kOwnerSidValueName);
    if (!legacySid.empty()) {
      return legacySid;
    }
  }

  return {};
}

void PersistDeviceOwnerSid(const std::wstring& sid) {
  if (sid.empty()) {
    return;
  }

  for (const auto hive : {HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER}) {
    if (WriteRegistryStringToRoot(hive, kRegistryRoot, kOwnerSidValueName, sid)) {
      return;
    }
  }
}

std::wstring ResolveDeviceOwnerSid(const std::wstring& currentUserSid) {
  auto ownerSid = ReadDeviceOwnerSid();
  if (!ownerSid.empty()) {
    return ownerSid;
  }

  if (currentUserSid.empty() || !IsCurrentTokenElevated()) {
    return {};
  }

  PersistDeviceOwnerSid(currentUserSid);
  return ReadDeviceOwnerSid();
}

bool IsAdminRole(const LocalUserRole role) {
  return role == LocalUserRole::DeviceOwnerAdmin || role == LocalUserRole::LocalAdmin;
}

}  // namespace

LocalUserRole QueryCurrentLocalUserRole() {
  const auto adminMembership = IsCurrentTokenInAdministratorsGroup();
  if (!adminMembership.has_value()) {
    return LocalUserRole::Unknown;
  }

  if (!(*adminMembership)) {
    return LocalUserRole::StandardUser;
  }

  const auto currentSid = QueryCurrentUserSid();
  const auto ownerSid = ResolveDeviceOwnerSid(currentSid);
  if (!ownerSid.empty() && !currentSid.empty() && _wcsicmp(ownerSid.c_str(), currentSid.c_str()) == 0) {
    return LocalUserRole::DeviceOwnerAdmin;
  }

  return LocalUserRole::LocalAdmin;
}

bool IsCurrentUserElevatedAdmin() {
  return IsCurrentTokenElevated() && IsAdminRole(QueryCurrentLocalUserRole());
}

bool IsCurrentTokenElevated() {
  HANDLE token = nullptr;
  if (!OpenEffectiveToken(TOKEN_QUERY, &token)) {
    return false;
  }

  TOKEN_ELEVATION elevation{};
  DWORD bytesReturned = 0;
  const auto elevated = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &bytesReturned) != FALSE &&
                        elevation.TokenIsElevated != 0;
  CloseHandle(token);
  return elevated;
}

std::wstring QueryCurrentUserSid() {
  HANDLE token = nullptr;
  if (!OpenEffectiveToken(TOKEN_QUERY, &token)) {
    return {};
  }

  DWORD bytesNeeded = 0;
  GetTokenInformation(token, TokenUser, nullptr, 0, &bytesNeeded);
  if (bytesNeeded == 0) {
    CloseHandle(token);
    return {};
  }

  std::vector<BYTE> buffer(bytesNeeded);
  if (GetTokenInformation(token, TokenUser, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesNeeded) == FALSE) {
    CloseHandle(token);
    return {};
  }

  const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(buffer.data());
  LPWSTR sidString = nullptr;
  if (ConvertSidToStringSidW(tokenUser->User.Sid, &sidString) == FALSE || sidString == nullptr) {
    CloseHandle(token);
    return {};
  }

  std::wstring sid(sidString);
  LocalFree(sidString);
  CloseHandle(token);
  return sid;
}

std::wstring LocalUserRoleToString(const LocalUserRole role) {
  switch (role) {
    case LocalUserRole::DeviceOwnerAdmin:
      return L"device_owner_admin";
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
  const auto elevated = IsCurrentTokenElevated();
  const auto isAdmin = IsAdminRole(role);
  const auto isOwner = role == LocalUserRole::DeviceOwnerAdmin;

  switch (action) {
    case LocalAction::ViewStatus:
    case LocalAction::PatchRefresh:
    case LocalAction::ExportSupportBundle:
      return LocalActionAuthorization{
          .role = role,
          .allowed = true,
          .requestOnly = false,
          .reason = L"Local status and update posture inspection are available to all local users."};

    case LocalAction::IssueSessionApproval:
      if (isAdmin && elevated) {
        return LocalActionAuthorization{
            .role = role,
            .allowed = true,
            .requestOnly = false,
            .reason = L"Administrator re-auth can issue a short-lived approval session for privileged local actions."};
      }

      return LocalActionAuthorization{
          .role = role,
          .allowed = false,
          .requestOnly = true,
          .reason = L"Issuing approval sessions requires an elevated administrator context."};

    case LocalAction::PatchInstall:
    case LocalAction::QuarantineMutate:
      if (isAdmin && elevated) {
        return LocalActionAuthorization{
            .role = role,
            .allowed = true,
            .requestOnly = false,
            .reason = L"Elevated administrators can run sensitive local response actions."};
      }

      return LocalActionAuthorization{
          .role = role,
          .allowed = false,
          .requestOnly = true,
          .reason = L"Sensitive local response actions require elevated administrator approval."};

    case LocalAction::StartServiceAction:
    case LocalAction::EditExclusions:
      if (isOwner && elevated) {
        return LocalActionAuthorization{
            .role = role,
            .allowed = true,
            .requestOnly = false,
            .reason = L"The device owner administrator can change long-lived local protection posture."};
      }

      if (isAdmin) {
        return LocalActionAuthorization{
            .role = role,
            .allowed = false,
            .requestOnly = true,
            .reason = L"This operation is reserved for the registered device owner administrator."};
      }

      return LocalActionAuthorization{
          .role = role,
          .allowed = false,
          .requestOnly = true,
          .reason = L"System-wide local protection changes require explicit device-owner approval."};

    default:
      return LocalActionAuthorization{
          .role = role,
          .allowed = false,
          .requestOnly = false,
          .reason = L"Fenrir could not determine whether this local action is safe to allow."};
  }
}

}  // namespace antivirus::agent
