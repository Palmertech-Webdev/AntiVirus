#pragma once

#include <filesystem>
#include <string>

#include "AgentConfig.h"

namespace antivirus::agent {

struct HardeningStatus {
  bool registryConfigured{false};
  bool uninstallProtectionEnabled{false};
  bool runtimePathsProtected{false};
  bool installPathProtected{false};
  bool elamDriverPresent{false};
  bool elamCertificateInstalled{false};
  bool launchProtectedConfigured{false};
  std::wstring uninstallTokenHash;
  std::wstring elamDriverPath;
  std::wstring statusMessage;
};

class HardeningManager {
 public:
  HardeningManager(const AgentConfig& config, std::filesystem::path installRoot);

  bool ApplyPostInstallHardening(const std::wstring& uninstallToken, std::wstring* errorMessage = nullptr) const;
  bool ApplyProtectedServiceRegistration(const std::wstring& serviceName, SC_HANDLE serviceHandle,
                                         const std::filesystem::path& elamDriverPath,
                                         std::wstring* errorMessage = nullptr) const;
  bool ValidateUninstallAuthorization(const std::wstring& uninstallToken, std::wstring* errorMessage = nullptr) const;
  HardeningStatus QueryStatus(const std::wstring& serviceName = L"AntiVirusAgent") const;

 private:
  AgentConfig config_;
  std::filesystem::path installRoot_;
};

}  // namespace antivirus::agent
