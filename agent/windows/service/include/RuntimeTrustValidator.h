#pragma once

#include <filesystem>
#include <string>

#include "AgentConfig.h"

namespace antivirus::agent {

struct RuntimeTrustValidation {
  bool trusted{false};
  bool runtimePathsTrusted{false};
  bool registryRuntimeMarkerPresent{false};
  bool registryRuntimeMatches{false};
  bool registryInstallMatches{false};
  bool serviceBinaryPresent{false};
  bool amsiProviderPresent{false};
  bool serviceBinarySigned{false};
  bool amsiProviderSigned{false};
  bool requireSignedBinaries{false};
  bool signatureWarning{false};
  std::wstring message;
};

RuntimeTrustValidation ValidateRuntimeTrust(const AgentConfig& config, const std::filesystem::path& installRoot);

}  // namespace antivirus::agent
