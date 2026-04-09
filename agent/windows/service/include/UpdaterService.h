#pragma once

#include <filesystem>
#include <string>
#include <vector>

#include "AgentConfig.h"

namespace antivirus::agent {

enum class UpdateApplyMode {
  InService,
  Maintenance
};

struct UpdateFilePlan {
  std::filesystem::path sourcePath;
  std::filesystem::path targetPath;
  std::wstring sha256;
  std::wstring requiredSigner;
  bool requireSignature{false};
};

struct UpdateManifest {
  std::wstring packageId;
  std::wstring packageType;
  std::wstring targetVersion;
  std::wstring channel;
  std::wstring packageSigner;
  std::filesystem::path manifestPath;
  std::vector<UpdateFilePlan> files;
};

struct UpdateResult {
  bool success{false};
  bool restartRequired{false};
  bool rollbackAttempted{false};
  bool rollbackPerformed{false};
  std::wstring transactionId;
  std::wstring packageId;
  std::wstring packageType;
  std::wstring targetVersion;
  std::wstring status;
  std::wstring errorMessage;
};

class UpdaterService {
 public:
  UpdaterService(const AgentConfig& config, std::filesystem::path installRoot);

  UpdateResult ApplyPackage(const std::filesystem::path& manifestPath, UpdateApplyMode mode) const;
  UpdateResult RollbackTransaction(const std::wstring& transactionId) const;

 private:
  AgentConfig config_;
  std::filesystem::path installRoot_;
};

}  // namespace antivirus::agent
