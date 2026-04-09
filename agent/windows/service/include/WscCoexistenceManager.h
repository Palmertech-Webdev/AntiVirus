#pragma once

#include <string>
#include <vector>

namespace antivirus::agent {

struct WscProductEntry {
  std::wstring name;
  std::wstring state;
  std::wstring signatureStatus;
  std::wstring remediationPath;
  std::wstring productGuid;
  bool isDefault{false};
};

struct WscCoexistenceSnapshot {
  bool available{false};
  std::wstring providerHealth;
  std::wstring errorMessage;
  std::vector<WscProductEntry> products;
};

class WscCoexistenceManager {
 public:
  WscCoexistenceSnapshot CaptureSnapshot() const;
  static std::wstring ToJson(const WscCoexistenceSnapshot& snapshot);
};

}  // namespace antivirus::agent
