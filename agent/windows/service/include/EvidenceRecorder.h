#pragma once

#include <filesystem>
#include <string>

#include "PolicySnapshot.h"
#include "ScanEngine.h"

namespace antivirus::agent {

struct EvidenceRecordResult {
  std::wstring recordId;
  std::filesystem::path recordPath;
};

class EvidenceRecorder {
 public:
  EvidenceRecorder(std::filesystem::path rootPath, std::filesystem::path databasePath = {});

  EvidenceRecordResult RecordScanFinding(const ScanFinding& finding, const PolicySnapshot& policy,
                                         const std::wstring& source) const;

 private:
  std::filesystem::path rootPath_;
  std::filesystem::path databasePath_;
};

}  // namespace antivirus::agent
