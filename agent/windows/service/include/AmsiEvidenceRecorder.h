#pragma once

#include <filesystem>
#include <string>

#include "AmsiScanEngine.h"
#include "PolicySnapshot.h"

namespace antivirus::agent {

struct AmsiEvidenceRecordResult {
  std::wstring recordId;
  std::filesystem::path recordPath;
};

class AmsiEvidenceRecorder {
 public:
  AmsiEvidenceRecorder(std::filesystem::path rootPath, std::filesystem::path databasePath = {});

  AmsiEvidenceRecordResult RecordInspection(const AmsiContentRequest& request, const AmsiInspectionOutcome& outcome,
                                            const PolicySnapshot& policy, const std::wstring& source) const;

 private:
  std::filesystem::path rootPath_;
  std::filesystem::path databasePath_;
};

}  // namespace antivirus::agent
