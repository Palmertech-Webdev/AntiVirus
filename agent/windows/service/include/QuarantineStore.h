#pragma once

#include <filesystem>
#include <string>

#include "ScanEngine.h"

namespace antivirus::agent {

struct QuarantineResult {
  bool attempted{false};
  bool success{false};
  std::wstring recordId;
  std::filesystem::path quarantinedPath;
  std::wstring errorMessage;
};

struct QuarantineEntry {
  std::wstring recordId;
  std::filesystem::path originalPath;
  std::filesystem::path quarantinedPath;
  std::wstring sha256;
  std::uintmax_t sizeBytes{0};
  std::wstring techniqueId;
  std::wstring localStatus;
};

struct QuarantineActionResult {
  bool success{false};
  std::wstring recordId;
  std::filesystem::path originalPath;
  std::filesystem::path quarantinedPath;
  std::wstring errorMessage;
};

class QuarantineStore {
 public:
  QuarantineStore(std::filesystem::path rootPath, std::filesystem::path databasePath = {});

  QuarantineResult QuarantineFile(const ScanFinding& finding) const;
  QuarantineActionResult RestoreFile(const std::wstring& recordId) const;
  QuarantineActionResult DeleteRecord(const std::wstring& recordId) const;

 private:
  QuarantineEntry LoadEntry(const std::wstring& recordId) const;
  std::filesystem::path rootPath_;
  std::filesystem::path databasePath_;
};

}  // namespace antivirus::agent
