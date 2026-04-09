#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace antivirus::agent {

struct FileObservation {
  std::filesystem::path path;
  std::uintmax_t sizeBytes{0};
  std::wstring lastWriteTimeUtc;
};

std::vector<FileObservation> CollectFileInventory(const std::vector<std::filesystem::path>& roots,
                                                  std::size_t maxRecords = 0);

}  // namespace antivirus::agent
