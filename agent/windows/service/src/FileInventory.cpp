#include "FileInventory.h"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <string>
#include <vector>

namespace antivirus::agent {
namespace {

std::wstring FileTimeToUtcString(const std::filesystem::file_time_type value) {
  const auto systemNow = std::chrono::system_clock::now();
  const auto fileNow = std::filesystem::file_time_type::clock::now();
  const auto adjusted = systemNow + std::chrono::duration_cast<std::chrono::system_clock::duration>(value - fileNow);
  const auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(adjusted.time_since_epoch());
  const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(milliseconds);
  const auto remainder = milliseconds - seconds;

  std::time_t timeValue = std::chrono::system_clock::to_time_t(adjusted);
  std::tm utcTime{};
  gmtime_s(&utcTime, &timeValue);

  wchar_t buffer[32] = {};
  swprintf(buffer, 32, L"%04d-%02d-%02dT%02d:%02d:%02d.%03lldZ", utcTime.tm_year + 1900, utcTime.tm_mon + 1,
           utcTime.tm_mday, utcTime.tm_hour, utcTime.tm_min, utcTime.tm_sec,
           static_cast<long long>(remainder.count()));
  return std::wstring(buffer);
}

}  // namespace

std::vector<FileObservation> CollectFileInventory(const std::vector<std::filesystem::path>& roots, std::size_t maxRecords) {
  std::vector<FileObservation> files;

  for (const auto& root : roots) {
    if (root.empty() || !std::filesystem::exists(root) || !std::filesystem::is_directory(root)) {
      continue;
    }

    for (const auto& entry :
         std::filesystem::directory_iterator(root, std::filesystem::directory_options::skip_permission_denied)) {
      if (!entry.is_regular_file()) {
        continue;
      }

      std::error_code sizeError;
      const auto size = entry.file_size(sizeError);
      if (sizeError) {
        continue;
      }

      std::error_code timeError;
      const auto lastWriteTime = entry.last_write_time(timeError);
      if (timeError) {
        continue;
      }

      files.push_back(FileObservation{
          .path = entry.path(),
          .sizeBytes = size,
          .lastWriteTimeUtc = FileTimeToUtcString(lastWriteTime)});
    }
  }

  std::sort(files.begin(), files.end(), [](const FileObservation& left, const FileObservation& right) {
    return left.lastWriteTimeUtc > right.lastWriteTimeUtc;
  });

  if (maxRecords > 0 && files.size() > maxRecords) {
    files.resize(maxRecords);
  }

  return files;
}

}  // namespace antivirus::agent
