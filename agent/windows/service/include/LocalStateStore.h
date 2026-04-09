#pragma once

#include <filesystem>

#include "AgentState.h"

namespace antivirus::agent {

class LocalStateStore {
 public:
  LocalStateStore(std::filesystem::path databasePath, std::filesystem::path legacyStateFilePath = {});

  AgentState LoadOrCreate() const;
  void Save(const AgentState& state) const;

 private:
  std::filesystem::path databasePath_;
  std::filesystem::path legacyStateFilePath_;
};

}  // namespace antivirus::agent
