#pragma once

#include <filesystem>
#include <string>

#include "ControlPlaneClient.h"

namespace antivirus::agent {

class CommandJournalStore {
 public:
  explicit CommandJournalStore(std::filesystem::path databasePath);

  void RecordPolled(const RemoteCommand& command) const;
  void RecordCompleted(const RemoteCommand& command, const std::wstring& resultJson) const;
  void RecordFailed(const RemoteCommand& command, const std::wstring& failureJson,
                    const std::wstring& errorMessage) const;

 private:
  std::filesystem::path databasePath_;
};

}  // namespace antivirus::agent
