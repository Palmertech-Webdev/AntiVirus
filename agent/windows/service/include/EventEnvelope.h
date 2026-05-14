#pragma once

#include <chrono>
#include <string>

namespace antivirus::agent {

enum class EventKind {
  FileCreate,
  FileOpen,
  FileWrite,
  FileExecute,
  ProcessStart,
  ScriptScan,
  NetworkConnect
};

struct ProcessContext {
  std::wstring imagePath;
  std::wstring commandLine;
  std::wstring parentImagePath;
  std::wstring userSid;
  std::wstring signer;
};

struct EventEnvelope {
  EventKind kind;
  std::wstring deviceId;
  std::wstring correlationId;
  std::wstring targetPath;
  std::wstring sha256;
  ProcessContext process;
  std::chrono::system_clock::time_point occurredAt;
  
  std::string ToJson() const;
};

}  // namespace antivirus::agent
