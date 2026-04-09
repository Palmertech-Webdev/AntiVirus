#pragma once

#include <string>

namespace antivirus::agent {

struct TelemetryRecord {
  std::wstring eventId;
  std::wstring eventType;
  std::wstring source;
  std::wstring summary;
  std::wstring occurredAt;
  std::wstring payloadJson;
};

}  // namespace antivirus::agent
