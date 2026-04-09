#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "AgentConfig.h"
#include "PolicySnapshot.h"
#include "ScanEngine.h"
#include "TelemetryRecord.h"

namespace antivirus::agent {

enum class AmsiContentSource {
  Stream,
  Notify
};

struct AmsiContentRequest {
  AmsiContentSource source{AmsiContentSource::Stream};
  std::wstring deviceId;
  std::wstring appName;
  std::wstring contentName;
  std::uint64_t sessionId{0};
  bool quiet{false};
  std::vector<unsigned char> content;
};

struct AmsiInspectionOutcome {
  bool detection{false};
  bool blocked{false};
  ScanFinding finding{};
  std::wstring appName;
  std::wstring contentName;
  std::wstring preview;
  std::uint64_t sessionId{0};
  AmsiContentSource source{AmsiContentSource::Stream};
  std::vector<TelemetryRecord> telemetry;
};

AmsiInspectionOutcome InspectAmsiContent(const AmsiContentRequest& request, const PolicySnapshot& policy,
                                         const AgentConfig& config);

}  // namespace antivirus::agent
