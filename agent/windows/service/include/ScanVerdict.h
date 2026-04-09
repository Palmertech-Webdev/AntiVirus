#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace antivirus::agent {

enum class VerdictDisposition {
  Unknown,
  Allow,
  Block,
  Quarantine
};

struct VerdictReason {
  std::wstring code;
  std::wstring message;
};

struct ScanVerdict {
  VerdictDisposition disposition{VerdictDisposition::Unknown};
  std::uint32_t confidence{0};
  std::wstring tacticId;
  std::wstring techniqueId;
  std::vector<VerdictReason> reasons;
};

}  // namespace antivirus::agent
