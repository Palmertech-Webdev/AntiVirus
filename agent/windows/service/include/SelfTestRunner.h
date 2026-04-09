#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace antivirus::agent {

struct AgentConfig;

enum class SelfTestStatus {
  Pass,
  Warning,
  Fail
};

struct SelfTestCheck {
  std::wstring id;
  std::wstring name;
  SelfTestStatus status{SelfTestStatus::Pass};
  std::wstring details;
  std::wstring remediation;
};

struct SelfTestReport {
  std::wstring generatedAt;
  std::wstring overallStatus;
  std::vector<SelfTestCheck> checks;
};

SelfTestReport RunSelfTest(const AgentConfig& config, const std::filesystem::path& installRoot);
std::wstring SelfTestReportToJson(const SelfTestReport& report);
int SelfTestExitCode(const SelfTestReport& report);

}  // namespace antivirus::agent
