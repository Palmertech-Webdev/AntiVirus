#pragma once

#include <Windows.h>

#include <filesystem>
#include <string>
#include <vector>

namespace antivirus::agent {

struct AgentConfig {
  std::wstring controlPlaneBaseUrl{L"http://127.0.0.1:4000"};
  std::filesystem::path runtimeDatabasePath{std::filesystem::path(L"runtime") / L"agent-runtime.db"};
  std::filesystem::path stateFilePath{std::filesystem::path(L"runtime") / L"agent-state.ini"};
  std::filesystem::path telemetryQueuePath{std::filesystem::path(L"runtime") / L"telemetry-queue.tsv"};
  std::filesystem::path updateRootPath{std::filesystem::path(L"runtime") / L"updates"};
  std::filesystem::path elamDriverPath{};
  std::filesystem::path quarantineRootPath{std::filesystem::path(L"runtime") / L"quarantine"};
  std::filesystem::path evidenceRootPath{std::filesystem::path(L"runtime") / L"evidence"};
  std::wstring realtimeProtectionPortName{L"\\AntiVirusRealtimePort"};
  std::wstring agentVersion{L"0.1.0-alpha"};
  std::wstring platformVersion{L"platform-0.1.0"};
  int syncIntervalSeconds{60};
  int syncIterations{1};
  int telemetryBatchSize{25};
  int realtimeBrokerRetrySeconds{5};
  bool isolationAllowLoopback{true};
  std::vector<std::wstring> isolationAllowedRemoteAddresses{};
  std::vector<std::wstring> isolationAllowedApplications{};
  std::vector<std::filesystem::path> scanExcludedPaths{};
};

AgentConfig LoadAgentConfig();
AgentConfig LoadAgentConfigForModule(HMODULE moduleHandle);
std::vector<std::filesystem::path> LoadConfiguredScanExclusions();
bool SaveConfiguredScanExclusions(const std::vector<std::filesystem::path>& exclusions);

}  // namespace antivirus::agent
