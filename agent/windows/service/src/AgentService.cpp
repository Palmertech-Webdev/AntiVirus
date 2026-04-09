#include "AgentService.h"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <vector>

#include "EvidenceRecorder.h"
#include "FileInventory.h"
#include "FileSnapshotCollector.h"
#include "HardeningManager.h"
#include "ProcessInventory.h"
#include "ProcessSnapshotCollector.h"
#include "QuarantineStore.h"
#include "RemediationEngine.h"
#include "ScanEngine.h"
#include "StringUtils.h"
#include "UpdaterService.h"
#include "WscCoexistenceManager.h"

namespace antivirus::agent {

AgentService::AgentService() = default;

AgentService::~AgentService() {
  if (stopEvent_ != nullptr) {
    CloseHandle(stopEvent_);
    stopEvent_ = nullptr;
  }
}

int AgentService::Run(const AgentRunMode mode) {
  try {
    if (stopEvent_ == nullptr) {
      stopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
      if (stopEvent_ == nullptr) {
        throw std::runtime_error("Unable to create the agent stop event");
      }
    }

    config_ = LoadAgentConfig();
    stateStore_ = std::make_unique<LocalStateStore>(config_.runtimeDatabasePath, config_.stateFilePath);
    controlPlaneClient_ = std::make_unique<ControlPlaneClient>(config_.controlPlaneBaseUrl);
    commandJournalStore_ = std::make_unique<CommandJournalStore>(config_.runtimeDatabasePath);
    telemetryQueueStore_ = std::make_unique<TelemetryQueueStore>(config_.runtimeDatabasePath, config_.telemetryQueuePath);
    realtimeProtectionBroker_ = std::make_unique<RealtimeProtectionBroker>(config_);
    processEtwSensor_ = std::make_unique<ProcessEtwSensor>(config_);
    networkIsolationManager_ = std::make_unique<NetworkIsolationManager>(config_);

    LoadLocalPolicyCache();
    realtimeProtectionBroker_->SetPolicy(policy_);
    realtimeProtectionBroker_->SetDeviceId(state_.deviceId);
    processEtwSensor_->SetDeviceId(state_.deviceId);
    networkIsolationManager_->SetDeviceId(state_.deviceId);
    realtimeProtectionBroker_->Start();
    processEtwSensor_->Start();
    networkIsolationManager_->Start();
    QueueEndpointStatusTelemetry();
    if (state_.isolated) {
      std::wstring isolationError;
      if (!networkIsolationManager_->ApplyIsolation(true, &isolationError)) {
        state_.isolated = false;
        QueueTelemetryEvent(L"network.isolation.resume.failed", L"network-wfp",
                            L"The endpoint could not restore WFP-backed isolation during startup.",
                            std::wstring(L"{\"errorMessage\":\"") +
                                Utf8ToWide(EscapeJsonString(isolationError.empty() ? L"Unknown startup isolation failure"
                                                                                  : isolationError)) +
                                L"\"}");
      }
    }
    StartTelemetrySpool();
    StartCommandLoop();
    QueueTelemetryEvent(L"service.started", L"agent-service", L"The endpoint agent boot sequence started.",
                        L"{\"phase\":\"bootstrap\"}");
    RunSyncLoop(mode);
    DrainProcessTelemetry();
    DrainRealtimeProtectionTelemetry();
    DrainNetworkTelemetry();
    networkIsolationManager_->Stop();
    processEtwSensor_->Stop();
    realtimeProtectionBroker_->Stop();
    PersistState();

    if (mode == AgentRunMode::Console) {
      std::wcout << L"Agent service skeleton is running." << std::endl;
      PrintStatus();
    }
    return 0;
  } catch (const std::exception& error) {
    std::wcerr << L"Agent service failed to initialize: " << Utf8ToWide(error.what()) << std::endl;
    return 1;
  }
}

void AgentService::RequestStop() {
  if (stopEvent_ != nullptr) {
    SetEvent(stopEvent_);
  }
}

std::wstring AgentService::BuildCyclePayload(const int cycle, const std::wstring& extraFields) {
  std::wstring payload = L"{\"cycle\":";
  payload += std::to_wstring(cycle);
  if (!extraFields.empty()) {
    payload += L",";
    payload += extraFields;
  }
  payload += L"}";
  return payload;
}

std::vector<std::filesystem::path> AgentService::BuildMonitoredRoots() const {
  std::vector<std::filesystem::path> roots;

  const auto userProfile = ReadEnvironmentVariable(L"USERPROFILE");
  if (!userProfile.empty()) {
    roots.emplace_back(std::filesystem::path(userProfile) / L"Downloads");
    roots.emplace_back(std::filesystem::path(userProfile) / L"Desktop");
  }

  roots.emplace_back(LR"(C:\Users\Public\Downloads)");
  return roots;
}

void AgentService::RunSyncLoop(const AgentRunMode mode) {
  const auto configuredIterations = std::max(config_.syncIterations, 1);
  int cycle = 1;

  while (!ShouldStop()) {
    QueueCycleTelemetry(cycle);
    DrainProcessTelemetry();
    DrainRealtimeProtectionTelemetry();
    DrainNetworkTelemetry();
    SyncWithControlPlane(cycle);
    DrainProcessTelemetry();
    DrainRealtimeProtectionTelemetry();
    DrainNetworkTelemetry();
    PollAndExecuteCommands(cycle);
    DrainProcessTelemetry();
    DrainRealtimeProtectionTelemetry();
    DrainNetworkTelemetry();
    FlushTelemetryQueue();
    PublishHeartbeat(cycle);
    DrainProcessTelemetry();
    DrainRealtimeProtectionTelemetry();
    DrainNetworkTelemetry();
    FlushTelemetryQueue();
    PersistState();

    const auto finishedConsoleRun = mode == AgentRunMode::Console && cycle >= configuredIterations;
    if (finishedConsoleRun) {
      break;
    }

    ++cycle;
    if (!WaitForNextCycle(mode, cycle)) {
      break;
    }
  }
}

bool AgentService::WaitForNextCycle(const AgentRunMode mode, const int nextCycle) const {
  if (ShouldStop()) {
    return false;
  }

  if (mode == AgentRunMode::Console) {
    std::wcout << L"Sleeping " << config_.syncIntervalSeconds << L" seconds before sync cycle " << nextCycle
               << std::endl;
  }

  const auto waitMilliseconds = static_cast<DWORD>(std::max(config_.syncIntervalSeconds, 1) * 1000);
  return WaitForSingleObject(stopEvent_, waitMilliseconds) != WAIT_OBJECT_0;
}

bool AgentService::ShouldStop() const {
  return stopEvent_ != nullptr && WaitForSingleObject(stopEvent_, 0) == WAIT_OBJECT_0;
}

void AgentService::SyncWithControlPlane(const int cycle) {
  bool attemptedRecovery = false;

  for (;;) {
    try {
      EnsureEnrollment();
      RefreshPolicy(cycle);
      lastControlPlaneSyncFailed_ = false;
      return;
    } catch (const std::exception& error) {
      if (!attemptedRecovery && RecoverDeviceIdentity(error, L"control-plane sync")) {
        attemptedRecovery = true;
        continue;
      }

      lastControlPlaneSyncFailed_ = true;
      QueueTelemetryEvent(L"control-plane.sync.failed", L"control-plane-client",
                          L"The agent could not complete a control-plane sync and is using cached state.",
                          BuildCyclePayload(cycle));
      std::wcerr << L"Control-plane sync failed, continuing with cached state: " << Utf8ToWide(error.what())
                 << std::endl;
      return;
    }
  }
}

void AgentService::EnsureEnrollment() {
  if (!state_.deviceId.empty()) {
    return;
  }

  const auto enrollment = controlPlaneClient_->Enroll(state_);
  state_.deviceId = enrollment.deviceId;
  state_.commandChannelUrl = enrollment.commandChannelUrl;
  state_.lastEnrollmentAt = enrollment.issuedAt;
  state_.policy = enrollment.policy;
  policy_ = enrollment.policy;
  realtimeProtectionBroker_->SetDeviceId(state_.deviceId);
  realtimeProtectionBroker_->SetPolicy(policy_);
  processEtwSensor_->SetDeviceId(state_.deviceId);
  networkIsolationManager_->SetDeviceId(state_.deviceId);
  QueueTelemetryEvent(L"device.enrolled", L"control-plane-client",
                      L"The endpoint enrolled with the control plane.",
                      std::wstring(L"{\"deviceId\":\"") + state_.deviceId + L"\"}");
}

void AgentService::ResetEnrollmentState() {
  state_.deviceId.clear();
  state_.commandChannelUrl.clear();
  state_.lastEnrollmentAt.clear();
  state_.lastHeartbeatAt.clear();
  state_.lastPolicySyncAt.clear();
  realtimeProtectionBroker_->SetDeviceId(L"");
  processEtwSensor_->SetDeviceId(L"");
  networkIsolationManager_->SetDeviceId(L"");
}

bool AgentService::RecoverDeviceIdentity(const std::exception& error, const std::wstring& operationName) {
  const auto* rejectedError = dynamic_cast<const DeviceIdentityRejectedError*>(&error);
  if (rejectedError == nullptr) {
    return false;
  }

  const auto previousDeviceId = state_.deviceId;
  QueueTelemetryEvent(L"device.identity.rejected", L"control-plane-client",
                      L"The control plane rejected the cached device identity and the agent is re-enrolling.",
                      std::wstring(L"{\"previousDeviceId\":\"") + previousDeviceId + L"\",\"operation\":\"" +
                          Utf8ToWide(EscapeJsonString(operationName)) + L"\"}");

  std::wcerr << L"Cached device identity was rejected during " << operationName
             << L"; clearing the cached registration and re-enrolling." << std::endl;

  ResetEnrollmentState();

  try {
    EnsureEnrollment();
    PersistState();
    std::wcout << L"Recovered control-plane identity. New device ID: " << state_.deviceId << std::endl;
    return true;
  } catch (const std::exception& recoveryError) {
    std::wcerr << L"Re-enrollment after identity rejection failed: " << Utf8ToWide(recoveryError.what()) << std::endl;
    return false;
  }
}

void AgentService::RefreshPolicy(const int cycle) {
  if (state_.deviceId.empty()) {
    return;
  }

  const auto policyCheckIn = controlPlaneClient_->CheckInPolicy(state_);
  state_.lastPolicySyncAt = policyCheckIn.retrievedAt;
  state_.policy = policyCheckIn.policy;
  policy_ = policyCheckIn.policy;
  realtimeProtectionBroker_->SetPolicy(policy_);
  QueueTelemetryEvent(L"policy.checked-in", L"control-plane-client",
                      policyCheckIn.changed ? L"The endpoint retrieved a newer effective policy."
                                            : L"The endpoint confirmed that policy is already current.",
                      BuildCyclePayload(cycle, std::wstring(L"\"revision\":\"") + policy_.revision + L"\""));
}

void AgentService::PollAndExecuteCommands(const int cycle) {
  if (state_.deviceId.empty()) {
    return;
  }

  bool attemptedRecovery = false;

  for (;;) {
    try {
      const auto pollResult = controlPlaneClient_->PollPendingCommands(state_);
      if (pollResult.items.empty()) {
        return;
      }

      QueueTelemetryEvent(L"commands.polled", L"command-executor",
                          L"The endpoint pulled pending response actions from the control plane.",
                          BuildCyclePayload(cycle, std::wstring(L"\"count\":") + std::to_wstring(pollResult.items.size())));

      for (const auto& command : pollResult.items) {
        if (commandJournalStore_) {
          commandJournalStore_->RecordPolled(command);
        }
        try {
          const auto resultJson = ExecuteCommand(command);
          controlPlaneClient_->CompleteCommand(state_, command.commandId, L"completed", resultJson);
          if (commandJournalStore_) {
            commandJournalStore_->RecordCompleted(command, resultJson);
          }
          QueueTelemetryEvent(L"command.completed", L"command-executor",
                              std::wstring(L"Completed remote command ") + command.type + L".",
                              std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"type\":\"" + command.type +
                                  L"\"}");
        } catch (const std::exception& error) {
          const auto errorMessage = Utf8ToWide(error.what());
          const auto failureJson = std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"error\":\"" +
                                   Utf8ToWide(EscapeJsonString(errorMessage)) + L"\"}";

          try {
            controlPlaneClient_->CompleteCommand(state_, command.commandId, L"failed", failureJson);
          } catch (const std::exception& completionError) {
            std::wcerr << L"Completing failed command state also failed: " << Utf8ToWide(completionError.what())
                       << std::endl;
          }

          if (commandJournalStore_) {
            commandJournalStore_->RecordFailed(command, failureJson, errorMessage);
          }

          QueueTelemetryEvent(L"command.failed", L"command-executor",
                              std::wstring(L"Remote command failed: ") + command.type + L".", failureJson);
        }
      }

      return;
    } catch (const std::exception& error) {
      if (!attemptedRecovery && RecoverDeviceIdentity(error, L"command polling")) {
        attemptedRecovery = true;
        continue;
      }

      QueueTelemetryEvent(L"command.poll.failed", L"command-executor",
                          L"The endpoint could not retrieve pending commands from the control plane.",
                          BuildCyclePayload(cycle));
      std::wcerr << L"Command polling failed: " << Utf8ToWide(error.what()) << std::endl;
      return;
    }
  }
}

std::wstring AgentService::ExecuteCommand(const RemoteCommand& command) {
  if (command.type == L"device.isolate") {
    return ExecuteIsolationCommand(command, true);
  }

  if (command.type == L"device.release") {
    return ExecuteIsolationCommand(command, false);
  }

  if (command.type == L"scan.targeted") {
    return ExecuteTargetedScan(command);
  }

  if (command.type == L"quarantine.restore") {
    return ExecuteQuarantineMutation(command, true);
  }

  if (command.type == L"quarantine.delete") {
    return ExecuteQuarantineMutation(command, false);
  }

  if (command.type == L"update.apply") {
    return ExecuteUpdateCommand(command, false);
  }

  if (command.type == L"update.rollback") {
    return ExecuteUpdateCommand(command, true);
  }

  if (command.type == L"agent.repair") {
    return ExecuteRepairCommand(command);
  }

  if (command.type == L"process.terminate") {
    return ExecuteProcessTerminationCommand(command, false);
  }

  if (command.type == L"process.tree.terminate") {
    return ExecuteProcessTerminationCommand(command, true);
  }

  if (command.type == L"persistence.cleanup") {
    return ExecutePersistenceCleanupCommand(command);
  }

  if (command.type == L"remediate.path") {
    return ExecutePathRemediationCommand(command);
  }

  throw std::runtime_error("Unsupported remote command type");
}

std::wstring AgentService::ExecuteTargetedScan(const RemoteCommand& command) {
  if (command.targetPath.empty()) {
    throw std::runtime_error("scan.targeted command is missing targetPath");
  }

  const std::filesystem::path targetPath(command.targetPath);
  std::error_code error;
  if (!std::filesystem::exists(targetPath, error)) {
    throw std::runtime_error("Targeted scan path does not exist");
  }

  auto findings = ScanTargets({targetPath}, policy_);
  QuarantineStore quarantineStore(config_.quarantineRootPath, config_.runtimeDatabasePath);
  EvidenceRecorder evidenceRecorder(config_.evidenceRootPath, config_.runtimeDatabasePath);

  for (auto& finding : findings) {
    if (finding.verdict.disposition == VerdictDisposition::Quarantine) {
      const auto quarantineResult = quarantineStore.QuarantineFile(finding);
      if (quarantineResult.success) {
        finding.remediationStatus = RemediationStatus::Quarantined;
        finding.quarantineRecordId = quarantineResult.recordId;
        finding.quarantinedPath = quarantineResult.quarantinedPath;
      } else {
        finding.remediationStatus = RemediationStatus::Failed;
        finding.remediationError =
            quarantineResult.errorMessage.empty() ? L"Unable to move the file into quarantine" : quarantineResult.errorMessage;
        finding.verdict.reasons.push_back({L"QUARANTINE_FAILED", finding.remediationError});
      }
    }

    const auto evidenceResult = evidenceRecorder.RecordScanFinding(finding, policy_, L"agent-service");
    finding.evidenceRecordId = evidenceResult.recordId;
  }

  QueueTelemetryEvent(BuildScanSummaryTelemetry(1, findings.size(), policy_, L"agent-service").eventType,
                      L"agent-service", BuildScanSummaryTelemetry(1, findings.size(), policy_, L"agent-service").summary,
                      BuildScanSummaryTelemetry(1, findings.size(), policy_, L"agent-service").payloadJson);
  for (const auto& finding : findings) {
    const auto record = BuildScanFindingTelemetry(finding, L"agent-service");
    QueueTelemetryEvent(record.eventType, record.source, record.summary, record.payloadJson);
  }

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"targetPath\":\"" +
         Utf8ToWide(EscapeJsonString(command.targetPath)) + L"\",\"findingCount\":" + std::to_wstring(findings.size()) +
         L"}";
}

std::wstring AgentService::ExecuteIsolationCommand(const RemoteCommand& command, const bool isolate) {
  if (!networkIsolationManager_) {
    throw std::runtime_error("The WFP isolation manager is not available");
  }

  std::wstring errorMessage;
  if (!networkIsolationManager_->ApplyIsolation(isolate, &errorMessage)) {
    throw std::runtime_error(WideToUtf8(errorMessage.empty() ? L"The WFP isolation manager rejected the requested state"
                                                            : errorMessage));
  }

  state_.isolated = networkIsolationManager_->IsolationActive();

  const auto eventType = isolate ? L"device.isolated" : L"device.released";
  const auto summary = isolate ? L"The endpoint entered WFP-backed host isolation after a remote action."
                               : L"The endpoint left WFP-backed host isolation after a remote action.";
  QueueTelemetryEvent(eventType, L"command-executor", summary,
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"wfpApplied\":true}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"isolated\":" +
         (state_.isolated ? L"true" : L"false") + L",\"wfpApplied\":true}";
}

std::wstring AgentService::ExecuteQuarantineMutation(const RemoteCommand& command, const bool restore) {
  if (command.recordId.empty()) {
    throw std::runtime_error("Quarantine command is missing recordId");
  }

  QuarantineStore quarantineStore(config_.quarantineRootPath, config_.runtimeDatabasePath);
  const auto result = restore ? quarantineStore.RestoreFile(command.recordId) : quarantineStore.DeleteRecord(command.recordId);

  if (!result.success) {
    throw std::runtime_error(WideToUtf8(result.errorMessage.empty() ? L"Quarantine operation failed" : result.errorMessage));
  }

  const auto eventType = restore ? L"quarantine.restored" : L"quarantine.deleted";
  const auto summary = restore ? L"A quarantined item was restored after a remote action."
                               : L"A quarantined item was deleted after a remote action.";
  QueueTelemetryEvent(eventType, L"command-executor", summary,
                      std::wstring(L"{\"recordId\":\"") + result.recordId + L"\",\"originalPath\":\"" +
                          Utf8ToWide(EscapeJsonString(result.originalPath.wstring())) + L"\",\"quarantinedPath\":\"" +
                          Utf8ToWide(EscapeJsonString(result.quarantinedPath.wstring())) + L"\"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"recordId\":\"" + result.recordId +
         L"\",\"action\":\"" + (restore ? std::wstring(L"restore") : std::wstring(L"delete")) + L"\"}";
}

std::wstring AgentService::ExecuteUpdateCommand(const RemoteCommand& command, const bool rollback) {
  const auto installRoot = config_.runtimeDatabasePath.parent_path().parent_path();
  UpdaterService updater(config_, installRoot);
  const auto result =
      rollback ? updater.RollbackTransaction(command.recordId)
               : updater.ApplyPackage(command.targetPath, UpdateApplyMode::InService);

  if (!result.success) {
    throw std::runtime_error(WideToUtf8(result.errorMessage.empty() ? L"Update operation failed" : result.errorMessage));
  }

  const auto eventType = rollback ? L"update.rolled_back" : L"update.applied";
  const auto summary = rollback ? L"The endpoint rolled back a staged platform update."
                                : L"The endpoint applied a staged platform or engine update.";
  QueueTelemetryEvent(eventType, L"command-executor", summary,
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"transactionId\":\"" +
                          result.transactionId + L"\",\"packageId\":\"" + result.packageId + L"\",\"status\":\"" +
                          result.status + L"\",\"restartRequired\":" +
                          (result.restartRequired ? std::wstring(L"true") : std::wstring(L"false")) + L"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"transactionId\":\"" + result.transactionId +
         L"\",\"packageId\":\"" + result.packageId + L"\",\"status\":\"" + result.status + L"\",\"restartRequired\":" +
         (result.restartRequired ? std::wstring(L"true") : std::wstring(L"false")) + L"}";
}

std::wstring AgentService::ExecuteRepairCommand(const RemoteCommand& command) {
  const auto installRoot = config_.runtimeDatabasePath.parent_path().parent_path();
  HardeningManager hardeningManager(config_, installRoot);
  std::wstring errorMessage;
  const auto applied = hardeningManager.ApplyPostInstallHardening(ReadEnvironmentVariable(L"ANTIVIRUS_UNINSTALL_TOKEN"),
                                                                  &errorMessage);
  lastHardeningCheckFailed_ = !applied;

  const WscCoexistenceManager wscManager;
  const auto wscSnapshot = wscManager.CaptureSnapshot();
  QueueTelemetryEvent(applied ? L"agent.repaired" : L"agent.repair.failed", L"command-executor",
                      applied ? L"The endpoint reapplied service hardening and coexistence checks."
                              : L"The endpoint could not fully reapply service hardening.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"hardeningApplied\":" +
                          (applied ? std::wstring(L"true") : std::wstring(L"false")) + L",\"wscAvailable\":" +
                          (wscSnapshot.available ? std::wstring(L"true") : std::wstring(L"false")) + L"}");

  if (!applied) {
    throw std::runtime_error(WideToUtf8(errorMessage.empty() ? L"Endpoint repair failed" : errorMessage));
  }

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"hardeningApplied\":true,\"wscAvailable\":" +
         (wscSnapshot.available ? std::wstring(L"true") : std::wstring(L"false")) + L"}";
}

std::wstring AgentService::ExecuteProcessTerminationCommand(const RemoteCommand& command, const bool includeChildren) {
  if (command.targetPath.empty()) {
    throw std::runtime_error("Process termination command is missing targetPath");
  }

  RemediationEngine remediationEngine(config_);
  const auto result = remediationEngine.TerminateProcessesForPath(command.targetPath, includeChildren);
  QueueTelemetryEvent(includeChildren ? L"process.tree.terminated" : L"process.terminated", L"command-executor",
                      includeChildren ? L"The endpoint terminated a malicious process tree."
                                      : L"The endpoint terminated a malicious process.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"targetPath\":\"" +
                          Utf8ToWide(EscapeJsonString(command.targetPath)) + L"\",\"terminatedCount\":" +
                          std::to_wstring(result.processesTerminated) + L"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"targetPath\":\"" +
         Utf8ToWide(EscapeJsonString(command.targetPath)) + L"\",\"terminatedCount\":" +
         std::to_wstring(result.processesTerminated) + L"}";
}

std::wstring AgentService::ExecutePersistenceCleanupCommand(const RemoteCommand& command) {
  if (command.targetPath.empty()) {
    throw std::runtime_error("Persistence cleanup command is missing targetPath");
  }

  RemediationEngine remediationEngine(config_);
  const auto result = remediationEngine.CleanupPersistenceForPath(command.targetPath);
  QueueTelemetryEvent(L"persistence.cleaned", L"command-executor",
                      L"The endpoint removed startup persistence tied to a malicious artifact.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"targetPath\":\"" +
                          Utf8ToWide(EscapeJsonString(command.targetPath)) + L"\",\"registryValuesRemoved\":" +
                          std::to_wstring(result.registryValuesRemoved) + L",\"startupArtifactsRemoved\":" +
                          std::to_wstring(result.startupArtifactsRemoved) + L"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"targetPath\":\"" +
         Utf8ToWide(EscapeJsonString(command.targetPath)) + L"\",\"registryValuesRemoved\":" +
         std::to_wstring(result.registryValuesRemoved) + L",\"startupArtifactsRemoved\":" +
         std::to_wstring(result.startupArtifactsRemoved) + L"}";
}

std::wstring AgentService::ExecutePathRemediationCommand(const RemoteCommand& command) {
  if (command.targetPath.empty()) {
    throw std::runtime_error("remediate.path command is missing targetPath");
  }

  RemediationEngine remediationEngine(config_);
  const auto result = remediationEngine.RemediatePath(command.targetPath, policy_);
  QueueTelemetryEvent(L"remediation.completed", L"command-executor",
                      L"The endpoint executed a full remediation workflow for a malicious artifact.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"targetPath\":\"" +
                          Utf8ToWide(EscapeJsonString(command.targetPath)) + L"\",\"terminatedCount\":" +
                          std::to_wstring(result.processesTerminated) + L",\"registryValuesRemoved\":" +
                          std::to_wstring(result.registryValuesRemoved) + L",\"startupArtifactsRemoved\":" +
                          std::to_wstring(result.startupArtifactsRemoved) + L",\"quarantineApplied\":" +
                          (result.quarantineApplied ? std::wstring(L"true") : std::wstring(L"false")) + L"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"targetPath\":\"" +
         Utf8ToWide(EscapeJsonString(command.targetPath)) + L"\",\"terminatedCount\":" +
         std::to_wstring(result.processesTerminated) + L",\"registryValuesRemoved\":" +
         std::to_wstring(result.registryValuesRemoved) + L",\"startupArtifactsRemoved\":" +
         std::to_wstring(result.startupArtifactsRemoved) + L",\"quarantineApplied\":" +
         (result.quarantineApplied ? std::wstring(L"true") : std::wstring(L"false")) + L",\"quarantineRecordId\":\"" +
         result.quarantineRecordId + L"\",\"evidenceRecordId\":\"" + result.evidenceRecordId + L"\"}";
}

void AgentService::PublishHeartbeat(const int cycle) {
  if (state_.deviceId.empty()) {
    return;
  }

  const auto wfpIsolationActive = networkIsolationManager_ && networkIsolationManager_->IsolationActive();
  const auto wfpUnavailable =
      policy_.networkContainmentEnabled && (!networkIsolationManager_ || !networkIsolationManager_->EngineReady());

  state_.isolated = wfpIsolationActive;
  state_.healthState = wfpIsolationActive
                           ? L"isolated"
                           : ((wfpUnavailable || lastControlPlaneSyncFailed_ || lastTelemetryFlushFailed_ ||
                               lastHardeningCheckFailed_)
                                  ? L"degraded"
                                  : L"healthy");

  bool attemptedRecovery = false;
  for (;;) {
    try {
      const auto heartbeat = controlPlaneClient_->SendHeartbeat(state_);
      state_.lastHeartbeatAt = heartbeat.receivedAt;
      lastControlPlaneSyncFailed_ = false;
      QueueTelemetryEvent(L"device.heartbeat", L"control-plane-client",
                          L"The endpoint heartbeat was acknowledged by the control plane.",
                          BuildCyclePayload(cycle, std::wstring(L"\"commandsPending\":") +
                                                       std::to_wstring(heartbeat.commandsPending)));
      return;
    } catch (const std::exception& error) {
      if (!attemptedRecovery && RecoverDeviceIdentity(error, L"heartbeat")) {
        attemptedRecovery = true;
        continue;
      }

      lastControlPlaneSyncFailed_ = true;
      QueueTelemetryEvent(L"device.heartbeat.failed", L"control-plane-client",
                          L"The endpoint heartbeat could not be delivered to the control plane.",
                          BuildCyclePayload(cycle));
      std::wcerr << L"Heartbeat failed, keeping the previous health state cached: " << Utf8ToWide(error.what())
                 << std::endl;
      return;
    }
  }
}

void AgentService::PersistState() {
  if (!stateStore_) {
    return;
  }

  stateStore_->Save(state_);
  telemetryQueueStore_->SavePending(pendingTelemetry_);
}

void AgentService::LoadLocalPolicyCache() {
  state_ = stateStore_->LoadOrCreate();
  state_.agentVersion = config_.agentVersion;
  state_.platformVersion = config_.platformVersion;
  policy_ = state_.policy;
  pendingTelemetry_ = telemetryQueueStore_->LoadPending();
}

void AgentService::StartTelemetrySpool() const {
  const auto deviceLabel = state_.deviceId.empty() ? std::wstring(L"(not yet enrolled)") : state_.deviceId;
  std::wcout << L"Telemetry spool ready for device " << deviceLabel << L" with " << pendingTelemetry_.size()
             << L" queued event(s)." << std::endl;
}

void AgentService::StartCommandLoop() const {
  if (!state_.commandChannelUrl.empty()) {
    std::wcout << L"Command polling configured at " << state_.commandChannelUrl << std::endl;
  } else {
    std::wcout << L"Command polling has not been assigned yet." << std::endl;
  }

  std::wcout << L"Real-time protection broker targeting port " << config_.realtimeProtectionPortName << std::endl;
  std::wcout << L"ETW process telemetry sensor " << (processEtwSensor_ && processEtwSensor_->IsActive() ? L"active"
                                                                                                          : L"fallback")
             << std::endl;
  std::wcout << L"WFP isolation manager "
             << (networkIsolationManager_ ? (networkIsolationManager_->EngineReady() ? L"ready" : L"unavailable")
                                          : L"not configured")
             << std::endl;
}

void AgentService::PrintStatus() const {
  const auto deviceLabel = state_.deviceId.empty() ? std::wstring(L"(pending)") : state_.deviceId;
  const auto lastPolicySync = state_.lastPolicySyncAt.empty() ? std::wstring(L"(never)") : state_.lastPolicySyncAt;
  const auto lastHeartbeat = state_.lastHeartbeatAt.empty() ? std::wstring(L"(never)") : state_.lastHeartbeatAt;

  std::wcout << L"Hostname: " << state_.hostname << std::endl;
  std::wcout << L"Device ID: " << deviceLabel << std::endl;
  std::wcout << L"Policy: " << policy_.policyName << L" (" << policy_.revision << L")" << std::endl;
  std::wcout << L"Health state: " << state_.healthState << std::endl;
  std::wcout << L"Last policy sync: " << lastPolicySync << std::endl;
  std::wcout << L"Last heartbeat: " << lastHeartbeat << std::endl;
  std::wcout << L"Real-time protection port: " << config_.realtimeProtectionPortName << std::endl;
  std::wcout << L"ETW process telemetry: "
             << (processEtwSensor_ && processEtwSensor_->IsActive() ? L"active" : L"fallback polling") << std::endl;
  std::wcout << L"WFP host isolation: "
             << (networkIsolationManager_ ? (networkIsolationManager_->IsolationActive()
                                                 ? L"active"
                                                 : (networkIsolationManager_->EngineReady() ? L"ready" : L"unavailable"))
                                          : L"not configured")
             << std::endl;
  std::wcout << L"Tamper protection: " << (lastHardeningCheckFailed_ ? L"degraded" : L"configured") << std::endl;
  std::wcout << L"Pending telemetry events: " << pendingTelemetry_.size() << std::endl;
}

void AgentService::QueueEndpointStatusTelemetry() {
  const auto installRoot = config_.runtimeDatabasePath.parent_path().parent_path();
  HardeningManager hardeningManager(config_, installRoot);
  const auto hardeningStatus = hardeningManager.QueryStatus();
  const auto protectedServiceExpected = hardeningStatus.elamDriverPresent || !config_.elamDriverPath.empty();
  lastHardeningCheckFailed_ =
      !(hardeningStatus.registryConfigured && hardeningStatus.runtimePathsProtected &&
        hardeningStatus.serviceControlProtected &&
        (!protectedServiceExpected || hardeningStatus.launchProtectedConfigured));
  QueueTelemetryEvent(lastHardeningCheckFailed_ ? L"tamper.protection.degraded" : L"tamper.protection.ready",
                      L"hardening-manager", hardeningStatus.statusMessage,
                      std::wstring(L"{\"registryConfigured\":") +
                          (hardeningStatus.registryConfigured ? std::wstring(L"true") : std::wstring(L"false")) +
                          L",\"runtimePathsProtected\":" +
                          (hardeningStatus.runtimePathsProtected ? std::wstring(L"true") : std::wstring(L"false")) +
                          L",\"serviceControlProtected\":" +
                          (hardeningStatus.serviceControlProtected ? std::wstring(L"true")
                                                                   : std::wstring(L"false")) +
                          L",\"uninstallProtectionEnabled\":" +
                          (hardeningStatus.uninstallProtectionEnabled ? std::wstring(L"true")
                                                                      : std::wstring(L"false")) +
                          L",\"elamDriverPresent\":" +
                          (hardeningStatus.elamDriverPresent ? std::wstring(L"true") : std::wstring(L"false")) +
                          L",\"elamCertificateInstalled\":" +
                          (hardeningStatus.elamCertificateInstalled ? std::wstring(L"true")
                                                                    : std::wstring(L"false")) +
                          L",\"launchProtectedConfigured\":" +
                          (hardeningStatus.launchProtectedConfigured ? std::wstring(L"true")
                                                                     : std::wstring(L"false")) +
                          L"}");

  const WscCoexistenceManager wscManager;
  const auto wscSnapshot = wscManager.CaptureSnapshot();
  QueueTelemetryEvent(wscSnapshot.available ? L"wsc.coexistence.ready" : L"wsc.coexistence.degraded",
                      L"wsc-coexistence", wscSnapshot.available
                                              ? L"Windows Security Center coexistence data was collected."
                                              : L"Windows Security Center coexistence data is unavailable on this host.",
                      WscCoexistenceManager::ToJson(wscSnapshot));
}

void AgentService::DrainProcessTelemetry() {
  if (!processEtwSensor_) {
    return;
  }

  const auto telemetry = processEtwSensor_->DrainTelemetry();
  if (!telemetry.empty()) {
    QueueTelemetryRecords(telemetry);
  }
}

void AgentService::DrainRealtimeProtectionTelemetry() {
  if (!realtimeProtectionBroker_) {
    return;
  }

  const auto telemetry = realtimeProtectionBroker_->DrainTelemetry();
  if (!telemetry.empty()) {
    QueueTelemetryRecords(telemetry);
  }
}

void AgentService::DrainNetworkTelemetry() {
  if (!networkIsolationManager_) {
    return;
  }

  const auto telemetry = networkIsolationManager_->DrainTelemetry();
  if (!telemetry.empty()) {
    QueueTelemetryRecords(telemetry);
  }
}

void AgentService::QueueCycleTelemetry(const int cycle) {
  QueueTelemetryEvent(L"service.sync.cycle", L"agent-service",
                      L"The endpoint is starting a scheduled sync cycle.",
                      BuildCyclePayload(cycle, std::wstring(L"\"hostname\":\"") + state_.hostname + L"\""));

  DrainProcessTelemetry();
  DrainNetworkTelemetry();
  if (!processEtwSensor_ || !processEtwSensor_->IsActive()) {
    const auto processInventory = CollectProcessInventory();
    const auto processSnapshotRecords = BuildProcessSnapshotTelemetry(processInventory, 4);
    if (processSnapshotRecords.empty()) {
      QueueTelemetryEvent(L"process.snapshot.empty", L"process-snapshot",
                          L"No process snapshot records were collected during this cycle.", BuildCyclePayload(cycle));
    } else {
      QueueTelemetryRecords(processSnapshotRecords);
    }
    QueueTelemetryRecords(processDeltaTracker_.CollectDeltaTelemetry(processInventory));
  }

  const auto fileInventory = CollectFileInventory(BuildMonitoredRoots());
  const auto fileSnapshotRecords = BuildRecentFileTelemetry(fileInventory, 4);
  if (fileSnapshotRecords.empty()) {
    QueueTelemetryEvent(L"file.snapshot.empty", L"file-snapshot",
                        L"No recent files were found in the monitored folders during this cycle.",
                        BuildCyclePayload(cycle));
  } else {
    QueueTelemetryRecords(fileSnapshotRecords);
  }
  QueueTelemetryRecords(fileDeltaTracker_.CollectDeltaTelemetry(fileInventory));

  if (networkIsolationManager_ && networkIsolationManager_->EngineReady()) {
    QueueTelemetryRecords(networkIsolationManager_->CollectConnectionSnapshotTelemetry(6));
  }
}

void AgentService::QueueTelemetryEvent(const std::wstring& eventType, const std::wstring& source,
                                       const std::wstring& summary, const std::wstring& payloadJson) {
  pendingTelemetry_.push_back(TelemetryRecord{
      .eventId = GenerateGuidString(),
      .eventType = eventType,
      .source = source,
      .summary = summary,
      .occurredAt = CurrentUtcTimestamp(),
      .payloadJson = payloadJson});

  telemetryQueueStore_->SavePending(pendingTelemetry_);
}

void AgentService::QueueTelemetryRecords(const std::vector<TelemetryRecord>& records) {
  pendingTelemetry_.insert(pendingTelemetry_.end(), records.begin(), records.end());
  telemetryQueueStore_->SavePending(pendingTelemetry_);
}

void AgentService::FlushTelemetryQueue() {
  if (state_.deviceId.empty() || pendingTelemetry_.empty()) {
    lastTelemetryFlushFailed_ = false;
    return;
  }

  lastTelemetryFlushFailed_ = false;
  bool attemptedRecovery = false;
  while (!pendingTelemetry_.empty() && !ShouldStop()) {
    const auto batchSize =
        std::min<std::size_t>(pendingTelemetry_.size(), static_cast<std::size_t>(config_.telemetryBatchSize));
    const std::vector<TelemetryRecord> batch(pendingTelemetry_.begin(), pendingTelemetry_.begin() + batchSize);

    try {
      const auto result = controlPlaneClient_->SendTelemetryBatch(state_, batch);
      pendingTelemetry_.erase(pendingTelemetry_.begin(), pendingTelemetry_.begin() + batchSize);
      telemetryQueueStore_->SavePending(pendingTelemetry_);
      std::wcout << L"Uploaded " << result.accepted << L" telemetry event(s) at " << result.receivedAt
                 << L". Backend now stores " << result.totalStored << L" event(s)." << std::endl;
    } catch (const std::exception& error) {
      if (!attemptedRecovery && RecoverDeviceIdentity(error, L"telemetry upload")) {
        attemptedRecovery = true;
        continue;
      }

      lastTelemetryFlushFailed_ = true;
      std::wcerr << L"Telemetry upload failed, leaving " << pendingTelemetry_.size()
                 << L" event(s) queued locally: " << Utf8ToWide(error.what()) << std::endl;
      break;
    }
  }
}

ScanVerdict AgentService::EvaluateEvent(const EventEnvelope& event) const {
  if (realtimeProtectionBroker_) {
    return realtimeProtectionBroker_->EvaluateEvent(event);
  }

  return ScanVerdict{};
}

}  // namespace antivirus::agent
