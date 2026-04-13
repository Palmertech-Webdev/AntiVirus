# Windows Agent Service Skeleton

This is the current user-mode core for the Windows endpoint service.

It is still early, but it now includes Windows Service registration, a minifilter-facing verdict broker, and the first real-time protection decision path. The service now supports:

- A real SCM-compatible Windows Service host with `--install`, `--repair`, `--upgrade`, `--rollback-update`, `--uninstall`, `--wsc-status`, `--self-test`, and `--console` modes
- Local persisted agent state
- Local persisted telemetry queue
- A SQLite-backed durable runtime database for policy cache, command journal, telemetry queue, quarantine index, evidence index, and scan history
- Local quarantine storage with per-item metadata manifests
- Local evidence records for scan decisions and remediation outcomes
- First-run enrollment with the control plane
- Policy check-in
- Heartbeat updates
- Remote command polling and completion for isolate, release, targeted scan, and quarantine actions
- Batched telemetry upload
- Real process and recent-file snapshot collection
- Process start/exit and file create/modify/delete delta tracking across sync cycles
- Service snapshot collection for installed services alongside the process inventory
- Configurable sync loop for development and testing
- Cached-policy startup when the control plane is unavailable
- Executable-relative runtime paths so service launches do not write into `System32`
- Trusted runtime-root boundary validation across runtime database, state, telemetry, update staging, quarantine, evidence, and journal paths
- Runtime trust validation that cross-checks registry runtime markers, install/runtime roots, and critical service binaries before install/repair and service startup
- Startup and remote `agent.repair` flows now fail closed when required hardening/runtime trust controls cannot be re-applied
- Phase 1 self-test gates that verify both malware blocking (disk-time and execute-time) and false-positive handling (cleanware allowance, browser/download/install clean-set coverage, signer trust, plus suppression allow-override flow)
- Phase 2 self-test gates that validate ransomware-style destructive write-burst containment while preserving allow-only behavior for benign backup/sync bulk-I/O workloads
- Phase 5 self-test gates and endpoint posture fields for PAM request visibility, PAM approval/denial audit visibility, and local Administrators membership exposure auditing
- Phase 6 self-test gates for unified local posture projection that combines AV findings, patch debt, reboot state, PAM workflow state, and local-admin exposure in one endpoint snapshot
- A local `pam-policy.json` model that constrains PAM by requester/action allowlists, reason requirements, path guards, and timed elevation window caps
- Tray PAM workflows now include built-in `run_windows_update` and `run_network_reset` actions so patch/remediation admin tasks route through the PAM broker instead of direct admin sessions
- `patch.windows.install` remote commands can opt into PAM routing with payload flag `routeThroughPam=true` (plus optional `reason`), which queues `run_windows_update` for policy-governed execution
- Richer PAM audit journaling that records approval source, duration, and completion/termination outcome metadata for each elevation decision
- Local support-bundle export and storage-maintenance command paths for sanitized diagnostics, full offline review bundles, and bounded cleanup of stale support/update artifacts
- A service-owned local control broker on `\\.\pipe\FenrirEndpointLocalApi` so dashboard-driven quarantine mutation and patch-install actions are authorized at the service boundary, not just in the UI
- A shared on-demand scan engine used by `antivirus-scannercli`
- A layered scan engine with file-type sniffing, content signatures, ZIP payload inspection, signer-aware reputation hints, and false-positive suppression for trusted system paths
- Scan exclusion paths so the agent can avoid quarantining its own runtime, evidence, update, and install directories
- An external signature-bundle path so detection content can ship independently of the core agent binary
- A real-time verdict broker that can accept minifilter-style file create/open/write/execute requests
- Real-time block/quarantine decisions flowing through the same evidence and telemetry pipeline as on-demand scans
- Context-aware real-time behavior-chain scoring using process image, parent image, command-line, and lure-path signals
- Cross-event behavior-chain correlation over rolling process-lineage windows to raise confidence on staged attacks
- ETW process and WFP network telemetry now feed that same behavior-correlation history so sequence detections carry runtime context
- Quarantine retry with process-tree containment when active malware handles prevent first-pass file quarantine
- Quarantine post-action verification (removed/locked/pending-delete states) with JSONL remediation journaling for audit
- A native AMSI scan engine shared by the AMSI provider DLL for script and fileless content inspection
- AMSI provider registration helpers exposed through `--register-amsi-provider` and `--unregister-amsi-provider`
- A native ETW process sensor for real-time process start/exit and image-load telemetry with user-mode enrichment
- Automatic fallback to the older polling process snapshot/delta path when a kernel ETW session cannot be started
- A native WFP network isolation manager for selective host isolation, classify-drop telemetry, and connection snapshot enrichment
- Automatic degraded-mode handling when the current host context cannot open the filtering engine
- A signed-update workflow with staged manifests, hash/signature verification, rollback metadata, and reboot-aware file replacement
- Post-install hardening for protected runtime paths, uninstall-token enforcement, recovery actions, and delayed auto-start service posture
- ELAM-aware launch-protected service registration for antimalware-light protected service posture when a signed ELAM driver is supplied
- Coexistence visibility for Windows Security Center, Microsoft Defender, and the local agent service launch-protected state
- Remote response actions for update apply/rollback, agent repair, process termination, persistence cleanup, and full artifact remediation
- A native local endpoint client with a tray icon, protection status view, recent threat history, quarantine management, and local scan actions
- A documented named-pipe-first local dashboard security boundary with role-based local action controls, privileged-session reauthentication, and standard-user request escalation rather than direct privileged execution
- A documented recovery model covering safe-mode repair, driver rollback, database rebuild, runtime-root reset, known-good reset, and emergency disable of bad content or policy
- A documented storage governance model for telemetry, evidence, quarantine, logs, patch history, and PAM audit retention plus disk-pressure behavior
- A documented support-bundle export model with sanitized and full diagnostic modes

The purpose of this folder is to establish the internal contracts we will build around:

- `PolicySnapshot` for effective policy state
- `EventEnvelope` for canonical endpoint telemetry
- `ScanVerdict` for explainable allow, block, and quarantine decisions
- `AgentService` as the orchestration point for cache, telemetry, scan dispatch, and command handling

## Immediate Follow-On Work

1. Build and sign the minifilter with the WDK, then validate it through the self-test and release-layout flow.
2. Validate the updater, ELAM registration, and launch-protected service flows from an elevated installer/service context with production code-signing material.
3. Validate the SQLite runtime store under crash/restart scenarios and add retention policies plus vacuum/maintenance tasks.
4. Validate the ETW process sensor and WFP isolation manager from an elevated service context with real policy-driven isolation actions.
5. Validate the AMSI provider against real PowerShell, WSH, and Office invocation flows after install-time registration is wired in.

## Commands

```powershell
.\fenrir-agent-service.exe --console
.\fenrir-agent-service.exe --install
.\fenrir-agent-service.exe --repair --elam-driver C:\Drivers\antivirus-elam.sys
.\fenrir-agent-service.exe --install --elam-driver C:\Drivers\antivirus-elam.sys
.\fenrir-agent-service.exe --upgrade C:\Temp\update.manifest
.\fenrir-agent-service.exe --rollback-update <transaction-id>
.\fenrir-agent-service.exe --uninstall
.\fenrir-agent-service.exe --uninstall --token <secret>
.\fenrir-agent-service.exe --wsc-status
.\fenrir-agent-service.exe --self-test
.\fenrir-agent-service.exe --register-amsi-provider
.\fenrir-agent-service.exe --unregister-amsi-provider
.\antivirus-endpoint-client.exe
.\antivirus-scannercli.exe --path C:\Users\Public\Downloads
.\antivirus-scannercli.exe --no-remediation C:\Temp\samples
.\antivirus-scannercli.exe --json --realtime-op execute C:\Temp\sample.ps1
.\antivirus-scannercli.exe --json --realtime-op create C:\Temp\sample.exe
.\\antivirus-amsitestcli.exe --notify --app PowerShell --text "Write-Host hello"
.\\antivirus-amsitestcli.exe --stream --app PowerShell --path C:\Temp\sample.ps1
.\\antivirus-etwtestcli.exe --json
.\\antivirus-wfptestcli.exe --json
.\\antivirus-wfptestcli.exe --apply --json
```

Remote command additions:

- `support.bundle.export`
- `support.bundle.export.full`
- `storage.maintenance.run`

Local broker command additions:

- `local.approval.execute`
- `local.breakglass.enable`
- `local.breakglass.disable`

Approval request queue files:

- Pending requests: `%ProgramData%\FenrirAgent\runtime\local-approval-requests.jsonl`
- Approval ledger: `%ProgramData%\FenrirAgent\runtime\local-approval-ledger.jsonl`

## Environment Variables

- `ANTIVIRUS_CONTROL_PLANE_URL`
- `ANTIVIRUS_RUNTIME_DB_PATH`
- `ANTIVIRUS_AGENT_STATE_FILE`
- `ANTIVIRUS_TELEMETRY_QUEUE_FILE`
- `ANTIVIRUS_UPDATE_ROOT`
- `ANTIVIRUS_JOURNAL_ROOT`
- `ANTIVIRUS_ELAM_DRIVER_PATH`
- `ANTIVIRUS_QUARANTINE_ROOT`
- `ANTIVIRUS_EVIDENCE_ROOT`
- `ANTIVIRUS_SIGNATURE_BUNDLE_PATH`
- `ANTIVIRUS_PHASE1_CLEANWARE_CORPUS_PATH`
- `ANTIVIRUS_PHASE1_UK_BUSINESS_CORPUS_PATH`
- `ANTIVIRUS_PHASE1_CORPUS_MAX_FILES`
- `ANTIVIRUS_AGENT_VERSION`
- `ANTIVIRUS_PLATFORM_VERSION`
- `ANTIVIRUS_REQUIRE_SIGNED_RUNTIME`
- `ANTIVIRUS_UNINSTALL_TOKEN`
- `ANTIVIRUS_SYNC_INTERVAL_SECONDS`
- `ANTIVIRUS_SYNC_ITERATIONS`
- `ANTIVIRUS_TELEMETRY_BATCH_SIZE`
- `ANTIVIRUS_REALTIME_PORT_NAME`
- `ANTIVIRUS_REALTIME_BROKER_RETRY_SECONDS`
- `ANTIVIRUS_ISOLATION_ALLOW_LOOPBACK`
- `ANTIVIRUS_ISOLATION_ALLOW_REMOTE`
- `ANTIVIRUS_ISOLATION_ALLOW_APPLICATIONS`
- `ANTIVIRUS_SCAN_EXCLUDE_PATHS`
- `ANTIVIRUS_ALLOW_SYSTEM_RESTORE`
- `ANTIVIRUS_SECURE_DELETE_QUARANTINE`
- `ANTIVIRUS_SECURE_DELETE_PASSES`
- `ANTIVIRUS_SUPPORT_RETENTION_DAYS`
- `ANTIVIRUS_EVIDENCE_RETENTION_DAYS`
- `ANTIVIRUS_UPDATE_RETENTION_DAYS`
- `ANTIVIRUS_QUARANTINE_RETENTION_DAYS`
- `ANTIVIRUS_JOURNAL_RETENTION_DAYS`
- `ANTIVIRUS_STORAGE_QUOTA_SUPPORT_MB`
- `ANTIVIRUS_STORAGE_QUOTA_EVIDENCE_MB`
- `ANTIVIRUS_STORAGE_QUOTA_UPDATE_MB`
- `ANTIVIRUS_STORAGE_QUOTA_QUARANTINE_MB`
- `ANTIVIRUS_STORAGE_QUOTA_JOURNAL_MB`
- `ANTIVIRUS_STORAGE_LOW_DISK_MB`
- `ANTIVIRUS_STORAGE_SECURE_DELETE`
- `ANTIVIRUS_STORAGE_SECURE_DELETE_PASSES`
- `ANTIVIRUS_STORAGE_AGGRESSIVE_LOW_DISK`

The default sync interval is now 60 seconds when the agent is run in multi-iteration mode.

## Local Bootstrap Policy Defaults

- Fresh local installs that are not yet enrolled in a remote control plane bootstrap with all core protections enabled by default.
- realtime protection: enabled
- cloud lookup: enabled
- script inspection (AMSI path): enabled
- network containment: enabled
- quarantine on malicious: enabled
- Local bootstrap policy identity: `policy-default` / `local-bootstrap` with policy name `Local Protection Baseline`.

## PAM Policy Template

- The service reads `pam-policy.json` from the runtime root (the same root directory that contains the runtime database path).
- A baseline template is included at `agent/windows/service/pam-policy.example.json`.
- Copy the template to your runtime root as `pam-policy.json` and then tune requester/action/path controls for your environment.

## Security Boundary And Governance Templates

- [Production-Readiness-Plan.md](/C:/Users/matt_admin/Documents/GitHub/AntiVirus/agent/windows/docs/Production-Readiness-Plan.md) is the canonical design record for the local UI/API security boundary, updater trust chain, recovery lifecycle, storage governance, patch governance, household role model, and release gates.
- `local-dashboard-security.example.json` defines the named-pipe-first local dashboard transport, ACL, role, origin-check, and session timeout defaults.
- `update-trust.example.json` defines pinned trust anchors, anti-downgrade rules, package provenance requirements, and channel recovery defaults.
- `storage-governance.example.json` defines retention, quota, and disk-pressure policy.
- `support-bundle.example.json` defines support export contents and sanitization defaults.
- `release-promotion.example.json` defines release-gate policy and hotfix triggers.

## Packaging

- Use [BuildReleaseLayout.ps1](/C:/Users/matt_admin/Documents/GitHub/AntiVirus/agent/windows/installer/BuildReleaseLayout.ps1) to stage the built binaries, docs, signature bundle, and optional driver artifacts into `agent/windows/out/dev`.
- Use [BuildInstallerBundle.ps1](/C:/Users/matt_admin/Documents/GitHub/AntiVirus/agent/windows/installer/BuildInstallerBundle.ps1) to produce a native `FenrirSetup.exe` installer in `agent/windows/out/install`.
- Use [GenerateUpdateManifest.ps1](/C:/Users/matt_admin/Documents/GitHub/AntiVirus/agent/windows/installer/GenerateUpdateManifest.ps1) to produce an updater manifest consumable by the rollback-aware update service.
- Use `--self-test` against the staged `out/dev` layout before treating a build as promotion-ready.
- Use [RunPhase2ExitCriteria.ps1](/C:/Users/matt_admin/Documents/GitHub/AntiVirus/agent/windows/tools/scannercli/RunPhase2ExitCriteria.ps1)
  when you want a standalone Phase 2 ransomware pass/fail report that ignores unrelated self-test warnings.
