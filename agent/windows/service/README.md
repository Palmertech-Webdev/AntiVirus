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
- Configurable sync loop for development and testing
- Cached-policy startup when the control plane is unavailable
- Executable-relative runtime paths so service launches do not write into `System32`
- A shared on-demand scan engine used by `antivirus-scannercli`
- A layered scan engine with file-type sniffing, content signatures, ZIP payload inspection, signer-aware reputation hints, and false-positive suppression for trusted system paths
- An external signature-bundle path so detection content can ship independently of the core agent binary
- A real-time verdict broker that can accept minifilter-style file create/open/write/execute requests
- Real-time block/quarantine decisions flowing through the same evidence and telemetry pipeline as on-demand scans
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
.\antivirus-agent-service.exe --console
.\antivirus-agent-service.exe --install
.\\antivirus-agent-service.exe --repair --elam-driver C:\Drivers\antivirus-elam.sys
.\\antivirus-agent-service.exe --install --elam-driver C:\Drivers\antivirus-elam.sys
.\\antivirus-agent-service.exe --upgrade C:\Temp\update.manifest
.\\antivirus-agent-service.exe --rollback-update <transaction-id>
.\antivirus-agent-service.exe --uninstall
.\\antivirus-agent-service.exe --uninstall --token <secret>
.\\antivirus-agent-service.exe --wsc-status
.\\antivirus-agent-service.exe --self-test
.\\antivirus-agent-service.exe --register-amsi-provider
.\\antivirus-agent-service.exe --unregister-amsi-provider
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

## Environment Variables

- `ANTIVIRUS_CONTROL_PLANE_URL`
- `ANTIVIRUS_RUNTIME_DB_PATH`
- `ANTIVIRUS_AGENT_STATE_FILE`
- `ANTIVIRUS_TELEMETRY_QUEUE_FILE`
- `ANTIVIRUS_UPDATE_ROOT`
- `ANTIVIRUS_ELAM_DRIVER_PATH`
- `ANTIVIRUS_QUARANTINE_ROOT`
- `ANTIVIRUS_EVIDENCE_ROOT`
- `ANTIVIRUS_SIGNATURE_BUNDLE_PATH`
- `ANTIVIRUS_AGENT_VERSION`
- `ANTIVIRUS_PLATFORM_VERSION`
- `ANTIVIRUS_UNINSTALL_TOKEN`
- `ANTIVIRUS_SYNC_INTERVAL_SECONDS`
- `ANTIVIRUS_SYNC_ITERATIONS`
- `ANTIVIRUS_TELEMETRY_BATCH_SIZE`
- `ANTIVIRUS_REALTIME_PORT_NAME`
- `ANTIVIRUS_REALTIME_BROKER_RETRY_SECONDS`
- `ANTIVIRUS_ISOLATION_ALLOW_LOOPBACK`
- `ANTIVIRUS_ISOLATION_ALLOW_REMOTE`
- `ANTIVIRUS_ISOLATION_ALLOW_APPLICATIONS`

The default sync interval is now 60 seconds when the agent is run in multi-iteration mode.

## Packaging

- Use [BuildInstallerBundle.ps1](/C:/Users/matt_admin/Documents/GitHub/AntiVirus/agent/windows/installer/BuildInstallerBundle.ps1) to produce a native `AntiVirusSetup.exe` installer that embeds the service, endpoint client, AMSI provider, scanner CLI, and signature bundle.
- Use [BuildReleaseLayout.ps1](/C:/Users/matt_admin/Documents/GitHub/AntiVirus/agent/windows/installer/BuildReleaseLayout.ps1) to stage the built binaries, docs, signature bundle, and optional driver artifacts into a release tree.
- Use [GenerateUpdateManifest.ps1](/C:/Users/matt_admin/Documents/GitHub/AntiVirus/agent/windows/installer/GenerateUpdateManifest.ps1) to produce an updater manifest consumable by the rollback-aware update service.
- Use `--self-test` against the staged layout before treating a build as promotion-ready.
