# Scanner CLI

`antivirus-scannercli` is the first local targeted-scan utility for the Windows agent.

Current behavior:

- Loads cached policy and endpoint identity from the local agent state store
- Scans explicit file and directory targets recursively
- Can simulate a minifilter real-time interception with `--realtime-op`
- Computes SHA-256 for suspicious files when possible
- Flags risky executable and script extensions with ATT&CK context
- Supports repeatable scan exclusions with `--exclude`
- Quarantines files that resolve to a quarantine verdict unless `--no-remediation` is used
- Writes local evidence records for each finding
- Queues `scan.completed` and enriched `scan.finding` telemetry into the local spool for later backend upload

Current examples:

```powershell
.\antivirus-scannercli.exe --path C:\Users\Public\Downloads
.\antivirus-scannercli.exe --json C:\Temp\sample.ps1
.\antivirus-scannercli.exe --no-telemetry C:\Temp\suspect-folder
.\antivirus-scannercli.exe --no-remediation C:\Temp\sample-drop
.\antivirus-scannercli.exe --exclude C:\Users\matt_admin\Documents\GitHub\AntiVirus\agent\windows\service\build C:\Temp\suspect-folder
.\antivirus-scannercli.exe --json --realtime-op execute C:\Temp\sample.ps1
.\antivirus-scannercli.exe --json --realtime-op create C:\Temp\dropper.exe
.\antivirus-scannercli.exe --json --realtime-op rename C:\Temp\sample.ps1
.\antivirus-scannercli.exe --json --realtime-op section-map C:\Temp\sample.ps1
```

This is still an early scan and real-time inspection scaffold, not the final detection engine. It does not yet unpack
archives, perform content emulation, restore quarantined files, or consult cloud reputation.

## Phase 1 Exit-Criteria Harness

Use `RunPhase1ExitCriteria.ps1` to evaluate the four Phase 1 AV exit criteria in one run:

- common malware blocked on write/execute
- remediation consistency across repeated runs
- false-positive rate against cleanware and UK business corpora
- scan performance thresholds (average and p95 milliseconds per file)
- minifilter/realtime edge-case matrix remains stable across create/open/write/execute/rename/section-map, ADS,
  reparse/junction/symlink paths, removable media, network shares, cloud-sync folders, large files,
  locked image-section handling, and archive-abuse paths
- minifilter package validation confirms INF/SYS/CAT artifact completeness and Authenticode signing posture

Use `GeneratePhase1HouseholdCorpus.ps1` to produce larger local synthetic corpora for repeatable false-positive and
performance checks.

Example:

```powershell
.\GeneratePhase1HouseholdCorpus.ps1 -WorkspaceRoot ..\..\..\.. -OutputRoot ./tmp-phase1-corpora-large -CleanwareCount 120 -UkBusinessCount 120
.\RunPhase1ExitCriteria.ps1 -WorkspaceRoot ..\..\..\.. -CleanwareCorpusPath ./tmp-phase1-corpora/cleanware -UkBusinessCorpusPath ./tmp-phase1-corpora/uk-business-software
```

Stronger evidence example (minimum corpus size requirements):

```powershell
.\RunPhase1ExitCriteria.ps1 -WorkspaceRoot ..\..\..\.. -CleanwareCorpusPath ./tmp-phase1-corpora-large/cleanware -UkBusinessCorpusPath ./tmp-phase1-corpora-large/uk-business-software -MinCleanwareFiles 100 -MinUkBusinessFiles 100
```

The script writes a JSON report to `tmp-phase1-exitcriteria/phase1-exitcriteria-report.json`.

Use `RunMinifilterEdgeCaseHarness.ps1` directly for focused kernel/minifilter edge-path validation:

```powershell
.\RunMinifilterEdgeCaseHarness.ps1 -WorkspaceRoot ..\..\..\..
```

Use `ValidateMinifilterPackage.ps1` to validate staged minifilter release artifacts and signatures:

```powershell
.\ValidateMinifilterPackage.ps1 -WorkspaceRoot ..\..\..\.. -DriverRoot ./agent/windows/out/dev/driver
```

Use `RunPhase1ElevatedCompletion.ps1` when you need strict elevated service-registration enforcement and a full
Phase 1 rerun in one command:

```powershell
.\RunPhase1ElevatedCompletion.ps1 -WorkspaceRoot ..\..\..\..
```

By default this helper requests elevation (if needed), attempts INF installation via `pnputil` and SetupAPI,
verifies `AntivirusMinifilter` service registration, runs `ValidateMinifilterPackage.ps1` with strict service
requirements, and then runs `RunPhase1ExitCriteria.ps1` with the standard corpus thresholds.

Use `-SkipFullPhase1Gate` to only perform elevated service registration and strict package validation.

## Phase 2 Exit-Criteria Harness

Use `RunPhase2ExitCriteria.ps1` to evaluate the Phase 2 ransomware-specific exit criteria from the service self-test
without treating unrelated packaging or protected-service posture warnings as a Phase 2 failure.

Current required checks:

- ransomware behavior-chain containment for destructive write bursts
- encrypted-extension burst detection
- staged script-to-impact lineage correlation
- false-positive resistance for benign backup/sync bulk-I/O
- false-positive resistance for benign photo/video export churn
- false-positive resistance for developer build churn

Example:

```powershell
.\RunPhase2ExitCriteria.ps1 -WorkspaceRoot ..\..\..\..
```

The script writes a JSON report to `tmp-phase2-exitcriteria/phase2-exitcriteria-report.json`.

Use `GeneratePhase2RansomwareCorpus.ps1` to produce a repeatable synthetic Phase 2 corpus with both malicious and
benign destructive-churn scenarios:

```powershell
.\GeneratePhase2RansomwareCorpus.ps1 -WorkspaceRoot ..\..\..\.. -OutputRoot ./tmp-phase2-corpora
```

That corpus is designed for Phase 2 behavior validation and tuning rather than file-signature detection.

## Phase 3 Exit-Criteria Harness

Use `RunPhase3ExitCriteria.ps1` to evaluate Phase 3 runtime trust, updater trust, and anti-tamper posture from
the service self-test.

Current required checks:

- runtime trust markers enforce fail-closed startup posture
- updater manifest trust validation and rollback simulation remain safe
- uninstall token gating and protected-service launch posture stay hardened

Example:

```powershell
.\RunPhase3ExitCriteria.ps1 -WorkspaceRoot ..\..\..\..
```

The script writes a JSON report to `tmp-phase3-exitcriteria/phase3-exitcriteria-report.json`.

## Phase 4 Exit-Criteria Harness

Use `RunPhase4ExitCriteria.ps1` to evaluate Phase 4 recovery and disaster-handling criteria from the service self-test.

Current required checks:

- runtime database corruption detection and clean recovery path
- rollback mode validation for signed update state transitions
- bad-content disablement and operator safety interlocks
- driver recovery posture across rollback and re-enable flows

Example:

```powershell
.\RunPhase4ExitCriteria.ps1 -WorkspaceRoot ..\..\..\..
```

The script writes a JSON report to `tmp-phase4-exitcriteria/phase4-exitcriteria-report.json`.

## Phase 5 Exit-Criteria Harness

Use `RunPhase5ExitCriteria.ps1` to evaluate Phase 5 destination and network-protection criteria from the service self-test.

Current required checks:

- destination reputation subsystem resolves IP/domain/URL indicators
- destination telemetry preserves process-lineage and remote-endpoint correlation
- network action bands remain separated (audit, warn, block)
- host isolation is guarded for high-confidence malicious outcomes

Example:

```powershell
.\RunPhase5ExitCriteria.ps1 -WorkspaceRoot ..\..\..\..
```

The script writes a JSON report to `tmp-phase5-exitcriteria/phase5-exitcriteria-report.json`.

## Phase 6 Exit-Criteria Harness

Use `RunPhase6ExitCriteria.ps1` to evaluate Phase 6 local-control, PAM, and household governance criteria from the service self-test.

Current required checks:

- named-pipe-first local control boundary remains enforced
- role separation and request-only approval routing for privileged actions
- break-glass and local recovery controls remain safe and reversible
- PAM queue and PAM audit visibility checks are present for local governance
- household role governance and admin baseline persistence checks are preserved

Example:

```powershell
.\RunPhase6ExitCriteria.ps1 -WorkspaceRoot ..\..\..\..
```

The script writes a JSON report to `tmp-phase6-exitcriteria/phase6-exitcriteria-report.json`.

## Phase 7 Exit-Criteria Harness

Use `RunPhase7ExitCriteria.ps1` to evaluate Phase 7 performance, compatibility, and stable-promotion gates from the service self-test.

Current required checks:

- resource budget snapshots for service memory and CPU posture
- Windows 10/11 compatibility baseline validation
- stable release-promotion gate linkage
- Defender companion-mode coexistence posture

Example:

```powershell
.\RunPhase7ExitCriteria.ps1 -WorkspaceRoot ..\..\..\..
```

The script writes a JSON report to `tmp-phase7-exitcriteria/phase7-exitcriteria-report.json`.
