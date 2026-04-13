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
```

This is still an early scan and real-time inspection scaffold, not the final detection engine. It does not yet unpack
archives, perform content emulation, restore quarantined files, or consult cloud reputation.

## Phase 1 Exit-Criteria Harness

Use `RunPhase1ExitCriteria.ps1` to evaluate the four Phase 1 AV exit criteria in one run:

- common malware blocked on write/execute
- remediation consistency across repeated runs
- false-positive rate against cleanware and UK business corpora
- scan performance thresholds (average and p95 milliseconds per file)

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
