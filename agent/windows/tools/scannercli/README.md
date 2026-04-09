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
