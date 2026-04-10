# AMSI Provider

`provider/amsi` contains the Windows AMSI provider implementation for script and fileless inspection.

What it does today:

- Implements `IAntimalwareProvider2` in a native in-proc DLL
- Handles both `Scan(IAmsiStream*)` and `Notify(...)`
- Loads local agent policy and identity from the same runtime store as the endpoint service
- Applies heuristic script and fileless detection for PowerShell, script host, macro-style launch, encoded payload, download cradle, and defense-evasion patterns
- Records local evidence and queues telemetry into the existing agent spool
- Quarantines backing files when AMSI content maps to a real on-disk file and policy allows quarantine

Build outputs:

- `fenrir-amsi-provider.dll`
- `fenrir-amsitestcli.exe`

Useful commands:

```powershell
.\fenrir-agent-service.exe --register-amsi-provider
.\fenrir-agent-service.exe --unregister-amsi-provider
.\fenrir-amsitestcli.exe --notify --app PowerShell --text "Write-Host hello"
.\fenrir-amsitestcli.exe --stream --app PowerShell --path C:\Temp\sample.ps1
```

The provider is buildable in this repo now. Production rollout still needs installer wiring, registration during install, and validation against real PowerShell/Wscript/Office AMSI invocation paths.
