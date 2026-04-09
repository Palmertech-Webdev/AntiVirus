# AMSI Test CLI

`antivirus-amsitestcli` exercises the in-repo AMSI provider without requiring COM registration.

It can:

- Feed text directly into the provider `Notify` path for fileless-style inspection
- Feed file content through a fake `IAmsiStream` for stream-based AMSI inspection
- Print the resulting `AMSI_RESULT` and any detection context

Examples:

```powershell
.\antivirus-amsitestcli.exe --notify --app PowerShell --text "Write-Host test"
.\antivirus-amsitestcli.exe --stream --app wscript.exe --path C:\Temp\sample.js
```
