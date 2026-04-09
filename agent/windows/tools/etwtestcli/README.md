# ETW Test CLI

`antivirus-etwtestcli.exe` is a small local harness for the process ETW sensor.

It starts the ETW sensor, launches a test process, waits for events to arrive, then prints the captured telemetry summary.

Examples:

```powershell
.\antivirus-etwtestcli.exe
.\antivirus-etwtestcli.exe --json
.\antivirus-etwtestcli.exe --seconds 3 --command "cmd.exe /c exit 0"
```

On non-elevated shells, a kernel ETW session may fail with access denied. In that case the tool will show the sensor failure event instead of process telemetry.
