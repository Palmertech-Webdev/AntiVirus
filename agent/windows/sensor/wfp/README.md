# WFP Network Sensor

This module hosts the Windows Filtering Platform integration for the Windows agent.

Current responsibilities:

- Open a dynamic WFP engine session from user mode
- Register an endpoint-owned provider and sublayer
- Apply or release selective host-isolation filters
- Preserve loopback, configured applications, and configured or control-plane-derived remote allowlists
- Subscribe to classify-drop net events for blocked-traffic telemetry
- Collect process-aware TCP connection snapshots for analyst context
- Surface degraded-mode telemetry when the host context cannot manage WFP

Current limitations:

- Live isolation still depends on an elevated service context with firewall-management privileges
- Connection snapshots are TCP-focused and do not yet include UDP flow coverage
- `device.isolate` is now WFP-backed in the agent, but richer response flows like per-rule containment and selective service exemptions still need policy depth

Test command:

```powershell
.\\antivirus-wfptestcli.exe --json
.\\antivirus-wfptestcli.exe --apply --json
```
