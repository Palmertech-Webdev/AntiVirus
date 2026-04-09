# ETW Process Sensor

This module is the event-driven process telemetry path for the Windows agent.

It starts a real-time ETW session against `Microsoft-Windows-Kernel-Process`, consumes process start, process exit, and image-load events, enriches them in user mode, and feeds the existing agent telemetry queue.

Current behavior:

- `process.started` events include PID, parent PID, image name/path, command line when ETW exposes it, session, user SID, integrity level, and best-effort signer
- `process.exited` events reuse cached process context and add exit code
- `image.loaded` events include module path, process linkage, image base/size, and best-effort signer
- The service automatically falls back to the older polling snapshot/delta path if ETW session startup fails, such as when the host process lacks sufficient privilege to start a kernel trace session

The smoke-test utility for this module is `antivirus-etwtestcli.exe`.
