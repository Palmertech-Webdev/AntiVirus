# Windows Agent Plan

## Scope

The Windows agent is responsible for local prevention, telemetry collection, enforcement, offline resilience, and response execution.

## Proposed Subsystems

- `driver/minifilter` - file I/O inspection and enforcement
- `driver/elam` - early-boot posture
- `provider/amsi` - script and memory/stream inspection
- `sensor/etw` - process and system event enrichment
- `sensor/wfp` - network telemetry and containment
- `service/core` - policy, scanning, verdicting, caching, and command handling
- `service/quarantine` - artefact storage and restore workflow
- `service/updater` - signed engine and platform updates
- `tools/endpointui` - local endpoint GUI and tray experience for end users and local support
- `tools/scannercli` - local targeted scan and diagnostics
- `installer` - install, upgrade, repair, and uninstall controls

## Engineering Priorities

1. Build the endpoint service, updater, policy cache, and telemetry spool first.
2. Add the minifilter scanning path before advanced analytics.
3. Add AMSI and ETW once the basic block-and-report loop is stable.
4. Add WFP isolation and deeper response workflows after central action dispatch is reliable.
5. Add ELAM and protected-service hardening after the core agent is operational.

## Recommended Implementation Notes

- Use native C/C++ with the WDK for drivers.
- Keep the user-mode core native as well to reduce integration risk with protected-service posture.
- Use a local SQLite or embedded store only for short-lived cache and queue state, not long-term analytics.
- Make every decision path produce a compact local evidence record for later backend upload.

## Canonical Output Layout

- `agent/windows/out/dev` is the canonical staged payload tree for local testing, release verification, and update-manifest generation.
- `agent/windows/out/install` is the canonical packaged-installer location for `FenrirSetup.exe`.
- `agent/windows/out/dev/build` is only the CMake intermediate workspace. Promotion-ready binaries should be consumed from `out/dev`, not directly from the build tree.

## First Build Targets

- Agent service starts at boot and loads policy from local cache
- Device enrollment and mTLS identity work
- Telemetry spool survives reboots and reconnects
- On-demand scan works before real-time enforcement is enabled

## Current Implementation Checkpoint

- `service/core` now has an SCM-compatible Windows Service host, cached policy loading, queued telemetry, command polling, and a shared on-demand scan engine.
- `tools/scannercli` now exists and can scan explicit files or directories, compute hashes, quarantine high-risk files, write evidence records, and queue enriched scan findings for later backend upload.
- `tools/endpointui` now exists as the local endpoint client with system tray presence, local status, threat history, quarantine management, and quick/full/folder scan actions backed by the same runtime database as the service.
- The backend and agent now support a first response loop for isolate/release, targeted scan, and quarantine restore/delete actions.
- `service/core` now includes a real-time verdict broker that can accept minifilter-style file create/open/write/execute requests, apply policy, quarantine where needed, and emit evidence plus telemetry.
- `driver/minifilter` now exists in-tree as a WDK-oriented source skeleton that uses the same protocol and communication-port design as the service broker.
- `provider/amsi` now exists as a native AMSI provider DLL with `Scan` and `Notify` support, local policy loading, heuristic script/fileless detections, evidence capture, telemetry spooling, and backing-file quarantine when applicable.
- `tools/amsitestcli` now exists to exercise the provider through stream and notify paths without requiring full system registration.
- `sensor/etw` now exists as a native ETW-backed process sensor for process start, process exit, and image-load telemetry with user-mode enrichment and automatic fallback to polling when kernel-session startup is unavailable.
- `tools/etwtestcli` now exists to smoke-test the ETW process sensor and validate event capture on elevated hosts.
- Local runtime data is still file-backed today; the next storage step is swapping that cache and spool to SQLite once we vendor or standardize a compatible library for the toolchain.
