# AntiVirus

Windows-first enterprise antivirus platform planning repo.

This repository starts with the product plan and system shape for a business-grade endpoint security product built around three surfaces:

- A Windows endpoint agent focused on prevention, telemetry, and response
- A backend for device management, event ingestion, storage, detections, and actions
- A management console for analysts and administrators

The design target is to become capable of meeting strong independent-test expectations, including AV-TEST business scoring, AV-Comparatives business approval, and ATP-style targeted attack resistance. Those are product goals, not day-one guarantees.

## Repo Layout

- `agent/windows` - Windows endpoint architecture and implementation plan
- `backend` - Cloud/on-prem management plane and data services plan
- `frontend` - Web console plan
- `backend/control-plane` - Runnable Fastify-based Phase 0 API scaffold
- `frontend/console` - Runnable Next.js management-console scaffold
- `agent/windows/service` - Native endpoint service skeleton and contracts
- `agent/windows/provider/amsi` - Native AMSI provider DLL and registration logic
- `agent/windows/sensor/etw` - Native ETW-backed process and image telemetry sensor
- `agent/windows/sensor/wfp` - Native WFP-backed network isolation and connection telemetry sensor
- `agent/windows/signatures` - External scan-engine signature content for packaged detection updates
- `agent/windows/installer` - Windows release-layout and update-manifest packaging scripts
- `docs/PRD.md` - Product requirements and MVP boundaries
- `docs/ARCHITECTURE.md` - System architecture and component responsibilities
- `docs/DATA_MODEL.md` - Recommended data model and event schema
- `docs/ROADMAP.md` - Phased delivery plan
- `docs/EMAIL_SECURITY.md` - Phase A email-security gateway and investigation plan
- `docs/DEVICE_RISK_SCORING.md` - Deterministic device risk scoring MVP, API surface, and verification steps

## Current Scaffold

```bash
npm install
npm test
npm run dev:backend
npm run dev:frontend
```

The current implementation focus is Phase 0 plus the first real-time protection slice:

- A file-backed control-plane API for health, enrollment, devices, alerts, heartbeat, policy check-in, and telemetry ingest
- A deterministic device risk scoring model with explainable category scores, override reasons, recommended actions, confidence scoring, seeded risk profiles, and device summary/detail API support
- A management-console shell wired to the backend dashboard endpoint with periodic refresh, recent telemetry, response actions, and quarantine inventory
- Device risk views in the console that surface per-device score, band, confidence, category breakdown, risk drivers, and telemetry completeness inside the existing device list and detail workflow
- A native Windows agent surface with an SCM-compatible service, a local endpoint client and tray app, canonical event/policy/verdict contracts, enrollment, heartbeat, command polling, a SQLite-backed runtime store, targeted scanning, quarantine/evidence handling, a content-aware scan engine, a real-time verdict broker, and change-detection sensors
- A WDK-oriented Windows minifilter source skeleton that shares a protocol with the user-mode real-time broker
- A native Windows AMSI provider DLL plus test CLI for script and fileless inspection, telemetry spooling, and evidence capture
- A native ETW process sensor plus test CLI for event-driven process start/exit and image-load telemetry with graceful polling fallback when kernel ETW privileges are unavailable
- A native WFP isolation manager plus test CLI for host isolation, connection snapshots, and blocked-traffic telemetry with graceful degraded mode when firewall-management privileges are unavailable
- A hardened Windows installer/service path with delayed auto-start, recovery actions, protected runtime paths, uninstall-token enforcement, ELAM-backed launch-protected antimalware service registration, staged update apply/rollback, and deeper remediation actions for process kill, persistence cleanup, and artifact cleanup
- A native self-test and release-packaging path that stages production-like builds, emits update manifests, and validates endpoint readiness across runtime storage, AMSI, ETW, WFP, hardening, signing, and minifilter packaging
- A Phase 2 anti-ransomware design note and synthetic corpus generator for behavior-chain validation without honeypots: [docs/RANSOMWARE_PHASE2.md](/C:/Users/matt_admin/Documents/GitHub/AntiVirus/docs/RANSOMWARE_PHASE2.md) and [GeneratePhase2RansomwareCorpus.ps1](/C:/Users/matt_admin/Documents/GitHub/AntiVirus/agent/windows/tools/scannercli/GeneratePhase2RansomwareCorpus.ps1)

## Recommended Build Order

1. Stand up the Windows agent service skeleton, local event pipeline, and signed update path.
2. Build backend device registration, policy delivery, telemetry ingest, and action dispatch.
3. Build the frontend device inventory, detections queue, and policy management views.
4. Add kernel and OS integrations in phases: minifilter, AMSI, ETW, WFP, ELAM, and full production WSC/provider registration.
5. Add containment, investigation, false-positive controls, update distribution, and enterprise management depth.

## Immediate Next Steps

1. Finalize the initial stack choices and hosting model.
2. Break Phase 0 and Phase 1 into executable tickets.
3. Scaffold the endpoint, backend, and frontend projects.
4. Set up CI/CD, code signing, secrets handling, and a malware-safe test lab before shipping any detection logic.
