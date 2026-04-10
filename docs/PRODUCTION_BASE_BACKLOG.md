# Production Base Backlog

## Scope Freeze

- Windows-first endpoint protection
- Central management
- DNS, network, and behaviour visibility
- Basic UK-focused free tier
- Email and identity are parked until the endpoint core is stable

## Acceptance Bars

- No system instability
- No broken Windows boots
- Low resource overhead
- Predictable offline mode
- Extremely low false positives

## Production Readiness Board

- Protection
- Stability
- Performance
- False positives
- Manageability
- Update safety
- Auditability
- Supportability

## P0 Blockers

- [blocker][P0] Production database and schema ownership
- [blocker][P0] Object storage for evidence and investigation packages
- [blocker][P0] Queue and job system for ingest, actions, and retries
- [blocker][P0] Secrets vault and secure secrets handling
- [blocker][P0] Signed update service
- [blocker][P0] Telemetry ingestion service separation from admin and query paths
- [blocker][P0] Remove file-backed state from real deployments
- [blocker][P0] Admin authentication
- [blocker][P0] MFA
- [blocker][P0] RBAC
- [blocker][P0] API key controls
- [blocker][P0] Session controls
- [blocker][P0] Audit logging for admin and response actions
- [blocker][P0] Code-signing process
- [blocker][P0] Driver-signing process
- [blocker][P0] Release manifest format
- [blocker][P0] Staged rollout rings
- [blocker][P0] Emergency rollback path
- [blocker][P0] Productionized endpoint service baseline: service, policy cache, updater, local event bus

## P1 Protection Uplifts

- [protection uplift][P1] Minifilter real-time scanning
- [protection uplift][P1] On-demand scan path
- [protection uplift][P1] Quarantine actions
- [protection uplift][P1] Process-tree termination
- [protection uplift][P1] AMSI inspection
- [protection uplift][P1] ETW process and image enrichment
- [protection uplift][P1] WFP telemetry
- [protection uplift][P1] Host isolation
- [protection uplift][P1] Selective block controls
- [protection uplift][P1] Device inventory workflow
- [protection uplift][P1] Alert detail workflow
- [protection uplift][P1] Policy deployment workflow
- [protection uplift][P1] Response audit history
- [protection uplift][P1] Remove UI-only admin placeholders so save/test, persistence, audit events, and health state are real backend objects

## P1 False-Positive Pipeline

- [protection uplift][P1] Cleanware corpus
- [protection uplift][P1] Common UK business software corpus
- [protection uplift][P1] Browser, download, and install test set
- [protection uplift][P1] Signed software trust tests
- [protection uplift][P1] Suppression workflow
- [protection uplift][P1] Exception approval with audit

## P2 Pilot Readiness And Quality

- [later nice-to-have][P2] File copy performance tests
- [later nice-to-have][P2] Archive extraction performance tests
- [later nice-to-have][P2] Browser download performance tests
- [later nice-to-have][P2] Office document performance tests
- [later nice-to-have][P2] Installer performance tests
- [later nice-to-have][P2] Low-end hardware performance tests
- [later nice-to-have][P2] Signed payload validation in the updater
- [later nice-to-have][P2] Failed update rollback
- [later nice-to-have][P2] Version drift reporting
- [later nice-to-have][P2] Reboot survival
- [later nice-to-have][P2] Interrupted update recovery
- [later nice-to-have][P2] Durable ingestion
- [later nice-to-have][P2] Retry logic
- [later nice-to-have][P2] Queue monitoring
- [later nice-to-have][P2] Evidence retention controls
- [later nice-to-have][P2] Backup and restore
- [later nice-to-have][P2] Operator audit search
- [later nice-to-have][P2] Health dashboards
- [later nice-to-have][P2] Failure alerting
- [later nice-to-have][P2] Broken agent recovery
- [later nice-to-have][P2] Failed update rollback runbook
- [later nice-to-have][P2] False-positive emergency suppression runbook
- [later nice-to-have][P2] Quarantine restore failure handling
- [later nice-to-have][P2] Driver crash triage
- [later nice-to-have][P2] Offline device recovery
- [later nice-to-have][P2] Privacy controls
- [later nice-to-have][P2] Retention policy
- [later nice-to-have][P2] Evidence handling rules
- [later nice-to-have][P2] Malware-safe storage handling
- [later nice-to-have][P2] Legal and policy review for telemetry and uploads
- [later nice-to-have][P2] Layered reputation
- [later nice-to-have][P2] Better script detections
- [later nice-to-have][P2] Persistence detections
- [later nice-to-have][P2] Loader and staged payload detections
- [later nice-to-have][P2] Malicious DNS and destination detection
- [later nice-to-have][P2] Behaviour-chain scoring
- [later nice-to-have][P2] Explainable detections with process tree, command line, file hash, signer, ATT&CK, related DNS and network events, and remediation actions
- [later nice-to-have][P2] UK-only pilot package with limited devices, single ring, daily review, manual rollback, and documented unsupported scenarios
- [later nice-to-have][P2] Internal validation pack for malware, cleanware, script abuse, LOLBins, staged payloads, ransomware behaviour, network abuse, and ATT&CK-aligned scenarios

## Parked Expansion Tickets

- Email gateway
- Identity connectors
- Incident-led console

## Execution Notes

- Do not start the parked expansion tickets until endpoint enrollment, telemetry ingest, alerting, quarantine, audit, and false-positive handling are stable.
- Treat the P0 items as blockers, the P1 items as protection uplifts, and the P2 items as pilot support and later nice-to-haves.