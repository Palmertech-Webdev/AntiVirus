# Product Requirements Document

## 1. Product Summary

Build a Windows-first enterprise antivirus product with central management, strong offline-aware protection, low false positives, low performance overhead, analyst-usable telemetry, and practical response actions.

The product should combine traditional antivirus controls with selected EDR-like telemetry and response so it can satisfy both business malware tests and targeted attack scenarios.

## 2. Product Goals

- Deliver strong protection against commodity malware and common intrusion techniques.
- Keep false positives extremely low, especially on common business software.
- Maintain low user-visible performance impact across daily workloads.
- Provide context-rich detections with process, file, script, and network evidence.
- Give administrators usable central policy, deployment, update, and response workflows.
- Degrade gracefully when cloud connectivity is reduced or unavailable.

## 3. Non-Goals For v1

- macOS, Linux, Android, or iOS support
- Full XDR or SIEM replacement
- Email security, secure web gateway, or DLP suite features
- Full application allowlisting across every workload type
- MSP multi-tenancy in the initial MVP

## 4. Target Users

- Security administrator managing policy, rollout, and updates
- SOC analyst triaging detections and triggering response actions
- IT administrator handling deployment, exceptions, and health
- Security operations lead reviewing coverage and test readiness

## 5. Product Modules

### 5.1 Windows Agent

Must provide:

- Real-time file protection for create, open, modify, and execute flows
- On-demand scan for files, folders, and common system areas
- Behavioral and post-execution detections
- AMSI-based script and memory/stream inspection
- File, process, script, and network telemetry collection
- Quarantine, delete/clean, process termination, and containment actions
- Offline cache for policy, signatures, reputation, and queued telemetry
- Tamper resistance, protected settings, and uninstall protection

### 5.2 Backend

Must provide:

- Device registration and identity
- Policy and exclusion management
- Telemetry ingestion and normalization
- Detection enrichment and ATT&CK mapping
- Alerting, response action dispatch, and audit trails
- Signature/reputation/update distribution
- Sample and investigation package storage
- Health, version, and update-state reporting

### 5.3 Frontend

Must provide:

- Device inventory and health view
- Detection queue and case detail view
- Process-tree and event timeline views
- Policy and exclusion management
- Quarantine and response workflows
- RBAC-aware admin settings, audit history, and update status

## 6. Functional Requirements By Release

### P0 - Foundation

- Secure build and release pipeline
- Code signing pipeline for agent binaries and updates
- Malware-safe test lab and sample handling procedures
- Backend authentication, device identity, and audit logging
- Repo scaffolding and core service interfaces

### P1 - MVP

- Minifilter-based real-time file scanning path
- On-demand scan support
- Endpoint service with local event bus and policy cache
- Cloud reputation lookups with offline fallback cache
- Basic behavioral rules focused on common loaders and script abuse
- Telemetry ingest for process, file, script, and basic network events
- Quarantine, process kill, and central action history
- Frontend device list, alert queue, alert detail, and policy editor

### P2 - Business Baseline

- AMSI provider integration
- ETW-backed enrichment for process and system context
- WFP-based network telemetry and selective block capability
- Host isolation action
- Investigation package collection
- Update channels, staged rollout, and health drift reporting
- RBAC, 2FA, API access, SIEM export, and exclusion governance
- False-positive suppression workflows and reputation overrides

### P3 - ATP / Enterprise Hardening

- Behavior-chain correlation instead of single-event scoring only
- ATT&CK tactic mapping for all high-severity detections and technique mapping where possible
- Automated investigation and rule-driven remediation approval
- Better memory-delivered, staged, and obfuscated attack coverage
- Performance tuning to protect low-end business devices
- Multi-tenant control plane if MSP/MSSP support is a target

## 7. User Stories

- As an admin, I can deploy the agent and verify protection, version, and update status centrally.
- As an analyst, I can see why something was blocked, including process tree, user, command line, script, and network context.
- As an admin, I can quarantine a file, kill a process chain, isolate a host, and collect evidence from one console.
- As an admin, I can approve or deny exclusions with a full audit trail.
- As an analyst, I can search events and alerts by device, hash, signer, command line, and ATT&CK mapping.

## 8. Acceptance Criteria

### Protection

- Detect and block common malware families in real-time and on-demand paths.
- Block common script-based execution chains, staged payloads, and living-off-the-land abuse patterns.
- Preserve meaningful protection when disconnected from the cloud.

### Performance

- No major user-visible lag on file operations, installs, launches, browsing, and downloads.
- Default policy stays below the internal performance budget defined in the roadmap.

### False Positives

- Zero false alarms on the internal common-business-software corpus.
- Very low false positives on broader cleanware and websites.

### Telemetry

- Every high-severity detection includes process lineage, command line, user context, timestamps, and linked file or script context.
- All response actions produce auditable records.

### Manageability

- Central policy, RBAC, 2FA, update status, exclusions, and action history are available from the console.
- API and SIEM export are available by the business-baseline release.

## 9. Success Metrics

- Endpoint online rate
- Signature/platform update freshness
- Mean time to detect
- Mean time to contain
- False positive rate by policy ring
- Scan throughput and CPU/memory budget
- Detection coverage across ATT&CK-aligned test scenarios

## 10. Key Dependencies

- EV code-signing and driver-signing pipeline
- Microsoft filter altitude request and driver release process
- ELAM and protected-service requirements
- Test lab with controlled malware handling
- Legal and privacy review for telemetry retention, uploads, and sample storage
