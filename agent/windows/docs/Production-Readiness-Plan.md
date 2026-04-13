# Fenrir Windows Production Readiness Plan

This document closes the remaining production-readiness gaps for the free household edition of Fenrir. It turns the current engineering phases into an explicit operating model covering local security boundaries, updater trust, recovery, governance, patch orchestration, PAM safety, storage, supportability, and release promotion.

The default posture in this document is:

- secure-by-default
- fail safe for privileged actions
- explainable local state
- reversible recovery for user-visible mistakes
- staged rollout for high-risk controls
- companion-friendly coexistence with built-in Windows protections unless Fenrir is explicitly promoted to primary AV posture

## 1. Local Dashboard And Local API Security Model

Fenrir treats the local dashboard and its control channel as part of the product security boundary.

### Binding and transport decisions

- The default local control plane is a Windows named pipe, not localhost HTTP.
- Pipe name: `\\.\pipe\Fenrir.Endpoint.LocalApi`.
- The endpoint UI connects through the named pipe from the interactive user session.
- Loopback HTTP or WebSocket is disabled by default.
- If a future WebView2-hosted renderer requires an internal loopback bridge, that bridge must bind only to `127.0.0.1` and `::1`, use a per-session ephemeral port, and require a signed session token minted by the service over the named pipe first.

### IPC ACL model

- The service creates the named pipe with an ACL that grants:
- `SYSTEM`: full control
- `BUILTIN\Administrators`: full control
- `INTERACTIVE`: read-only handshake and status query access
- Standard users never receive direct write access for privileged actions.

### Local authentication and authorization

- Local identity is mapped from the caller’s Windows access token.
- Fenrir distinguishes:
- `device_owner_admin`
- `local_admin`
- `standard_user`
- `child_or_managed_user`
- Standard users can view local status, personal scan history, and device posture summary.
- Standard users cannot directly action quarantine restore, patch install, service repair, PAM policy change, or exclusion creation.
- Standard users can request privileged actions, but the request must be approved through PAM or a local administrator confirmation path.

### CSRF, origin, and session protections

- If loopback web transport is ever enabled, Fenrir enforces:
- allowlist of `app://local-fenrir`, `https://appassets.example/fenrir`, or equivalent packaged origins only
- strict `Origin` and `Host` validation
- same-site session cookies are not used as the sole protection boundary
- anti-CSRF nonce per privileged request
- session binding to Windows logon session ID
- WebSocket upgrades only after token-bound named-pipe bootstrap

### Session timeout and re-authentication

- Read-only local status sessions expire after 30 minutes of inactivity.
- Privileged action sessions expire after 5 minutes of inactivity.
- Re-authentication is required for:
- quarantine restore
- exclusion change
- patch install-now
- service repair
- update rollback
- PAM policy changes
- uninstall

### Privileged action model

- Threat acknowledgement, quarantine delete, and viewing device-wide security history require admin.
- Viewing personal detections may be allowed to the originating standard user when file ownership and privacy checks permit it.
- Patching and remediation requests from a standard user become queued approval requests, not direct execution.

## 2. Updater Trust And Supply-Chain Security

Fenrir uses a chained trust model for self-update and signed content update.

### Trust anchors

- Binary and platform updates are signed with a dedicated product release-signing certificate.
- Signature and rule updates are signed with a separate content-signing certificate.
- Trust anchors are embedded in the installed product and pinned in the runtime trust store.
- Update manifests are signed and validated before payload download or staging is accepted.

### Key ownership model

- Release-signing keys are owned by the product release authority and stored in hardware-backed signing infrastructure.
- Content-signing keys are owned by the threat-content authority and isolated from platform release keys.
- Driver-signing keys and operational flow are tracked separately because Windows kernel signing has different operational requirements.

### Rotation and revocation

- Fenrir supports overlapping trust anchors so a new key can be trusted before the old one is retired.
- Every manifest includes a signing key ID and chain metadata.
- Emergency revocation is distributed as a signed revocation bundle that the service checks before accepting new updates.
- Revoked keys can sign neither platform nor content updates after the revocation bundle is applied.

### Anti-downgrade and provenance

- Platform updates enforce monotonic version progression unless the package is an explicit signed rollback package referencing a recorded transaction.
- Signature/rule updates enforce monotonic generation numbers.
- Manifest acceptance requires:
- trusted signer
- non-revoked key
- package hash match
- expected package type
- allowed channel
- not below minimum allowed version or generation

### Channel corruption recovery

- If the update channel is poisoned, unreachable, or returns untrusted content, Fenrir:
- rejects the payload
- records the failure locally
- falls back to the last trusted cached manifest and content where safe
- does not install unsigned or weakly explained content
- exposes `update channel unhealthy` in local posture

### Update class distinction

- `rules/signatures`: fast cadence, content signer, no service binary replacement, lower rollback blast radius
- `engine/platform`: service/UI/provider binaries, release signer, staged apply, rollback metadata required
- `driver/hardening payload`: strongest validation and explicit reboot-safe application path

## 3. Full Recovery And Disaster Model

Fenrir must always provide a path back to a bootable and supportable system.

### Recovery classes

- safe-mode recovery path
- broken-driver recovery path
- broken-service recovery path
- broken-database recovery path
- corrupted runtime-root recovery path
- PAM lockout recovery path
- bad protection-content recovery path

### Recovery decisions

- Fenrir ships a recovery command path in the service and installer.
- The installer includes a repair mode and a known-good reset mode.
- Known-good reset preserves identity and core install state while disabling custom policy, exclusions, and optional modules until recovery succeeds.
- A bad rules/signature update can be locally disabled without removing the platform binaries.
- A bad platform update can be rolled back using recorded transaction metadata.

### Driver and service failure handling

- If the minifilter or other optional kernel component fails to load, the service enters degraded mode and records `kernel coverage degraded`.
- The endpoint remains operable in user-mode protection rather than crash-looping.
- Driver disable and rollback commands are available through repair mode.
- Service startup failure triggers repair guidance and a protected fallback policy path.

### Database and runtime-root recovery

- SQLite runtime DB is backed up before destructive migrations.
- Corruption triggers:
- backup copy preservation
- database quarantine into a recovery folder
- rebuild from last trusted policy/state where possible
- explicit incident record for support
- Runtime-root trust failure triggers fail-closed for sensitive actions and offers repair or known-good reset.

### Offline recovery tooling

- The installer package includes repair and uninstall tooling runnable from elevated command prompt.
- Offline instructions must document:
- stopping the service
- disabling the driver if necessary
- invoking rollback
- invoking known-good reset
- exporting support bundle before purge

## 4. Uninstall, Downgrade, Migration, And Repair Lifecycle

Fenrir defines the full product lifecycle, not just install and update.

### Install and upgrade

- Existing builds migrate forward through explicit schema and state migrations.
- Upgrade preserves quarantine, evidence, history, patch history, and PAM audit by default.

### Repair install

- Repair revalidates runtime trust markers, service registration, provider registration, ACLs, scheduled tasks, and local UI linkage.
- Repair does not purge quarantine or incident history unless `reset-content-state` is explicitly requested.

### Uninstall model

- Uninstall requires administrator approval and, if uninstall protection is enabled, the uninstall token or a local break-glass path.
- Uninstall offers:
- preserve evidence and history
- preserve quarantine manifests but purge payloads
- full purge

### Downgrade handling

- Normal downgrade is blocked.
- Signed rollback to a known-good prior transaction is allowed when the recorded rollback package matches the installed transaction lineage.

### Data preservation options

- Quarantine: preserve metadata by default; payloads optional
- Evidence: preserve by default
- History and patch history: preserve by default
- PAM audit data: preserve by default
- Full purge requires explicit operator confirmation

## 5. Storage Governance And Data Lifecycle

Fenrir must remain stable on long-lived household machines.

### Retention defaults

- telemetry spool: 7 days or 256 MB
- evidence metadata: 30 days or 512 MB
- quarantine payloads: 30 days or 2 GB
- patch history: 180 days or 128 MB
- PAM audit: 180 days or 128 MB
- crash and repair logs: 30 days or 128 MB

### Disk pressure behavior

- At 10 percent free disk or 5 GB remaining, Fenrir enters storage-constrained mode.
- In storage-constrained mode:
- low-priority logs rotate aggressively
- telemetry spool is compacted
- expired quarantine payloads purge first
- evidence keeps metadata and deletes large duplicate blobs first

### Secure deletion rules

- Purged quarantine payloads are deleted with best-effort secure wipe where practical for local disk files.
- On SSDs and modern filesystems, Fenrir records deletion intent and removes filesystem references while warning that hardware-level overwrite is not guaranteed.

### Rotation and export

- Logs and evidence files use bounded rolling files.
- Incident and patch history can be exported as signed JSON bundles.
- Support bundles can be generated without raw quarantined payloads unless explicitly requested.

## 6. Windows Integration Specifics

### Windows Security Center and Defender coexistence

- Fenrir free edition defaults to companion mode initially.
- In companion mode, Defender remains enabled and Fenrir registers as a secondary local protection product only where the platform permits and the team has verified correct behavior.
- Primary AV replacement mode is deferred until sustained validation is complete.

### Service protection target

- Target: launch-protected antimalware-light service posture where signing prerequisites are met.
- If protected posture cannot be established, Fenrir records degraded hardening state and continues in standard protected-service-compatible mode.

### ELAM decision

- ELAM remains in scope but deferred for broad household rollout until signing, driver stability, and recovery tooling are proven.
- The product should explicitly expose ELAM status as:
- `not_installed`
- `installed_not_active`
- `active`
- `deferred`

### WDAC, ASR, and SmartScreen

- Fenrir assumes coexistence with SmartScreen and ASR.
- Fenrir does not disable ASR or WDAC.
- If WDAC blocks part of Fenrir’s runtime, the support bundle should capture that posture for diagnosis.

## 7. Kernel Coverage And File-System Edge-Case Matrix

Fenrir’s minifilter and real-time inspection model must explicitly cover awkward file-system behavior.

### Required edge cases

- rename and move, including extension swaps
- alternate data streams
- reparse points, junctions, and symlinks
- removable drives
- network shares
- cloud-sync folders
- sparse files
- large files
- locked image sections
- paging I/O decisions
- archive bomb and decompression abuse

### Product decisions

- Reparse traversal is bounded and loop-aware.
- ADS writes are scanned and journaled separately from default stream writes.
- Remote shares are treated as inspectable but may downgrade to audit-only when the filesystem semantics are unsafe for blocking.
- Cloud-sync folders receive false-positive dampening but not blanket exclusions.
- Large-file inspection uses size ceilings, partial hashing, and time budgets.
- Archive recursion has depth, child-count, and expanded-size ceilings.

## 8. Explicit DNS / Web / Network Protection Plan

Network protection is a first-class subsystem, not just enrichment.

### Subsystem model

- WFP telemetry and containment manager
- DNS and destination reputation resolver
- browser/download correlation path
- host isolation policy engine

### Action modes

- `audit`
- `warn`
- `block`

### Trigger rules

- destination block when high-confidence malicious verdict exists
- warn when suspicious but low-confidence
- isolate host only on high-confidence active compromise or ransomware containment policy

### Metadata boundaries

- Fenrir may use destination IP, domain, URL, SNI, and process lineage metadata.
- Fenrir does not perform HTTPS interception in the free household edition.
- Reputation cache obeys TTL per source and supports privacy-minimized lookup order.

## 9. External Intelligence / Reputation Model

Fenrir formalizes local intelligence enrichment.

### Provider abstraction

- Providers can supply verdicts on:
- file hash
- signer
- URL
- domain
- IP
- certificate metadata

### Local cache schema

- indicator type
- value
- source provider
- verdict
- confidence
- first seen
- last refreshed
- expiry
- privacy class

### Lookup order

- local signed threat pack
- local cache
- privacy-preserving external provider order
- offline fallback to local heuristics when network is unavailable

### Weighting rules

- signed local packs can hard-block where confidence is high
- external providers contribute weighted confidence, not absolute truth, unless an explicit high-trust provider policy is configured

## 10. Patch Risk Intelligence And Prioritization

Patching is not just mechanics; it is risk communication.

### Required scoring

- KEV or known-exploited prioritization when intelligence exists
- unsupported software severity
- end-of-life detection
- browser urgency
- remote-access tool urgency
- VPN client urgency

### User-facing priority bands

- `patch now`
- `patch soon`
- `monitor`
- `manual only`
- `unsupported / replace`

### Local dashboard scoring

- Device patch posture score weights:
- Windows security debt
- browser lag
- remote access tool lag
- unsupported or EOL software
- pending reboot after successful security update

## 11. Broader Windows Patch Scope Details

Fenrir’s Windows patch coverage includes:

- cumulative updates
- security updates
- critical updates
- .NET updates
- Defender intelligence and platform updates
- servicing stack updates
- out-of-band updates
- failed updates
- pending reboot state

### Policy defaults

- security and quality updates: auto-install
- feature updates: deferred by policy
- driver updates: opt-in or policy-based, not default-on
- optional updates: opt-in
- Microsoft Update broader product scope: optional but recommended for Office-capable systems
- Store/AppX/UWP updates: report-only initially, later orchestrated if safe provider path is implemented
- firmware and BIOS: report and route to vendor tooling, not silent-default install

## 12. Third-Party Patch Trust Model

Fenrir uses ordered providers plus governance rules.

### Provider order

- trusted native silent updater
- winget
- Fenrir-maintained recipe
- manual required

### Governance rules

- vendor allowlist by publisher and signer
- installer hash verification when recipe-managed
- signer validation for every provider type where possible
- silent switches must be explicitly catalogued and tested
- if publisher, signer, or channel changes unexpectedly, Fenrir pauses automation and marks the app for review
- interactive installers are skipped in silent-only mode
- reboot behavior is catalogued per package family

### Failed patch fallback

- failed upgrade records exact error and rollback recommendation
- if vendor provides clean uninstall or repair fallback, Fenrir can surface it but not silently chain destructive rollback without policy approval

## 13. PAM Recovery, Governance, And Safety Rails

PAM must be recoverable and staged.

### Break-glass model

- one-time local recovery code or uninstall token path
- service-side break-glass mode that temporarily relaxes broker enforcement after local administrator verification
- explicit expiry on break-glass mode

### Recovery cases

- UI cannot launch
- service running but token brokering fails
- PAM policy file corrupt
- repeated denial storm or request flood

### Household approvals

- one device owner or local admin can approve elevation
- standard users cannot approve elevation for other users
- child accounts can request, but approval must come from owner/admin

### Adoption path

- audit only
- broker preferred
- broker enforced
- admin reduction
- admin removal

## 14. Performance Budgets And Compatibility Matrix

Performance budgets must be explicit.

### Initial targets

- idle RAM for service: target under 250 MB
- average background CPU: under 2 percent on modern systems
- scan burst CPU: bounded and visible
- copy/download latency impact: avoid more than low double-digit percentage overhead on common household workloads
- boot impact: no noticeable persistent boot regression beyond service initialization window

### Compatibility coverage

- Windows 10 supported baseline
- Windows 11 supported baseline
- low-end hardware set
- laptop sleep/resume
- metered networks
- battery saver
- fullscreen/gaming mode

## 15. Parser And Hostile-Input Safety

Fenrir must treat scanned content and installer metadata as hostile.

### Requirements

- parser fuzzing for archive, shortcut, script, OLE, and metadata parsers
- size limits
- timeouts
- recursion ceilings
- safe failure to allow-or-audit with recorded parser error, never crash

### Patch metadata safety

- installer metadata parsing uses strict schemas
- command output parsers have bounded line and token limits
- malformed metadata cannot cause arbitrary command execution

## 16. Quarantine Restore Governance

### Restore rules

- restore requires admin approval
- re-scan on restore is mandatory
- restore destination defaults to original path if safe, otherwise user-selected recovery path
- known-bad items always present override warnings
- restore is fully audited with actor, time, reason, and destination

### Purge

- malicious payload purge follows retention and secure-deletion policy
- metadata survives longer than payload where support value remains high

## 17. Incident And Support Export Model

Fenrir needs a formal support/export path.

### Bundle contents

- local posture summary
- service and driver status
- recent incident timeline
- patch history
- PAM audit summary
- redacted logs
- configuration snapshot
- optional raw evidence references

### Privacy modes

- sanitized share mode by default
- full forensic mode only with explicit user choice

### Import

- offline diagnostic bundle import is supported for local review tooling

## 18. Policy And Exception Governance

### Rules

- only admins can create durable exclusions
- temporary exclusions have expiry
- exclusions can be path, hash, signer, or process scoped
- dangerous exclusions require warning and second confirmation
- all changes are audited
- suppressions are distinct from exclusions
- restore-default policy is always available

## 19. Household Multi-User Model

Fenrir is device-wide but role-aware.

### Roles

- device owner/admin
- other local admin
- standard user
- child/managed user

### Visibility

- device owner/admin: full device-wide view
- standard user: personal requests and limited threat visibility
- child user: request-only for privileged operations

### Approval rules

- one user cannot approve another user’s request unless they are an administrator
- device-wide patching remains admin-owned
- per-user history is separated where privacy matters

## 20. Release Promotion Criteria Between Phases

Phase exit criteria are necessary but not sufficient for promotion.

### Internal to beta

- core phase gates pass
- crash rate below budget
- no critical upgrade/uninstall regressions
- no unresolved high-confidence local privilege escalation issues
- no unresolved rollback failure affecting supported hosts

### Beta to stable

- sustained pass rate on phase gates
- false-positive budget within target
- rollback path verified
- support bundle and recovery tooling validated
- no critical patch orchestration trust defects

### Hotfix triggers

- false-positive outbreak
- broken update or rollback
- service startup regression
- PAM lockout defect
- quarantine restore corruption

## Default Release Decisions For The Free Edition

- local dashboard transport: named pipe first
- localhost web transport: disabled by default
- Defender coexistence: companion mode first
- ELAM: in scope, deferred for broad rollout
- driver updates: opt-in
- feature updates: deferred
- third-party patching: high-risk apps prioritized
- PAM rollout: staged, not enforced by default on first install
- support export: available locally with sanitized mode default

## Required Artifacts To Keep Current

- local dashboard security policy template
- updater trust policy template
- storage governance policy template
- support bundle manifest template
- release promotion gates template

The companion example files live alongside the service so they can be staged with the Windows runtime and installer payloads.
