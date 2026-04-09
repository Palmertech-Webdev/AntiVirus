# Roadmap

## Phase 0 - Foundation And Risk Burn-Down

Goal: make the project shippable from a platform and security perspective before deep detection work starts.

Deliverables:

- Monorepo structure and CI/CD
- Code-signing, secrets, and release controls
- Windows build environment with WDK and test-signing flow
- Malware-safe lab, cleanware corpus, and performance benchmark harness
- Backend auth, enrollment API, audit trail, and initial schema
- Frontend shell with login, navigation, and RBAC placeholders

Exit criteria:

- Signed agent packages can be built and distributed in a controlled ring
- Devices can enroll and report health to the backend
- Test harnesses exist for malware simulation, false-positive testing, and performance sampling

## Phase 1 - MVP Protection Plane

Goal: ship a first real endpoint protection path with central visibility.

Deliverables:

- Endpoint service skeleton with policy cache, telemetry spool, updater, and local event bus
- Minifilter-based real-time scan pipeline
- On-demand scanning engine and targeted scan entry point
- Basic local signature/reputation engine with cloud lookup fallback
- Process, file, and script telemetry to backend
- Alert generation and analyst-facing alert detail view
- Quarantine and process-tree termination actions

Exit criteria:

- Malware can be blocked on disk and at execution time
- Alerts explain the main evidence chain
- Admins can deploy policy and perform basic response actions centrally

## Phase 2 - Business Baseline

Goal: close the biggest gaps against independent business-product expectations.

Deliverables:

- AMSI provider
- ETW enrichment pipeline
- WFP-based network telemetry and selective block controls
- Host isolation
- Investigation bundle collection
- Exclusions workflow with approval and audit
- Update channels, staged rollout, and device drift reporting
- API access, SIEM export, RBAC hardening, and 2FA

Exit criteria:

- Product has central management depth suitable for pilot customers
- Offline mode and cloud-recovery behavior are defined and tested
- False-positive review loop and suppression workflow are operational

## Phase 3 - ATP-Grade Detection And Response

Goal: move from basic AV plus telemetry into strong targeted-attack resistance.

Deliverables:

- Behavior-chain analytics across file, process, script, and network events
- Higher-fidelity ATT&CK mapping
- Memory-delivered and staged-attack focused detections
- Automated investigation and guided remediation playbooks
- Better clean-up and artefact removal coverage
- Performance tuning on low-end business hardware

Exit criteria:

- Internal ATT&CK-aligned test set shows strong chain detection, not only single-event alerts
- Response actions can contain a host and preserve evidence with minimal analyst effort

## Phase 4 - Enterprise Scale And Commercial Readiness

Goal: prepare for broad deployment and channel readiness.

Deliverables:

- Multi-tenancy if MSP/MSSP is required
- Delegated administration and tenant isolation
- Self-service deployment links and push deployment options
- Broader reporting and long-term retention options
- Support tooling, diagnostics, and documented operational runbooks

Exit criteria:

- Support, deployment, and admin workflows scale beyond a small pilot
- Channel or enterprise buyers can operate the product without bespoke engineering help

## Post-Core Expansion Roadmap

These phases are the recommended next integrations after the endpoint, backend, and management core are stable. They should not distract from the current protection-plane milestones, but they should guide data-model and API decisions now so later expansion does not require a redesign.

### Entry Gate For Expansion Work

Start these phases only when the current platform can reliably provide:

- Stable endpoint enrollment, policy delivery, telemetry ingest, alerting, and response actions
- Working quarantine, audit trail, RBAC, and retention controls
- Operator-usable dashboard and investigation views for endpoint detections
- Predictable offline behavior, update flow, and false-positive handling

## Expansion Phase A - Email Security Gateway And Mail Investigation

Goal: add email as the first major non-endpoint security source by placing the product in the inbound mail path and turning message flow into searchable, explainable security telemetry.

Detailed plan: `docs/EMAIL_SECURITY.md`

Deliverables:

- `backend/mail-gateway` service for SMTP ingress, queueing, retries, relay, and tenant-aware mail routing
- Domain onboarding flow covering MX cutover planning, DNS validation, connector configuration, and downstream mailbox routing
- Mail-auth processing for SPF, DKIM, DMARC, and ARC preservation where needed
- MIME parsing, attachment extraction, archive handling, URL extraction, and normalized mail-event records
- Baseline email verdicting for malware, risky attachments, sender abuse, phishing indicators, and policy-driven delivery actions
- Mail quarantine, release, purge, and audit workflows integrated into the control plane
- Console pages for domain health, message trace, mail quarantine, and message-detail investigation

Exit criteria:

- Inbound mail can flow through the platform to the downstream mailbox service without unacceptable delivery loss or latency
- Analysts can trace a message end to end, understand why it was allowed or blocked, and take quarantine or release actions
- Mail events, artefacts, and operator actions are stored with the same audit and governance expectations as endpoint actions

## Expansion Phase B - Unified Incident-Led Console

Goal: evolve the console from endpoint-alert views into a cross-asset investigation workspace centered on incidents rather than individual detections.

Deliverables:

- Incident as a first-class top-level object that can group related endpoint and email alerts
- Navigation model centered on Dashboard, Incidents, Devices, Identities, Email, Alerts, Policies, Reports, and Administration
- Incident queue with ownership, status, severity, confidence, affected-asset count, and source mix
- Incident-detail experience with timeline, evidence, entities, notes, and response actions in one place
- Global search across incident IDs, hostnames, usernames, email addresses, hashes, URLs, domains, and IPs
- Shared entity model for devices, users, mailboxes, files, URLs, hashes, and network indicators
- Minimal local endpoint client posture that stays focused on status and quick actions instead of deep investigation

Exit criteria:

- Analysts can start from an incident, understand scope quickly, and take the most common response actions without hopping between unrelated screens
- Related endpoint and email alerts can be correlated into one explainable investigation record
- Search and navigation feel operationally useful for daily SOC or IT-admin workflows

## Expansion Phase C - Identity And SaaS Signal Integration

Goal: add identity as a first-class investigation surface so incidents can span devices, users, mailboxes, and sign-in activity.

Deliverables:

- Connector framework for identity and productivity-service telemetry, starting with Microsoft 365 and Microsoft Entra-style signals where appropriate
- Identity entity pages for risky users, risky sign-ins, MFA state, related devices, related mail activity, and linked incidents
- Correlation rules that tie user risk, sign-in anomalies, mail activity, and endpoint behavior into a single incident timeline
- Response workflows for user disablement, session revocation, password-reset enforcement, and approval-gated identity actions
- Tenant-aware access controls and audit coverage for high-impact identity remediation actions
- Console views that let analysts pivot cleanly between device, identity, and mail evidence

Exit criteria:

- Analysts can investigate a user-centric incident across sign-ins, devices, and related mail activity without leaving the platform
- Identity response actions are controlled, auditable, and safe enough for pilot customers
- The incident model remains understandable even as more signal sources are added

## Expansion Phase D - SOC Operations, Reporting, And Automation Depth

Goal: make the platform feel operationally complete for security teams by improving reporting, workflow maturity, and repeatable response.

Deliverables:

- SOC-focused reporting for incident volume, affected assets, email threats, user risk, response times, and false-positive trends
- Saved searches, investigation bookmarks, case notes, and exportable evidence packages
- Rule-driven response automation and approval workflows for common low-risk actions
- Administration views for connectors, API keys, data retention, branding, licensing, and audit export
- Broader integration points for SIEM, ticketing, and downstream workflow systems where commercially relevant
- Clear separation between protection policy management and administrative platform configuration

Exit criteria:

- Customers can measure platform value through operational reporting instead of raw telemetry volume alone
- Repetitive analyst tasks can be automated or approval-gated without weakening auditability
- Administrative workflows, connector management, and protection workflows are all usable without bespoke support

## Cross-Cutting Workstreams

These must run across every phase:

- False-positive reduction
- Performance testing
- Secure update design
- Driver stability and crash triage
- Telemetry privacy controls
- Documentation and operator training
- Search quality and investigation explainability
- Deliverability, abuse-prevention, and retention governance for future mail handling

## Suggested Team Shape

- 2 to 3 Windows endpoint engineers
- 1 kernel / driver specialist
- 2 backend engineers
- 1 frontend engineer
- 1 detection engineer / malware researcher
- 1 QA / test automation engineer
- Shared DevOps and security review support

## Milestone Advice

Treat these as gating milestones, not just feature buckets:

1. Agent enrolls, updates, and survives reboot safely.
2. Real-time protection blocks malware without destabilizing the system.
3. Console can explain detections and drive response actions.
4. Offline behavior is predictable and safe.
5. False-positive rate is low enough for pilot deployment.
