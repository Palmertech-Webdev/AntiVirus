Phase 2 — Business baseline
Objective
Close the largest gaps between a promising endpoint product and a credible business-grade protection platform.
What must be built
AMSI integration
PowerShell inspection
WSH/VBA-compatible inspection where visible to AMSI
Script-content and stream-aware telemetry
ETW enrichment pipeline
Process start/stop
Image load
Key system event enrichment
Better process lineage and execution context
WFP-based networking
Network telemetry
Selective block controls
Host isolation
Connection-state awareness
Destination/domain/IP evidence
Host isolation
Central isolate and release
Safe local enforcement
Audit trail
Clear operator feedback
Investigation and evidence
Investigation bundle collection
Evidence packaging
Short-lived secure download flow
Retention controls
Exclusions and governance
Exclusions workflow
Approval model
Audit history
Expiry and review
Update and deployment maturity
Update channels
Staged rollout rings
Drift reporting
Version health
Rollback safety
Access and enterprise control
RBAC hardening
MFA
API access
SIEM export
Audit export
Backend requirements
Telemetry ingest must handle higher volumes cleanly
Detection and enrichment workers must begin separating from control-plane concerns, which matches your architecture guidance of modular monolith plus dedicated data services.
Storage split should now be real:
PostgreSQL for transactional records
ClickHouse for high-volume telemetry
Object storage for artefacts
Redis for hot state and short-lived coordination. This follows your documented storage strategy.
Frontend requirements
Better triage flow
Process tree and event timeline views
Better action history
Health drift and update state views
Administration and audit surfaces that are properly enforceable and explainable
Exit criteria
Product has central management depth suitable for pilots
Offline and cloud-recovery behaviour are defined and tested
False-positive suppression workflow is operational
Operators can isolate a host, inspect evidence, and justify action decisions quickly.