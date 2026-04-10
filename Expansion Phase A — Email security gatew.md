Expansion Phase A — Email security gateway and mail investigation
Objective
Add email as the first major non-endpoint signal source by sitting in the inbound mail path and turning email flow into searchable, explainable security telemetry.
What must be built
Mail gateway service
SMTP ingress
Queueing
Retry handling
Safe relay
Tenant-aware mail routing
Domain onboarding
MX cutover planning
DNS validation
Downstream route configuration
Connector health
Message analysis
SPF, DKIM, DMARC, ARC result capture
MIME parsing
Attachment extraction
Archive handling
URL extraction and normalisation
Verdicting
Attachment risk
Sender abuse
Phishing indicators
Policy-driven delivery actions
Quarantine, hold, reject, junk, allow
Investigation workflows
Message trace
Mail quarantine
Message detail
Release and purge actions
Full audit coverage
Exit criteria
Mail can flow through Fenrir without unacceptable delivery risk
Analysts can trace and explain email decisions
Mail actions follow the same governance and audit standards as endpoint actions.