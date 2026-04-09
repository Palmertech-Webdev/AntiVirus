# Data Model

## 1. Storage Strategy

Use different stores for different workloads:

- PostgreSQL for configuration, identities, alerts, actions, and audit
- ClickHouse for raw and normalized telemetry at volume
- Object storage for samples, bundles, and quarantined evidence

## 2. Core Transactional Entities

### Tenant

- `tenant_id`
- `name`
- `status`
- `created_at`
- `subscription_tier`

### User

- `user_id`
- `tenant_id`
- `email`
- `display_name`
- `auth_provider`
- `mfa_enabled`
- `status`

### RoleAssignment

- `role_assignment_id`
- `tenant_id`
- `user_id`
- `role_name`
- `scope_type`
- `scope_id`

### Device

- `device_id`
- `tenant_id`
- `hostname`
- `domain`
- `os_version`
- `agent_version`
- `platform_version`
- `last_seen_at`
- `health_state`
- `is_isolated`
- `policy_id`

### Policy

- `policy_id`
- `tenant_id`
- `name`
- `ring`
- `realtime_protection_enabled`
- `cloud_protection_level`
- `script_scanning_enabled`
- `network_protection_enabled`
- `tamper_protection_enabled`
- `response_defaults`
- `created_by`
- `updated_at`

### Exclusion

- `exclusion_id`
- `tenant_id`
- `policy_id`
- `type`
- `value`
- `reason`
- `approval_state`
- `expires_at`

### Alert

- `alert_id`
- `tenant_id`
- `device_id`
- `severity`
- `category`
- `verdict`
- `title`
- `summary`
- `first_seen_at`
- `last_seen_at`
- `status`
- `tactic_ids`
- `technique_ids`
- `primary_process_guid`

### ResponseAction

- `action_id`
- `tenant_id`
- `device_id`
- `alert_id`
- `action_type`
- `requested_by`
- `requested_at`
- `status`
- `completed_at`
- `result_summary`

### QuarantineItem

- `quarantine_item_id`
- `tenant_id`
- `device_id`
- `sha256`
- `original_path`
- `disposition`
- `quarantined_at`
- `restorable`
- `alert_id`

### InvestigationBundle

- `bundle_id`
- `tenant_id`
- `device_id`
- `requested_by`
- `requested_at`
- `status`
- `object_key`
- `expires_at`

### AuditRecord

- `audit_record_id`
- `tenant_id`
- `actor_type`
- `actor_id`
- `action`
- `target_type`
- `target_id`
- `occurred_at`
- `metadata_json`

## 3. Telemetry Model

Store high-volume telemetry in ClickHouse using a canonical envelope plus event-specific fields.

### Canonical Event Envelope

- `tenant_id`
- `device_id`
- `event_id`
- `event_type`
- `occurred_at`
- `ingested_at`
- `process_guid`
- `parent_process_guid`
- `user_sid`
- `session_id`
- `integrity_level`
- `policy_id`
- `action_taken`
- `verdict`
- `raw_json`

### Process Event Fields

- `image_path`
- `command_line`
- `sha256`
- `signer`
- `parent_image_path`
- `token_elevation`
- `start_time`
- `exit_time`

### File Event Fields

- `path`
- `operation`
- `sha256`
- `size`
- `origin_process_guid`
- `zone_identifier`
- `reputation`
- `quarantine_state`

### Script Event Fields

- `script_host`
- `content_hash`
- `content_excerpt`
- `decoded_content_available`
- `session_correlation_id`
- `source_application`

### Network Event Fields

- `destination_ip`
- `destination_domain`
- `url`
- `port`
- `protocol`
- `direction`
- `allow_block_reason`
- `c2_score`

## 4. Detection Model

### DetectionRule

- `rule_id`
- `name`
- `rule_type`
- `severity`
- `enabled`
- `tactic_ids`
- `technique_ids`
- `logic_version`

### DetectionObservation

- `observation_id`
- `alert_id`
- `event_id`
- `evidence_type`
- `score`
- `explanation`

This lets an alert explain not only that something was suspicious, but which concrete events and behaviors contributed to the verdict.

## 5. Retention Guidance

- Hot telemetry: 30 days searchable at full fidelity
- Warm telemetry: 90 to 180 days depending customer tier
- Alerts and audit logs: at least 1 year
- Investigation bundles and uploaded samples: shorter default retention with explicit governance

## 6. API Design Implications

The data model supports these major API groups:

- Enrollment and device identity
- Policy and exclusions
- Telemetry ingest
- Alerts and investigations
- Quarantine and response actions
- Update and health reporting
- Admin, RBAC, and audit export
