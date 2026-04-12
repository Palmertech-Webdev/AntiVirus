# Backend Plan

## Scope

The backend is the management and data plane for enrollment, policy, telemetry ingest, detections, response actions, updates, and audit.

## Recommended Initial Modules

- `control-plane` - Fastify-based auth, devices, policies, exclusions, actions, admin scaffold
- `api/ingest` - endpoint telemetry ingestion
- `workers/detection` - rule evaluation, enrichment, ATT&CK mapping
- `workers/commands` - action dispatch and delivery tracking
- `workers/update` - package metadata, channel rollout, reputation data
- `storage/postgres` - transactional data
- `storage/clickhouse` - telemetry analytics
- `storage/object` - bundles and artefacts

## API Priorities

1. `POST /enroll`
2. `POST /telemetry/batch`
3. `GET /policy/current`
4. `POST /actions`
5. `GET /devices`
6. `GET /alerts`

## Design Notes

- Start as a modular monolith to keep auth, policy, alerts, and actions cohesive.
- Split ingest workers from admin APIs early if telemetry volume grows faster than expected.
- Keep detection explanations first-class so the frontend can show why a verdict happened.
- Build every admin mutation with an audit trail from day one.

## First Build Targets

- Device enrollment and certificate-backed identity
- Policy CRUD and policy assignment
- Device heartbeat and health state
- Telemetry batch ingest with schema validation
- Alert creation and response-action recording

## Current Status

The repository now includes a runnable `control-plane` scaffold for:

- `GET /health`
- `GET /api/v1/dashboard`
- `GET /api/v1/devices`
- `GET /api/v1/alerts`
- `GET /api/v1/telemetry`
- `GET /api/v1/policies/default`
- `POST /api/v1/enroll`
- `POST /api/v1/devices/:deviceId/heartbeat`
- `POST /api/v1/devices/:deviceId/policy-check-in`
- `POST /api/v1/devices/:deviceId/telemetry`

State is persisted to a JSON file in `backend/control-plane/data/state.json` by default. Set `CONTROL_PLANE_STATE_FILE` to override that path for local experiments or tests.

## Phase 0 Security Baseline (Control Plane)

- The control plane now defaults to `HOST=127.0.0.1` (loopback-only) unless you explicitly set `HOST`.
- If you bind to a non-loopback host, startup is blocked when bootstrap admin secrets are still default.
- Device and admin query-string tokens are disabled by default:
  - `adminSessionToken` in URL is rejected unless `FENRIR_ALLOW_ADMIN_TOKEN_QUERY_PARAM=true`
  - `deviceApiKey` in URL is rejected unless `FENRIR_ALLOW_DEVICE_API_KEY_QUERY_PARAM=true`
- Device endpoints now require an API key by default (`FENRIR_ALLOW_UNAUTHENTICATED_DEVICE_TRAFFIC=true` can be used for temporary legacy compatibility).
- CORS now defaults to local origins only (`localhost`/`127.0.0.1` on ports `3000` and `4000`).
  - Override list via `FENRIR_ALLOWED_CORS_ORIGINS` (comma-separated origins)
  - Open all origins only with `FENRIR_ALLOW_ALL_CORS_ORIGINS=true`
