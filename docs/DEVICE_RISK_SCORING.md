# Device Risk Scoring MVP

Fenrir now includes a deterministic device security scoring MVP that turns endpoint telemetry and derived security posture into an explainable per-device score.

## What It Does

- Calculates a per-device `overallScore` from `0` to `100`, where higher is worse.
- Calculates a separate `confidenceScore` from `0` to `100` based on telemetry completeness.
- Produces weighted category scores for:
  - `patch_posture`
  - `software_hygiene`
  - `threat_activity`
  - `exposure`
  - `network_behaviour`
  - `control_health`
  - `identity_posture`
- Applies explicit critical overrides for ransomware, unprotected active malware, exposed unpatched admin surfaces, C2 beaconing, and data exfiltration.
- Returns explainability data:
  - top risk drivers
  - override reasons
  - recommended actions
  - missing telemetry fields
  - optional ATT&CK tactics and techniques

## Data Model Notes

The scoring MVP extends the existing control-plane state instead of creating a parallel subsystem.

- `deviceRiskTelemetry[]`
  - canonical telemetry snapshot per device for scoring inputs
- `deviceScoreHistory[]`
  - historical score snapshots with explainability data
- `DeviceSummary`
  - now carries `riskScore`, `riskBand`, and `confidenceScore`
- `DeviceDetail`
  - now carries `latestScore`, `scoreHistory`, and `riskTelemetry`

The control plane also derives scoring inputs from existing Fenrir data when direct scoring telemetry is incomplete:

- alerts
- evidence
- scan history
- endpoint posture
- installed software
- recent telemetry

## API Surface

The existing device API was extended with risk-scoring endpoints:

- `GET /api/v1/devices`
- `GET /api/v1/devices/:deviceId`
- `POST /api/v1/devices/:deviceId/risk-telemetry`
  - device-authenticated
- `POST /api/v1/devices/:deviceId/score/recalculate`
- `GET /api/v1/devices/:deviceId/score`
- `GET /api/v1/devices/:deviceId/score-history`
- `GET /api/v1/devices/:deviceId/findings`
- `GET /api/v1/devices/:deviceId/risk-summary`

The `risk-summary` response is the current AI-facing explanation surface. It returns the stored score plus a concise analyst summary and a fuller explanation grounded in the actual scoring output.

## Seed and Demo Data

Seeded demo state now includes eight varied device profiles:

- low risk workstation
- guarded / lightly drifting device
- elevated posture issues
- high threat activity example
- ransomware override example
- C2 / exfiltration override example
- exposed admin surface override example
- low-confidence incomplete telemetry example

Demo data is loaded by the control plane when demo seeding is enabled, which is the default behavior for the current local test harness.

## Local Run

From the repo root:

```bash
npm install
npm run dev:backend
npm run dev:frontend
```

The backend serves the control plane on port `4000` and the frontend serves the console on port `3000`.

## Verification

Backend:

```bash
cd backend/control-plane
npm run check
npm run build
npm run test
```

Frontend:

```bash
cd frontend/console
npm run check
npm run build
```

Workspace:

```bash
cd ..
npm run check
npm run build
npm run test
```

## Manual Verification Checklist

1. Open the Devices page and confirm devices are sorted by highest risk.
2. Confirm the device table shows score, band, and confidence.
3. Open a device detail page and confirm:
   - score summary renders
   - weighted category breakdown renders
   - top risk drivers render
   - override reasons render when present
   - recommended actions render
   - missing telemetry fields render when confidence is reduced
4. Call `GET /api/v1/devices/:deviceId/risk-summary` and confirm the summary matches the score payload.
5. Post a device-authenticated `risk-telemetry` payload and confirm the score updates.
