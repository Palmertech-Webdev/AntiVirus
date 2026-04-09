# Frontend Plan

## Scope

The frontend is the analyst and administrator console for the product.

## Primary Areas

- Dashboard
- Devices
- Device detail
- Alerts
- Alert detail / investigation
- Policies
- Exclusions
- Quarantine
- Updates and health
- Admin / audit

## UX Priorities

- Show device health and protection drift immediately.
- Let analysts move from alert to process tree to action in one flow.
- Make policy rollout and exclusions understandable, not hidden behind opaque switches.
- Surface clear reason codes, ATT&CK mapping, and action results.

## First Build Targets

- Authenticated app shell
- Device inventory table
- Alert queue with severity and status
- Alert detail page with evidence timeline
- Policy editor with version history

## Suggested Stack

- Next.js
- React
- TypeScript
- Backend-driven auth and RBAC

## Current Status

The repository now includes a wired Next.js operations console with:

- Fleet overview at `/` backed by the control-plane dashboard endpoint
- Per-device drill-down pages at `/devices/[deviceId]` backed by the device-detail endpoint
- Fleet health, posture coverage, alert queue, command queue, quarantine, evidence, scan history, telemetry, and policy panels
- Live backend fetch with fallback mock data for offline UI work and frontend iteration
- Automatic one-minute refresh on both overview and device pages
- Shared typed API client and frontend contracts aligned with the backend control-plane model
- A frontend shape that is ready to grow into investigations, action workflows, reporting, auth, and integration pages without rewriting the base data plumbing
