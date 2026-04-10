# Admin Authentication And Audit Controls

## Goal

Lock the admin surface before pilot by making every privileged console and API action authenticated, authorized, and audited.

## Current State

- Device-authenticated endpoint APIs already exist for agent enrollment, telemetry, and command execution.
- Admin-facing control-plane routes still need a proper production auth boundary.
- RBAC, MFA, API-key controls, and session management are defined as core requirements, not optional hardening.

## P0 Control Set

- Admin identity and login
- MFA for all privileged users
- Role-based access control for admin, analyst, operator, and read-only views
- Scoped API keys or service tokens for automation
- Session lifetime, idle timeout, and revocation controls
- Audit events for login, policy changes, response actions, connector changes, key issuance, and role changes

## Implementation Order

1. Define the admin principal and session model.
2. Add auth middleware for console and control-plane admin routes.
3. Enforce roles on policy, response, connector, and settings routes.
4. Emit audit events for every privileged change and every failed authorization attempt.
5. Surface audit history and session state in the console.

## Acceptance Criteria

- No privileged admin route is reachable without authentication.
- MFA is required for privileged users.
- Every policy, connector, and response change has an audit record.
- API keys can be issued, scoped, rotated, and revoked.
- Device authentication stays separate from admin authentication.

## Notes

- Keep the endpoint/device auth path intact so agent enrollment and telemetry continue to work during the admin auth rollout.
- Do not start expansion work until the admin and audit path is stable.