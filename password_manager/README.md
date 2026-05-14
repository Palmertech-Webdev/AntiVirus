# Fenrir Password Manager Scaffold

This workspace is the secure-by-design scaffold for a zero-knowledge personal password manager with one account usable across multiple trusted devices.

## Design goals

- zero-knowledge vault encryption
- one user account across multiple devices
- per-device trust and approval
- local-first decryption only
- no plaintext vault data on the server
- secure recovery without vendor-side decryption
- future support for passwords, passkeys, TOTP, notes, cards, identities, and documents

## Secure-by-design rules

- no `unsafe` code in the core crates
- no plaintext secrets written to logs
- no master password or root key leaves the client
- no server-side decryption capability
- use modern memory-hard key derivation and AEAD encryption
- model devices as individually trusted and revocable
- keep cryptography, vault types, and sync protocol separate

## Workspace layout

- `docs/ARCHITECTURE.md` - high-level system and trust boundaries
- `docs/THREAT_MODEL.md` - attacker model and production security requirements
- `crates/pm_core` - cryptography, vault types, and secure primitives
- `crates/pm_protocol` - encrypted sync and device-enrolment protocol types
- `crates/pm_client` - client orchestration scaffolding for account creation, unlock, sync, and enrolment

## Current scope

This scaffold intentionally focuses on the security-critical core first.
It does not yet include a desktop UI, browser extension UI, mobile shell, or production backend implementation.

Those surfaces should consume the shared Rust core rather than reimplement security logic themselves.
