# Architecture

## Objective

Build a zero-knowledge personal password manager for one user across multiple trusted devices.

The backend must never be able to decrypt the vault.
All encryption and decryption of vault contents happen on the client.

## Core security model

### Secrets

- **Master Password**: user-chosen secret
- **Account Secret**: random high-entropy secret generated on signup
- **Root Key**: derived on-device from master password, account secret, and salt using Argon2id
- **Vault Key**: random symmetric key that wraps item keys
- **Item Keys**: random symmetric key per vault item
- **Device Keys**: per-device key material for device trust and enrolment

### Encryption hierarchy

1. user creates account on a trusted client
2. client generates account secret and vault key
3. client derives root key using Argon2id
4. vault key is wrapped by the root key
5. each item is encrypted with a dedicated item key
6. each item key is wrapped by the vault key
7. only encrypted objects are uploaded to the server

## Trust boundaries

### Trusted

- local client process after successful unlock
- platform secure storage APIs
- audited cryptographic libraries

### Untrusted or partially trusted

- sync server
- object store
- metadata database
- admin and support tooling
- notification systems
- network transport after TLS termination

## Multi-device model

Each device is individually enrolled and trusted.
New devices should be approved by an already trusted device where possible.

### Device lifecycle

- pending
- trusted
- revoked

### Device properties

- device ID
- device name
- platform
- signing public key
- key-exchange public key
- first seen
- last seen
- revocation state

## Backend services

This scaffold assumes these services will exist later:

- identity service
- encrypted object sync service
- device registry service
- attachment store
- security event service
- breach monitoring service

## Data storage split

Keep these domains separate:

- account metadata
- encrypted vault objects
- encrypted attachments
- device registry
- security events

## Client responsibilities

The client core is responsible for:

- account bootstrap
- root-key derivation
- vault encryption and decryption
- per-item encryption
- local secure caching
- sync conflict handling
- device approval flows
- recovery material generation

## Recovery posture

Recovery must not introduce vendor-side decryption.
Allowed recovery paths should be based on:

- trusted existing device
- user-held recovery kit
- recovery code

## Non-goals for the initial scaffold

- team sharing
- family plans
- server-side search over plaintext fields
- browser-only architecture
- admin access to decrypted vaults
