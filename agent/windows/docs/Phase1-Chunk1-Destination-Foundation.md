# Phase 1 Chunk 1: Destination Intelligence Foundation

This document defines the first implementation slice for Phase 1 web, phishing, and email-link protection.

## Goal

Provide a single shared contract for destination protection so the agent can reason about:

- domains
- URLs
- destination reputation
- phishing confidence
- warn/block/allow decisions
- evidence and telemetry output

without duplicating logic across WFP, browser-aware flows, email-origin logic, or endpoint UI.

## New Shared Contracts

`service/include/DestinationProtection.h` defines:

- `DestinationAction`
- `DestinationThreatCategory`
- `DestinationReasonCode`
- `DestinationPolicySnapshot`
- `DestinationContext`
- `DestinationIntelligenceRecord`
- `DestinationVerdict`
- `DestinationEvidenceRecord`

`service/src/DestinationProtection.cpp` provides:

- default policy construction
- enum/string normalization helpers
- reason-code packing and unpacking
- destination indicator normalization
- baseline action selection
- JSON serialization for telemetry/evidence payloads
- user-facing summary generation

## Why This Comes First

The current agent already has:

- real-time verdicting
- threat-intel lookups
- WFP telemetry and containment
- telemetry queueing
- evidence recording
- endpoint UI history surfaces

What was missing was a dedicated, shared destination-protection contract. Without this layer, DNS blocking, browser risk scoring, phishing scoring, and email-link uplift would each drift into separate models.

## Immediate Follow-On Wiring

The next implementation pass should connect these contracts to the runtime service through:

1. `PolicySnapshot` extension for destination-protection controls.
2. SQLite persistence for destination-intelligence cache and destination-policy fields.
3. WFP path integration so network decisions can produce `DestinationVerdict`.
4. endpoint UI history cards for blocked and warned destinations.
5. evidence and telemetry writers using `DestinationEvidenceRecord`.

## Example Policy

`service/web-protection-policy.example.json` is the first schema example for local/default Phase 1 behaviour. It should be treated as the canonical example while the runtime policy store is being extended.

## Acceptance Criteria For Chunk 1

Chunk 1 is considered structurally complete when:

- all Phase 1 destination decisions can use one shared verdict model;
- reason codes are stable and serializable;
- destination actions are policy-driven rather than ad hoc;
- evidence/telemetry payloads can be produced consistently;
- later WFP/browser/email layers can build on the same foundation without redefining their own enums or schemas.
