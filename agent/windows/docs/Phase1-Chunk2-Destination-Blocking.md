# Phase 1 Chunk 2: Destination Blocking Path

This document records the first implementation slice for destination blocking on top of the Phase 1 Chunk 1 contracts.

## Goal

Convert destination reputation and phishing intelligence into a shared **block / warn / allow** decision path that can later be consumed by:

- WFP destination enforcement
- browser-aware protection
- email-origin link handling
- endpoint UI history and alerts

## New Component

`service/include/DestinationVerdictEngine.h`
`service/src/DestinationVerdictEngine.cpp`

The destination verdict engine is responsible for:

- calling existing destination reputation lookup logic
- mapping that reputation into destination categories
- assigning policy-driven actions (`allow`, `warn`, `block`, `degraded_allow`)
- creating stable reason codes
- generating a reusable evidence record payload

## Why This Matters

Before this change, destination reputation was effectively a late-stage enrichment path inside the service loop. That made it useful for telemetry and host-isolation escalation, but not for a clean, reusable destination decision model.

The new engine creates one place where destination decisions are made. That is the prerequisite for proper user-facing website blocking and future WFP/browser/email integrations.

## Current Scope

This slice does **not** yet rewrite the live WFP classify flow. It provides the shared decision engine and wires it into the service build so later enforcement paths can consume one stable model.

## Immediate Follow-On Work

1. Extend `PolicySnapshot` with destination-protection fields.
2. Extend runtime SQLite schema with destination-intelligence cache and destination-policy persistence.
3. Replace direct `LookupDestinationReputation(...)` usage in `AgentService::DrainNetworkTelemetry()` with `DestinationVerdictEngine`.
4. Emit dedicated destination warning/block telemetry instead of generic reputation-hit records.
5. Surface destination-block history in endpoint UI.
6. Add a WFP-facing request/evaluation path for low-latency destination verdict checks.

## Acceptance Criteria For This Slice

This slice is structurally complete when:

- the destination-verdict engine compiles as part of `antivirus-agent-core`;
- destination reputation can be converted into a stable destination verdict;
- block/warn/allow is policy-driven instead of ad hoc;
- evidence records can be produced from one consistent source;
- later WFP/browser/email work can reuse the same destination decision engine.
