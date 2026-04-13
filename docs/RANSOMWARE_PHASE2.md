# Phase 2 Anti-Ransomware

This document defines Fenrir's Phase 2 anti-ransomware model. The focus is behavior-chain detection and rapid
containment without honeypots, bait files, or simplistic "many ZIPs = ransomware" shortcuts.

## Policy Model

Phase 2 is modeled as a set of cooperating controls that operate on process context, process lineage, and destructive
file-impact behavior:

- `realtimeProtectionEnabled`
  Enables the user-mode broker and minifilter-facing interception path.
- `scriptInspectionEnabled`
  Lets AMSI and script telemetry contribute pre-impact lineage context.
- `networkContainmentEnabled`
  Allows host isolation after high-confidence impact-stage detections.
- `quarantineOnMalicious`
  Allows artifact quarantine after a blocking decision where the path is still recoverable.

Operationally, the ransomware policy model assumes these behaviors must be scored together rather than in isolation:

- pre-impact staging
  Office, browser, LOLBin, or script-host lineage; encoded commands; download cradles; dynamic execution.
- impact staging
  Recovery inhibition, backup tamper, safe-mode or recovery-environment tamper, or crypto primitive invocation.
- destructive file churn
  High-rate writes, cross-directory traversal, suspicious encrypted extensions, and rewrite bursts against user data.
- false-positive dampening
  Backup, sync, media export, and developer-build contexts lower confidence when destructive intent is absent.

The current implementation expresses this through:

- context-aware real-time hits in `RealtimeProtectionBroker`
- rolling lineage correlation windows across ETW, network, script, and runtime events
- ransomware burst scoring across user-data write history
- selective negative scoring for benign bulk-I/O process context

## Containment Model

Phase 2 containment is designed to happen before or during early encryption impact:

1. Intercept write, create, open, and execute events through the real-time broker.
2. Score current process context and inherited lineage history.
3. Block the request immediately when confidence crosses the ransomware threshold.
4. Record evidence and changed-path context for follow-on triage.
5. Quarantine the artifact when policy allows.
6. If quarantine fails because handles are live, terminate the related process tree and retry.
7. If policy allows and the isolation manager is available, isolate the host network-wise.

Current implemented containment paths:

- direct block from the real-time verdict broker
- process-tree termination before quarantine retry
- evidence capture for the intercepted event
- optional WFP-based isolation under policy

Still reserved for later phases:

- transactional rollback of changed user files
- kernel-enforced write freezing beyond the intercepted request path
- automated restore from snapshots or protected backup state

## Reason Codes

Phase 2 reason codes are intended to be specific enough for triage, automation, and tuning. The key ransomware-related
reason codes currently used by the service are:

- `REALTIME_RECOVERY_INHIBITION`
  Recovery inhibition commands such as `vssadmin delete shadows`, `wbadmin delete`, `bcdedit /set`, or `reagentc /disable`.
- `REALTIME_RANSOMWARE_WRITE_BURST`
  Rapid multi-directory write churn across user-data locations.
- `REALTIME_RANSOMWARE_EXTENSION_BURST`
  Burst writes using encrypted-impact extensions like `.locked` or `.encrypted`.
- `REALTIME_RANSOMWARE_CROSS_DIRECTORY_CHURN`
  High-rate cross-directory write activity with broad extension spread.
- `REALTIME_RANSOMWARE_PREIMPACT_CHAIN`
  Destructive write churn correlated with crypto primitives or recovery inhibition.
- `REALTIME_CHAIN_RANSOMWARE_IMPACT`
  Prior lineage staging correlated with later recovery inhibition or impact behavior.
- `REALTIME_CHAIN_CORRELATED`
  General lineage correlation marker showing the event was elevated by prior related activity.
- `REALTIME_BENIGN_BULK_IO_CONTEXT`
  Backup, sync, or migration-like process context that should dampen ransomware confidence.
- `REALTIME_BENIGN_BULK_IO_DAMPENING`
  Additional dampening when burst thresholds are crossed in an otherwise benign bulk-I/O workflow.

Related on-demand or content reason codes that feed Phase 2 correlation:

- `RECOVERY_INHIBITION`
- `RANSOM_NOTE_ARTIFACT`
- `ENCRYPTED_IMPACT_ARTIFACT`
- `MASS_ENCRYPTION_SCRIPT`

## Evidence Expectations

Phase 2 evidence should let an operator understand what happened quickly:

- blocked path and operation
- process image, parent image, command line, and user SID
- reason-code set and confidence
- artifact evidence record id
- quarantine record id when applicable
- scope hints from the burst window

The self-test coverage now validates:

- destructive write-burst containment
- encrypted-extension burst containment
- staged script-to-impact lineage correlation
- false-positive resistance for backup/sync bulk I/O
- false-positive resistance for photo/video export
- false-positive resistance for developer builds

## Test Corpus

Phase 2 synthetic corpus generation is provided by:

- [GeneratePhase2RansomwareCorpus.ps1](/C:/Users/matt_admin/Documents/GitHub/AntiVirus/agent/windows/tools/scannercli/GeneratePhase2RansomwareCorpus.ps1)

The generated corpus is intended for repeatable scenario validation, not signature matching. It includes:

- destructive write-burst samples
- encrypted-extension rename-burst samples
- staged script lineage samples
- benign backup/sync samples
- benign media-export samples
- benign developer-build samples

## Exit Criteria

Phase 2 is considered complete when all of the following are true:

- ransomware-style destructive behavior is blocked from behavior chains, not honeypots
- the standalone Phase 2 exit-criteria harness passes
- benign backup, sync, export, and build churn do not trip containment
- evidence and reason codes are specific enough for triage and tuning
- unrelated packaging or posture warnings do not mask Phase 2 readiness
