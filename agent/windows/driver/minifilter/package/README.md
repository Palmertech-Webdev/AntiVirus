# Windows Minifilter Skeleton

This folder contains the real-time file protection driver scaffold for the Windows agent.

What is implemented here:

- A WDK-oriented minifilter source file with Filter Manager registration
- A communication-port design that sends file create/open/write/execute requests to the user-mode broker
- Pre-operation interception points for:
- `IRP_MJ_CREATE` (create/open/execute intent)
- `IRP_MJ_WRITE`
- `IRP_MJ_SET_INFORMATION` (rename/link/disposition sensitive classes)
- `IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION` (section-map and locked image-section paths)
- Broker-driven allow or block replies using the shared real-time protocol in [RealtimeProtectionProtocol.h](/C:/Users/matt_admin/Documents/GitHub/AntiVirus/agent/windows/shared/include/RealtimeProtectionProtocol.h)
- Strict fail-closed handling for high-risk contexts (reparse, ADS-like paths, remote/removable volumes, section-sync risk)

What is still required before this becomes production-usable:

- Build with the Windows Driver Kit and a proper signing chain
- Add full process and signer enrichment in kernel-safe form
- Add stream-handle or section-object context caching to reduce duplicate scans
- Expand paging-I/O nuance and cache policies for high-throughput workloads
- Add per-policy exclusions, cache lifetimes, and fail-open/fail-closed tuning
- Add installer packaging, altitude assignment, and production service registration

This driver can be built in this repository when WDK/MSVC tooling is available.

## Production Signing Path

1. Build and locally package the driver with [BuildMinifilterDriver.ps1](/C:/Users/matt_admin/Documents/GitHub/AntiVirus/agent/windows/driver/minifilter/BuildMinifilterDriver.ps1).
2. Generate an attestation CAB submission bundle with [PrepareAttestationSubmission.ps1](/C:/Users/matt_admin/Documents/GitHub/AntiVirus/agent/windows/driver/minifilter/PrepareAttestationSubmission.ps1).
3. Submit that CAB in Microsoft Partner Center for attestation signing.
4. Restage the returned Microsoft-signed `.sys` and `.cat` with [ApplyAttestedMinifilterPayload.ps1](/C:/Users/matt_admin/Documents/GitHub/AntiVirus/agent/windows/driver/minifilter/ApplyAttestedMinifilterPayload.ps1).
5. Rebuild the installer and validate with [ValidateMinifilterPackage.ps1](/C:/Users/matt_admin/Documents/GitHub/AntiVirus/agent/windows/tools/scannercli/ValidateMinifilterPackage.ps1).

Until Microsoft-attested artifacts are staged, Windows can reject driver load with `error 577` on Secure Boot systems, and setup will continue in reduced-protection mode.

## Local Testing Path (No EV, No Partner Center)

For local development and QA machines, you can run the minifilter in Windows test mode with a self-signed certificate.

Run this from an elevated PowerShell session:

`.\EnableLocalMinifilterTestMode.ps1`

What it does:

- Creates or reuses a local `CN=Antivirus Test Driver Signing` certificate in `LocalMachine\My`
- Trusts that cert in `LocalMachine\Root` and `LocalMachine\TrustedPublisher`
- Re-signs `AntivirusMinifilter.sys` and `AntivirusMinifilter.cat`
- Stages artifacts into `agent/windows/out/dev/driver`
- Enables `TESTSIGNING` boot mode
- Installs the driver package via `pnputil`
- Writes a report to `package/local-test-mode-report.json`

Notes:

- This is for test environments only, not production deployment.
- If Secure Boot blocks `TESTSIGNING`, disable Secure Boot in firmware, rerun the script, and reboot.
