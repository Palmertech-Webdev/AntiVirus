# Windows Minifilter Skeleton

This folder contains the real-time file protection driver scaffold for the Windows agent.

What is implemented here:

- A WDK-oriented minifilter source file with Filter Manager registration
- A communication-port design that sends file create/open/write/execute requests to the user-mode broker
- Pre-operation interception points for `IRP_MJ_CREATE` and `IRP_MJ_WRITE`
- Broker-driven allow or block replies using the shared real-time protocol in [RealtimeProtectionProtocol.h](/C:/Users/matt_admin/Documents/GitHub/AntiVirus/agent/windows/shared/include/RealtimeProtectionProtocol.h)

What is still required before this becomes production-usable:

- Build with the Windows Driver Kit and a proper signing chain
- Add full process and signer enrichment in kernel-safe form
- Add stream-handle or section-object context caching to reduce duplicate scans
- Add paging-I/O and rename edge-case handling
- Add per-policy exclusions, cache lifetimes, and fail-open/fail-closed tuning
- Add installer packaging, altitude assignment, and production service registration

This repository environment does not currently include the WDK kernel headers or MSVC driver toolchain, so this driver source is checked in but not compiled here yet.

When you do have a signed WDK build output, use [BuildDriverPackage.ps1](/C:/Users/matt_admin/Documents/GitHub/AntiVirus/agent/windows/driver/minifilter/BuildDriverPackage.ps1) to stage the `.inf`, `.sys`, and `.cat` into a releaseable driver package.
