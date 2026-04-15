# Windows Installer And Release Packaging

This folder contains the production-facing release-layout and update-manifest scaffolding for the Windows agent.

What is included:

- `BuildReleaseLayout.ps1` to gather the built binaries, signature bundle, and minifilter payload artifacts into the canonical `agent/windows/out/dev` tree
- `BuildInstallerBundle.ps1` to build and stage a native `FenrirSetup.exe` installer into `agent/windows/out/install`
- `GenerateUpdateManifest.ps1` to emit updater manifests in the format consumed by [UpdaterService.cpp](/C:/Users/matt_admin/Documents/GitHub/AntiVirus/agent/windows/service/src/UpdaterService.cpp)
- `native/` containing the source for the embedded-payload Windows setup application

The staged installer and raw release layout also carry the MinGW thread runtime (`libwinpthread-1.dll`) when the build toolchain requires it, so clean Windows machines do not need a preinstalled GCC runtime to launch the setup EXE or the installed endpoint binaries.

`FenrirSetup.exe` also deploys `WebView2Loader.dll` and now checks whether Microsoft Edge WebView2 Runtime is available on the target host. If the runtime is missing, setup still completes but logs and completion text explicitly warn that the endpoint client will run in native fallback mode until WebView2 Runtime is installed.

If you provide `-WebView2RuntimeInstallerPath` to `BuildInstallerBundle.ps1` or `BuildReleaseLayout.ps1`, that run embeds the specified installer as a setup payload dependency and attempts a silent WebView2 runtime install on hosts where runtime detection fails. If you omit the parameter, no WebView2 runtime installer payload is embedded.

By default, both `BuildReleaseLayout.ps1` and `BuildInstallerBundle.ps1` now require a complete minifilter payload (`AntivirusMinifilter.inf`, `AntivirusMinifilter.sys`, `AntivirusMinifilter.cat`) in the staged release path. Supply `-DriverArtifactRoot` or pre-stage a package under `agent/windows/driver/minifilter/package` when running these scripts. For non-production developer-only runs, you can explicitly opt out with `-AllowMissingMinifilterPayload`.

Canonical output layout:

- `agent/windows/out/dev` for the unpacked development and release-stage payload tree
- `agent/windows/out/install` for the packaged `FenrirSetup.exe`
- `agent/windows/out/dev/build` only for CMake intermediates; promotion-ready payloads should be read from `out/dev`, not from the build tree

Typical flow:

1. Build the user-mode agent binaries with CMake.
2. Run `BuildInstallerBundle.ps1` to produce a one-click installer executable in `out/install`.
3. Build and sign the minifilter with the WDK on a driver-capable workstation when kernel payloads are ready to ship.
4. Run `BuildReleaseLayout.ps1` to stage the raw release tree in `out/dev`, including INF/SYS/CAT minifilter payload artifacts.
5. Run `GenerateUpdateManifest.ps1` to create a rollback-aware platform or definitions package.
6. Validate the staged endpoint with `fenrir-agent-service.exe --self-test`.

If setup fails while registering the Windows service with `OpenSCManagerW failed with error 5`, restart `FenrirSetup.exe` from an elevated Administrator context.

Example:

```powershell
# Download official x64 Evergreen Standalone Runtime installer (offline-capable)
New-Item -ItemType Directory -Path ..\out\install\deps -Force | Out-Null
Invoke-WebRequest -Uri https://go.microsoft.com/fwlink/p/?LinkId=2124701 -OutFile ..\out\install\deps\MicrosoftEdgeWebView2RuntimeInstallerX64.exe

pwsh -ExecutionPolicy Bypass -File .\BuildReleaseLayout.ps1 `
  -BuildRoot ..\out\dev\build `
  -OutputRoot ..\out\dev `
  -InstallerOutputRoot ..\out\install `
  -WebView2RuntimeInstallerPath C:\Dependencies\MicrosoftEdgeWebView2Setup.exe `
  -DriverArtifactRoot C:\DriverDrop

pwsh -ExecutionPolicy Bypass -File .\BuildInstallerBundle.ps1 `
  -BuildRoot ..\out\dev\build `
  -DevOutputRoot ..\out\dev `
  -OutputRoot ..\out\install `
  -DriverArtifactRoot C:\DriverDrop `
  -WebView2RuntimeInstallerPath C:\Dependencies\MicrosoftEdgeWebView2Setup.exe

pwsh -ExecutionPolicy Bypass -File .\GenerateUpdateManifest.ps1 `
  -ReleaseRoot ..\out\dev `
  -PackageId platform-0.1.0 `
  -TargetVersion 0.1.0-alpha
```

This is still release scaffolding, not a Microsoft-partner-signed commercial MSI pipeline. It gives us a repeatable internal packaging path while we stay pre-release.

## Trust, Recovery, And Lifecycle

- The installer and updater trust chain, anti-downgrade rules, key-rotation model, emergency revocation path, repair lifecycle, uninstall preservation rules, known-good reset mode, and rollback governance are defined in [Production-Readiness-Plan.md](/C:/Users/matt_admin/Documents/GitHub/AntiVirus/agent/windows/docs/Production-Readiness-Plan.md).
- The companion updater trust template lives at [update-trust.example.json](/C:/Users/matt_admin/Documents/GitHub/AntiVirus/agent/windows/service/update-trust.example.json).
- The packaged experience is expected to preserve evidence, patch history, and PAM audit by default during upgrade and repair, while uninstall offers preserve-versus-purge choices instead of destructive one-path removal.
