param(
    [string]$BuildRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'out\dev\build'),
    [string]$DevOutputRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'out\dev'),
    [string]$OutputRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'out\install'),
    [string]$WebView2RuntimeInstallerPath = '',
    [switch]$Clean
)

$ErrorActionPreference = 'Stop'

function Ensure-Directory {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
}

function Remove-LegacyBuildOutputs {
    param([string]$BuildRoot)

    foreach ($name in @(
        'fenrir-agent-service.exe',
        'fenrir-amsi-provider.dll',
        'fenrir-amsitestcli.exe',
        'fenrir-endpoint-client.exe',
        'fenrir-etwtestcli.exe',
        'fenrir-pam.exe',
        'fenrir-scannercli.exe',
        'fenrir-wfptestcli.exe',
        'FenrirSetup.exe',
        'WebView2Loader.dll'
    )) {
        $candidate = Join-Path $BuildRoot $name
        if (Test-Path -LiteralPath $candidate) {
            Remove-Item -LiteralPath $candidate -Force
        }
    }
}

$windowsRoot = Split-Path $PSScriptRoot -Parent
$serviceSourceRoot = Join-Path $windowsRoot 'service'
$buildRootFull = [System.IO.Path]::GetFullPath($BuildRoot)
$devOutputRootFull = [System.IO.Path]::GetFullPath($DevOutputRoot)
$outputRootFull = [System.IO.Path]::GetFullPath($OutputRoot)
$webView2RuntimeInstallerFullPath = ''

if ($WebView2RuntimeInstallerPath) {
    $webView2RuntimeInstallerFullPath = [System.IO.Path]::GetFullPath($WebView2RuntimeInstallerPath)
    if (-not (Test-Path -LiteralPath $webView2RuntimeInstallerFullPath)) {
        throw "Configured WebView2 runtime installer was not found: $webView2RuntimeInstallerFullPath"
    }
}

if ($Clean -and (Test-Path -LiteralPath $outputRootFull)) {
    Remove-Item -LiteralPath $outputRootFull -Recurse -Force
}

Ensure-Directory -Path $buildRootFull
Ensure-Directory -Path $outputRootFull

$cmakeConfigureArgs = @(
    '-S', $serviceSourceRoot,
    '-B', $buildRootFull,
    "-DANTIVIRUS_DEV_OUTPUT_ROOT=$devOutputRootFull",
    "-DANTIVIRUS_INSTALL_OUTPUT_ROOT=$outputRootFull",
    "-DANTIVIRUS_WEBVIEW2_BOOTSTRAPPER:FILEPATH=$webView2RuntimeInstallerFullPath"
)

cmake @cmakeConfigureArgs | Out-Host
if ($LASTEXITCODE -ne 0) {
    throw "CMake configure failed with exit code $LASTEXITCODE"
}

cmake --build $buildRootFull --target antivirus-setup | Out-Host
if ($LASTEXITCODE -ne 0) {
    throw "CMake build failed with exit code $LASTEXITCODE"
}

$setupTarget = Join-Path $outputRootFull 'FenrirSetup.exe'
if (-not (Test-Path -LiteralPath $setupTarget)) {
    throw "Installer output was not produced: $setupTarget"
}

Remove-LegacyBuildOutputs -BuildRoot $buildRootFull

Write-Host "Installer bundle written to $setupTarget"
