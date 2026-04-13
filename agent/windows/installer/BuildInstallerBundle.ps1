param(
    [string]$BuildRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'out\dev\build'),
    [string]$DevOutputRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'out\dev'),
    [string]$OutputRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'out\install'),
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

if ($Clean -and (Test-Path -LiteralPath $outputRootFull)) {
    Remove-Item -LiteralPath $outputRootFull -Recurse -Force
}

Ensure-Directory -Path $buildRootFull
Ensure-Directory -Path $outputRootFull

cmake -S $serviceSourceRoot -B $buildRootFull `
    -DANTIVIRUS_DEV_OUTPUT_ROOT="$devOutputRootFull" `
    -DANTIVIRUS_INSTALL_OUTPUT_ROOT="$outputRootFull" | Out-Host

cmake --build $buildRootFull --target antivirus-setup | Out-Host

$setupTarget = Join-Path $outputRootFull 'FenrirSetup.exe'
if (-not (Test-Path -LiteralPath $setupTarget)) {
    throw "Installer output was not produced: $setupTarget"
}

Remove-LegacyBuildOutputs -BuildRoot $buildRootFull

Write-Host "Installer bundle written to $setupTarget"
