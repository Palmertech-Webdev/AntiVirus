param(
    [string]$BuildRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'out\dev\build'),
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

$windowsRoot = Split-Path $PSScriptRoot -Parent
$serviceSourceRoot = Join-Path $windowsRoot 'service'
$buildRootFull = [System.IO.Path]::GetFullPath($BuildRoot)
$outputRootFull = [System.IO.Path]::GetFullPath($OutputRoot)

if ($Clean -and (Test-Path -LiteralPath $outputRootFull)) {
    Remove-Item -LiteralPath $outputRootFull -Recurse -Force
}

Ensure-Directory -Path $outputRootFull

if (-not (Test-Path -LiteralPath (Join-Path $buildRootFull 'CMakeCache.txt'))) {
    cmake -S $serviceSourceRoot -B $buildRootFull | Out-Host
}

cmake --build $buildRootFull --target antivirus-setup | Out-Host

$setupSource = Join-Path $buildRootFull 'FenrirSetup.exe'
if (-not (Test-Path -LiteralPath $setupSource)) {
    throw "Installer output was not produced: $setupSource"
}

$setupTarget = Join-Path $outputRootFull 'FenrirSetup.exe'
Copy-Item -LiteralPath $setupSource -Destination $setupTarget -Force

Write-Host "Installer bundle written to $setupTarget"
