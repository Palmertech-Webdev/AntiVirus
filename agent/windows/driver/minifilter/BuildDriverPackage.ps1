param(
    [Parameter(Mandatory = $true)]
    [string]$ArtifactRoot,
    [string]$OutputRoot = (Join-Path $PSScriptRoot 'package')
)

$ErrorActionPreference = 'Stop'
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Ensure-Directory {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
}

$artifactRoot = (Resolve-Path $ArtifactRoot).Path
$outputRoot = [System.IO.Path]::GetFullPath($OutputRoot)
Ensure-Directory -Path $outputRoot

$requiredArtifacts = @(
    @{ Source = (Join-Path $PSScriptRoot 'AntivirusMinifilter.inf'); Target = (Join-Path $outputRoot 'AntivirusMinifilter.inf') },
    @{ Source = (Join-Path $artifactRoot 'AntivirusMinifilter.sys'); Target = (Join-Path $outputRoot 'AntivirusMinifilter.sys') },
    @{ Source = (Join-Path $artifactRoot 'AntivirusMinifilter.cat'); Target = (Join-Path $outputRoot 'AntivirusMinifilter.cat') }
)

foreach ($artifact in $requiredArtifacts) {
    if (-not (Test-Path -LiteralPath $artifact.Source)) {
        throw "Missing driver package artifact: $($artifact.Source)"
    }

    Copy-Item -LiteralPath $artifact.Source -Destination $artifact.Target -Force
}

Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'README.md') -Destination (Join-Path $outputRoot 'README.md') -Force

$inventory = Get-ChildItem -LiteralPath $outputRoot -File | ForEach-Object {
    [pscustomobject]@{
        path = $_.Name
        sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        sizeBytes = $_.Length
    }
}

$document = [pscustomobject]@{
    generatedAt = [DateTime]::UtcNow.ToString('o')
    outputRoot = $outputRoot
    artifacts = $inventory
} | ConvertTo-Json -Depth 3
[System.IO.File]::WriteAllText((Join-Path $outputRoot 'driver-package.json'), $document, $utf8NoBom)

Write-Host "Driver package written to $outputRoot"
