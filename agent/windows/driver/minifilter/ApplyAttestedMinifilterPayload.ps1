param(
    [Parameter(Mandatory = $true)]
    [string]$AttestedSourceRoot,
    [string]$DriverInfPath = (Join-Path $PSScriptRoot 'AntivirusMinifilter.inf'),
    [string]$PackageRoot = (Join-Path $PSScriptRoot 'package'),
    [string]$StageDriverRoot = (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'out\dev\driver')
)

$ErrorActionPreference = 'Stop'
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Ensure-Directory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
}

function Find-ArtifactPath {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $direct = Join-Path $Root $Name
    if (Test-Path -LiteralPath $direct) {
        return (Get-Item -LiteralPath $direct).FullName
    }

    $candidate = Get-ChildItem -LiteralPath $Root -Recurse -File -Filter $Name -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if ($null -ne $candidate) {
        return $candidate.FullName
    }

    return ''
}

$attestedSourceRootFull = [System.IO.Path]::GetFullPath($AttestedSourceRoot)
$driverInfFull = [System.IO.Path]::GetFullPath($DriverInfPath)
$packageRootFull = [System.IO.Path]::GetFullPath($PackageRoot)
$stageDriverRootFull = [System.IO.Path]::GetFullPath($StageDriverRoot)

if (-not (Test-Path -LiteralPath $attestedSourceRootFull)) {
    throw "Attested source root does not exist: $attestedSourceRootFull"
}
if (-not (Test-Path -LiteralPath $driverInfFull)) {
    throw "Driver INF was not found: $driverInfFull"
}

$attestedSysPath = Find-ArtifactPath -Root $attestedSourceRootFull -Name 'AntivirusMinifilter.sys'
$attestedCatPath = Find-ArtifactPath -Root $attestedSourceRootFull -Name 'AntivirusMinifilter.cat'
if (-not $attestedSysPath) {
    throw "Could not locate AntivirusMinifilter.sys under $attestedSourceRootFull"
}
if (-not $attestedCatPath) {
    throw "Could not locate AntivirusMinifilter.cat under $attestedSourceRootFull"
}

$sysSignature = Get-AuthenticodeSignature -LiteralPath $attestedSysPath
$catSignature = Get-AuthenticodeSignature -LiteralPath $attestedCatPath
if ($sysSignature.Status -ne 'Valid' -or $catSignature.Status -ne 'Valid') {
    throw "Attested signature validation failed (sys=$($sysSignature.Status), cat=$($catSignature.Status))."
}

Ensure-Directory -Path $packageRootFull
Ensure-Directory -Path $stageDriverRootFull

$readmePath = Join-Path $PSScriptRoot 'README.md'
$targets = @(
    @{ Source = $driverInfFull; Target = (Join-Path $packageRootFull 'AntivirusMinifilter.inf') },
    @{ Source = $attestedSysPath; Target = (Join-Path $packageRootFull 'AntivirusMinifilter.sys') },
    @{ Source = $attestedCatPath; Target = (Join-Path $packageRootFull 'AntivirusMinifilter.cat') },
    @{ Source = $driverInfFull; Target = (Join-Path $stageDriverRootFull 'AntivirusMinifilter.inf') },
    @{ Source = $attestedSysPath; Target = (Join-Path $stageDriverRootFull 'AntivirusMinifilter.sys') },
    @{ Source = $attestedCatPath; Target = (Join-Path $stageDriverRootFull 'AntivirusMinifilter.cat') }
)

if (Test-Path -LiteralPath $readmePath) {
    $targets += @(
        @{ Source = $readmePath; Target = (Join-Path $packageRootFull 'README.md') },
        @{ Source = $readmePath; Target = (Join-Path $stageDriverRootFull 'README.md') }
    )
}

foreach ($target in $targets) {
    Copy-Item -LiteralPath $target.Source -Destination $target.Target -Force
}

$report = [pscustomobject]@{
    importedAtUtc = [DateTime]::UtcNow.ToString('o')
    attestedSourceRoot = $attestedSourceRootFull
    packageRoot = $packageRootFull
    stageDriverRoot = $stageDriverRootFull
    signatureStatus = [pscustomobject]@{
        sys = [string]$sysSignature.Status
        cat = [string]$catSignature.Status
        sysSigner = if ($sysSignature.SignerCertificate) { [string]$sysSignature.SignerCertificate.Subject } else { '' }
        catSigner = if ($catSignature.SignerCertificate) { [string]$catSignature.SignerCertificate.Subject } else { '' }
    }
    artifacts = @(
        [pscustomobject]@{
            path = 'AntivirusMinifilter.sys'
            sha256 = (Get-FileHash -LiteralPath (Join-Path $packageRootFull 'AntivirusMinifilter.sys') -Algorithm SHA256).Hash.ToLowerInvariant()
            sizeBytes = (Get-Item -LiteralPath (Join-Path $packageRootFull 'AntivirusMinifilter.sys')).Length
        },
        [pscustomobject]@{
            path = 'AntivirusMinifilter.cat'
            sha256 = (Get-FileHash -LiteralPath (Join-Path $packageRootFull 'AntivirusMinifilter.cat') -Algorithm SHA256).Hash.ToLowerInvariant()
            sizeBytes = (Get-Item -LiteralPath (Join-Path $packageRootFull 'AntivirusMinifilter.cat')).Length
        }
    )
}

[System.IO.File]::WriteAllText(
    (Join-Path $packageRootFull 'attestation-import-report.json'),
    ($report | ConvertTo-Json -Depth 8),
    $utf8NoBom
)

Write-Host "Imported Microsoft-attested minifilter payload into:"
Write-Host "  package: $packageRootFull"
Write-Host "  stage:   $stageDriverRootFull"
Write-Host "Import report written to $(Join-Path $packageRootFull 'attestation-import-report.json')"
