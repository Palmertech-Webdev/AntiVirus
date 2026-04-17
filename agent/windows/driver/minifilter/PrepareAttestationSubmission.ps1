param(
    [string]$DriverPackageRoot = (Join-Path $PSScriptRoot 'package'),
    [string]$OutputRoot = (Join-Path $PSScriptRoot 'package\attestation-submission'),
    [string]$CabinetName = 'AntivirusMinifilter-attestation.cab',
    [switch]$IncludeDriverBuildReport
)

$ErrorActionPreference = 'Stop'
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Ensure-Directory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
}

function Resolve-ExecutablePath {
    param([Parameter(Mandatory = $true)][string]$Name)
    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -ne $command -and $command.Source) {
        return $command.Source
    }
    return ''
}

function Get-ArtifactInventory {
    param([Parameter(Mandatory = $true)][string]$Root)
    return Get-ChildItem -LiteralPath $Root -File | Sort-Object Name | ForEach-Object {
        [pscustomobject]@{
            path = $_.Name
            sizeBytes = $_.Length
            sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
}

$driverPackageRootFull = [System.IO.Path]::GetFullPath($DriverPackageRoot)
$outputRootFull = [System.IO.Path]::GetFullPath($OutputRoot)
$cabinetNameTrimmed = [System.IO.Path]::GetFileName($CabinetName)
if ([string]::IsNullOrWhiteSpace($cabinetNameTrimmed)) {
    throw 'CabinetName must include a file name.'
}

Ensure-Directory -Path $outputRootFull
$cabInputRoot = Join-Path $outputRootFull 'cab-input'
if (Test-Path -LiteralPath $cabInputRoot) {
    Remove-Item -LiteralPath $cabInputRoot -Recurse -Force
}
Ensure-Directory -Path $cabInputRoot

$requiredFiles = @(
    'AntivirusMinifilter.inf',
    'AntivirusMinifilter.sys',
    'AntivirusMinifilter.cat'
)

foreach ($name in $requiredFiles) {
    $source = Join-Path $driverPackageRootFull $name
    if (-not (Test-Path -LiteralPath $source)) {
        throw "Missing required driver package artifact: $source"
    }
    Copy-Item -LiteralPath $source -Destination (Join-Path $cabInputRoot $name) -Force
}

$driverBuildReportPath = Join-Path $driverPackageRootFull 'driver-build-report.json'
if ($IncludeDriverBuildReport -and (Test-Path -LiteralPath $driverBuildReportPath)) {
    Copy-Item -LiteralPath $driverBuildReportPath -Destination (Join-Path $cabInputRoot 'driver-build-report.json') -Force
}

$sysSignature = Get-AuthenticodeSignature -LiteralPath (Join-Path $cabInputRoot 'AntivirusMinifilter.sys')
$catSignature = Get-AuthenticodeSignature -LiteralPath (Join-Path $cabInputRoot 'AntivirusMinifilter.cat')

$manifest = [pscustomobject]@{
    generatedAtUtc = [DateTime]::UtcNow.ToString('o')
    driverPackageRoot = $driverPackageRootFull
    submissionArtifacts = Get-ArtifactInventory -Root $cabInputRoot
    signatureStatus = [pscustomobject]@{
        sys = [string]$sysSignature.Status
        cat = [string]$catSignature.Status
        sysSigner = if ($sysSignature.SignerCertificate) { [string]$sysSignature.SignerCertificate.Subject } else { '' }
        catSigner = if ($catSignature.SignerCertificate) { [string]$catSignature.SignerCertificate.Subject } else { '' }
    }
}

[System.IO.File]::WriteAllText(
    (Join-Path $cabInputRoot 'submission-manifest.json'),
    ($manifest | ConvertTo-Json -Depth 8),
    $utf8NoBom
)

$nextSteps = @(
    "Fenrir minifilter attestation submission bundle",
    "Generated (UTC): $($manifest.generatedAtUtc)",
    "",
    "1. Upload the CAB in Microsoft Partner Center (Hardware -> Driver signing -> Attestation signing).",
    "2. Download the Microsoft-signed package from the portal.",
    "3. Replace AntivirusMinifilter.sys and AntivirusMinifilter.cat in:",
    "   - agent/windows/driver/minifilter/package",
    "   - agent/windows/out/dev/driver",
    "4. Rebuild FenrirSetup.exe and rerun repair/install to restore full minifilter enforcement."
)
[System.IO.File]::WriteAllLines((Join-Path $outputRootFull 'ATTESTATION-NEXT-STEPS.txt'), $nextSteps, $utf8NoBom)

$makecabPath = Resolve-ExecutablePath -Name 'makecab.exe'
if (-not $makecabPath) {
    throw 'makecab.exe was not found on PATH. Install Windows cabinet tools and rerun.'
}

$cabinetPath = Join-Path $outputRootFull $cabinetNameTrimmed
if (Test-Path -LiteralPath $cabinetPath) {
    Remove-Item -LiteralPath $cabinetPath -Force
}

$ddfPath = Join-Path $cabInputRoot 'attestation-submission.ddf'
$ddf = @(
    '.OPTION EXPLICIT',
    ".Set CabinetNameTemplate=$cabinetNameTrimmed",
    ".Set DiskDirectoryTemplate=`"$outputRootFull`"",
    '.Set Cabinet=ON',
    '.Set Compress=ON',
    '.Set CompressionType=MSZIP',
    '.Set MaxDiskSize=0',
    '.Set UniqueFiles=OFF',
    '"AntivirusMinifilter.inf"',
    '"AntivirusMinifilter.sys"',
    '"AntivirusMinifilter.cat"',
    '"submission-manifest.json"'
)
if (Test-Path -LiteralPath (Join-Path $cabInputRoot 'driver-build-report.json')) {
    $ddf += '"driver-build-report.json"'
}

[System.IO.File]::WriteAllLines($ddfPath, $ddf, $utf8NoBom)

Push-Location $cabInputRoot
try {
    & $makecabPath /F $ddfPath | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "makecab failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}

if (-not (Test-Path -LiteralPath $cabinetPath)) {
    throw "Attestation CAB was not generated: $cabinetPath"
}

Write-Host "Attestation submission CAB written to $cabinetPath"
Write-Host "Attestation notes written to $(Join-Path $outputRootFull 'ATTESTATION-NEXT-STEPS.txt')"
