param(
    [string]$ReleaseRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'out\release'),
    [string]$OutputPath = '',
    [string]$PackageId = 'platform',
    [string]$PackageType = 'platform',
    [string]$TargetVersion = '0.1.0-alpha',
    [string]$Channel = 'stable',
    [string]$PackageSigner = '',
    [string[]]$Files = @(
        'fenrir-agent-service.exe',
        'fenrir-amsi-provider.dll',
        'signatures\default-signatures.tsv'
    )
)

$ErrorActionPreference = 'Stop'

$releaseRoot = (Resolve-Path $ReleaseRoot).Path
if (-not $OutputPath) {
    $OutputPath = Join-Path $releaseRoot "$PackageId.manifest"
}

$manifestLines = [System.Collections.Generic.List[string]]::new()
$manifestLines.Add('# AntiVirus update manifest')
$manifestLines.Add("package_id=$PackageId")
$manifestLines.Add("package_type=$PackageType")
$manifestLines.Add("target_version=$TargetVersion")
$manifestLines.Add("channel=$Channel")
if ($PackageSigner) {
    $manifestLines.Add("package_signer=$PackageSigner")
}

foreach ($relativePath in $Files) {
    $normalizedRelativePath = $relativePath -replace '/', '\\'
    $sourcePath = Join-Path $releaseRoot $normalizedRelativePath
    if (-not (Test-Path -LiteralPath $sourcePath)) {
        throw "Cannot add missing manifest file: $sourcePath"
    }

    $hash = (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $requireSignature = if ($PackageSigner) { 'true' } else { 'false' }
    $manifestLines.Add("file=$normalizedRelativePath|$normalizedRelativePath|$hash|$PackageSigner|$requireSignature")
}

[System.IO.File]::WriteAllLines($OutputPath, $manifestLines, [System.Text.Encoding]::Unicode)
Write-Host "Update manifest written to $OutputPath"