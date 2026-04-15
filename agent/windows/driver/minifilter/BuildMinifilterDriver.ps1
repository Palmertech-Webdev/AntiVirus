param(
    [string]$ProjectPath = (Join-Path $PSScriptRoot 'AntivirusMinifilter.vcxproj'),
    [string]$BuildRoot = (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'out\dev\driver-build'),
    [string]$OutputRoot = (Join-Path $PSScriptRoot 'package'),
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',
    [ValidateSet('x64')]
    [string]$Platform = 'x64',
    [string]$DriverInfPath = (Join-Path $PSScriptRoot 'AntivirusMinifilter.inf'),
    [string]$SigningCertificateThumbprint = '',
    [string]$SigningPfxPath = '',
    [string]$SigningPfxPassword = '',
    [string]$TimestampServer = 'http://timestamp.digicert.com',
    [switch]$AllowUnsignedArtifacts,
    [switch]$Clean
)

$ErrorActionPreference = 'Stop'
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Ensure-Directory {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
}

function Resolve-Executable {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -ne $command -and $command.Source) {
        return $command.Source
    }

    if ($Name -ieq 'msbuild.exe') {
        $vswherePath = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
        if (Test-Path -LiteralPath $vswherePath) {
            $installPath = & $vswherePath -latest -products * -requires Microsoft.Component.MSBuild -property installationPath
            if ($LASTEXITCODE -eq 0 -and $installPath) {
                $candidate = Join-Path $installPath 'MSBuild\Current\Bin\MSBuild.exe'
                if (Test-Path -LiteralPath $candidate) {
                    return $candidate
                }
            }
        }
    }

    return ''
}

function Resolve-WindowsKitExecutable {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -ne $command -and $command.Source) {
        return $command.Source
    }

    $kitsRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    if (-not (Test-Path -LiteralPath $kitsRoot)) {
        return ''
    }

    $versions = Get-ChildItem -LiteralPath $kitsRoot -Directory | Sort-Object Name -Descending
    foreach ($version in $versions) {
        $candidate = Join-Path $version.FullName (Join-Path 'x64' $Name)
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    return ''
}

function Find-BuiltDriverBinary {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BuildRoot,
        [Parameter(Mandatory = $true)]
        [string]$DriverName
    )

    $directCandidate = Join-Path $BuildRoot $DriverName
    if (Test-Path -LiteralPath $directCandidate) {
        return (Get-Item -LiteralPath $directCandidate).FullName
    }

    $candidates = Get-ChildItem -LiteralPath $BuildRoot -Recurse -File -Filter $DriverName -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTimeUtc -Descending
    if ($candidates.Count -gt 0) {
        return $candidates[0].FullName
    }

    return ''
}

function Sign-File {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SignToolPath,
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [string]$Thumbprint,
        [string]$PfxPath,
        [string]$PfxPassword,
        [string]$TimestampServer
    )

    $signArgs = @('sign', '/fd', 'SHA256', '/td', 'SHA256', '/tr', $TimestampServer)

    if ($PfxPath) {
        $signArgs += @('/f', $PfxPath)
        if ($PfxPassword) {
            $signArgs += @('/p', $PfxPassword)
        }
    }
    elseif ($Thumbprint) {
        $signArgs += @('/sha1', $Thumbprint)
    }

    $signArgs += $FilePath

    & $SignToolPath @signArgs | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "signtool failed for $FilePath with exit code $LASTEXITCODE"
    }
}

$projectPathFull = [System.IO.Path]::GetFullPath($ProjectPath)
$buildRootFull = [System.IO.Path]::GetFullPath($BuildRoot)
$outputRootFull = [System.IO.Path]::GetFullPath($OutputRoot)
$driverInfFull = [System.IO.Path]::GetFullPath($DriverInfPath)

if (-not (Test-Path -LiteralPath $projectPathFull)) {
    throw "Minifilter project file was not found: $projectPathFull"
}

if (-not (Test-Path -LiteralPath $driverInfFull)) {
    throw "Minifilter INF file was not found: $driverInfFull"
}

if ($SigningPfxPath) {
    $SigningPfxPath = [System.IO.Path]::GetFullPath($SigningPfxPath)
    if (-not (Test-Path -LiteralPath $SigningPfxPath)) {
        throw "Configured signing PFX does not exist: $SigningPfxPath"
    }
}

if ($Clean) {
    if (Test-Path -LiteralPath $buildRootFull) {
        Remove-Item -LiteralPath $buildRootFull -Recurse -Force
    }
    if (Test-Path -LiteralPath $outputRootFull) {
        Remove-Item -LiteralPath $outputRootFull -Recurse -Force
    }
}

Ensure-Directory -Path $buildRootFull
Ensure-Directory -Path $outputRootFull

$msbuildPath = Resolve-Executable -Name 'msbuild.exe'
if (-not $msbuildPath) {
    throw 'MSBuild was not found. Install Visual Studio Build Tools (C++ workload) with WDK support.'
}

$inf2catPath = Resolve-WindowsKitExecutable -Name 'inf2cat.exe'
if (-not $inf2catPath) {
    throw 'inf2cat.exe was not found. Install the Windows Driver Kit (WDK).'
}

$hasSigningMaterial = -not [string]::IsNullOrWhiteSpace($SigningCertificateThumbprint) -or -not [string]::IsNullOrWhiteSpace($SigningPfxPath)
$signToolPath = ''
if ($hasSigningMaterial) {
    $signToolPath = Resolve-WindowsKitExecutable -Name 'signtool.exe'
    if (-not $signToolPath) {
        throw 'signtool.exe was not found. Install the Windows SDK/WDK signing tools.'
    }
}

$msbuildArgs = @(
    $projectPathFull,
    '/t:Build',
    "/p:Configuration=$Configuration",
    "/p:Platform=$Platform",
    "/p:OutDir=$($buildRootFull.TrimEnd('\\'))\\",
    "/p:IntDir=$($buildRootFull.TrimEnd('\\'))\\obj\\"
)

& $msbuildPath @msbuildArgs | Out-Host
if ($LASTEXITCODE -ne 0) {
    throw "Driver build failed with exit code $LASTEXITCODE"
}

$builtSysPath = Find-BuiltDriverBinary -BuildRoot $buildRootFull -DriverName 'AntivirusMinifilter.sys'
if (-not $builtSysPath) {
    throw "Built driver binary AntivirusMinifilter.sys was not found under $buildRootFull"
}

$outputInfPath = Join-Path $outputRootFull 'AntivirusMinifilter.inf'
$outputSysPath = Join-Path $outputRootFull 'AntivirusMinifilter.sys'
$outputCatPath = Join-Path $outputRootFull 'AntivirusMinifilter.cat'
$outputReadmePath = Join-Path $outputRootFull 'README.md'

Copy-Item -LiteralPath $driverInfFull -Destination $outputInfPath -Force
Copy-Item -LiteralPath $builtSysPath -Destination $outputSysPath -Force
if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'README.md')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'README.md') -Destination $outputReadmePath -Force
}

& $inf2catPath '/driver:'"$outputRootFull" '/os:10_X64' | Out-Host
if ($LASTEXITCODE -ne 0) {
    throw "inf2cat failed with exit code $LASTEXITCODE"
}

if (-not (Test-Path -LiteralPath $outputCatPath)) {
    throw "Catalog file was not generated: $outputCatPath"
}

if ($hasSigningMaterial) {
    Sign-File -SignToolPath $signToolPath -FilePath $outputSysPath -Thumbprint $SigningCertificateThumbprint -PfxPath $SigningPfxPath -PfxPassword $SigningPfxPassword -TimestampServer $TimestampServer
    Sign-File -SignToolPath $signToolPath -FilePath $outputCatPath -Thumbprint $SigningCertificateThumbprint -PfxPath $SigningPfxPath -PfxPassword $SigningPfxPassword -TimestampServer $TimestampServer
}
elseif (-not $AllowUnsignedArtifacts) {
    throw 'No signing material was supplied. Provide -SigningCertificateThumbprint or -SigningPfxPath, or pass -AllowUnsignedArtifacts for non-production testing.'
}

$sysSignature = Get-AuthenticodeSignature -LiteralPath $outputSysPath
$catSignature = Get-AuthenticodeSignature -LiteralPath $outputCatPath
$sysValid = $sysSignature.Status -eq 'Valid'
$catValid = $catSignature.Status -eq 'Valid'

if ((-not $sysValid -or -not $catValid) -and -not $AllowUnsignedArtifacts) {
    throw "Signature validation failed (sys=$($sysSignature.Status), cat=$($catSignature.Status))."
}

$reportPath = Join-Path $outputRootFull 'driver-build-report.json'
$inventory = Get-ChildItem -LiteralPath $outputRootFull -File | ForEach-Object {
    [pscustomobject]@{
        path = $_.Name
        sizeBytes = $_.Length
        sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

$report = [pscustomobject]@{
    generatedAtUtc = [DateTime]::UtcNow.ToString('o')
    projectPath = $projectPathFull
    buildRoot = $buildRootFull
    outputRoot = $outputRootFull
    configuration = $Configuration
    platform = $Platform
    signed = [bool]($sysValid -and $catValid)
    signatureStatus = [pscustomobject]@{
        sys = [string]$sysSignature.Status
        cat = [string]$catSignature.Status
        sysSigner = if ($sysSignature.SignerCertificate) { [string]$sysSignature.SignerCertificate.Subject } else { '' }
        catSigner = if ($catSignature.SignerCertificate) { [string]$catSignature.SignerCertificate.Subject } else { '' }
    }
    artifacts = $inventory
}

[System.IO.File]::WriteAllText($reportPath, ($report | ConvertTo-Json -Depth 6), $utf8NoBom)
Write-Host "Driver package written to $outputRootFull"
Write-Host "Driver build report written to $reportPath"
