param(
    [string]$BuildRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'out\dev\build'),
    [string]$OutputRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'out\dev'),
    [string]$InstallerOutputRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'out\install'),
    [string]$DriverArtifactRoot = '',
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

function Copy-IfPresent {
    param(
        [string]$Source,
        [string]$Destination
    )

    if (-not (Test-Path -LiteralPath $Source)) {
        throw "Required release artifact is missing: $Source"
    }

    Ensure-Directory -Path (Split-Path -Parent $Destination)
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
}

function Get-RelativePath {
    param(
        [string]$Root,
        [string]$Path
    )

    $rootFull = [System.IO.Path]::GetFullPath($Root)
    $pathFull = [System.IO.Path]::GetFullPath($Path)
    if ($pathFull.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $pathFull.Substring($rootFull.Length).TrimStart('\\')
    }

    return $pathFull
}

function Get-CMakeCacheValue {
    param(
        [string]$CachePath,
        [string]$VariableName
    )

    if (-not (Test-Path -LiteralPath $CachePath)) {
        return ''
    }

    $match = Select-String -Path $CachePath -Pattern "^${VariableName}:.*=(.+)$" | Select-Object -First 1
    if ($null -eq $match) {
        return ''
    }

    return $match.Matches[0].Groups[1].Value.Trim()
}

function Assert-PathPresent {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Required release artifact is missing: $Path"
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

function Find-MinGwRuntimeDll {
    param(
        [string]$BuildRoot,
        [string]$DllName
    )

    $cachePath = Join-Path $BuildRoot 'CMakeCache.txt'
    $compilerPath = Get-CMakeCacheValue -CachePath $cachePath -VariableName 'CMAKE_CXX_COMPILER'
    if (-not $compilerPath) {
        return ''
    }

    $compilerDir = Split-Path -Parent $compilerPath
    foreach ($candidate in @(
        (Join-Path $compilerDir $DllName),
        (Join-Path (Join-Path $compilerDir '..\\bin') $DllName)
    )) {
        $fullCandidate = [System.IO.Path]::GetFullPath($candidate)
        if (Test-Path -LiteralPath $fullCandidate) {
            return $fullCandidate
        }
    }

    return ''
}

function Test-PathWithin {
    param(
        [string]$Root,
        [string]$Path
    )

    $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd('\')
    $pathFull = [System.IO.Path]::GetFullPath($Path)
    if ($pathFull.Length -lt $rootFull.Length) {
        return $false
    }

    return $pathFull.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)
}

$windowsRoot = Split-Path $PSScriptRoot -Parent
$serviceSourceRoot = Join-Path $windowsRoot 'service'
$buildRoot = [System.IO.Path]::GetFullPath($BuildRoot)
$outputRoot = [System.IO.Path]::GetFullPath($OutputRoot)
$installerOutputRoot = [System.IO.Path]::GetFullPath($InstallerOutputRoot)
$webView2RuntimeInstallerFullPath = ''

if ($WebView2RuntimeInstallerPath) {
    $webView2RuntimeInstallerFullPath = [System.IO.Path]::GetFullPath($WebView2RuntimeInstallerPath)
    if (-not (Test-Path -LiteralPath $webView2RuntimeInstallerFullPath)) {
        throw "Configured WebView2 runtime installer was not found: $webView2RuntimeInstallerFullPath"
    }
}

if ($Clean -and (Test-Path -LiteralPath $outputRoot)) {
    Remove-Item -LiteralPath $outputRoot -Recurse -Force
}

Ensure-Directory -Path $buildRoot

$cmakeConfigureArgs = @(
    '-S', $serviceSourceRoot,
    '-B', $buildRoot,
    "-DANTIVIRUS_DEV_OUTPUT_ROOT=$outputRoot",
    "-DANTIVIRUS_INSTALL_OUTPUT_ROOT=$installerOutputRoot",
    "-DANTIVIRUS_WEBVIEW2_BOOTSTRAPPER:FILEPATH=$webView2RuntimeInstallerFullPath"
)

cmake @cmakeConfigureArgs | Out-Host
if ($LASTEXITCODE -ne 0) {
    throw "CMake configure failed with exit code $LASTEXITCODE"
}

cmake --build $buildRoot --target antivirus-agent-service antivirus-endpoint-client antivirus-pam-client antivirus-amsi-provider antivirus-scannercli antivirus-amsitestcli antivirus-etwtestcli antivirus-wfptestcli | Out-Host
if ($LASTEXITCODE -ne 0) {
    throw "CMake build failed with exit code $LASTEXITCODE"
}

Ensure-Directory -Path $outputRoot
Ensure-Directory -Path (Join-Path $outputRoot 'tools')
Ensure-Directory -Path (Join-Path $outputRoot 'signatures')
Ensure-Directory -Path (Join-Path $outputRoot 'driver')
Ensure-Directory -Path (Join-Path $outputRoot 'docs')

$requiredBuiltArtifacts = @(
    (Join-Path $outputRoot 'fenrir-agent-service.exe'),
    (Join-Path $outputRoot 'fenrir-endpoint-client.exe'),
    (Join-Path $outputRoot 'fenrir-pam.exe'),
    (Join-Path $outputRoot 'fenrir-amsi-provider.dll'),
    (Join-Path $outputRoot 'WebView2Loader.dll'),
    (Join-Path $outputRoot 'tools\fenrir-scannercli.exe'),
    (Join-Path $outputRoot 'tools\fenrir-amsitestcli.exe'),
    (Join-Path $outputRoot 'tools\fenrir-etwtestcli.exe'),
    (Join-Path $outputRoot 'tools\fenrir-wfptestcli.exe')
)

foreach ($artifactPath in $requiredBuiltArtifacts) {
    Assert-PathPresent -Path $artifactPath
}

$artifactMap = @(
    @{ Source = (Join-Path $windowsRoot 'service\README.md'); Target = (Join-Path $outputRoot 'docs\service-README.md') },
    @{ Source = (Join-Path $windowsRoot 'tools\endpointui\README.md'); Target = (Join-Path $outputRoot 'docs\endpoint-client-README.md') },
    @{ Source = (Join-Path $windowsRoot 'installer\README.md'); Target = (Join-Path $outputRoot 'docs\installer-README.md') },
    @{ Source = (Join-Path $windowsRoot 'signatures\default-signatures.tsv'); Target = (Join-Path $outputRoot 'signatures\default-signatures.tsv') },
    @{ Source = (Join-Path $windowsRoot 'driver\minifilter\AntivirusMinifilter.inf'); Target = (Join-Path $outputRoot 'driver\AntivirusMinifilter.inf') },
    @{ Source = (Join-Path $windowsRoot 'driver\minifilter\README.md'); Target = (Join-Path $outputRoot 'driver\README.md') }
)

foreach ($artifact in $artifactMap) {
    Copy-IfPresent -Source $artifact.Source -Destination $artifact.Target
}

$winpthreadRuntime = Find-MinGwRuntimeDll -BuildRoot $buildRoot -DllName 'libwinpthread-1.dll'
if ($winpthreadRuntime) {
    Copy-IfPresent -Source $winpthreadRuntime -Destination (Join-Path $outputRoot 'libwinpthread-1.dll')
    Copy-IfPresent -Source $winpthreadRuntime -Destination (Join-Path $outputRoot 'tools\libwinpthread-1.dll')
}

if ($DriverArtifactRoot) {
    $driverRoot = (Resolve-Path $DriverArtifactRoot).Path
    foreach ($name in @('AntivirusMinifilter.sys', 'AntivirusMinifilter.cat')) {
        $source = Join-Path $driverRoot $name
        if (Test-Path -LiteralPath $source) {
            Copy-IfPresent -Source $source -Destination (Join-Path $outputRoot "driver\$name")
        }
    }
}

$inventory = @()
Get-ChildItem -LiteralPath $outputRoot -Recurse -File | ForEach-Object {
    if (-not (Test-PathWithin -Root $buildRoot -Path $_.FullName)) {
        $relativePath = Get-RelativePath -Root $outputRoot -Path $_.FullName
        $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        $inventory += [pscustomobject]@{
            path = $relativePath
            sizeBytes = $_.Length
            sha256 = $hash
        }
    }
}

$inventoryPath = Join-Path $outputRoot 'release-inventory.json'
$inventoryDocument = [pscustomobject]@{
    generatedAt = [DateTime]::UtcNow.ToString('o')
    buildRoot = $buildRoot
    outputRoot = $outputRoot
    artifacts = $inventory
}
$inventoryDocument | ConvertTo-Json -Depth 4 | Out-File -LiteralPath $inventoryPath -Encoding utf8

Remove-LegacyBuildOutputs -BuildRoot $buildRoot

Write-Host "Release layout written to $outputRoot"
Write-Host "Inventory written to $inventoryPath"
