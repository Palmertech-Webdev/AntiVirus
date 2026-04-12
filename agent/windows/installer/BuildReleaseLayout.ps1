param(
    [string]$BuildRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'out\dev\build'),
    [string]$OutputRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'out\dev'),
    [string]$DriverArtifactRoot = '',
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

$windowsRoot = Split-Path $PSScriptRoot -Parent
$buildRoot = (Resolve-Path $BuildRoot).Path
$outputRoot = [System.IO.Path]::GetFullPath($OutputRoot)

if ($Clean -and (Test-Path -LiteralPath $outputRoot)) {
    $outputFull = [System.IO.Path]::GetFullPath($outputRoot)
    $buildFull = [System.IO.Path]::GetFullPath($buildRoot)
    Get-ChildItem -LiteralPath $outputRoot -Force | Where-Object {
        $itemFull = [System.IO.Path]::GetFullPath($_.FullName)
        -not $itemFull.StartsWith($buildFull, [System.StringComparison]::OrdinalIgnoreCase)
    } | Remove-Item -Recurse -Force
}

Ensure-Directory -Path $outputRoot
Ensure-Directory -Path (Join-Path $outputRoot 'tools')
Ensure-Directory -Path (Join-Path $outputRoot 'signatures')
Ensure-Directory -Path (Join-Path $outputRoot 'driver')
Ensure-Directory -Path (Join-Path $outputRoot 'docs')

$artifactMap = @(
    @{ Source = (Join-Path $buildRoot 'fenrir-agent-service.exe'); Target = (Join-Path $outputRoot 'fenrir-agent-service.exe') },
    @{ Source = (Join-Path $buildRoot 'fenrir-endpoint-client.exe'); Target = (Join-Path $outputRoot 'fenrir-endpoint-client.exe') },
    @{ Source = (Join-Path $buildRoot 'WebView2Loader.dll'); Target = (Join-Path $outputRoot 'WebView2Loader.dll') },
    @{ Source = (Join-Path $buildRoot 'fenrir-amsi-provider.dll'); Target = (Join-Path $outputRoot 'fenrir-amsi-provider.dll') },
    @{ Source = (Join-Path $buildRoot 'fenrir-scannercli.exe'); Target = (Join-Path $outputRoot 'tools\fenrir-scannercli.exe') },
    @{ Source = (Join-Path $buildRoot 'fenrir-amsitestcli.exe'); Target = (Join-Path $outputRoot 'tools\fenrir-amsitestcli.exe') },
    @{ Source = (Join-Path $buildRoot 'fenrir-etwtestcli.exe'); Target = (Join-Path $outputRoot 'tools\fenrir-etwtestcli.exe') },
    @{ Source = (Join-Path $buildRoot 'fenrir-wfptestcli.exe'); Target = (Join-Path $outputRoot 'tools\fenrir-wfptestcli.exe') },
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
    $relativePath = Get-RelativePath -Root $outputRoot -Path $_.FullName
    $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $inventory += [pscustomobject]@{
        path = $relativePath
        sizeBytes = $_.Length
        sha256 = $hash
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

Write-Host "Release layout written to $outputRoot"
Write-Host "Inventory written to $inventoryPath"
