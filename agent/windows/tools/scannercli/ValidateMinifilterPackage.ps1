param(
  [string]$WorkspaceRoot = ".",
  [string]$DriverRoot = "./agent/windows/out/dev/driver",
  [string]$WorkingRoot = "./tmp-phase1-minifilter-package",
  [string]$ExpectedServiceName = "AntivirusMinifilter",
  [bool]$RequireSignedArtifacts = $true,
  [bool]$RequireServiceInstalled = $true,
  [bool]$RequireServiceRunning = $true,
  [bool]$RequireBrokerProbe = $true,
  [bool]$RequireLiveInterception = $true
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

function Resolve-AbsolutePath {
  param(
    [Parameter(Mandatory = $true)]
    [string]$InputPath,
    [switch]$MustExist
  )

  $candidate = $InputPath
  if (-not [System.IO.Path]::IsPathRooted($candidate)) {
    $candidate = Join-Path $script:WorkspaceRootAbsolute $candidate
  }

  $resolved = [System.IO.Path]::GetFullPath($candidate)
  if ($MustExist -and -not (Test-Path -LiteralPath $resolved)) {
    throw "Path does not exist: $resolved"
  }

  return $resolved
}

function Add-Check {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Name,
    [Parameter(Mandatory = $true)]
    [string]$Status,
    [Parameter(Mandatory = $true)]
    [string]$Details
  )

  $script:Checks.Add([PSCustomObject]@{
      name = $Name
      status = $Status
      details = $Details
    }) | Out-Null
}

function Get-AuthenticodeDetails {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path
  )

  try {
    $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
    $subject = ""
    if ($null -ne $signature.SignerCertificate) {
      $subject = [string]$signature.SignerCertificate.Subject
    }

    return [PSCustomObject]@{
      status = [string]$signature.Status
      statusMessage = [string]$signature.StatusMessage
      signerSubject = $subject
      isValid = ([string]$signature.Status -eq "Valid")
    }
  } catch {
    return [PSCustomObject]@{
      status = "Error"
      statusMessage = $_.Exception.Message
      signerSubject = ""
      isValid = $false
    }
  }
}

function Test-IsRunningAsAdministrator {
  try {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch {
    return $false
  }
}

$workspaceCandidate = $WorkspaceRoot
if (-not [System.IO.Path]::IsPathRooted($workspaceCandidate)) {
  $workspaceCandidate = Join-Path (Get-Location) $workspaceCandidate
}
$script:WorkspaceRootAbsolute = [System.IO.Path]::GetFullPath($workspaceCandidate)
$driverRootAbsolute = Resolve-AbsolutePath -InputPath $DriverRoot
$workingRootAbsolute = Resolve-AbsolutePath -InputPath $WorkingRoot
$null = New-Item -ItemType Directory -Force -Path $workingRootAbsolute

$script:Checks = [System.Collections.Generic.List[object]]::new()

$infPath = Join-Path $driverRootAbsolute "AntivirusMinifilter.inf"
$sysPath = Join-Path $driverRootAbsolute "AntivirusMinifilter.sys"
$catPath = Join-Path $driverRootAbsolute "AntivirusMinifilter.cat"

$infExists = Test-Path -LiteralPath $infPath
$sysExists = Test-Path -LiteralPath $sysPath
$catExists = Test-Path -LiteralPath $catPath

if ($infExists -and $sysExists -and $catExists) {
  Add-Check -Name "driver_artifacts" -Status "pass" -Details "Driver package includes INF, SYS, and CAT artifacts."
} else {
  $missing = @()
  if (-not $infExists) {
    $missing += "INF"
  }
  if (-not $sysExists) {
    $missing += "SYS"
  }
  if (-not $catExists) {
    $missing += "CAT"
  }

  Add-Check -Name "driver_artifacts" -Status "fail" -Details ("Driver package is missing artifact(s): {0}" -f ($missing -join ", "))
}

if ($infExists) {
  $infText = Get-Content -LiteralPath $infPath -Raw
  $catalogMatch = [regex]::Match($infText, "(?im)^CatalogFile\s*=\s*(.+)$")
  $serviceMatch = [regex]::Match($infText, '(?im)^ServiceName\s*=\s*"?([^"\r\n]+)"?')

  $catalogValue = if ($catalogMatch.Success) { $catalogMatch.Groups[1].Value.Trim() } else { "" }
  $serviceValue = if ($serviceMatch.Success) { $serviceMatch.Groups[1].Value.Trim() } else { "" }

  if ($catalogValue -ieq "AntivirusMinifilter.cat") {
    Add-Check -Name "inf_catalog_binding" -Status "pass" -Details "INF CatalogFile entry points to AntivirusMinifilter.cat."
  } else {
    Add-Check -Name "inf_catalog_binding" -Status "fail" -Details ("INF CatalogFile entry is '{0}' (expected AntivirusMinifilter.cat)." -f $catalogValue)
  }

  if ($serviceValue -ieq $ExpectedServiceName) {
    Add-Check -Name "inf_service_name" -Status "pass" -Details ("INF ServiceName entry is '{0}'." -f $serviceValue)
  } else {
    Add-Check -Name "inf_service_name" -Status "fail" -Details ("INF ServiceName entry is '{0}' (expected '{1}')." -f $serviceValue, $ExpectedServiceName)
  }
}

$sysSignature = $null
if ($sysExists) {
  $sysSignature = Get-AuthenticodeDetails -Path $sysPath
  if ($sysSignature.isValid) {
    Add-Check -Name "sys_signature" -Status "pass" -Details "Driver SYS Authenticode signature status is Valid."
  } else {
    $status = if ($RequireSignedArtifacts) { "fail" } else { "warning" }
    Add-Check -Name "sys_signature" -Status $status -Details ("Driver SYS signature status is '{0}' ({1})." -f $sysSignature.status, $sysSignature.statusMessage)
  }
}

$catSignature = $null
if ($catExists) {
  $catSignature = Get-AuthenticodeDetails -Path $catPath
  if ($catSignature.isValid) {
    Add-Check -Name "cat_signature" -Status "pass" -Details "Driver CAT Authenticode signature status is Valid."
  } else {
    $status = if ($RequireSignedArtifacts) { "fail" } else { "warning" }
    Add-Check -Name "cat_signature" -Status $status -Details ("Driver CAT signature status is '{0}' ({1})." -f $catSignature.status, $catSignature.statusMessage)
  }
}

$service = Get-Service -Name $ExpectedServiceName -ErrorAction SilentlyContinue
if ($null -ne $service) {
  Add-Check -Name "service_registration" -Status "pass" -Details ("Service '{0}' is registered with state '{1}'." -f $ExpectedServiceName, [string]$service.Status)
} else {
  if ($RequireServiceInstalled) {
    Add-Check -Name "service_registration" -Status "fail" -Details ("Service '{0}' is not registered on this host." -f $ExpectedServiceName)
  } else {
    Add-Check -Name "service_registration" -Status "warning" -Details ("Service '{0}' is not registered on this host (warning only for packaging validation)." -f $ExpectedServiceName)
  }
}

if ($null -ne $service) {
  if ([string]$service.Status -eq "Running") {
    Add-Check -Name "service_running" -Status "pass" -Details ("Service '{0}' is running." -f $ExpectedServiceName)
  } else {
    $status = if ($RequireServiceRunning) { "fail" } else { "warning" }
    Add-Check -Name "service_running" -Status $status -Details ("Service '{0}' is registered but state is '{1}'." -f $ExpectedServiceName, [string]$service.Status)
  }
} else {
  $status = if ($RequireServiceRunning) { "fail" } else { "warning" }
  Add-Check -Name "service_running" -Status $status -Details ("Service '{0}' is not registered, so running-state validation could not be performed." -f $ExpectedServiceName)
}

$fltmcPath = Join-Path $env:SystemRoot "System32\fltmc.exe"
if (Test-Path -LiteralPath $fltmcPath) {
  try {
    $fltmcOutput = & $fltmcPath filters 2>&1 | Out-String
    $fltmcExitCode = $LASTEXITCODE
    $minifilterLoaded = $false
    if ($fltmcExitCode -eq 0) {
      $minifilterLoaded = $fltmcOutput -match [regex]::Escape($ExpectedServiceName)
    }

    if ($minifilterLoaded) {
      Add-Check -Name "live_interception_path" -Status "pass" -Details ("fltmc reports '{0}' in the loaded minifilter list." -f $ExpectedServiceName)
    } else {
      $status = if ($RequireLiveInterception) { "fail" } else { "warning" }
      $details = if ($fltmcExitCode -ne 0) {
        "fltmc filters failed with exit code $fltmcExitCode."
      } else {
        ("fltmc did not report '{0}' in the loaded minifilter list." -f $ExpectedServiceName)
      }
      Add-Check -Name "live_interception_path" -Status $status -Details $details
    }
  } catch {
    $status = if ($RequireLiveInterception) { "fail" } else { "warning" }
    Add-Check -Name "live_interception_path" -Status $status -Details ("Could not query loaded minifilters with fltmc: {0}" -f $_.Exception.Message)
  }
} else {
  $status = if ($RequireLiveInterception) { "fail" } else { "warning" }
  Add-Check -Name "live_interception_path" -Status $status -Details "fltmc.exe was not found; live minifilter load validation could not run."
}

$scannerCliPath = Resolve-AbsolutePath -InputPath "./agent/windows/out/dev/tools/fenrir-scannercli.exe"
if (Test-Path -LiteralPath $scannerCliPath) {
  try {
    $probeRoot = Join-Path $workingRootAbsolute "broker-probe"
    $null = New-Item -ItemType Directory -Force -Path $probeRoot
    $probePath = Join-Path $probeRoot "broker-execute-eicar.ps1"
    $probePayload = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    Set-Content -LiteralPath $probePath -Value $probePayload -Encoding ASCII

    $probeOutput = & $scannerCliPath --json --realtime-op execute $probePath 2>&1 | Out-String
    $probeExitCode = $LASTEXITCODE
    $blocked = ($probeExitCode -eq 2 -or $probeExitCode -eq 3)

    if ($blocked) {
      Add-Check -Name "broker_execute_probe" -Status "pass" -Details ("Realtime broker execute probe blocked the staged EICAR sample (exit code {0})." -f $probeExitCode)
    } else {
      $status = if ($RequireBrokerProbe) { "fail" } else { "warning" }
      $truncatedOutput = if ($probeOutput.Length -gt 512) { $probeOutput.Substring(0, 512) + "..." } else { $probeOutput }
      Add-Check -Name "broker_execute_probe" -Status $status -Details ("Realtime broker execute probe did not block staged sample (exit code {0}). Output: {1}" -f $probeExitCode, $truncatedOutput.Trim())
    }
  } catch {
    $status = if ($RequireBrokerProbe) { "fail" } else { "warning" }
    Add-Check -Name "broker_execute_probe" -Status $status -Details ("Could not run realtime broker execute probe: {0}" -f $_.Exception.Message)
  }
} else {
  $status = if ($RequireBrokerProbe) { "fail" } else { "warning" }
  Add-Check -Name "broker_execute_probe" -Status $status -Details ("Scanner CLI was not found at '{0}'." -f $scannerCliPath)
}

$inventory = [System.Collections.Generic.List[object]]::new()
foreach ($artifactPath in @($infPath, $sysPath, $catPath)) {
  if (-not (Test-Path -LiteralPath $artifactPath)) {
    continue
  }

  $item = Get-Item -LiteralPath $artifactPath
  $hash = (Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $inventory.Add([PSCustomObject]@{
      path = $artifactPath
      sizeBytes = $item.Length
      sha256 = $hash
      lastWriteTimeUtc = $item.LastWriteTimeUtc.ToString("o")
    }) | Out-Null
}

$failedChecks = @($script:Checks | Where-Object { $_.status -eq "fail" })
$warningChecks = @($script:Checks | Where-Object { $_.status -eq "warning" })
$allPass = $failedChecks.Count -eq 0
$overallStatus = if ($failedChecks.Count -gt 0) { "fail" } elseif ($warningChecks.Count -gt 0) { "warning" } else { "pass" }

$reportPath = Join-Path $workingRootAbsolute "minifilter-package-validation-report.json"
$report = [PSCustomObject]@{
  generatedAtUtc = [DateTime]::UtcNow.ToString("o")
  workspaceRoot = $script:WorkspaceRootAbsolute
  driverRoot = $driverRootAbsolute
  requireSignedArtifacts = $RequireSignedArtifacts
  requireServiceInstalled = [bool]$RequireServiceInstalled
  requireServiceRunning = [bool]$RequireServiceRunning
  requireBrokerProbe = [bool]$RequireBrokerProbe
  requireLiveInterception = [bool]$RequireLiveInterception
  expectedServiceName = $ExpectedServiceName
  overallStatus = $overallStatus
  allPass = $allPass
  checks = $script:Checks
  signatures = [PSCustomObject]@{
    sys = $sysSignature
    cat = $catSignature
  }
  artifacts = $inventory
}

$reportJson = ConvertTo-Json -InputObject $report -Depth 8
Set-Content -Path $reportPath -Value $reportJson -Encoding UTF8

foreach ($check in $script:Checks) {
  Write-Host ("{0}`t{1}`t{2}" -f $check.name, $check.status, $check.details)
}
Write-Host "REPORT_PATH=$reportPath"
Write-Host ("MINIFILTER_PACKAGE_VALIDATION={0}" -f ($(if ($allPass) { "PASS" } else { "FAIL" })))

if ($allPass) {
  exit 0
}

exit 2
