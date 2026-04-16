param(
  [string]$WorkspaceRoot = ".",
  [string]$DriverRoot = "./agent/windows/out/dev/driver",
  [string]$ExpectedServiceName = "AntivirusMinifilter",
  [string]$PackageValidationWorkingRoot = "./tmp-phase1-minifilter-package",
  [string]$Phase1WorkingRoot = "./tmp-phase1-exitcriteria",
  [string]$Phase1ScannerRuntimeRoot = "./tmp-phase1-runtime",
  [string]$CleanwareCorpusPath = "./tmp-phase1-corpora/cleanware",
  [string]$UkBusinessCorpusPath = "./tmp-phase1-corpora/uk-business-software",
  [int]$MinCleanwareFiles = 100,
  [int]$MinUkBusinessFiles = 100,
  [switch]$SkipFullPhase1Gate
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

function Test-IsRunningAsAdministrator {
  try {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch {
    return $false
  }
}

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

function Test-WorkspaceRootCandidate {
  param(
    [Parameter(Mandatory = $true)]
    [string]$CandidatePath
  )

  if ([string]::IsNullOrWhiteSpace($CandidatePath)) {
    return $false
  }

  $root = [System.IO.Path]::GetFullPath($CandidatePath)
  $scannerToolsRoot = Join-Path $root "agent/windows/tools/scannercli"
  $phase1Script = Join-Path $scannerToolsRoot "RunPhase1ExitCriteria.ps1"
  $validateScript = Join-Path $scannerToolsRoot "ValidateMinifilterPackage.ps1"
  $agentRoot = Join-Path $root "agent/windows"

  return (Test-Path -LiteralPath $phase1Script) -and
    (Test-Path -LiteralPath $validateScript) -and
    (Test-Path -LiteralPath $agentRoot)
}

function Find-WorkspaceRootFromStart {
  param(
    [Parameter(Mandatory = $true)]
    [string]$StartPath
  )

  $cursor = [System.IO.Path]::GetFullPath($StartPath)
  while ($true) {
    if (Test-WorkspaceRootCandidate -CandidatePath $cursor) {
      return $cursor
    }

    $parent = [System.IO.Directory]::GetParent($cursor)
    if ($null -eq $parent) {
      break
    }

    $cursor = $parent.FullName
  }

  return ""
}

function Resolve-WorkspaceRoot {
  param(
    [Parameter(Mandatory = $true)]
    [string]$InputWorkspaceRoot
  )

  $candidate = if ([string]::IsNullOrWhiteSpace($InputWorkspaceRoot)) { "." } else { $InputWorkspaceRoot }
  if (-not [System.IO.Path]::IsPathRooted($candidate)) {
    $candidate = Join-Path (Get-Location) $candidate
  }

  $resolvedCandidate = [System.IO.Path]::GetFullPath($candidate)
  if (Test-WorkspaceRootCandidate -CandidatePath $resolvedCandidate) {
    return $resolvedCandidate
  }

  $searchRoots = @(
    (Get-Location).Path,
    $PSScriptRoot,
    $resolvedCandidate
  )

  foreach ($searchRoot in $searchRoots) {
    $found = Find-WorkspaceRootFromStart -StartPath $searchRoot
    if (-not [string]::IsNullOrWhiteSpace($found)) {
      Write-Warning (("WorkspaceRoot '{0}' resolved to repository root '{1}' via upward search.") -f $InputWorkspaceRoot, $found)
      return $found
    }
  }

  throw (("Workspace root could not be resolved from '{0}'. Run from the repository root or pass -WorkspaceRoot with the repository root path.") -f $InputWorkspaceRoot)
}

function Get-HostExecutablePath {
  try {
    $processPath = (Get-Process -Id $PID).Path
    if (-not [string]::IsNullOrWhiteSpace($processPath) -and (Test-Path -LiteralPath $processPath)) {
      return $processPath
    }
  } catch {
  }

  return "powershell.exe"
}

function Invoke-NativeCommand {
  param(
    [Parameter(Mandatory = $true)]
    [string]$FilePath,
    [Parameter(Mandatory = $true)]
    [string[]]$Arguments,
    [switch]$AllowFailure
  )

  Write-Host ((">> {0} {1}") -f $FilePath, ($Arguments -join " "))
  & $FilePath @Arguments | Out-Host
  $exitCode = $LASTEXITCODE

  if (-not $AllowFailure -and $exitCode -ne 0) {
    throw (("Command failed with exit code {0}: {1} {2}") -f $exitCode, $FilePath, ($Arguments -join " "))
  }

  return $exitCode
}

$script:WorkspaceRootAbsolute = Resolve-WorkspaceRoot -InputWorkspaceRoot $WorkspaceRoot
$scriptPath = [System.IO.Path]::GetFullPath($MyInvocation.MyCommand.Path)
$hostExecutablePath = Get-HostExecutablePath

Write-Host (("WORKSPACE_ROOT={0}") -f $script:WorkspaceRootAbsolute)

if (-not (Test-IsRunningAsAdministrator)) {
  Write-Host "Requesting elevation to enforce strict minifilter service registration checks..."

  $relaunchArgs = @(
    "-NoProfile",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
    $scriptPath,
    "-WorkspaceRoot",
    $script:WorkspaceRootAbsolute,
    "-DriverRoot",
    $DriverRoot,
    "-ExpectedServiceName",
    $ExpectedServiceName,
    "-PackageValidationWorkingRoot",
    $PackageValidationWorkingRoot,
    "-Phase1WorkingRoot",
    $Phase1WorkingRoot,
    "-Phase1ScannerRuntimeRoot",
    $Phase1ScannerRuntimeRoot,
    "-CleanwareCorpusPath",
    $CleanwareCorpusPath,
    "-UkBusinessCorpusPath",
    $UkBusinessCorpusPath,
    "-MinCleanwareFiles",
    $MinCleanwareFiles.ToString(),
    "-MinUkBusinessFiles",
    $MinUkBusinessFiles.ToString()
  )

  if ($SkipFullPhase1Gate) {
    $relaunchArgs += "-SkipFullPhase1Gate"
  }

  try {
    $process = Start-Process -FilePath $hostExecutablePath -ArgumentList $relaunchArgs -Verb RunAs -PassThru -Wait
    exit $process.ExitCode
  } catch {
    throw "Elevation was cancelled or failed. Re-run in an elevated shell."
  }
}

$driverRootAbsolute = Resolve-AbsolutePath -InputPath $DriverRoot -MustExist
$validateScriptPath = Join-Path $script:WorkspaceRootAbsolute "agent/windows/tools/scannercli/ValidateMinifilterPackage.ps1"
$phase1ScriptPath = Join-Path $script:WorkspaceRootAbsolute "agent/windows/tools/scannercli/RunPhase1ExitCriteria.ps1"

if (-not (Test-Path -LiteralPath $validateScriptPath)) {
  throw "Package validation script was not found: $validateScriptPath"
}
if (-not (Test-Path -LiteralPath $phase1ScriptPath)) {
  throw "Phase 1 gate script was not found: $phase1ScriptPath"
}

$infPath = Join-Path $driverRootAbsolute "AntivirusMinifilter.inf"
$sysPath = Join-Path $driverRootAbsolute "AntivirusMinifilter.sys"
$catPath = Join-Path $driverRootAbsolute "AntivirusMinifilter.cat"

foreach ($requiredPath in @($infPath, $sysPath, $catPath)) {
  if (-not (Test-Path -LiteralPath $requiredPath)) {
    throw "Required driver artifact was not found: $requiredPath"
  }
}

$pnputilPath = Join-Path $env:SystemRoot "System32\pnputil.exe"
if (Test-Path -LiteralPath $pnputilPath) {
  $pnputilExitCode = Invoke-NativeCommand -FilePath $pnputilPath -Arguments @("/add-driver", $infPath, "/install") -AllowFailure
  if ($pnputilExitCode -ne 0) {
    Write-Warning "pnputil returned a non-zero exit code. SetupAPI INF install will run next."
  }
} else {
  Write-Warning "pnputil.exe was not found; continuing with SetupAPI INF install."
}

$rundll32Path = Join-Path $env:SystemRoot "System32\rundll32.exe"
if (-not (Test-Path -LiteralPath $rundll32Path)) {
  throw "rundll32.exe was not found: $rundll32Path"
}

$setupApiExitCode = Invoke-NativeCommand -FilePath $rundll32Path -Arguments @(
  "setupapi.dll,InstallHinfSection",
  "DefaultInstall",
  "132",
  $infPath
) -AllowFailure

if ($setupApiExitCode -ne 0) {
  Write-Warning "SetupAPI INF install returned a non-zero exit code. Service registration will still be verified explicitly."
}

$service = Get-Service -Name $ExpectedServiceName -ErrorAction SilentlyContinue
if ($null -eq $service) {
  throw (("Service '{0}' is still not registered after INF installation attempts.") -f $ExpectedServiceName)
}

Write-Host (("SERVICE_REGISTRATION=PASS name={0} state={1}") -f $ExpectedServiceName, [string]$service.Status)

$validateArgs = @(
  "-NoProfile",
  "-ExecutionPolicy",
  "Bypass",
  "-File",
  $validateScriptPath,
  "-WorkspaceRoot",
  $script:WorkspaceRootAbsolute,
  "-DriverRoot",
  $driverRootAbsolute,
  "-WorkingRoot",
  $PackageValidationWorkingRoot,
  "-ExpectedServiceName",
  $ExpectedServiceName,
  "-RequireSignedArtifacts:$true",
  "-RequireServiceInstalled:$true"
)

$validateExitCode = Invoke-NativeCommand -FilePath $hostExecutablePath -Arguments $validateArgs -AllowFailure
if ($validateExitCode -ne 0) {
  throw (("ValidateMinifilterPackage.ps1 failed with exit code {0}") -f $validateExitCode)
}

if (-not $SkipFullPhase1Gate) {
  $phase1Args = @(
    "-NoProfile",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
    $phase1ScriptPath,
    "-WorkspaceRoot",
    $script:WorkspaceRootAbsolute,
    "-WorkingRoot",
    $Phase1WorkingRoot,
    "-ScannerRuntimeRoot",
    $Phase1ScannerRuntimeRoot,
    "-CleanwareCorpusPath",
    $CleanwareCorpusPath,
    "-UkBusinessCorpusPath",
    $UkBusinessCorpusPath,
    "-MinCleanwareFiles",
    $MinCleanwareFiles.ToString(),
    "-MinUkBusinessFiles",
    $MinUkBusinessFiles.ToString(),
    "-RequireMinifilterServiceInstalled:$true"
  )

  $phase1ExitCode = Invoke-NativeCommand -FilePath $hostExecutablePath -Arguments $phase1Args -AllowFailure
  if ($phase1ExitCode -ne 0) {
    throw (("RunPhase1ExitCriteria.ps1 failed with exit code {0}") -f $phase1ExitCode)
  }
}

$packageReportPath = Join-Path (Resolve-AbsolutePath -InputPath $PackageValidationWorkingRoot) "minifilter-package-validation-report.json"
Write-Host (("PACKAGE_REPORT_PATH={0}") -f $packageReportPath)

if (-not $SkipFullPhase1Gate) {
  $phase1ReportPath = Join-Path (Resolve-AbsolutePath -InputPath $Phase1WorkingRoot) "phase1-exitcriteria-report.json"
  Write-Host (("PHASE1_REPORT_PATH={0}") -f $phase1ReportPath)
}

Write-Host "PHASE1_ELEVATED_COMPLETION=PASS"
exit 0