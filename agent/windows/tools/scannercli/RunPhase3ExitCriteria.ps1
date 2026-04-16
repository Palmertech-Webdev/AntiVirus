param(
  [string]$ServicePath = "./agent/windows/out/dev/fenrir-agent-service.exe",
  [string]$WorkspaceRoot = ".",
  [string]$WorkingRoot = "./tmp-phase3-exitcriteria",
  [switch]$SkipCorpus,
  [switch]$SkipHostileInputFuzz,
  [string[]]$RequiredCheckIds = @(
    "phase3_runtime_trust_fail_closed",
    "phase3_updater_manifest_trust_and_rollback",
    "phase3_uninstall_service_launch_posture"
  ),
  [string[]]$WarningAllowedCheckIds = @(
    "phase3_uninstall_service_launch_posture"
  )
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

$workspaceCandidate = $WorkspaceRoot
if (-not [System.IO.Path]::IsPathRooted($workspaceCandidate)) {
  $workspaceCandidate = Join-Path (Get-Location) $workspaceCandidate
}
$script:WorkspaceRootAbsolute = [System.IO.Path]::GetFullPath($workspaceCandidate)
$serviceAbsolute = Resolve-AbsolutePath -InputPath $ServicePath -MustExist
$workingRootAbsolute = Resolve-AbsolutePath -InputPath $WorkingRoot
New-Item -ItemType Directory -Force -Path $workingRootAbsolute | Out-Null

if ($SkipCorpus -or $SkipHostileInputFuzz) {
  Write-Warning "SkipCorpus/SkipHostileInputFuzz flags are retained for backward compatibility and do not alter Phase 3 trust gate behavior."
}

$stdout = & $serviceAbsolute --self-test
$selfTestExitCode = $LASTEXITCODE
$jsonText = ($stdout | Out-String).Trim()
if ([string]::IsNullOrWhiteSpace($jsonText)) {
  throw "Service returned no JSON output."
}

try {
  $selfTestReport = $jsonText | ConvertFrom-Json
} catch {
  throw "Service returned non-JSON self-test output.`nOutput: $jsonText"
}

$phase3Checks = @()
if ($null -ne $selfTestReport.checks) {
  foreach ($check in @($selfTestReport.checks)) {
    if ($null -eq $check) {
      continue
    }

    $checkId = ""
    try {
      $checkId = [string]$check.id
    } catch {
      $checkId = ""
    }

    if ($checkId.StartsWith("phase3_", [System.StringComparison]::OrdinalIgnoreCase)) {
      $phase3Checks += $check
    }
  }
}

$indexedChecks = @{}
foreach ($check in $phase3Checks) {
  $indexedChecks["$($check.id)"] = $check
}

$criteria = [System.Collections.Generic.List[object]]::new()
foreach ($requiredId in $RequiredCheckIds) {
  if ($indexedChecks.ContainsKey($requiredId)) {
    $check = $indexedChecks[$requiredId]
    $status = "$($check.status)"
    $isPass = $status -eq "pass" -or ($WarningAllowedCheckIds -contains $requiredId -and $status -eq "warning")
    $criteria.Add([PSCustomObject]@{
        Criterion = $requiredId
        Status = if ($isPass) { "pass" } else { "fail" }
        RawStatus = $status
        Details = "$($check.details)"
        Remediation = "$($check.remediation)"
      }) | Out-Null
  } else {
    $criteria.Add([PSCustomObject]@{
        Criterion = $requiredId
        Status = "fail"
        RawStatus = "missing"
        Details = "Required Phase 3 check was not present in self-test output."
        Remediation = "Ensure the service self-test publishes the required Phase 3 trust and anti-tamper checks."
      }) | Out-Null
  }
}

$phase3UnexpectedChecks = @()
foreach ($check in $phase3Checks) {
  if ($RequiredCheckIds -notcontains ([string]$check.id)) {
    $phase3UnexpectedChecks += $check
  }
}

$failedCriteriaCount = 0
foreach ($criterion in $criteria) {
  if ([string]$criterion.Status -ne "pass") {
    $failedCriteriaCount++
  }
}

$allCriteriaPass = $failedCriteriaCount -eq 0
$reportPath = Join-Path $workingRootAbsolute "phase3-exitcriteria-report.json"
$additionalPhase3Checks = @()
foreach ($check in $phase3UnexpectedChecks) {
  $additionalPhase3Checks += [PSCustomObject]@{
    id = "$($check.id)"
    name = "$($check.name)"
    status = "$($check.status)"
    details = "$($check.details)"
    remediation = "$($check.remediation)"
  }
}

$report = [PSCustomObject]@{
  generatedAtUtc = [DateTime]::UtcNow.ToString("o")
  servicePath = $serviceAbsolute
  selfTestExitCode = $selfTestExitCode
  selfTestOverallStatus = "$($selfTestReport.overallStatus)"
  requiredCheckIds = $RequiredCheckIds
  warningAllowedCheckIds = $WarningAllowedCheckIds
  criteria = $criteria
  additionalPhase3Checks = $additionalPhase3Checks
  allCriteriaPass = $allCriteriaPass
}

$reportJson = ConvertTo-Json -InputObject $report -Depth 8
Set-Content -Path $reportPath -Encoding UTF8 -Value $reportJson

foreach ($criterion in $criteria) {
  Write-Host ("{0}`t{1}`t{2}" -f "$($criterion.Criterion)", "$($criterion.Status)", "$($criterion.Details)")
}

Write-Host "REPORT_PATH=$reportPath"
Write-Host ("PHASE3_EXIT_CRITERIA={0}" -f ($(if ($allCriteriaPass) { "PASS" } else { "FAIL" })))

if ($allCriteriaPass) {
  exit 0
}

exit 2
