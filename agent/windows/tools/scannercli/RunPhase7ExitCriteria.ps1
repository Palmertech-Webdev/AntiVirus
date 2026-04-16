param(
  [string]$ServicePath = "./agent/windows/out/dev/fenrir-agent-service.exe",
  [string]$WorkspaceRoot = ".",
  [string]$WorkingRoot = "./tmp-phase7-exitcriteria",
  [string[]]$RequiredCheckIds = @(
    "phase7_resource_budget_snapshot",
    "phase7_windows_compatibility_baseline",
    "phase7_release_promotion_gates",
    "phase7_defender_companion_mode"
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

$stdout = & $serviceAbsolute --self-test
$selfTestExitCode = $LASTEXITCODE
$jsonText = ($stdout | Out-String).Trim()
if ([string]::IsNullOrWhiteSpace($jsonText)) {
  throw "Service returned no JSON output."
}

try {
  $selfTestReport = ConvertFrom-Json -InputObject $jsonText
} catch {
  throw "Service returned non-JSON self-test output.`nOutput: $jsonText"
}

$phase7Checks = @()
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

    if ($checkId.StartsWith("phase7_", [System.StringComparison]::OrdinalIgnoreCase)) {
      $phase7Checks += $check
    }
  }
}

$indexedChecks = @{}
foreach ($check in $phase7Checks) {
  $indexedChecks["$($check.id)"] = $check
}

$criteria = [System.Collections.Generic.List[object]]::new()
foreach ($requiredId in $RequiredCheckIds) {
  if ($indexedChecks.ContainsKey($requiredId)) {
    $check = $indexedChecks[$requiredId]
    $criteria.Add([PSCustomObject]@{
        Criterion = $requiredId
        Status = if ("$($check.status)" -eq "pass") { "pass" } else { "fail" }
        RawStatus = "$($check.status)"
        Details = "$($check.details)"
        Remediation = "$($check.remediation)"
      }) | Out-Null
  } else {
    $criteria.Add([PSCustomObject]@{
        Criterion = $requiredId
        Status = "fail"
        RawStatus = "missing"
        Details = "Required Phase 7 check was not present in self-test output."
        Remediation = "Ensure the service self-test publishes the required Phase 7 performance, compatibility, and promotion checks."
      }) | Out-Null
  }
}

$phase7UnexpectedChecks = @()
foreach ($check in $phase7Checks) {
  if ($RequiredCheckIds -notcontains ([string]$check.id)) {
    $phase7UnexpectedChecks += $check
  }
}

$failedCriteriaCount = 0
foreach ($criterion in $criteria) {
  if ([string]$criterion.Status -ne "pass") {
    $failedCriteriaCount++
  }
}
$allCriteriaPass = $failedCriteriaCount -eq 0
$reportPath = Join-Path $workingRootAbsolute "phase7-exitcriteria-report.json"
$additionalPhase7Checks = @()
foreach ($check in $phase7UnexpectedChecks) {
  $additionalPhase7Checks += [PSCustomObject]@{
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
  criteria = $criteria
  additionalPhase7Checks = $additionalPhase7Checks
  allCriteriaPass = $allCriteriaPass
}

$reportJson = ConvertTo-Json -InputObject $report -Depth 8
Set-Content -Path $reportPath -Encoding UTF8 -Value $reportJson

foreach ($criterion in $criteria) {
  Write-Host ("{0}`t{1}`t{2}" -f "$($criterion.Criterion)", "$($criterion.Status)", "$($criterion.Details)")
}

Write-Host "REPORT_PATH=$reportPath"
Write-Host ("PHASE7_EXIT_CRITERIA={0}" -f ($(if ($allCriteriaPass) { "PASS" } else { "FAIL" })))

if ($allCriteriaPass) {
  exit 0
}

exit 2
