param(
  [string]$ServicePath = "./agent/windows/out/dev/fenrir-agent-service.exe",
  [string]$WorkspaceRoot = ".",
  [string]$WorkingRoot = "./tmp-phase5-exitcriteria",
  [string[]]$RequiredCheckIds = @(
    "phase5_pam_request_queue_visibility",
    "phase5_pam_audit_visibility",
    "phase5_admin_membership_audit",
    "phase5_household_role_policy_governance",
    "phase5_admin_baseline_persistence"
  ),
  [string[]]$WarningAllowedCheckIds = @(
    "phase5_admin_membership_audit",
    "phase5_household_role_policy_governance"
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
  $selfTestReport = $jsonText | ConvertFrom-Json
} catch {
  throw "Service returned non-JSON self-test output.`nOutput: $jsonText"
}

$phase5Checks = @()
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

    if ($checkId.StartsWith("phase5_", [System.StringComparison]::OrdinalIgnoreCase)) {
      $phase5Checks += $check
    }
  }
}

$indexedChecks = @{}
foreach ($check in $phase5Checks) {
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
        Details = "Required Phase 5 check was not present in self-test output."
        Remediation = "Ensure the service self-test publishes the required Phase 5 PAM and admin-posture checks."
      }) | Out-Null
  }
}

$phase5UnexpectedChecks = @()
foreach ($check in $phase5Checks) {
  if ($RequiredCheckIds -notcontains ([string]$check.id)) {
    $phase5UnexpectedChecks += $check
  }
}
$failedCriteriaCount = 0
foreach ($criterion in $criteria) {
  if ([string]$criterion.Status -ne "pass") {
    $failedCriteriaCount++
  }
}
$allCriteriaPass = $failedCriteriaCount -eq 0
$reportPath = Join-Path $workingRootAbsolute "phase5-exitcriteria-report.json"
$report = [PSCustomObject]@{
  generatedAtUtc = [DateTime]::UtcNow.ToString("o")
  servicePath = $serviceAbsolute
  selfTestExitCode = $selfTestExitCode
  selfTestOverallStatus = "$($selfTestReport.overallStatus)"
  requiredCheckIds = $RequiredCheckIds
  warningAllowedCheckIds = $WarningAllowedCheckIds
  criteria = $criteria
  additionalPhase5Checks = @($phase5UnexpectedChecks | ForEach-Object {
      [PSCustomObject]@{
        id = "$($_.id)"
        name = "$($_.name)"
        status = "$($_.status)"
        details = "$($_.details)"
        remediation = "$($_.remediation)"
      }
    })
  allCriteriaPass = $allCriteriaPass
}

$report | ConvertTo-Json -Depth 8 | Set-Content -Path $reportPath -Encoding UTF8
$criteria | Format-Table -AutoSize
Write-Host "REPORT_PATH=$reportPath"
Write-Host ("PHASE5_EXIT_CRITERIA={0}" -f ($(if ($allCriteriaPass) { "PASS" } else { "FAIL" })))

if ($allCriteriaPass) {
  exit 0
}

exit 2
