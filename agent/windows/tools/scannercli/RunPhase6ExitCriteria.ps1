param(
  [string]$ServicePath = "./agent/windows/out/dev/fenrir-agent-service.exe",
  [string]$WorkspaceRoot = ".",
  [string]$WorkingRoot = "./tmp-phase6-exitcriteria",
  [string[]]$RequiredCheckIds = @(
    "phase6_integrated_posture_snapshot",
    "phase6_posture_output_coverage"
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

$phase6Checks = @()
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

    if ($checkId.StartsWith("phase6_", [System.StringComparison]::OrdinalIgnoreCase)) {
      $phase6Checks += $check
    }
  }
}

$indexedChecks = @{}
foreach ($check in $phase6Checks) {
  $indexedChecks["$($check.id)"] = $check
}

$criteria = [System.Collections.Generic.List[object]]::new()
foreach ($requiredId in $RequiredCheckIds) {
  if ($indexedChecks.ContainsKey($requiredId)) {
    $check = $indexedChecks[$requiredId]
    $criteria.Add([PSCustomObject]@{
        Criterion = $requiredId
        Status = if ("$($check.status)" -eq "pass") { "pass" } else { "fail" }
        Details = "$($check.details)"
        Remediation = "$($check.remediation)"
      }) | Out-Null
  } else {
    $criteria.Add([PSCustomObject]@{
        Criterion = $requiredId
        Status = "fail"
        Details = "Required Phase 6 check was not present in self-test output."
        Remediation = "Ensure the service self-test publishes the required Phase 6 integration checks."
      }) | Out-Null
  }
}

$phase6UnexpectedChecks = @()
foreach ($check in $phase6Checks) {
  if ($RequiredCheckIds -notcontains ([string]$check.id)) {
    $phase6UnexpectedChecks += $check
  }
}
$failedCriteriaCount = 0
foreach ($criterion in $criteria) {
  if ([string]$criterion.Status -ne "pass") {
    $failedCriteriaCount++
  }
}
$allCriteriaPass = $failedCriteriaCount -eq 0
$reportPath = Join-Path $workingRootAbsolute "phase6-exitcriteria-report.json"
$report = [PSCustomObject]@{
  generatedAtUtc = [DateTime]::UtcNow.ToString("o")
  servicePath = $serviceAbsolute
  selfTestExitCode = $selfTestExitCode
  selfTestOverallStatus = "$($selfTestReport.overallStatus)"
  requiredCheckIds = $RequiredCheckIds
  criteria = $criteria
  additionalPhase6Checks = @($phase6UnexpectedChecks | ForEach-Object {
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
Write-Host ("PHASE6_EXIT_CRITERIA={0}" -f ($(if ($allCriteriaPass) { "PASS" } else { "FAIL" })))

if ($allCriteriaPass) {
  exit 0
}

exit 2
