param(
  [string]$ServicePath = "./agent/windows/out/dev/fenrir-agent-service.exe",
  [string]$WorkspaceRoot = ".",
  [string]$WorkingRoot = "./tmp-phase2-cleanware-suite"
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

$requiredChecks = @(
  "phase2_cleanware_corpus_awareness",
  "phase2_false_positive_corpus_awareness",
  "phase2_ransomware_false_positive_bulk_io",
  "phase2_ransomware_false_positive_photo_export",
  "phase2_ransomware_false_positive_developer_build"
)

$phase2Checks = @()
if ($null -ne $selfTestReport.checks) {
  foreach ($check in @($selfTestReport.checks)) {
    if ($null -eq $check) {
      continue
    }

    $checkId = "$($check.id)"
    if ($checkId -like "phase2_*") {
      $phase2Checks += $check
    }
  }
}

$indexedChecks = @{}
foreach ($check in $phase2Checks) {
  $indexedChecks["$($check.id)"] = $check
}

$criteria = [System.Collections.Generic.List[object]]::new()
foreach ($id in $requiredChecks) {
  if ($indexedChecks.ContainsKey($id)) {
    $check = $indexedChecks[$id]
    $statusText = "$($check.status)"
    $passStatus = $false
    if ($id -like "phase2_*_corpus_awareness") {
      if ($statusText -eq "pass" -or $statusText -eq "warning") {
        $passStatus = $true
      }
    } else {
      if ($statusText -eq "pass") {
        $passStatus = $true
      }
    }

    $criteria.Add([PSCustomObject]@{
        Criterion = $id
        Status = if ($passStatus) { "pass" } else { "fail" }
        Details = "$($check.details)"
      }) | Out-Null
  } else {
    $criteria.Add([PSCustomObject]@{
        Criterion = $id
        Status = "fail"
        Details = "Required cleanware check missing from self-test output."
      }) | Out-Null
  }
}

$allCriteriaPass = @($criteria | Where-Object { $_.Status -ne "pass" }).Count -eq 0
$reportPath = Join-Path $workingRootAbsolute "phase2-cleanware-suite-report.json"
$report = [PSCustomObject]@{
  generatedAtUtc = [DateTime]::UtcNow.ToString("o")
  servicePath = $serviceAbsolute
  selfTestExitCode = $selfTestExitCode
  selfTestOverallStatus = "$($selfTestReport.overallStatus)"
  criteria = $criteria
  allCriteriaPass = $allCriteriaPass
}

$report | ConvertTo-Json -Depth 8 | Set-Content -Path $reportPath -Encoding UTF8
$criteria | Format-Table -AutoSize
Write-Host "REPORT_PATH=$reportPath"
Write-Host ("PHASE2_CLEANWARE_SUITE={0}" -f ($(if ($allCriteriaPass) { "PASS" } else { "FAIL" })))

if ($allCriteriaPass) {
  exit 0
}

exit 2
