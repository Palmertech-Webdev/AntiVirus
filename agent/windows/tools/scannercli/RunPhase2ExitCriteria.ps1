param(
  [string]$ServicePath = "./agent/windows/out/dev/fenrir-agent-service.exe",
  [string]$WorkspaceRoot = ".",
  [string]$WorkingRoot = "./tmp-phase2-exitcriteria",
  [string[]]$RequiredCheckIds = @(
    "phase2_ransomware_behavior_chain",
    "phase2_ransomware_extension_burst",
    "phase2_ransomware_staged_impact_chain",
    "phase2_ransomware_false_positive_bulk_io",
    "phase2_ransomware_false_positive_photo_export",
    "phase2_ransomware_false_positive_developer_build",
    "phase2_rule_quality_budget"
  ),
  [string[]]$OptionalCheckIds = @(
    "phase2_cleanware_corpus_awareness",
    "phase2_false_positive_corpus_awareness"
  ),
  [double]$MinPhase2PassRatePercent = 80.0,
  [double]$MaxFalsePositiveRatePercent = 34.0,
  [int]$MaxFalsePositiveFailures = 1,
  [int]$MinRuleQualityScore = 70
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

function Get-CheckStatus {
  param(
    [Parameter(Mandatory = $true)]
    [hashtable]$IndexedChecks,
    [Parameter(Mandatory = $true)]
    [string]$CheckId
  )

  if (-not $IndexedChecks.ContainsKey($CheckId)) {
    return "missing"
  }

  return "$($IndexedChecks[$CheckId].status)"
}

function Add-CriterionResult {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Criterion,
    [Parameter(Mandatory = $true)]
    [bool]$Pass,
    [Parameter(Mandatory = $true)]
    [AllowEmptyString()]
    [string]$Details,
    [Parameter(Mandatory = $true)]
    [AllowEmptyString()]
    [string]$Remediation
  )

  $status = "fail"
  if ($Pass) {
    $status = "pass"
  }

  $script:Criteria.Add([PSCustomObject]@{
      Criterion = $Criterion
      Status = $status
      Details = $Details
      Remediation = $Remediation
    }) | Out-Null
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

$phase2Checks = [System.Collections.Generic.List[object]]::new()
if ($null -ne $selfTestReport.checks) {
  foreach ($check in @($selfTestReport.checks)) {
    if ($null -eq $check) {
      continue
    }

    $checkId = "$($check.id)"
    if ($checkId -like "phase2_*") {
      $phase2Checks.Add($check) | Out-Null
    }
  }
}

$indexedChecks = @{}
foreach ($check in $phase2Checks) {
  $checkId = "$($check.id)"
  if (-not [string]::IsNullOrWhiteSpace($checkId)) {
    $indexedChecks[$checkId] = $check
  }
}

$script:Criteria = [System.Collections.Generic.List[object]]::new()

foreach ($requiredId in $RequiredCheckIds) {
  if ($indexedChecks.ContainsKey($requiredId)) {
    $check = $indexedChecks[$requiredId]
    $statusText = "$($check.status)"
    Add-CriterionResult -Criterion $requiredId -Pass ($statusText -eq "pass") -Details "$($check.details)" -Remediation "$($check.remediation)"
  } else {
    Add-CriterionResult -Criterion $requiredId -Pass $false -Details "Required Phase 2 check was not present in self-test output." -Remediation "Ensure the service self-test publishes the required Phase 2 exit-criteria checks."
  }
}

foreach ($optionalId in $OptionalCheckIds) {
  if ($RequiredCheckIds -contains $optionalId) {
    continue
  }

  if ($indexedChecks.ContainsKey($optionalId)) {
    $check = $indexedChecks[$optionalId]
    $statusText = "$($check.status)"
    Add-CriterionResult -Criterion $optionalId -Pass ($statusText -ne "fail") -Details "$($check.details)" -Remediation "$($check.remediation)"
  }
}

$detectionCheckIds = @(
  "phase2_ransomware_behavior_chain",
  "phase2_ransomware_extension_burst",
  "phase2_ransomware_staged_impact_chain"
)
$benignCheckIds = @(
  "phase2_ransomware_false_positive_bulk_io",
  "phase2_ransomware_false_positive_photo_export",
  "phase2_ransomware_false_positive_developer_build"
)

$detectionPasses = 0
$detectionTotal = 0
foreach ($id in $detectionCheckIds) {
  $statusText = Get-CheckStatus -IndexedChecks $indexedChecks -CheckId $id
  if ($statusText -ne "missing") {
    $detectionTotal += 1
    if ($statusText -eq "pass") {
      $detectionPasses += 1
    }
  }
}

$benignFails = 0
$benignTotal = 0
foreach ($id in $benignCheckIds) {
  $statusText = Get-CheckStatus -IndexedChecks $indexedChecks -CheckId $id
  if ($statusText -ne "missing") {
    $benignTotal += 1
    if ($statusText -eq "fail") {
      $benignFails += 1
    }
  }
}

$computedPassRatePercent = 0.0
if ($detectionTotal -gt 0 -and $benignTotal -gt 0) {
  $computedPassRatePercent = (($detectionPasses + ($benignTotal - $benignFails)) * 100.0) / ($detectionTotal + $benignTotal)
}

$summaryPassRatePercent = $null
if ($null -ne $selfTestReport.summary -and $null -ne $selfTestReport.summary.phase2) {
  $summaryValue = "$($selfTestReport.summary.phase2.passRatePercent)"
  if (-not [string]::IsNullOrWhiteSpace($summaryValue)) {
    [double]$parsedPassRate = 0.0
    if ([double]::TryParse($summaryValue, [ref]$parsedPassRate)) {
      $summaryPassRatePercent = $parsedPassRate
    }
  }
}

$phase2PassRatePercent = $computedPassRatePercent
if ($null -ne $summaryPassRatePercent) {
  $phase2PassRatePercent = $summaryPassRatePercent
}

$falsePositiveRatePercent = 0.0
if ($benignTotal -gt 0) {
  $falsePositiveRatePercent = ($benignFails * 100.0) / $benignTotal
}

$ruleQualityScore = 0
$ruleQualityScoreAvailable = $false
if ($indexedChecks.ContainsKey("phase2_rule_quality_budget")) {
  $details = "$($indexedChecks["phase2_rule_quality_budget"].details)"
  $match = [regex]::Match($details, "ruleQualityScore\s*=\s*(\d+)", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
  if ($match.Success) {
    [int]$parsedRuleQuality = 0
    if ([int]::TryParse($match.Groups[1].Value, [ref]$parsedRuleQuality)) {
      $ruleQualityScore = $parsedRuleQuality
      $ruleQualityScoreAvailable = $true
    }
  }
}

Add-CriterionResult -Criterion "phase2_pass_rate_budget" -Pass ($phase2PassRatePercent -ge $MinPhase2PassRatePercent) -Details "phase2PassRatePercent=$phase2PassRatePercent (minimum $MinPhase2PassRatePercent)" -Remediation "Improve Phase 2 detection and benign workload stability until aggregate pass-rate budget is met."

Add-CriterionResult -Criterion "phase2_false_positive_rate_budget" -Pass ($falsePositiveRatePercent -le $MaxFalsePositiveRatePercent -and $benignFails -le $MaxFalsePositiveFailures) -Details "falsePositiveRatePercent=$falsePositiveRatePercent, benignFails=$benignFails (limits: rate <= $MaxFalsePositiveRatePercent, fails <= $MaxFalsePositiveFailures)" -Remediation "Retune non-execute ladders and cleanware dampening so benign workloads stay inside false-positive budget."

$ruleQualityPass = $ruleQualityScoreAvailable -and $ruleQualityScore -ge $MinRuleQualityScore
$ruleQualityDetails = "ruleQualityScore could not be extracted from phase2_rule_quality_budget details."
if ($ruleQualityScoreAvailable) {
  $ruleQualityDetails = "ruleQualityScore=$ruleQualityScore (minimum $MinRuleQualityScore)"
}
Add-CriterionResult -Criterion "phase2_rule_quality_score_budget" -Pass $ruleQualityPass -Details $ruleQualityDetails -Remediation "Publish ruleQualityScore in phase2_rule_quality_budget details and tune signatures/weights until minimum score is met."

$phase2UnexpectedChecks = [System.Collections.Generic.List[object]]::new()
foreach ($phase2Check in $phase2Checks) {
  $phase2CheckId = "$($phase2Check.id)"
  if ([string]::IsNullOrWhiteSpace($phase2CheckId)) {
    continue
  }

  if (($RequiredCheckIds -contains $phase2CheckId) -or ($OptionalCheckIds -contains $phase2CheckId)) {
    continue
  }

  $phase2UnexpectedChecks.Add($phase2Check) | Out-Null
}

$allCriteriaPass = @($script:Criteria | Where-Object { $_.Status -ne "pass" }).Count -eq 0
$reportPath = Join-Path $workingRootAbsolute "phase2-exitcriteria-report.json"

$computedRuleQualityScore = $null
if ($ruleQualityScoreAvailable) {
  $computedRuleQualityScore = $ruleQualityScore
}

$additionalPhase2Checks = [System.Collections.Generic.List[object]]::new()
foreach ($extra in $phase2UnexpectedChecks) {
  $additionalPhase2Checks.Add([PSCustomObject]@{
      id = "$($extra.id)"
      name = "$($extra.name)"
      status = "$($extra.status)"
      details = "$($extra.details)"
      remediation = "$($extra.remediation)"
    }) | Out-Null
}

$report = [PSCustomObject]@{
  generatedAtUtc = [DateTime]::UtcNow.ToString("o")
  servicePath = $serviceAbsolute
  selfTestExitCode = $selfTestExitCode
  selfTestOverallStatus = "$($selfTestReport.overallStatus)"
  requiredCheckIds = $RequiredCheckIds
  optionalCheckIds = $OptionalCheckIds
  budgets = [PSCustomObject]@{
    minPhase2PassRatePercent = $MinPhase2PassRatePercent
    maxFalsePositiveRatePercent = $MaxFalsePositiveRatePercent
    maxFalsePositiveFailures = $MaxFalsePositiveFailures
    minRuleQualityScore = $MinRuleQualityScore
  }
  computedMetrics = [PSCustomObject]@{
    phase2PassRatePercent = $phase2PassRatePercent
    falsePositiveRatePercent = $falsePositiveRatePercent
    benignFailures = $benignFails
    ruleQualityScore = $computedRuleQualityScore
    detectionPasses = $detectionPasses
    detectionTotal = $detectionTotal
    benignTotal = $benignTotal
  }
  criteria = @($script:Criteria)
  additionalPhase2Checks = @($additionalPhase2Checks)
  allCriteriaPass = $allCriteriaPass
}

$report | ConvertTo-Json -Depth 8 | Set-Content -Path $reportPath -Encoding UTF8
$script:Criteria | Format-Table -AutoSize
Write-Host "REPORT_PATH=$reportPath"
Write-Host ("PHASE2_EXIT_CRITERIA={0}" -f ($(if ($allCriteriaPass) { "PASS" } else { "FAIL" })))

if ($allCriteriaPass) {
  exit 0
}

exit 2
