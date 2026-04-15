param(
  [string]$ScannerPath = "./agent/windows/out/dev/tools/fenrir-scannercli.exe",
  [string]$WorkspaceRoot = ".",
  [string]$WorkingRoot = "./tmp-phase1-exitcriteria",
  [string]$CleanwareCorpusPath = "./tmp-phase1-corpora/cleanware",
  [string]$UkBusinessCorpusPath = "./tmp-phase1-corpora/uk-business-software",
  [int]$MinCleanwareFiles = 1,
  [int]$MinUkBusinessFiles = 1,
  [int]$RemediationRuns = 8,
  [int]$RemediationSamplesPerRun = 3,
  [int]$PerformanceRuns = 8,
  [double]$PerformanceMaxAvgMsPerFile = 150,
  [double]$PerformanceMaxP95MsPerFile = 250,
  [string]$MinifilterWorkingRoot = "./tmp-phase1-minifilter-edge",
  [switch]$RequireFullMinifilterEdgeCoverage,
  [string]$MinifilterDriverRoot = "./agent/windows/out/dev/driver",
  [string]$MinifilterPackageWorkingRoot = "./tmp-phase1-minifilter-package",
  [switch]$SkipMinifilterEdgeCases,
  [switch]$SkipMinifilterPackageValidation,
  [bool]$RequireMinifilterServiceInstalled = $true
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

function Invoke-ScannerJson {
  param(
    [Parameter(Mandatory = $true)]
    [string[]]$Arguments
  )

  $stdout = & $script:ScannerAbsolute @Arguments
  $exitCode = $LASTEXITCODE
  $jsonText = ($stdout | Out-String).Trim()
  if ([string]::IsNullOrWhiteSpace($jsonText)) {
    throw "Scanner returned no JSON output. Arguments: $($Arguments -join ' ')"
  }

  try {
    $parsed = $jsonText | ConvertFrom-Json
  } catch {
    throw "Scanner returned non-JSON output. Arguments: $($Arguments -join ' ')`nOutput: $jsonText"
  }

  $findings = @()
  if ($null -ne $parsed.findings) {
    $findings = @($parsed.findings)
  }

  return [PSCustomObject]@{
    ExitCode = $exitCode
    Findings = $findings
    RawJson = $jsonText
  }
}

function New-EicarSample {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path
  )

  $eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Path) | Out-Null
  Set-Content -Path $Path -Value $eicar -Encoding ASCII
}

function Get-P95 {
  param(
    [Parameter(Mandatory = $true)]
    [double[]]$Values
  )

  if ($Values.Count -eq 0) {
    return 0.0
  }

  $sorted = $Values | Sort-Object
  $rank = [Math]::Ceiling(0.95 * $sorted.Count)
  $index = [Math]::Max(0, [int]$rank - 1)
  return [double]$sorted[$index]
}

function Add-CriterionResult {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Name,
    [Parameter(Mandatory = $true)]
    [bool]$Pass,
    [Parameter(Mandatory = $true)]
    [string]$Details
  )

  $script:CriteriaResults.Add([PSCustomObject]@{
      Criterion = $Name
      Status = if ($Pass) { "pass" } else { "fail" }
      Details = $Details
    }) | Out-Null
}

$workspaceCandidate = $WorkspaceRoot
if (-not [System.IO.Path]::IsPathRooted($workspaceCandidate)) {
  $workspaceCandidate = Join-Path (Get-Location) $workspaceCandidate
}
$script:WorkspaceRootAbsolute = [System.IO.Path]::GetFullPath($workspaceCandidate)
$script:ScannerAbsolute = Resolve-AbsolutePath -InputPath $ScannerPath -MustExist
$workingRootAbsolute = Resolve-AbsolutePath -InputPath $WorkingRoot
New-Item -ItemType Directory -Force -Path $workingRootAbsolute | Out-Null

$cleanwareCorpusAbsolute = Resolve-AbsolutePath -InputPath $CleanwareCorpusPath
$ukCorpusAbsolute = Resolve-AbsolutePath -InputPath $UkBusinessCorpusPath

$script:CriteriaResults = [System.Collections.Generic.List[object]]::new()

# Criterion 1: Common malware blocked on write or execute.
$criterion1Root = Join-Path $workingRootAbsolute "criterion1-blocking"
New-Item -ItemType Directory -Force -Path $criterion1Root | Out-Null
$writeSamplePath = Join-Path $criterion1Root "eicar-write.ps1"
$executeSamplePath = Join-Path $criterion1Root "eicar-execute.ps1"
New-EicarSample -Path $writeSamplePath
New-EicarSample -Path $executeSamplePath

$writeResult = Invoke-ScannerJson -Arguments @("--json", "--realtime-op", "write", $writeSamplePath)
$executeResult = Invoke-ScannerJson -Arguments @("--json", "--realtime-op", "execute", $executeSamplePath)

$writeDisposition = if ($writeResult.Findings.Count -gt 0) { "$($writeResult.Findings[0].disposition)" } else { "none" }
$executeDisposition = if ($executeResult.Findings.Count -gt 0) { "$($executeResult.Findings[0].disposition)" } else { "none" }
$writeBlocked = $writeDisposition -in @("block", "quarantine")
$executeBlocked = $executeDisposition -in @("block", "quarantine")

Add-CriterionResult -Name "Common malware blocked on write or execute" -Pass ($writeBlocked -and $executeBlocked) -Details ("write={0}, execute={1}" -f $writeDisposition, $executeDisposition)

# Criterion 2: Remediation succeeds consistently.
$remediationRoot = Join-Path $workingRootAbsolute "criterion2-remediation"
New-Item -ItemType Directory -Force -Path $remediationRoot | Out-Null
$remediationRunSummaries = @()
$remediationPass = $true

for ($run = 1; $run -le $RemediationRuns; $run++) {
  $runRoot = Join-Path $remediationRoot ("run" + $run)
  New-Item -ItemType Directory -Force -Path $runRoot | Out-Null

  $expectedSamples = @()
  for ($sample = 1; $sample -le $RemediationSamplesPerRun; $sample++) {
    $samplePath = Join-Path $runRoot ("sample" + $sample + ".txt")
    New-EicarSample -Path $samplePath
    $expectedSamples += $samplePath
  }

  $findingsCount = 0
  $blockedCount = 0
  $quarantinedCount = 0
  $errorCount = 0

  foreach ($samplePath in $expectedSamples) {
    $sampleScanResult = Invoke-ScannerJson -Arguments @("--json", "--path", $samplePath)
    $sampleFindings = @($sampleScanResult.Findings)
    $findingsCount += $sampleFindings.Count

    foreach ($finding in $sampleFindings) {
      $dispositionText = ""
      try {
        $dispositionText = [string]$finding.disposition
      } catch {
        $dispositionText = ""
      }
      if ($dispositionText -in @("block", "quarantine")) {
        $blockedCount++
      }

      $remediationStatusText = ""
      try {
        $remediationStatusText = [string]$finding.remediationStatus
      } catch {
        $remediationStatusText = ""
      }
      if ($remediationStatusText -eq "quarantined") {
        $quarantinedCount++
      }

      $rawRemediationError = $null
      try {
        $rawRemediationError = $finding.remediationError
      } catch {
        $rawRemediationError = $null
      }

      if ($null -eq $rawRemediationError) {
        continue
      }

      $remediationErrorText = ""
      try {
        $remediationErrorText = [string]$rawRemediationError
      } catch {
        $errorCount++
        continue
      }

      if (-not [string]::IsNullOrWhiteSpace($remediationErrorText)) {
        $errorCount++
      }
    }
  }

  $originalMissingCount = 0
  foreach ($path in $expectedSamples) {
    if (-not (Test-Path -LiteralPath $path)) {
      $originalMissingCount++
    }
  }

  $runPass =
    $findingsCount -eq $RemediationSamplesPerRun -and
    $blockedCount -eq $RemediationSamplesPerRun -and
    $quarantinedCount -eq $RemediationSamplesPerRun -and
    $errorCount -eq 0 -and
    $originalMissingCount -eq $RemediationSamplesPerRun

  if (-not $runPass) {
    $remediationPass = $false
  }

  $remediationRunSummaries += ("run{0}: findings={1}, blocked={2}, quarantined={3}, missingOriginals={4}, pass={5}" -f
      $run,
      $findingsCount,
      $blockedCount,
      $quarantinedCount,
      $originalMissingCount,
      $runPass)
}

Add-CriterionResult -Name "Remediation succeeds consistently" -Pass $remediationPass -Details ($remediationRunSummaries -join "; ")

# Criterion 3: False positives are low enough for normal household use.
$falsePositivePass = $true
$falsePositiveDetails = @()

$corpora = @(
  [PSCustomObject]@{ Name = "cleanware"; Path = $cleanwareCorpusAbsolute; MinFiles = $MinCleanwareFiles },
  [PSCustomObject]@{ Name = "uk-business"; Path = $ukCorpusAbsolute; MinFiles = $MinUkBusinessFiles }
)

foreach ($corpus in $corpora) {
  if (-not (Test-Path -LiteralPath $corpus.Path)) {
    $falsePositivePass = $false
    $falsePositiveDetails += ("{0}: missing path {1}" -f $corpus.Name, $corpus.Path)
    continue
  }

  $fileCount = @(Get-ChildItem -Path $corpus.Path -Recurse -File -ErrorAction SilentlyContinue).Count
  if ($fileCount -eq 0) {
    $falsePositivePass = $false
    $falsePositiveDetails += ("{0}: no files in corpus path" -f $corpus.Name)
    continue
  }

  if ($fileCount -lt $corpus.MinFiles) {
    $falsePositivePass = $false
    $falsePositiveDetails += ("{0}: files={1} is below required minimum {2}" -f $corpus.Name, $fileCount, $corpus.MinFiles)
    continue
  }

  $scanResult = Invoke-ScannerJson -Arguments @("--json", "--no-remediation", "--path", $corpus.Path)
  $findingCount = @($scanResult.Findings).Count
  if ($findingCount -ne 0) {
    $falsePositivePass = $false
  }

  $falsePositiveDetails += ("{0}: files={1}, minRequired={2}, findings={3}" -f $corpus.Name, $fileCount, $corpus.MinFiles, $findingCount)
}

Add-CriterionResult -Name "False positives are low enough for normal household use" -Pass $falsePositivePass -Details ($falsePositiveDetails -join "; ")

# Criterion 4: System performance remains acceptable.
$performancePass = $true
$performanceDetails = @()
$performanceTargets = [System.Collections.Generic.List[string]]::new()
$seenPerformanceTargets = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
foreach ($targetCandidate in @($cleanwareCorpusAbsolute, $ukCorpusAbsolute)) {
  if ($seenPerformanceTargets.Add([string]$targetCandidate)) {
    $null = $performanceTargets.Add([string]$targetCandidate)
  }
}
$totalPerformanceFiles = 0
foreach ($target in $performanceTargets) {
  if (Test-Path -LiteralPath $target) {
    $totalPerformanceFiles += @(Get-ChildItem -Path $target -Recurse -File -ErrorAction SilentlyContinue).Count
  }
}

if ($totalPerformanceFiles -eq 0) {
  $performancePass = $false
  $performanceDetails += "no files found for performance targets"
} else {
  $performanceRunsMs = @()
  $performanceRunsMsPerFile = @()

  $perfArgs = @("--json", "--no-remediation")
  foreach ($target in $performanceTargets) {
    $perfArgs += @("--path", $target)
  }

  for ($run = 1; $run -le $PerformanceRuns; $run++) {
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $findings = @((Invoke-ScannerJson -Arguments $perfArgs).Findings).Count
    $stopwatch.Stop()

    if ($findings -ne 0) {
      $performancePass = $false
      $performanceDetails += ("run{0}: expected 0 findings but got {1}" -f $run, $findings)
    }

    $elapsedMs = [math]::Round($stopwatch.Elapsed.TotalMilliseconds, 2)
    $msPerFile = [math]::Round(($stopwatch.Elapsed.TotalMilliseconds / $totalPerformanceFiles), 2)
    $performanceRunsMs += $elapsedMs
    $performanceRunsMsPerFile += $msPerFile
  }

  $avgMsPerFile = [math]::Round((($performanceRunsMsPerFile | Measure-Object -Average).Average), 2)
  $p95MsPerFile = [math]::Round((Get-P95 -Values $performanceRunsMsPerFile), 2)

  if ($avgMsPerFile -gt $PerformanceMaxAvgMsPerFile -or $p95MsPerFile -gt $PerformanceMaxP95MsPerFile) {
    $performancePass = $false
  }

  $performanceDetails += ("files={0}, runs={1}, avgMsPerFile={2}, p95MsPerFile={3}, limitAvg={4}, limitP95={5}" -f
      $totalPerformanceFiles,
      $PerformanceRuns,
      $avgMsPerFile,
      $p95MsPerFile,
      $PerformanceMaxAvgMsPerFile,
      $PerformanceMaxP95MsPerFile)
  $performanceDetails += ("runMsPerFile={0}" -f ($performanceRunsMsPerFile -join ","))
}

Add-CriterionResult -Name "System performance remains acceptable" -Pass $performancePass -Details ($performanceDetails -join "; ")

$minifilterEdgeCaseReportPath = ""
$minifilterPackageReportPath = ""
if (-not $SkipMinifilterEdgeCases) {
  $minifilterHarnessPath = Join-Path $script:WorkspaceRootAbsolute "agent/windows/tools/scannercli/RunMinifilterEdgeCaseHarness.ps1"
  if (-not (Test-Path -LiteralPath $minifilterHarnessPath)) {
    throw "Minifilter edge-case harness script was not found: $minifilterHarnessPath"
  }

  $minifilterWorkingRootAbsolute = Resolve-AbsolutePath -InputPath $MinifilterWorkingRoot
  $minifilterEdgeCaseReportPath = Join-Path $minifilterWorkingRootAbsolute "minifilter-edgecase-report.json"

  $minifilterHarnessExitCode = 1
  try {
    & $minifilterHarnessPath -WorkspaceRoot $script:WorkspaceRootAbsolute -ScannerPath $ScannerPath -WorkingRoot $MinifilterWorkingRoot -RequireFullCoverage:([bool]$RequireFullMinifilterEdgeCoverage)
    $minifilterHarnessExitCode = $LASTEXITCODE
  } catch {
    $minifilterHarnessExitCode = 1
  }

  $minifilterEdgeDetails = "Minifilter edge-case harness completed."
  if (Test-Path -LiteralPath $minifilterEdgeCaseReportPath) {
    try {
      $edgeReport = Get-Content -LiteralPath $minifilterEdgeCaseReportPath -Raw | ConvertFrom-Json
      $requiredFailures = @($edgeReport.requiredCoverageFailures)
      $requiredSkipped = @($edgeReport.requiredCoverageSkipped)
      $minifilterEdgeDetails = ("cases={0}, failedCases={1}, skippedCases={2}, requiredCoverageSatisfied={3}" -f
          $edgeReport.caseCount,
          $edgeReport.failedCaseCount,
          $edgeReport.skippedCaseCount,
          $edgeReport.requiredCoverageSatisfied)

      if ($requiredFailures.Count -gt 0) {
        $minifilterEdgeDetails += (", requiredCoverageFailures={0}" -f ($requiredFailures -join ","))
      }
      if ($requiredSkipped.Count -gt 0) {
        $minifilterEdgeDetails += (", requiredCoverageSkipped={0}" -f ($requiredSkipped -join ","))
      }
    } catch {
      $minifilterEdgeDetails = "Minifilter edge-case harness ran, but report parsing failed."
    }
  }

  Add-CriterionResult -Name "Minifilter edge-case matrix remains stable" -Pass ($minifilterHarnessExitCode -eq 0) -Details $minifilterEdgeDetails
}

if (-not $SkipMinifilterPackageValidation) {
  $minifilterPackageValidatorPath = Join-Path $script:WorkspaceRootAbsolute "agent/windows/tools/scannercli/ValidateMinifilterPackage.ps1"
  if (-not (Test-Path -LiteralPath $minifilterPackageValidatorPath)) {
    throw "Minifilter package validation script was not found: $minifilterPackageValidatorPath"
  }

  $minifilterPackageWorkingRootAbsolute = Resolve-AbsolutePath -InputPath $MinifilterPackageWorkingRoot
  $minifilterPackageReportPath = Join-Path $minifilterPackageWorkingRootAbsolute "minifilter-package-validation-report.json"

  $packageValidationExitCode = 1
  try {
    & $minifilterPackageValidatorPath -WorkspaceRoot $script:WorkspaceRootAbsolute -DriverRoot $MinifilterDriverRoot -WorkingRoot $MinifilterPackageWorkingRoot -RequireSignedArtifacts $true -RequireServiceInstalled:([bool]$RequireMinifilterServiceInstalled)
    $packageValidationExitCode = $LASTEXITCODE
  } catch {
    $packageValidationExitCode = 1
  }

  $packageDetails = "Minifilter package validation completed."
  if (Test-Path -LiteralPath $minifilterPackageReportPath) {
    try {
      $packageReport = Get-Content -LiteralPath $minifilterPackageReportPath -Raw | ConvertFrom-Json
      $failedChecks = [System.Collections.Generic.List[string]]::new()
      $warningChecks = [System.Collections.Generic.List[string]]::new()
      foreach ($check in @($packageReport.checks)) {
        if ($check.status -eq "fail") {
          $null = $failedChecks.Add([string]$check.name)
          continue
        }

        if ($check.status -eq "warning") {
          $null = $warningChecks.Add([string]$check.name)
        }
      }

      $packageDetails = ("overallStatus={0}, failedChecks={1}, warningChecks={2}" -f
          $packageReport.overallStatus,
          $failedChecks.Count,
          $warningChecks.Count)

      if ($failedChecks.Count -gt 0) {
        $packageDetails += (", failed={0}" -f ($failedChecks -join ","))
      }
      if ($warningChecks.Count -gt 0) {
        $packageDetails += (", warnings={0}" -f ($warningChecks -join ","))
      }
    } catch {
      $packageDetails = "Minifilter package validation ran, but report parsing failed."
    }
  }

  Add-CriterionResult -Name "Minifilter package build/sign validation passes" -Pass ($packageValidationExitCode -eq 0) -Details $packageDetails
}

$failedCriteriaCount = 0
foreach ($criterion in $script:CriteriaResults) {
  if ($criterion.Status -ne "pass") {
    $failedCriteriaCount += 1
  }
}
$allCriteriaPass = $failedCriteriaCount -eq 0
$reportPath = Join-Path $workingRootAbsolute "phase1-exitcriteria-report.json"
$report = [PSCustomObject]@{
  generatedAtUtc = [DateTime]::UtcNow.ToString("o")
  scannerPath = $script:ScannerAbsolute
  configuration = [PSCustomObject]@{
    remediationRuns = $RemediationRuns
    remediationSamplesPerRun = $RemediationSamplesPerRun
    performanceRuns = $PerformanceRuns
    performanceMaxAvgMsPerFile = $PerformanceMaxAvgMsPerFile
    performanceMaxP95MsPerFile = $PerformanceMaxP95MsPerFile
    minCleanwareFiles = $MinCleanwareFiles
    minUkBusinessFiles = $MinUkBusinessFiles
    cleanwareCorpusPath = $cleanwareCorpusAbsolute
    ukBusinessCorpusPath = $ukCorpusAbsolute
    minifilterWorkingRoot = Resolve-AbsolutePath -InputPath $MinifilterWorkingRoot
    minifilterDriverRoot = Resolve-AbsolutePath -InputPath $MinifilterDriverRoot
    minifilterPackageWorkingRoot = Resolve-AbsolutePath -InputPath $MinifilterPackageWorkingRoot
    requireFullMinifilterEdgeCoverage = [bool]$RequireFullMinifilterEdgeCoverage
    requireMinifilterServiceInstalled = [bool]$RequireMinifilterServiceInstalled
    skipMinifilterEdgeCases = [bool]$SkipMinifilterEdgeCases
    skipMinifilterPackageValidation = [bool]$SkipMinifilterPackageValidation
  }
  minifilterEdgeCaseReportPath = $minifilterEdgeCaseReportPath
  minifilterPackageReportPath = $minifilterPackageReportPath
  criteria = $script:CriteriaResults
  allCriteriaPass = $allCriteriaPass
}

$reportJson = ConvertTo-Json -InputObject $report -Depth 8
Set-Content -Path $reportPath -Encoding UTF8 -Value $reportJson
foreach ($criterion in $script:CriteriaResults) {
  Write-Host ("{0}`t{1}`t{2}" -f "$($criterion.Criterion)", "$($criterion.Status)", "$($criterion.Details)")
}
Write-Host "REPORT_PATH=$reportPath"
Write-Host ("PHASE1_EXIT_CRITERIA={0}" -f ($(if ($allCriteriaPass) { "PASS" } else { "FAIL" })))

if ($allCriteriaPass) {
  exit 0
}

exit 2
