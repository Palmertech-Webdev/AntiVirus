param(
  [string]$ServicePath = "./agent/windows/out/dev/fenrir-agent-service.exe",
  [string]$AmsiCliPath = "./agent/windows/out/dev/tools/fenrir-amsitestcli.exe",
  [string]$ScannerPath = "./agent/windows/out/dev/tools/fenrir-scannercli.exe",
  [string]$WorkspaceRoot = ".",
  [string]$WorkingRoot = "./tmp-phase3-exitcriteria",
  [string]$CorpusRoot = "./tmp-phase3-corpora",
  [string]$HostileFuzzWorkingRoot = "./tmp-phase3-hostile-fuzz",
  [switch]$SkipCorpus,
  [switch]$SkipHostileInputFuzz,
  [string[]]$RequiredCheckIds = @(
    "phase3_amsi_script_depth",
    "phase3_amsi_false_positive_benign"
  )
)

$ErrorActionPreference = "Stop"

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

function Get-AmsiAppName {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path
  )

  switch ([System.IO.Path]::GetExtension($Path).ToLowerInvariant()) {
    ".ps1" { return "PowerShell" }
    ".js" { return "wscript.exe" }
    ".jse" { return "wscript.exe" }
    ".vbs" { return "wscript.exe" }
    ".vbe" { return "wscript.exe" }
    ".hta" { return "mshta.exe" }
    default { return "PowerShell" }
  }
}

function Parse-AmsiCliResult {
  param(
    [Parameter(Mandatory = $true)]
    [string]$RawOutput
  )

  $text = $RawOutput.Trim()
  $blockedMatch = [regex]::Match($text, '"blocked":(true|false)')
  $resultMatch = [regex]::Match($text, '"result":([0-9]+)')

  if (-not $blockedMatch.Success) {
    throw "Unable to parse AMSI CLI blocked state from output: $text"
  }

  return [PSCustomObject]@{
    blocked = $blockedMatch.Groups[1].Value -eq "true"
    result = if ($resultMatch.Success) { [int]$resultMatch.Groups[1].Value } else { -1 }
    raw = $text
  }
}

$workspaceCandidate = $WorkspaceRoot
if (-not [System.IO.Path]::IsPathRooted($workspaceCandidate)) {
  $workspaceCandidate = Join-Path (Get-Location) $workspaceCandidate
}
$script:WorkspaceRootAbsolute = [System.IO.Path]::GetFullPath($workspaceCandidate)
$serviceAbsolute = Resolve-AbsolutePath -InputPath $ServicePath -MustExist
$workingRootAbsolute = Resolve-AbsolutePath -InputPath $WorkingRoot
$corpusRootAbsolute = Resolve-AbsolutePath -InputPath $CorpusRoot
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

$phase3Checks = @()
if ($null -ne $selfTestReport.checks) {
  $phase3Checks = @($selfTestReport.checks | Where-Object { $_.id -like "phase3_*" })
}

$indexedChecks = @{}
foreach ($check in $phase3Checks) {
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
        Details = "Required Phase 3 check was not present in self-test output."
        Remediation = "Ensure the service self-test publishes the required Phase 3 exit-criteria checks."
      }) | Out-Null
  }
}

$phase3UnexpectedChecks = @($phase3Checks | Where-Object { $RequiredCheckIds -notcontains "$($_.id)" })
$corpusResults = [System.Collections.Generic.List[object]]::new()
$hostileFuzzReportPath = ""

if (-not $SkipCorpus) {
  $generatorPath = Join-Path $script:WorkspaceRootAbsolute "agent/windows/tools/scannercli/GeneratePhase3AdversarialCorpus.ps1"
  if (-not (Test-Path -LiteralPath $corpusRootAbsolute)) {
    if (-not (Test-Path -LiteralPath $generatorPath)) {
      throw "Phase 3 corpus root does not exist and corpus generator was not found: $generatorPath"
    }

    & powershell -ExecutionPolicy Bypass -File $generatorPath -WorkspaceRoot $script:WorkspaceRootAbsolute -OutputRoot $corpusRootAbsolute
    if ($LASTEXITCODE -ne 0) {
      throw "Phase 3 corpus generator failed with exit code $LASTEXITCODE"
    }
  }

  $amsiCliAbsolute = Resolve-AbsolutePath -InputPath $AmsiCliPath -MustExist
  $manifestPath = Join-Path $corpusRootAbsolute "phase3-corpus-manifest.json"
  $expectedSamples = @()
  if (Test-Path -LiteralPath $manifestPath) {
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $expectedSamples = @($manifest.samples)
  }

  $missingSamples = @()
  if ($expectedSamples.Count -gt 0) {
    $missingSamples = @($expectedSamples | Where-Object {
          -not (Test-Path -LiteralPath (Join-Path $corpusRootAbsolute $_.relativePath.Replace('/', '\')))
        })
  }

  $criteria.Add([PSCustomObject]@{
      Criterion = "phase3_corpus_integrity"
      Status = if ($missingSamples.Count -eq 0) { "pass" } else { "fail" }
      Details = if ($missingSamples.Count -eq 0) {
        "All expected Phase 3 corpus samples were present before AMSI validation."
      } else {
        "Some expected Phase 3 corpus samples were missing before AMSI validation: " + (($missingSamples | ForEach-Object { $_.relativePath }) -join "; ")
      }
      Remediation = if ($missingSamples.Count -eq 0) { "" } else { "Check Windows Security or other endpoint controls for quarantined Phase 3 corpus samples, then regenerate the corpus before rerunning the gate." }
    }) | Out-Null

  $maliciousFiles = @(Get-ChildItem -LiteralPath (Join-Path $corpusRootAbsolute "malicious") -File -Recurse -ErrorAction Stop)
  $benignFiles = @(Get-ChildItem -LiteralPath (Join-Path $corpusRootAbsolute "benign") -File -Recurse -ErrorAction Stop)

  foreach ($sample in $maliciousFiles) {
    $appName = Get-AmsiAppName -Path $sample.FullName
    $sampleJson = & $amsiCliAbsolute --stream --json --app $appName --path $sample.FullName
    if ($LASTEXITCODE -eq 1) {
      throw "AMSI test CLI failed while scanning malicious sample: $($sample.FullName)"
    }

    $parsed = Parse-AmsiCliResult -RawOutput (($sampleJson | Out-String).Trim())
    $corpusResults.Add([PSCustomObject]@{
        sample = $sample.FullName
        class = "malicious"
        blocked = [bool]$parsed.blocked
        result = [int]$parsed.result
      }) | Out-Null
  }

  foreach ($sample in $benignFiles) {
    $appName = Get-AmsiAppName -Path $sample.FullName
    $sampleJson = & $amsiCliAbsolute --stream --json --app $appName --path $sample.FullName
    if ($LASTEXITCODE -eq 1) {
      throw "AMSI test CLI failed while scanning benign sample: $($sample.FullName)"
    }

    $parsed = Parse-AmsiCliResult -RawOutput (($sampleJson | Out-String).Trim())
    $corpusResults.Add([PSCustomObject]@{
        sample = $sample.FullName
        class = "benign"
        blocked = [bool]$parsed.blocked
        result = [int]$parsed.result
      }) | Out-Null
  }

  $maliciousMisses = @($corpusResults | Where-Object { $_.class -eq "malicious" -and -not $_.blocked })
  $benignFalsePositives = @($corpusResults | Where-Object { $_.class -eq "benign" -and $_.blocked })

  $criteria.Add([PSCustomObject]@{
      Criterion = "phase3_corpus_malicious_blocking"
      Status = if ($maliciousMisses.Count -eq 0) { "pass" } else { "fail" }
      Details = if ($maliciousMisses.Count -eq 0) {
        "All malicious Phase 3 corpus samples were blocked by the AMSI test path."
      } else {
        "Some malicious Phase 3 corpus samples were allowed: " + (($maliciousMisses | Select-Object -ExpandProperty sample) -join "; ")
      }
      Remediation = if ($maliciousMisses.Count -eq 0) { "" } else { "Strengthen AMSI scoring and staged-attack correlation until all malicious Phase 3 corpus samples are blocked." }
    }) | Out-Null

  $criteria.Add([PSCustomObject]@{
      Criterion = "phase3_corpus_benign_allow"
      Status = if ($benignFalsePositives.Count -eq 0) { "pass" } else { "fail" }
      Details = if ($benignFalsePositives.Count -eq 0) {
        "All benign Phase 3 corpus samples remained allowed through the AMSI test path."
      } else {
        "Some benign Phase 3 corpus samples were blocked: " + (($benignFalsePositives | Select-Object -ExpandProperty sample) -join "; ")
      }
      Remediation = if ($benignFalsePositives.Count -eq 0) { "" } else { "Retune AMSI heuristics so administrative, inventory, and build-health scripts remain allowed." }
    }) | Out-Null
}

if (-not $SkipHostileInputFuzz) {
  $hostileHarnessPath = Join-Path $script:WorkspaceRootAbsolute "agent/windows/tools/scannercli/RunHostileInputFuzzHarness.ps1"
  if (-not (Test-Path -LiteralPath $hostileHarnessPath)) {
    throw "Hostile input fuzz harness script was not found: $hostileHarnessPath"
  }

  $hostileHarnessOutput = & powershell -ExecutionPolicy Bypass -File $hostileHarnessPath -WorkspaceRoot $script:WorkspaceRootAbsolute -ScannerPath $ScannerPath -WorkingRoot $HostileFuzzWorkingRoot
  $hostileHarnessExitCode = $LASTEXITCODE
  $hostileHarnessText = ($hostileHarnessOutput | Out-String).Trim()

  $reportMatch = [regex]::Match($hostileHarnessText, "REPORT_PATH=([^`r`n]+)")
  if ($reportMatch.Success) {
    $hostileFuzzReportPath = $reportMatch.Groups[1].Value.Trim()
  }

  $criteria.Add([PSCustomObject]@{
      Criterion = "phase3_hostile_input_fuzz_harness"
      Status = if ($hostileHarnessExitCode -eq 0) { "pass" } else { "fail" }
      Details = if ($hostileHarnessExitCode -eq 0) {
        "Hostile-input scanner fuzz harness completed successfully."
      } else {
        "Hostile-input scanner fuzz harness reported failures."
      }
      Remediation = if ($hostileHarnessExitCode -eq 0) {
        ""
      } else {
        "Review the hostile-input fuzz report and harden parser/realtime paths until all samples complete without harness failures."
      }
    }) | Out-Null
}

$allCriteriaPass = @($criteria | Where-Object { $_.Status -ne "pass" }).Count -eq 0
$reportPath = Join-Path $workingRootAbsolute "phase3-exitcriteria-report.json"
$report = [PSCustomObject]@{
  generatedAtUtc = [DateTime]::UtcNow.ToString("o")
  servicePath = $serviceAbsolute
  selfTestExitCode = $selfTestExitCode
  selfTestOverallStatus = "$($selfTestReport.overallStatus)"
  requiredCheckIds = $RequiredCheckIds
  criteria = $criteria
  corpusRoot = if ($SkipCorpus) { "" } else { $corpusRootAbsolute }
  corpusResults = $corpusResults
  hostileInputFuzzReportPath = $hostileFuzzReportPath
  additionalPhase3Checks = @($phase3UnexpectedChecks | ForEach-Object {
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
Write-Host ("PHASE3_EXIT_CRITERIA={0}" -f ($(if ($allCriteriaPass) { "PASS" } else { "FAIL" })))

if ($allCriteriaPass) {
  exit 0
}

exit 2
