param(
  [string]$ScannerPath = "./agent/windows/out/dev/tools/fenrir-scannercli.exe",
  [string]$WorkspaceRoot = ".",
  [string]$WorkingRoot = "./tmp-phase1-minifilter-edge"
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

function Invoke-RealtimeCase {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Scanner,
    [Parameter(Mandatory = $true)]
    [string]$Operation,
    [Parameter(Mandatory = $true)]
    [string]$TargetPath,
    [Parameter(Mandatory = $true)]
    [int[]]$ExpectedExitCodes,
    [Parameter(Mandatory = $true)]
    [string]$RuntimeRoot,
    [switch]$RequireJsonOutput
  )

  New-Item -ItemType Directory -Force -Path $RuntimeRoot | Out-Null
  $runtimeDbPath = Join-Path $RuntimeRoot "agent-runtime.db"
  $stateFilePath = Join-Path $RuntimeRoot "agent-state.ini"
  $telemetryPath = Join-Path $RuntimeRoot "telemetry-queue.tsv"
  $updateRoot = Join-Path $RuntimeRoot "update"
  $journalRoot = Join-Path $RuntimeRoot "journal"
  $quarantineRoot = Join-Path $RuntimeRoot "quarantine"
  $evidenceRoot = Join-Path $RuntimeRoot "evidence"

  New-Item -ItemType Directory -Force -Path $updateRoot, $journalRoot, $quarantineRoot, $evidenceRoot | Out-Null

  $savedEnvironment = @{
    ANTIVIRUS_RUNTIME_DB_PATH = $env:ANTIVIRUS_RUNTIME_DB_PATH
    ANTIVIRUS_AGENT_STATE_FILE = $env:ANTIVIRUS_AGENT_STATE_FILE
    ANTIVIRUS_TELEMETRY_QUEUE_FILE = $env:ANTIVIRUS_TELEMETRY_QUEUE_FILE
    ANTIVIRUS_UPDATE_ROOT = $env:ANTIVIRUS_UPDATE_ROOT
    ANTIVIRUS_JOURNAL_ROOT = $env:ANTIVIRUS_JOURNAL_ROOT
    ANTIVIRUS_QUARANTINE_ROOT = $env:ANTIVIRUS_QUARANTINE_ROOT
    ANTIVIRUS_EVIDENCE_ROOT = $env:ANTIVIRUS_EVIDENCE_ROOT
  }

  $env:ANTIVIRUS_RUNTIME_DB_PATH = $runtimeDbPath
  $env:ANTIVIRUS_AGENT_STATE_FILE = $stateFilePath
  $env:ANTIVIRUS_TELEMETRY_QUEUE_FILE = $telemetryPath
  $env:ANTIVIRUS_UPDATE_ROOT = $updateRoot
  $env:ANTIVIRUS_JOURNAL_ROOT = $journalRoot
  $env:ANTIVIRUS_QUARANTINE_ROOT = $quarantineRoot
  $env:ANTIVIRUS_EVIDENCE_ROOT = $evidenceRoot

  try {
    $stdout = & $Scanner --json --no-telemetry --no-remediation --realtime-op $Operation --path $TargetPath
    $exitCode = $LASTEXITCODE
    $output = ($stdout | Out-String).Trim()
  } finally {
    foreach ($entry in $savedEnvironment.GetEnumerator()) {
      if ($null -eq $entry.Value) {
        Remove-Item -Path "Env:$($entry.Key)" -ErrorAction SilentlyContinue
      } else {
        Set-Item -Path "Env:$($entry.Key)" -Value $entry.Value
      }
    }
  }

  $jsonValid = $false
  if ($RequireJsonOutput) {
    if (-not [string]::IsNullOrWhiteSpace($output)) {
      try {
        $null = $output | ConvertFrom-Json
        $jsonValid = $true
      } catch {
        $jsonValid = $false
      }
    }
  }

  $exitOk = $ExpectedExitCodes -contains $exitCode
  $status = if ($exitOk -and ((-not $RequireJsonOutput) -or $jsonValid)) { "pass" } else { "fail" }

  return [PSCustomObject]@{
    operation = $Operation
    targetPath = $TargetPath
    expectedExitCodes = $ExpectedExitCodes
    exitCode = $exitCode
    requireJsonOutput = [bool]$RequireJsonOutput
    jsonValid = $jsonValid
    status = $status
    output = $output
  }
}

$workspaceCandidate = $WorkspaceRoot
if (-not [System.IO.Path]::IsPathRooted($workspaceCandidate)) {
  $workspaceCandidate = Join-Path (Get-Location) $workspaceCandidate
}
$script:WorkspaceRootAbsolute = [System.IO.Path]::GetFullPath($workspaceCandidate)
$scannerAbsolute = Resolve-AbsolutePath -InputPath $ScannerPath -MustExist
$workingRootAbsolute = Resolve-AbsolutePath -InputPath $WorkingRoot
$sampleRoot = Join-Path $workingRootAbsolute "samples"
New-Item -ItemType Directory -Force -Path $sampleRoot | Out-Null

$normalFile = Join-Path $sampleRoot "edge-normal.txt"
Set-Content -Path $normalFile -Value "Fenrir realtime edge-case normal sample" -Encoding UTF8

$suspiciousFile = Join-Path $sampleRoot "edge-script.ps1"
Set-Content -Path $suspiciousFile -Value "Write-Host 'fenrir edge case sample'" -Encoding UTF8

$unicodeName = "edge-unicode-" + [string][char]0x4E2D + [string][char]0x6587 + ".ps1"
$unicodeFile = Join-Path $sampleRoot $unicodeName
Set-Content -Path $unicodeFile -Value "Write-Output 'unicode filename test'" -Encoding UTF8

$longLeaf = Join-Path $sampleRoot "long-path"
for ($index = 0; $index -lt 5; $index++) {
  $longLeaf = Join-Path $longLeaf ("segment-{0:D2}-edge-case" -f $index)
}
New-Item -ItemType Directory -Force -Path $longLeaf | Out-Null
$longPathFile = Join-Path $longLeaf "edge-long-path-script.ps1"
Set-Content -Path $longPathFile -Value "Write-Output 'long path test'" -Encoding UTF8

$missingCreatePath = Join-Path $sampleRoot "missing-create-target.exe"
$directoryTarget = $sampleRoot

$cases = @(
  @{ Operation = "create"; TargetPath = $missingCreatePath; ExpectedExitCodes = @(0, 2, 3); RequireJson = $true },
  @{ Operation = "open"; TargetPath = $normalFile; ExpectedExitCodes = @(0, 2, 3); RequireJson = $true },
  @{ Operation = "write"; TargetPath = $suspiciousFile; ExpectedExitCodes = @(0, 2, 3); RequireJson = $true },
  @{ Operation = "execute"; TargetPath = $suspiciousFile; ExpectedExitCodes = @(0, 2, 3); RequireJson = $true },
  @{ Operation = "execute"; TargetPath = $unicodeFile; ExpectedExitCodes = @(0, 2, 3); RequireJson = $true },
  @{ Operation = "execute"; TargetPath = $longPathFile; ExpectedExitCodes = @(0, 2, 3); RequireJson = $true },
  @{ Operation = "open"; TargetPath = $directoryTarget; ExpectedExitCodes = @(1); RequireJson = $false }
)

$results = [System.Collections.Generic.List[object]]::new()
for ($index = 0; $index -lt $cases.Count; $index++) {
  $case = $cases[$index]
  $runtimeRoot = Join-Path $workingRootAbsolute ("runtime-case-{0:D2}" -f $index)
  $result = Invoke-RealtimeCase -Scanner $scannerAbsolute -Operation $case.Operation -TargetPath $case.TargetPath -ExpectedExitCodes $case.ExpectedExitCodes -RuntimeRoot $runtimeRoot -RequireJsonOutput:([bool]$case.RequireJson)
  $results.Add($result) | Out-Null
}

$failures = @($results | Where-Object { $_.status -ne "pass" })
$allPass = $failures.Count -eq 0
$reportPath = Join-Path $workingRootAbsolute "minifilter-edgecase-report.json"
$report = [PSCustomObject]@{
  generatedAtUtc = [DateTime]::UtcNow.ToString("o")
  scannerPath = $scannerAbsolute
  caseCount = $cases.Count
  allPass = $allPass
  failures = $failures
  results = $results
}

$report | ConvertTo-Json -Depth 8 | Set-Content -Path $reportPath -Encoding UTF8
Write-Host "REPORT_PATH=$reportPath"
Write-Host ("MINIFILTER_EDGE_CASES={0}" -f ($(if ($allPass) { "PASS" } else { "FAIL" })))

if ($allPass) {
  exit 0
}

exit 2
