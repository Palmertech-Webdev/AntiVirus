param(
  [string]$ScannerPath = "./agent/windows/out/dev/tools/fenrir-scannercli.exe",
  [string]$WorkspaceRoot = ".",
  [string]$WorkingRoot = "./tmp-phase3-hostile-fuzz",
  [int]$MutationCount = 48
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

function Write-BinaryFile {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path,
    [Parameter(Mandatory = $true)]
    [byte[]]$Bytes
  )

  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Path) | Out-Null
  [System.IO.File]::WriteAllBytes($Path, $Bytes)
}

$workspaceCandidate = $WorkspaceRoot
if (-not [System.IO.Path]::IsPathRooted($workspaceCandidate)) {
  $workspaceCandidate = Join-Path (Get-Location) $workspaceCandidate
}
$script:WorkspaceRootAbsolute = [System.IO.Path]::GetFullPath($workspaceCandidate)
$scannerAbsolute = Resolve-AbsolutePath -InputPath $ScannerPath -MustExist
$workingRootAbsolute = Resolve-AbsolutePath -InputPath $WorkingRoot
$fuzzRoot = Join-Path $workingRootAbsolute "samples"
New-Item -ItemType Directory -Force -Path $fuzzRoot | Out-Null

$seedSamples = @(
  @{ Relative = "malformed/truncated-central-directory.zip"; Bytes = [byte[]](0x50,0x4B,0x03,0x04,0x14,0x00,0x00,0x00,0x08,0x00) },
  @{ Relative = "malformed/oversized-entry-count.zip"; Bytes = [byte[]](0x50,0x4B,0x05,0x06,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0x10,0x00,0x00,0x00) },
  @{ Relative = "malformed/broken-shell-link.lnk"; Bytes = [byte[]](0x4C,0x00,0x00,0x00,0x01,0x14,0x02,0x00,0x00,0x00,0x00,0x00) },
  @{ Relative = "malformed/ole-header-only.doc"; Bytes = [byte[]](0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1,0x00,0x00,0x00,0x00) },
  @{ Relative = "malformed/invalid-js-utf16.js"; Bytes = [byte[]](0xFF,0xFE,0x61,0x00,0x62,0x00,0x63,0x00,0x00) },
  @{ Relative = "malformed/null-heavy-hta.hta"; Bytes = [byte[]](0x3C,0x68,0x74,0x6D,0x6C,0x3E,0x00,0x00,0x00,0x3C,0x2F,0x68,0x74,0x6D,0x6C,0x3E) }
)

$samplePaths = [System.Collections.Generic.List[string]]::new()
foreach ($sample in $seedSamples) {
  $absolutePath = Join-Path $fuzzRoot $sample.Relative
  Write-BinaryFile -Path $absolutePath -Bytes $sample.Bytes
  $samplePaths.Add($absolutePath) | Out-Null
}

$extensions = @(".zip", ".lnk", ".doc", ".hta", ".js", ".pdf")
$random = [System.Random]::new(1337)
for ($index = 0; $index -lt $MutationCount; $index++) {
  $length = 128 + $random.Next(0, 4096)
  $bytes = New-Object byte[] $length
  $random.NextBytes($bytes)
  $extension = $extensions[$random.Next(0, $extensions.Length)]
  $relativePath = "mutated/fuzz-{0:D4}{1}" -f $index, $extension
  $absolutePath = Join-Path $fuzzRoot $relativePath
  Write-BinaryFile -Path $absolutePath -Bytes $bytes
  $samplePaths.Add($absolutePath) | Out-Null
}

$results = [System.Collections.Generic.List[object]]::new()
$failures = [System.Collections.Generic.List[object]]::new()

$savedEnvironment = @{
  ANTIVIRUS_RUNTIME_DB_PATH = $env:ANTIVIRUS_RUNTIME_DB_PATH
  ANTIVIRUS_AGENT_STATE_FILE = $env:ANTIVIRUS_AGENT_STATE_FILE
  ANTIVIRUS_TELEMETRY_QUEUE_FILE = $env:ANTIVIRUS_TELEMETRY_QUEUE_FILE
  ANTIVIRUS_UPDATE_ROOT = $env:ANTIVIRUS_UPDATE_ROOT
  ANTIVIRUS_JOURNAL_ROOT = $env:ANTIVIRUS_JOURNAL_ROOT
  ANTIVIRUS_QUARANTINE_ROOT = $env:ANTIVIRUS_QUARANTINE_ROOT
  ANTIVIRUS_EVIDENCE_ROOT = $env:ANTIVIRUS_EVIDENCE_ROOT
}

for ($sampleIndex = 0; $sampleIndex -lt $samplePaths.Count; $sampleIndex++) {
  $samplePath = $samplePaths[$sampleIndex]

  $runtimeRoot = Join-Path $workingRootAbsolute ("runtime-{0:D4}" -f $sampleIndex)
  $runtimeDbPath = Join-Path $runtimeRoot "agent-runtime.db"
  $stateFilePath = Join-Path $runtimeRoot "agent-state.ini"
  $telemetryPath = Join-Path $runtimeRoot "telemetry-queue.tsv"
  $updateRoot = Join-Path $runtimeRoot "update"
  $journalRoot = Join-Path $runtimeRoot "journal"
  $quarantineRoot = Join-Path $runtimeRoot "quarantine"
  $evidenceRoot = Join-Path $runtimeRoot "evidence"

  New-Item -ItemType Directory -Force -Path $updateRoot, $journalRoot, $quarantineRoot, $evidenceRoot | Out-Null

  $env:ANTIVIRUS_RUNTIME_DB_PATH = $runtimeDbPath
  $env:ANTIVIRUS_AGENT_STATE_FILE = $stateFilePath
  $env:ANTIVIRUS_TELEMETRY_QUEUE_FILE = $telemetryPath
  $env:ANTIVIRUS_UPDATE_ROOT = $updateRoot
  $env:ANTIVIRUS_JOURNAL_ROOT = $journalRoot
  $env:ANTIVIRUS_QUARANTINE_ROOT = $quarantineRoot
  $env:ANTIVIRUS_EVIDENCE_ROOT = $evidenceRoot

  $stdout = & $scannerAbsolute --json --no-remediation --no-telemetry --path $samplePath
  $exitCode = $LASTEXITCODE
  $jsonText = ($stdout | Out-String).Trim()

  $parseOk = $false
  $findingCount = 0
  if (-not [string]::IsNullOrWhiteSpace($jsonText)) {
    try {
      $parsed = $jsonText | ConvertFrom-Json
      if ($null -ne $parsed.findings) {
        $findingCount = @($parsed.findings).Count
      }
      $parseOk = $true
    } catch {
      $parseOk = $false
    }
  }

  $exitOk = @($exitCode -eq 0, $exitCode -eq 2, $exitCode -eq 3) -contains $true
  $status = if ($exitOk -and $parseOk) { "pass" } else { "fail" }

  $result = [PSCustomObject]@{
    samplePath = $samplePath
    exitCode = $exitCode
    jsonParsed = $parseOk
    findingCount = $findingCount
    status = $status
  }
  $results.Add($result) | Out-Null

  if ($status -ne "pass") {
    $failures.Add([PSCustomObject]@{
        samplePath = $samplePath
        exitCode = $exitCode
        output = $jsonText
      }) | Out-Null
  }
}

foreach ($entry in $savedEnvironment.GetEnumerator()) {
  if ($null -eq $entry.Value) {
    Remove-Item -Path "Env:$($entry.Key)" -ErrorAction SilentlyContinue
  } else {
    Set-Item -Path "Env:$($entry.Key)" -Value $entry.Value
  }
}

$reportPath = Join-Path $workingRootAbsolute "hostile-input-fuzz-report.json"
$allPass = $failures.Count -eq 0
$report = [PSCustomObject]@{
  generatedAtUtc = [DateTime]::UtcNow.ToString("o")
  scannerPath = $scannerAbsolute
  sampleCount = $samplePaths.Count
  mutationCount = $MutationCount
  allPass = $allPass
  failures = $failures
  results = $results
}

$report | ConvertTo-Json -Depth 8 | Set-Content -Path $reportPath -Encoding UTF8
Write-Host "REPORT_PATH=$reportPath"
Write-Host ("HOSTILE_INPUT_FUZZ={0}" -f ($(if ($allPass) { "PASS" } else { "FAIL" })))

if ($allPass) {
  exit 0
}

exit 2
