param(
  [string]$ScannerPath = "./agent/windows/out/dev/tools/fenrir-scannercli.exe",
  [string]$WorkspaceRoot = ".",
  [string]$WorkingRoot = "./tmp-phase1-minifilter-edge",
  [switch]$RequireFullCoverage
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

function New-SkippedCaseResult {
  param(
    [Parameter(Mandatory = $true)]
    [string]$CaseName,
    [Parameter(Mandatory = $true)]
    [string]$Category,
    [Parameter(Mandatory = $true)]
    [string]$Operation,
    [Parameter(Mandatory = $true)]
    [string]$TargetPath,
    [Parameter(Mandatory = $true)]
    [string]$Reason
  )

  return [PSCustomObject]@{
    caseName = $CaseName
    category = $Category
    operation = $Operation
    targetPath = $TargetPath
    expectedExitCodes = @()
    exitCode = -1
    requireJsonOutput = $false
    jsonValid = $false
    findingCount = 0
    dispositions = @()
    reasonCodes = @()
    status = "skip"
    skipReason = $Reason
    output = ""
  }
}

function Get-UniqueStrings {
  param(
    [AllowEmptyCollection()]
    [string[]]$Values = @()
  )

  $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  $unique = [System.Collections.Generic.List[string]]::new()
  foreach ($value in @($Values)) {
    if ([string]::IsNullOrWhiteSpace($value)) {
      continue
    }

    if ($seen.Add($value)) {
      $null = $unique.Add($value)
    }
  }

  return @($unique)
}

function Invoke-RealtimeCase {
  param(
    [Parameter(Mandatory = $true)]
    [string]$CaseName,
    [Parameter(Mandatory = $true)]
    [string]$Category,
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
    [switch]$RequireJsonOutput,
    [int]$MinimumFindings = 0
  )

  $null = New-Item -ItemType Directory -Force -Path $RuntimeRoot
  $runtimeDbPath = Join-Path $RuntimeRoot "agent-runtime.db"
  $stateFilePath = Join-Path $RuntimeRoot "agent-state.ini"
  $telemetryPath = Join-Path $RuntimeRoot "telemetry-queue.tsv"
  $updateRoot = Join-Path $RuntimeRoot "update"
  $journalRoot = Join-Path $RuntimeRoot "journal"
  $quarantineRoot = Join-Path $RuntimeRoot "quarantine"
  $evidenceRoot = Join-Path $RuntimeRoot "evidence"

  $null = New-Item -ItemType Directory -Force -Path $updateRoot, $journalRoot, $quarantineRoot, $evidenceRoot

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
    $stdout = & $Scanner --json --no-telemetry --no-remediation --realtime-op $Operation --path $TargetPath 2>&1
    $exitCode = $LASTEXITCODE

    $capturedLines = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in @($stdout)) {
      if ($entry -is [System.Management.Automation.ErrorRecord]) {
        $null = $capturedLines.Add($entry.ToString())
      } else {
        $null = $capturedLines.Add([string]$entry)
      }
    }

    $output = [string]::Join([Environment]::NewLine, $capturedLines)
    $output = $output.Trim()
  } finally {
    foreach ($entry in $savedEnvironment.GetEnumerator()) {
      if ($null -eq $entry.Value) {
        Remove-Item -Path "Env:$($entry.Key)" -ErrorAction SilentlyContinue
      } else {
        Set-Item -Path "Env:$($entry.Key)" -Value $entry.Value
      }
    }
  }

  $parsed = $null
  $findings = @()
  $jsonValid = $false
  if ($RequireJsonOutput) {
    if (-not [string]::IsNullOrWhiteSpace($output)) {
      try {
        $parsed = ConvertFrom-Json -InputObject $output
        if ($null -ne $parsed.findings) {
          $findings = @($parsed.findings)
        }
        $jsonValid = $true
      } catch {
        $jsonValid = $false
      }
    }
  }

  $reasonCodes = @()
  $dispositions = @()
  foreach ($finding in $findings) {
    try {
      $dispositionText = [string]$finding.disposition
      if (-not [string]::IsNullOrWhiteSpace($dispositionText)) {
        $dispositions += $dispositionText
      }
    } catch {
    }

    try {
      foreach ($reason in @($finding.reasons)) {
        if ($null -ne $reason -and -not [string]::IsNullOrWhiteSpace([string]$reason.code)) {
          $reasonCodes += [string]$reason.code
        }
      }
    } catch {
    }
  }

  $findingThresholdMet = $true
  if ($MinimumFindings -gt 0) {
    $findingThresholdMet = @($findings).Count -ge $MinimumFindings
  }

  $exitOk = $ExpectedExitCodes -contains $exitCode
  $status = if ($exitOk -and ((-not $RequireJsonOutput) -or $jsonValid) -and $findingThresholdMet) { "pass" } else { "fail" }

  return [PSCustomObject]@{
    caseName = $CaseName
    category = $Category
    operation = $Operation
    targetPath = $TargetPath
    expectedExitCodes = $ExpectedExitCodes
    exitCode = $exitCode
    requireJsonOutput = [bool]$RequireJsonOutput
    jsonValid = $jsonValid
    findingCount = @($findings).Count
    dispositions = Get-UniqueStrings -Values @($dispositions)
    reasonCodes = Get-UniqueStrings -Values @($reasonCodes)
    status = $status
    skipReason = ""
    output = $output
  }
}

function Get-CoverageStatus {
  param(
    [Parameter(Mandatory = $true)]
    [object[]]$Results,
    [Parameter(Mandatory = $true)]
    [string]$Category
  )

  $categoryResults = [System.Collections.Generic.List[object]]::new()
  foreach ($result in @($Results)) {
    if ($result.category -eq $Category) {
      $null = $categoryResults.Add($result)
    }
  }

  if ($categoryResults.Count -eq 0) {
    return "missing"
  }

  $passCount = 0
  $skipCount = 0
  foreach ($categoryResult in $categoryResults) {
    if ($categoryResult.status -eq "fail") {
      return "fail"
    }

    if ($categoryResult.status -eq "pass") {
      $passCount += 1
      continue
    }

    if ($categoryResult.status -eq "skip") {
      $skipCount += 1
    }
  }

  if ($passCount -gt 0 -and $skipCount -gt 0) {
    return "partial"
  }

  if ($passCount -gt 0) {
    return "pass"
  }

  if ($skipCount -gt 0) {
    return "skip"
  }

  return "missing"
}

function Add-ZipEntry {
  param(
    [Parameter(Mandatory = $true)]
    [object]$Archive,
    [Parameter(Mandatory = $true)]
    [string]$EntryName,
    [string]$Content = "fenrir-edge-archive"
  )

  $entry = $Archive.CreateEntry($EntryName)
  $stream = $entry.Open()
  $writer = New-Object System.IO.StreamWriter($stream, [System.Text.Encoding]::UTF8)
  try {
    $writer.Write($Content)
  } finally {
    $writer.Dispose()
    $stream.Dispose()
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
$null = New-Item -ItemType Directory -Force -Path $sampleRoot

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
$null = New-Item -ItemType Directory -Force -Path $longLeaf
$longPathFile = Join-Path $longLeaf "edge-long-path-script.ps1"
Set-Content -Path $longPathFile -Value "Write-Output 'long path test'" -Encoding UTF8

$adsHostFile = Join-Path $sampleRoot "edge-ads-host.txt"
Set-Content -Path $adsHostFile -Value "Fenrir ADS host" -Encoding UTF8
$adsPath = "${adsHostFile}:edge-hidden-stream.ps1"
Set-Content -LiteralPath $adsPath -Value "Write-Output 'ads edge test'" -Encoding UTF8

$cloudSyncRoot = Join-Path $sampleRoot "OneDrive Edge Sync"
$null = New-Item -ItemType Directory -Force -Path $cloudSyncRoot
$cloudSyncFile = Join-Path $cloudSyncRoot "edge-cloud-sync-script.ps1"
Set-Content -Path $cloudSyncFile -Value "Write-Output 'cloud sync edge test'" -Encoding UTF8

$largeFile = Join-Path $sampleRoot "edge-large-file.bin"
$largeFileStream = [System.IO.File]::Open($largeFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
try {
  $largeFileStream.SetLength(80MB)
} finally {
  $largeFileStream.Dispose()
}

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archiveAbuseFile = Join-Path $sampleRoot "edge-archive-abuse.zip"
if (Test-Path -LiteralPath $archiveAbuseFile) {
  Remove-Item -LiteralPath $archiveAbuseFile -Force
}

$archive = [System.IO.Compression.ZipFile]::Open($archiveAbuseFile, [System.IO.Compression.ZipArchiveMode]::Create)
try {
  Add-ZipEntry -Archive $archive -EntryName "invoice.pdf.exe" -Content "MZ"
  Add-ZipEntry -Archive $archive -EntryName "stage/payload.ps1" -Content "Write-Output 'archive script payload'"
  Add-ZipEntry -Archive $archive -EntryName "stage/dropper.lnk" -Content "shortcut"
  for ($entryIndex = 0; $entryIndex -lt 512; $entryIndex++) {
    Add-ZipEntry -Archive $archive -EntryName ("bulk/entry-{0:D4}.txt" -f $entryIndex) -Content "edge"
  }
} finally {
  $archive.Dispose()
}

$reparseTargetRoot = Join-Path $sampleRoot "reparse-target"
$null = New-Item -ItemType Directory -Force -Path $reparseTargetRoot
$reparseTargetFile = Join-Path $reparseTargetRoot "reparse-target-script.ps1"
Set-Content -Path $reparseTargetFile -Value "Write-Output 'reparse target file'" -Encoding UTF8

$junctionRoot = Join-Path $sampleRoot "edge-junction"
$junctionFile = Join-Path $junctionRoot "reparse-target-script.ps1"
$junctionReady = $false
$junctionSkipReason = ""
try {
  if (Test-Path -LiteralPath $junctionRoot) {
    Remove-Item -LiteralPath $junctionRoot -Recurse -Force
  }
  $null = New-Item -ItemType Junction -Path $junctionRoot -Target $reparseTargetRoot -ErrorAction Stop
  $junctionReady = Test-Path -LiteralPath $junctionFile
  if (-not $junctionReady) {
    $junctionSkipReason = "Junction was created but the linked target path was not accessible."
  }
} catch {
  $junctionSkipReason = "Junction creation failed in this environment: $($_.Exception.Message)"
}

$symlinkRoot = Join-Path $sampleRoot "edge-symlink"
$symlinkFile = Join-Path $symlinkRoot "reparse-target-script.ps1"
$symlinkReady = $false
$symlinkSkipReason = ""
try {
  if (Test-Path -LiteralPath $symlinkRoot) {
    Remove-Item -LiteralPath $symlinkRoot -Recurse -Force
  }
  $null = New-Item -ItemType SymbolicLink -Path $symlinkRoot -Target $reparseTargetRoot -ErrorAction Stop
  $symlinkReady = Test-Path -LiteralPath $symlinkFile
  if (-not $symlinkReady) {
    $symlinkSkipReason = "Symlink was created but the linked target path was not accessible."
  }
} catch {
  $symlinkSkipReason = "Symlink creation failed in this environment: $($_.Exception.Message)"
}

$removableSamplePath = ""
$removableSkipReason = ""
try {
  $removableDrive = $null
  foreach ($candidateDrive in @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=2" -ErrorAction Stop)) {
    $removableDrive = $candidateDrive
    break
  }

  if ($null -eq $removableDrive -or [string]::IsNullOrWhiteSpace($removableDrive.DeviceID)) {
    $removableSkipReason = "No removable drive was detected on this endpoint."
  } else {
    $removableRoot = $removableDrive.DeviceID
    if (-not $removableRoot.EndsWith("\\")) {
      $removableRoot += "\\"
    }
    $removableSamplePath = Join-Path $removableRoot "fenrir-edge-removable.ps1"
    Set-Content -Path $removableSamplePath -Value "Write-Output 'removable edge case'" -Encoding UTF8
  }
} catch {
  $removableSkipReason = "Removable-media setup failed: $($_.Exception.Message)"
}

$networkSharePath = ""
if ([string]::IsNullOrWhiteSpace($env:SystemDrive)) {
  $networkSharePath = "\\\\localhost\\c$\\fenrir-edge-missing-network-target.ps1"
} else {
  $systemDrive = $env:SystemDrive.TrimEnd(':')
  $networkSharePath = "\\\\localhost\\$($systemDrive)$\\fenrir-edge-missing-network-target.ps1"
}

$lockedImagePath = Join-Path $sampleRoot "edge-locked-image.exe"
$lockedImageSource = Join-Path $env:WINDIR "System32\\notepad.exe"
if (-not (Test-Path -LiteralPath $lockedImageSource)) {
  $lockedImageSource = $scannerAbsolute
}
Copy-Item -LiteralPath $lockedImageSource -Destination $lockedImagePath -Force

$lockedImageHandle = $null
$lockedImageSection = $null
$lockedImageReady = $false
$lockedImageSkipReason = ""
try {
  $lockedImageHandle = [System.IO.File]::Open($lockedImagePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
  $lockedImageSection = [System.IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile(
    $lockedImageHandle,
    $null,
    0,
    [System.IO.MemoryMappedFiles.MemoryMappedFileAccess]::Read,
    [System.IO.HandleInheritability]::None,
    $false)
  $lockedImageReady = $true
} catch {
  $lockedImageSkipReason = "Could not hold a locked image section in this context: $($_.Exception.Message)"
}

$missingCreatePath = Join-Path $sampleRoot "missing-create-target.exe"
$directoryTarget = $sampleRoot

$cases = [System.Collections.Generic.List[object]]::new()
$null = $cases.Add([PSCustomObject]@{ CaseName = "core-create-missing"; Category = "operation-create"; Operation = "create"; TargetPath = $missingCreatePath; ExpectedExitCodes = @(0, 2, 3); RequireJson = $true; MinimumFindings = 0; SkipReason = "" })
$null = $cases.Add([PSCustomObject]@{ CaseName = "core-open-normal"; Category = "operation-open"; Operation = "open"; TargetPath = $normalFile; ExpectedExitCodes = @(0, 2, 3); RequireJson = $true; MinimumFindings = 0; SkipReason = "" })
$null = $cases.Add([PSCustomObject]@{ CaseName = "core-write-script"; Category = "operation-write"; Operation = "write"; TargetPath = $suspiciousFile; ExpectedExitCodes = @(0, 2, 3); RequireJson = $true; MinimumFindings = 0; SkipReason = "" })
$null = $cases.Add([PSCustomObject]@{ CaseName = "core-rename-script"; Category = "operation-rename"; Operation = "rename"; TargetPath = $suspiciousFile; ExpectedExitCodes = @(0, 2, 3); RequireJson = $true; MinimumFindings = 0; SkipReason = "" })
$null = $cases.Add([PSCustomObject]@{ CaseName = "core-execute-script"; Category = "operation-execute"; Operation = "execute"; TargetPath = $suspiciousFile; ExpectedExitCodes = @(0, 2, 3); RequireJson = $true; MinimumFindings = 0; SkipReason = "" })
$null = $cases.Add([PSCustomObject]@{ CaseName = "core-section-map-script"; Category = "operation-section-map"; Operation = "section-map"; TargetPath = $suspiciousFile; ExpectedExitCodes = @(0, 2, 3); RequireJson = $true; MinimumFindings = 0; SkipReason = "" })

$null = $cases.Add([PSCustomObject]@{ CaseName = "edge-ads-stream"; Category = "ads"; Operation = "create"; TargetPath = $adsPath; ExpectedExitCodes = @(0, 2, 3); RequireJson = $true; MinimumFindings = 0; SkipReason = "" })
$null = $cases.Add([PSCustomObject]@{ CaseName = "edge-cloud-sync"; Category = "cloud-sync-folders"; Operation = "write"; TargetPath = $cloudSyncFile; ExpectedExitCodes = @(0, 2, 3); RequireJson = $true; MinimumFindings = 0; SkipReason = "" })
$null = $cases.Add([PSCustomObject]@{ CaseName = "edge-large-file"; Category = "large-files"; Operation = "open"; TargetPath = $largeFile; ExpectedExitCodes = @(0, 2, 3); RequireJson = $true; MinimumFindings = 0; SkipReason = "" })
$null = $cases.Add([PSCustomObject]@{ CaseName = "edge-archive-abuse"; Category = "archive-abuse"; Operation = "open"; TargetPath = $archiveAbuseFile; ExpectedExitCodes = @(0, 2, 3); RequireJson = $true; MinimumFindings = 0; SkipReason = "" })
$null = $cases.Add([PSCustomObject]@{ CaseName = "edge-network-share"; Category = "network-shares"; Operation = "create"; TargetPath = $networkSharePath; ExpectedExitCodes = @(0, 2, 3); RequireJson = $true; MinimumFindings = 0; SkipReason = "" })

if ($junctionReady) {
  $null = $cases.Add([PSCustomObject]@{ CaseName = "edge-reparse-junction"; Category = "reparse-points"; Operation = "open"; TargetPath = $junctionFile; ExpectedExitCodes = @(0, 2, 3); RequireJson = $true; MinimumFindings = 0; SkipReason = "" })
  $null = $cases.Add([PSCustomObject]@{ CaseName = "edge-junction"; Category = "junctions"; Operation = "rename"; TargetPath = $junctionFile; ExpectedExitCodes = @(0, 2, 3); RequireJson = $true; MinimumFindings = 0; SkipReason = "" })
} else {
  $null = $cases.Add([PSCustomObject]@{ CaseName = "edge-reparse-junction"; Category = "reparse-points"; Operation = "open"; TargetPath = $junctionFile; ExpectedExitCodes = @(); RequireJson = $false; MinimumFindings = 0; SkipReason = $junctionSkipReason })
  $null = $cases.Add([PSCustomObject]@{ CaseName = "edge-junction"; Category = "junctions"; Operation = "rename"; TargetPath = $junctionFile; ExpectedExitCodes = @(); RequireJson = $false; MinimumFindings = 0; SkipReason = $junctionSkipReason })
}

if ($symlinkReady) {
  $null = $cases.Add([PSCustomObject]@{ CaseName = "edge-symlink"; Category = "symlinks"; Operation = "open"; TargetPath = $symlinkFile; ExpectedExitCodes = @(0, 2, 3); RequireJson = $true; MinimumFindings = 0; SkipReason = "" })
  if (-not $junctionReady) {
    $null = $cases.Add([PSCustomObject]@{ CaseName = "edge-reparse-symlink"; Category = "reparse-points"; Operation = "open"; TargetPath = $symlinkFile; ExpectedExitCodes = @(0, 2, 3); RequireJson = $true; MinimumFindings = 0; SkipReason = "" })
  }
} else {
  $null = $cases.Add([PSCustomObject]@{ CaseName = "edge-symlink"; Category = "symlinks"; Operation = "open"; TargetPath = $symlinkFile; ExpectedExitCodes = @(); RequireJson = $false; MinimumFindings = 0; SkipReason = $symlinkSkipReason })
}

if (-not [string]::IsNullOrWhiteSpace($removableSamplePath)) {
  $null = $cases.Add([PSCustomObject]@{ CaseName = "edge-removable-media"; Category = "removable-media"; Operation = "open"; TargetPath = $removableSamplePath; ExpectedExitCodes = @(0, 2, 3); RequireJson = $true; MinimumFindings = 0; SkipReason = "" })
} else {
  $null = $cases.Add([PSCustomObject]@{ CaseName = "edge-removable-media"; Category = "removable-media"; Operation = "open"; TargetPath = ""; ExpectedExitCodes = @(); RequireJson = $false; MinimumFindings = 0; SkipReason = $removableSkipReason })
}

if ($lockedImageReady) {
  $null = $cases.Add([PSCustomObject]@{ CaseName = "edge-locked-image-section"; Category = "locked-image-sections"; Operation = "section-map"; TargetPath = $lockedImagePath; ExpectedExitCodes = @(0, 2, 3); RequireJson = $true; MinimumFindings = 0; SkipReason = "" })
} else {
  $null = $cases.Add([PSCustomObject]@{ CaseName = "edge-locked-image-section"; Category = "locked-image-sections"; Operation = "section-map"; TargetPath = $lockedImagePath; ExpectedExitCodes = @(); RequireJson = $false; MinimumFindings = 0; SkipReason = $lockedImageSkipReason })
}

$null = $cases.Add([PSCustomObject]@{ CaseName = "edge-execute-unicode"; Category = "unicode-paths"; Operation = "execute"; TargetPath = $unicodeFile; ExpectedExitCodes = @(0, 2, 3); RequireJson = $true; MinimumFindings = 0; SkipReason = "" })
$null = $cases.Add([PSCustomObject]@{ CaseName = "edge-execute-long-path"; Category = "long-paths"; Operation = "execute"; TargetPath = $longPathFile; ExpectedExitCodes = @(0, 2, 3); RequireJson = $true; MinimumFindings = 0; SkipReason = "" })
$null = $cases.Add([PSCustomObject]@{ CaseName = "edge-open-directory-invalid-input"; Category = "input-validation"; Operation = "open"; TargetPath = $directoryTarget; ExpectedExitCodes = @(1); RequireJson = $false; MinimumFindings = 0; SkipReason = "" })

$results = [System.Collections.Generic.List[object]]::new()
for ($index = 0; $index -lt $cases.Count; $index++) {
  $case = $cases[$index]
  if (-not [string]::IsNullOrWhiteSpace($case.SkipReason)) {
    $result = New-SkippedCaseResult -CaseName $case.CaseName -Category $case.Category -Operation $case.Operation -TargetPath $case.TargetPath -Reason $case.SkipReason
    $null = $results.Add($result)
    continue
  }

  $runtimeRoot = Join-Path $workingRootAbsolute ("runtime-case-{0:D2}" -f $index)
  $result = Invoke-RealtimeCase -CaseName $case.CaseName -Category $case.Category -Scanner $scannerAbsolute -Operation $case.Operation -TargetPath $case.TargetPath -ExpectedExitCodes $case.ExpectedExitCodes -RuntimeRoot $runtimeRoot -RequireJsonOutput:([bool]$case.RequireJson) -MinimumFindings $case.MinimumFindings
  $null = $results.Add($result)
}

if ($null -ne $lockedImageSection) {
  $lockedImageSection.Dispose()
}
if ($null -ne $lockedImageHandle) {
  $lockedImageHandle.Dispose()
}

$failures = [System.Collections.Generic.List[object]]::new()
$skipped = [System.Collections.Generic.List[object]]::new()
foreach ($result in $results) {
  if ($result.status -ne "pass") {
    if ($result.status -eq "skip") {
      $null = $skipped.Add($result)
    } else {
      $null = $failures.Add($result)
    }
  }
}

$requiredCoverageItems = @(
  "operation-create",
  "operation-open",
  "operation-write",
  "operation-execute",
  "operation-rename",
  "operation-section-map",
  "ads",
  "reparse-points",
  "junctions",
  "symlinks",
  "removable-media",
  "network-shares",
  "cloud-sync-folders",
  "large-files",
  "locked-image-sections",
  "archive-abuse"
)

$coverage = [ordered]@{}
foreach ($coverageItem in $requiredCoverageItems) {
  $coverage[$coverageItem] = Get-CoverageStatus -Results @($results) -Category $coverageItem
}

$coverageFailures = @()
$coverageSkips = @()
foreach ($coverageEntry in $coverage.GetEnumerator()) {
  if ($coverageEntry.Value -in @("fail", "missing")) {
    $coverageFailures += $coverageEntry.Key
  } elseif ($coverageEntry.Value -in @("skip", "partial")) {
    $coverageSkips += $coverageEntry.Key
  }
}

$requiredCoverageSatisfied = $coverageFailures.Count -eq 0 -and (($coverageSkips.Count -eq 0) -or (-not $RequireFullCoverage))
$allPass = $failures.Count -eq 0 -and $requiredCoverageSatisfied
$reportPath = Join-Path $workingRootAbsolute "minifilter-edgecase-report.json"
$report = [PSCustomObject]@{
  generatedAtUtc = [DateTime]::UtcNow.ToString("o")
  scannerPath = $scannerAbsolute
  caseCount = $cases.Count
  failedCaseCount = $failures.Count
  skippedCaseCount = $skipped.Count
  requireFullCoverage = [bool]$RequireFullCoverage
  requiredCoverageSatisfied = $requiredCoverageSatisfied
  requiredCoverageFailures = @($coverageFailures)
  requiredCoverageSkipped = @($coverageSkips)
  coverage = [PSCustomObject]$coverage
  allPass = $allPass
  failures = @($failures)
  skipped = @($skipped)
  results = $results
}

$reportJson = ConvertTo-Json -InputObject $report -Depth 8
Set-Content -Path $reportPath -Encoding UTF8 -Value $reportJson
Write-Host "REPORT_PATH=$reportPath"
Write-Host ("MINIFILTER_EDGE_CASES={0}" -f ($(if ($allPass) { "PASS" } else { "FAIL" })))

if ($allPass) {
  exit 0
}

exit 2
