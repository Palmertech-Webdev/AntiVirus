param(
  [string]$WorkspaceRoot = ".",
  [string]$OutputRoot = "./tmp-phase2-corpora",
  [int]$FilesPerScenario = 24
)

$ErrorActionPreference = "Stop"

function Resolve-AbsolutePath {
  param(
    [Parameter(Mandatory = $true)]
    [string]$InputPath
  )

  $candidate = $InputPath
  if (-not [System.IO.Path]::IsPathRooted($candidate)) {
    $candidate = Join-Path $script:WorkspaceRootAbsolute $candidate
  }

  return [System.IO.Path]::GetFullPath($candidate)
}

function Ensure-Directory {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path
  )

  New-Item -ItemType Directory -Force -Path $Path | Out-Null
}

function Write-ScenarioFiles {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Root,
    [Parameter(Mandatory = $true)]
    [string[]]$Directories,
    [Parameter(Mandatory = $true)]
    [string[]]$Extensions,
    [Parameter(Mandatory = $true)]
    [string]$Content,
    [switch]$EncryptedTail,
    [string]$ManifestName,
    [hashtable]$Manifest
  )

  $files = @()
  for ($index = 0; $index -lt $FilesPerScenario; $index++) {
    $directoryName = $Directories[$index % $Directories.Count]
    $extension = $Extensions[$index % $Extensions.Count]
    if ($EncryptedTail -and $index -ge [Math]::Max(8, [Math]::Floor($FilesPerScenario / 2))) {
      $extension = if (($index % 2) -eq 0) { ".locked" } else { ".encrypted" }
    }

    $directoryPath = Join-Path $Root $directoryName
    Ensure-Directory -Path $directoryPath
    $path = Join-Path $directoryPath ("sample-{0:D3}{1}" -f ($index + 1), $extension)
    Set-Content -Path $path -Value $Content -Encoding ASCII
    $files += $path
  }

  $Manifest.files = $files
  $Manifest | ConvertTo-Json -Depth 6 | Set-Content -Path (Join-Path $Root $ManifestName) -Encoding UTF8
}

$workspaceCandidate = $WorkspaceRoot
if (-not [System.IO.Path]::IsPathRooted($workspaceCandidate)) {
  $workspaceCandidate = Join-Path (Get-Location) $workspaceCandidate
}
$script:WorkspaceRootAbsolute = [System.IO.Path]::GetFullPath($workspaceCandidate)
$outputRootAbsolute = Resolve-AbsolutePath -InputPath $OutputRoot
Ensure-Directory -Path $outputRootAbsolute

$userDataDirectories = @("documents", "desktop", "downloads", "pictures", "shared")
$documentExtensions = @(".docx", ".xlsx", ".pdf", ".jpg", ".txt", ".csv")
$mediaExtensions = @(".jpg", ".jpeg", ".png", ".json", ".txt", ".csv")
$buildExtensions = @(".obj", ".pdb", ".lib", ".tlog", ".cache", ".ilk")

$scenarioDefinitions = @(
  @{
    Name = "ransomware-write-burst"
    Type = "malicious"
    Content = "Fenrir Phase 2 synthetic ransomware write-burst content."
    Extensions = $documentExtensions
    EncryptedTail = $false
    Manifest = @{
      scenario = "ransomware-write-burst"
      expectedOutcome = "block"
      intent = "High-rate multi-directory rewrite churn across user data."
    }
  },
  @{
    Name = "ransomware-extension-burst"
    Type = "malicious"
    Content = "Fenrir Phase 2 synthetic extension-burst content."
    Extensions = $documentExtensions
    EncryptedTail = $true
    Manifest = @{
      scenario = "ransomware-extension-burst"
      expectedOutcome = "block"
      intent = "Encrypted-extension rename and write burst across user data."
    }
  },
  @{
    Name = "ransomware-staged-impact"
    Type = "malicious"
    Content = "Fenrir Phase 2 synthetic staged-impact content."
    Extensions = $documentExtensions
    EncryptedTail = $false
    Manifest = @{
      scenario = "ransomware-staged-impact"
      expectedOutcome = "block"
      intent = "Scripted staging followed by impact-phase destructive writes."
    }
  },
  @{
    Name = "benign-backup-sync"
    Type = "benign"
    Content = "Fenrir Phase 2 synthetic benign backup/sync content."
    Extensions = $documentExtensions
    EncryptedTail = $false
    Manifest = @{
      scenario = "benign-backup-sync"
      expectedOutcome = "allow"
      intent = "Benign backup or sync bulk I/O."
    }
  },
  @{
    Name = "benign-photo-video-export"
    Type = "benign"
    Content = "Fenrir Phase 2 synthetic benign media export content."
    Extensions = $mediaExtensions
    EncryptedTail = $false
    Manifest = @{
      scenario = "benign-photo-video-export"
      expectedOutcome = "allow"
      intent = "Benign photo or video export churn."
    }
  },
  @{
    Name = "benign-developer-build"
    Type = "benign"
    Content = "Fenrir Phase 2 synthetic benign developer build content."
    Extensions = $buildExtensions
    EncryptedTail = $false
    Manifest = @{
      scenario = "benign-developer-build"
      expectedOutcome = "allow"
      intent = "Benign developer build output churn."
    }
  }
)

$summary = [System.Collections.Generic.List[object]]::new()
foreach ($scenario in $scenarioDefinitions) {
  $scenarioRoot = Join-Path $outputRootAbsolute $scenario.Name
  Ensure-Directory -Path $scenarioRoot
  $manifest = @{}
  foreach ($entry in $scenario.Manifest.GetEnumerator()) {
    $manifest[$entry.Key] = $entry.Value
  }
  Write-ScenarioFiles -Root $scenarioRoot `
    -Directories $userDataDirectories `
    -Extensions $scenario.Extensions `
    -Content $scenario.Content `
    -EncryptedTail:([bool]$scenario.EncryptedTail) `
    -ManifestName "scenario.json" `
    -Manifest $manifest

  $summary.Add([PSCustomObject]@{
      scenario = $scenario.Name
      type = $scenario.Type
      expectedOutcome = $scenario.Manifest.expectedOutcome
      root = $scenarioRoot
      fileCount = $FilesPerScenario
    }) | Out-Null
}

$summaryPath = Join-Path $outputRootAbsolute "phase2-corpus-summary.json"
$summary | ConvertTo-Json -Depth 6 | Set-Content -Path $summaryPath -Encoding UTF8
Write-Host "PHASE2_CORPUS_ROOT=$outputRootAbsolute"
Write-Host "PHASE2_CORPUS_SUMMARY=$summaryPath"
