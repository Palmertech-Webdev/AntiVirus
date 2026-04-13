param(
  [string]$WorkspaceRoot = ".",
  [string]$OutputRoot = "./tmp-phase1-corpora-large",
  [int]$CleanwareCount = 150,
  [int]$UkBusinessCount = 150
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

function Write-CorpusFile {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Root,
    [Parameter(Mandatory = $true)]
    [string]$RelativePath,
    [Parameter(Mandatory = $true)]
    [string]$Content
  )

  $filePath = Join-Path $Root $RelativePath
  $directory = Split-Path -Parent $filePath
  New-Item -ItemType Directory -Force -Path $directory | Out-Null
  Set-Content -Path $filePath -Value $Content -Encoding UTF8
}

$workspaceCandidate = $WorkspaceRoot
if (-not [System.IO.Path]::IsPathRooted($workspaceCandidate)) {
  $workspaceCandidate = Join-Path (Get-Location) $workspaceCandidate
}
$script:WorkspaceRootAbsolute = [System.IO.Path]::GetFullPath($workspaceCandidate)
$outputRootAbsolute = Resolve-AbsolutePath -InputPath $OutputRoot
$cleanwareRoot = Join-Path $outputRootAbsolute "cleanware"
$ukRoot = Join-Path $outputRootAbsolute "uk-business-software"

New-Item -ItemType Directory -Force -Path $cleanwareRoot, $ukRoot | Out-Null

for ($index = 1; $index -le $CleanwareCount; $index++) {
  $mod = $index % 8
  switch ($mod) {
    0 {
      Write-CorpusFile -Root $cleanwareRoot -RelativePath ("household/budget/budget-{0}.csv" -f $index) -Content (
        "category,amount,owner`nutilities,{0},household`nfood,{1},household`ntransport,{2},household" -f
          (80 + $index),
          (120 + $index),
          (45 + $index)
      )
    }
    1 {
      Write-CorpusFile -Root $cleanwareRoot -RelativePath ("household/docs/maintenance-{0}.txt" -f $index) -Content (
        "Home maintenance checklist entry {0}: boiler service scheduled, smoke alarm check completed, garden supplies restocked." -f
          $index
      )
    }
    2 {
      $albumItemCount = 20 + ($index % 15)
      Write-CorpusFile -Root $cleanwareRoot -RelativePath ("household/photos/album-index-{0}.json" -f $index) -Content (
        "{`"albumId`":`"$index`",`"title`":`"Family Album $index`",`"itemCount`":$albumItemCount,`"location`":`"local-library`"}"
      )
    }
    3 {
      Write-CorpusFile -Root $cleanwareRoot -RelativePath ("household/school/schedule-{0}.md" -f $index) -Content (
        "# Week {0} School Schedule`n- Monday: maths homework review`n- Wednesday: reading practice`n- Friday: sports kit reminder" -f
          $index
      )
    }
    4 {
      Write-CorpusFile -Root $cleanwareRoot -RelativePath ("household/shopping/list-{0}.txt" -f $index) -Content (
        "Shopping list {0}: milk, bread, fruit, pasta, cleaning supplies, stationery." -f $index
      )
    }
    5 {
      Write-CorpusFile -Root $cleanwareRoot -RelativePath ("household/bills/utility-{0}.xml" -f $index) -Content (
        "<utility><month>{0}</month><provider>local-energy</provider><status>paid</status><reference>HB{1:0000}</reference></utility>" -f
          ((($index - 1) % 12) + 1),
          $index
      )
    }
    6 {
      Write-CorpusFile -Root $cleanwareRoot -RelativePath ("household/home-inventory/inventory-{0}.csv" -f $index) -Content (
        "room,item,quantity`nkitchen,mug,6`nliving-room,book,12`nbedroom,lamp,2"
      )
    }
    Default {
      Write-CorpusFile -Root $cleanwareRoot -RelativePath ("household/travel/itinerary-{0}.txt" -f $index) -Content (
        "Travel plan {0}: train booking confirmed, hotel reference recorded, local attractions list prepared." -f $index
      )
    }
  }
}

for ($index = 1; $index -le $UkBusinessCount; $index++) {
  $mod = $index % 8
  switch ($mod) {
    0 {
      Write-CorpusFile -Root $ukRoot -RelativePath ("finance/payroll/payroll-summary-{0}.csv" -f $index) -Content (
        "employee,department,gross`nalex,finance,{0}`njamie,operations,{1}`npat,support,{2}" -f
          (2500 + $index),
          (2300 + $index),
          (2100 + $index)
      )
    }
    1 {
      Write-CorpusFile -Root $ukRoot -RelativePath ("finance/vat/vat-notes-{0}.txt" -f $index) -Content (
        "VAT period note {0}: purchase ledger reconciled, sales totals reviewed, submission checklist complete." -f
          $index
      )
    }
    2 {
      Write-CorpusFile -Root $ukRoot -RelativePath ("finance/invoices/invoice-register-{0}.csv" -f $index) -Content (
        "invoiceId,customer,total`nINV-{0:0000},northwind,{1}`nINV-{2:0000},contoso,{3}" -f
          $index,
          (450 + $index),
          ($index + 1),
          (330 + $index)
      )
    }
    3 {
      Write-CorpusFile -Root $ukRoot -RelativePath ("operations/compliance/checklist-{0}.md" -f $index) -Content (
        "# Compliance Checklist {0}`n- Data retention reviewed`n- Access review completed`n- Incident log archived" -f
          $index
      )
    }
    4 {
      Write-CorpusFile -Root $ukRoot -RelativePath ("operations/support/ticket-report-{0}.txt" -f $index) -Content (
        "Support report {0}: resolved customer account update issue and documented follow-up actions." -f
          $index
      )
    }
    5 {
      Write-CorpusFile -Root $ukRoot -RelativePath ("it/software/software-inventory-{0}.json" -f $index) -Content (
        "{`"recordId`":$index,`"suite`":`"office-productivity`",`"status`":`"approved`",`"owner`":`"it-team`"}"
      )
    }
    6 {
      Write-CorpusFile -Root $ukRoot -RelativePath ("procurement/orders/order-log-{0}.csv" -f $index) -Content (
        "orderId,supplier,value`nPO-{0:0000},stationery-hub,{1}`nPO-{2:0000},hardware-direct,{3}" -f
          $index,
          (90 + $index),
          ($index + 1),
          (170 + $index)
      )
    }
    Default {
      Write-CorpusFile -Root $ukRoot -RelativePath ("management/meetings/minutes-{0}.txt" -f $index) -Content (
        "Meeting minutes {0}: reviewed quarterly goals, staffing plans, and customer satisfaction actions." -f
          $index
      )
    }
  }
}

$cleanwareFiles = @(Get-ChildItem -Path $cleanwareRoot -Recurse -File -ErrorAction SilentlyContinue).Count
$ukFiles = @(Get-ChildItem -Path $ukRoot -Recurse -File -ErrorAction SilentlyContinue).Count

[PSCustomObject]@{
  outputRoot = $outputRootAbsolute
  cleanwareRoot = $cleanwareRoot
  ukBusinessRoot = $ukRoot
  cleanwareFiles = $cleanwareFiles
  ukBusinessFiles = $ukFiles
} | Format-List
