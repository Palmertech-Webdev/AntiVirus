param(
    [string]$DriverPackageRoot = (Join-Path $PSScriptRoot 'package'),
    [string]$StageDriverRoot = (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'out\dev\driver'),
    [string]$CertificateSubject = 'CN=Antivirus Test Driver Signing',
    [int]$CertificateValidityYears = 5,
    [string]$ExpectedServiceName = 'AntivirusMinifilter',
    [bool]$ConfigureBootForTestSigning = $true,
    [bool]$InstallDriverPackage = $true,
    [bool]$ResignDriverArtifacts = $true
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Test-IsRunningAsAdministrator {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-Directory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
}

function Resolve-WindowsKitExecutable {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -ne $command -and $command.Source) {
        return $command.Source
    }

    $kitsRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    if (-not (Test-Path -LiteralPath $kitsRoot)) {
        return ''
    }

    $versions = Get-ChildItem -LiteralPath $kitsRoot -Directory | Sort-Object Name -Descending
    foreach ($version in $versions) {
        foreach ($arch in @('x64', 'x86', 'arm64')) {
            $candidate = Join-Path $version.FullName (Join-Path $arch $Name)
            if (Test-Path -LiteralPath $candidate) {
                return $candidate
            }
        }
    }

    return ''
}

function Get-OrCreateSigningCertificate {
    param(
        [Parameter(Mandatory = $true)][string]$Subject,
        [Parameter(Mandatory = $true)][int]$ValidityYears
    )

    $existing = Get-ChildItem -Path Cert:\LocalMachine\My |
        Where-Object { $_.Subject -eq $Subject } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1
    if ($null -ne $existing) {
        return $existing
    }

    $friendlyName = 'Fenrir Local Test Driver Signing'
    return New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $Subject `
        -CertStoreLocation 'Cert:\LocalMachine\My' `
        -FriendlyName $friendlyName `
        -KeyAlgorithm RSA `
        -KeyLength 3072 `
        -HashAlgorithm SHA256 `
        -NotAfter (Get-Date).AddYears($ValidityYears) `
        -KeyExportPolicy Exportable
}

function Ensure-CertificateTrust {
    param(
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    function Import-CertificateWithFallback {
        param(
            [Parameter(Mandatory = $true)][string]$CertificatePath,
            [Parameter(Mandatory = $true)][string]$StoreLocation,
            [Parameter(Mandatory = $true)][string]$CertUtilStoreName
        )

        try {
            Import-Certificate -FilePath $CertificatePath -CertStoreLocation $StoreLocation -ErrorAction Stop | Out-Null
            return
        }
        catch {
            $importException = $_.Exception
            $certutilOutput = (& certutil.exe -f -addstore $CertUtilStoreName $CertificatePath 2>&1 | Out-String)
            if ($LASTEXITCODE -eq 0) {
                return
            }

            $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            $message = @(
                "Failed to import the Fenrir test signing certificate into $StoreLocation.",
                "Import-Certificate error: $($importException.Message)",
                "certutil exit code: $LASTEXITCODE",
                "certutil output: $($certutilOutput.Trim())",
                "Current identity: $identity",
                'Run this script from an elevated Administrator PowerShell session and ensure endpoint policy allows writes to LocalMachine certificate stores.'
            ) -join ' '
            throw $message
        }
    }

    $thumbprint = $Certificate.Thumbprint
    $alreadyRoot = Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq $thumbprint } | Select-Object -First 1
    $alreadyTrustedPublisher = Get-ChildItem -Path Cert:\LocalMachine\TrustedPublisher | Where-Object { $_.Thumbprint -eq $thumbprint } | Select-Object -First 1

    if ($alreadyRoot -and $alreadyTrustedPublisher) {
        return
    }

    $tempCerPath = Join-Path ([System.IO.Path]::GetTempPath()) ("fenrir-minifilter-test-cert-{0}.cer" -f $thumbprint)
    try {
        Export-Certificate -Cert $Certificate -FilePath $tempCerPath -Force | Out-Null

        if (-not $alreadyRoot) {
            Import-CertificateWithFallback -CertificatePath $tempCerPath -StoreLocation 'Cert:\LocalMachine\Root' -CertUtilStoreName 'Root'
        }
        if (-not $alreadyTrustedPublisher) {
            Import-CertificateWithFallback -CertificatePath $tempCerPath -StoreLocation 'Cert:\LocalMachine\TrustedPublisher' -CertUtilStoreName 'TrustedPublisher'
        }
    }
    finally {
        if (Test-Path -LiteralPath $tempCerPath) {
            Remove-Item -LiteralPath $tempCerPath -Force
        }
    }
}

function Sign-DriverArtifact {
    param(
        [Parameter(Mandatory = $true)][string]$SignToolPath,
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string]$Thumbprint
    )

    & $SignToolPath sign /v /fd SHA256 /sha1 $Thumbprint /sm /s MY $FilePath | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "signtool failed for $FilePath with exit code $LASTEXITCODE"
    }
}

function Ensure-TestSigningBootMode {
    $result = [ordered]@{
        configured = $false
        rebootRequired = $false
        secureBoot = 'Unknown'
        message = ''
    }

    try {
        $secureBootEnabled = Confirm-SecureBootUEFI
        $result.secureBoot = if ($secureBootEnabled) { 'Enabled' } else { 'Disabled' }
    }
    catch {
        try {
            $secureBootReg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -Name UEFISecureBootEnabled -ErrorAction Stop
            if ([int]$secureBootReg.UEFISecureBootEnabled -eq 1) {
                $result.secureBoot = 'Enabled'
            }
            elseif ([int]$secureBootReg.UEFISecureBootEnabled -eq 0) {
                $result.secureBoot = 'Disabled'
            }
            else {
                $result.secureBoot = 'Unknown'
            }
        }
        catch {
            $result.secureBoot = 'Unknown'
        }
    }

    $output = (& bcdedit -set TESTSIGNING ON 2>&1 | Out-String)
    if ($LASTEXITCODE -eq 0) {
        $result.configured = $true
        $result.rebootRequired = $true
        $result.message = 'TESTSIGNING boot option enabled.'
        return [pscustomobject]$result
    }

    if ($output -match 'Secure Boot policy') {
        $result.message = 'Could not enable TESTSIGNING because Secure Boot policy is active. Disable Secure Boot in firmware, then rerun this script.'
        return [pscustomobject]$result
    }

    $trimmed = $output.Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed)) {
        $trimmed = "bcdedit returned exit code $LASTEXITCODE."
    }
    $result.message = $trimmed
    return [pscustomobject]$result
}

function Get-MinifilterServiceStartType {
    param([Parameter(Mandatory = $true)][string]$ServiceName)

    $queryOutput = (& sc.exe qc $ServiceName 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) {
        return [pscustomobject]@{
            exists = $false
            startType = 'NotInstalled'
            raw = $queryOutput.Trim()
        }
    }

    $startType = 'Unknown'
    if ($queryOutput -match 'START_TYPE\s*:\s*0\s+BOOT_START') {
        $startType = 'BOOT_START'
    }
    elseif ($queryOutput -match 'START_TYPE\s*:\s*1\s+SYSTEM_START') {
        $startType = 'SYSTEM_START'
    }
    elseif ($queryOutput -match 'START_TYPE\s*:\s*2\s+AUTO_START') {
        $startType = 'AUTO_START'
    }
    elseif ($queryOutput -match 'START_TYPE\s*:\s*3\s+DEMAND_START') {
        $startType = 'DEMAND_START'
    }
    elseif ($queryOutput -match 'START_TYPE\s*:\s*4\s+DISABLED') {
        $startType = 'DISABLED'
    }

    return [pscustomobject]@{
        exists = $true
        startType = $startType
        raw = $queryOutput.Trim()
    }
}

function Ensure-MinifilterServiceEnabled {
    param([Parameter(Mandatory = $true)][string]$ServiceName)

    $stateBefore = Get-MinifilterServiceStartType -ServiceName $ServiceName
    if (-not $stateBefore.exists) {
        return [pscustomobject]@{
            attempted = $false
            changed = $false
            success = $false
            message = "Service '$ServiceName' is not installed."
            before = $stateBefore.startType
            after = 'NotInstalled'
        }
    }

    if ($stateBefore.startType -ne 'DISABLED') {
        return [pscustomobject]@{
            attempted = $false
            changed = $false
            success = $true
            message = "Service '$ServiceName' start type is $($stateBefore.startType)."
            before = $stateBefore.startType
            after = $stateBefore.startType
        }
    }

    $configOutput = (& sc.exe config $ServiceName start= boot 2>&1 | Out-String)
    $configSucceeded = $LASTEXITCODE -eq 0
    $stateAfter = Get-MinifilterServiceStartType -ServiceName $ServiceName

    return [pscustomobject]@{
        attempted = $true
        changed = $true
        success = $configSucceeded -and $stateAfter.startType -eq 'BOOT_START'
        message = $configOutput.Trim()
        before = $stateBefore.startType
        after = $stateAfter.startType
    }
}

if (-not (Test-IsRunningAsAdministrator)) {
    throw 'EnableLocalMinifilterTestMode.ps1 must be run from an elevated Administrator PowerShell session.'
}

$driverPackageRootFull = [System.IO.Path]::GetFullPath($DriverPackageRoot)
$stageDriverRootFull = [System.IO.Path]::GetFullPath($StageDriverRoot)
Ensure-Directory -Path $driverPackageRootFull
Ensure-Directory -Path $stageDriverRootFull

$sysPath = Join-Path $driverPackageRootFull 'AntivirusMinifilter.sys'
$catPath = Join-Path $driverPackageRootFull 'AntivirusMinifilter.cat'
$infPath = Join-Path $driverPackageRootFull 'AntivirusMinifilter.inf'
$readmePath = Join-Path $driverPackageRootFull 'README.md'

foreach ($path in @($sysPath, $catPath, $infPath)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Required minifilter artifact not found: $path"
    }
}

$certificate = Get-OrCreateSigningCertificate -Subject $CertificateSubject -ValidityYears $CertificateValidityYears
if ($null -eq $certificate) {
    throw 'Could not create or find a local test signing certificate.'
}
if (-not $certificate.HasPrivateKey) {
    throw "Certificate '$($certificate.Subject)' does not have an accessible private key."
}

Ensure-CertificateTrust -Certificate $certificate

$signToolPath = Resolve-WindowsKitExecutable -Name 'signtool.exe'
if (-not $signToolPath) {
    throw 'signtool.exe was not found. Install Windows SDK/WDK signing tools.'
}

if ($ResignDriverArtifacts) {
    Sign-DriverArtifact -SignToolPath $signToolPath -FilePath $sysPath -Thumbprint $certificate.Thumbprint
    Sign-DriverArtifact -SignToolPath $signToolPath -FilePath $catPath -Thumbprint $certificate.Thumbprint
}

$signatureSys = Get-AuthenticodeSignature -LiteralPath $sysPath
$signatureCat = Get-AuthenticodeSignature -LiteralPath $catPath
if ($signatureSys.Status -ne 'Valid' -or $signatureCat.Status -ne 'Valid') {
    throw "Post-sign validation failed (sys=$($signatureSys.Status), cat=$($signatureCat.Status))."
}

foreach ($name in @('AntivirusMinifilter.inf', 'AntivirusMinifilter.sys', 'AntivirusMinifilter.cat', 'README.md')) {
    $sourcePath = Join-Path $driverPackageRootFull $name
    if (-not (Test-Path -LiteralPath $sourcePath)) {
        continue
    }
    Copy-Item -LiteralPath $sourcePath -Destination (Join-Path $stageDriverRootFull $name) -Force
}

$bootConfig = [pscustomobject]@{
    configured = $false
    rebootRequired = $false
    secureBoot = 'Unknown'
    message = 'Boot configuration step skipped.'
}
if ($ConfigureBootForTestSigning) {
    $bootConfig = Ensure-TestSigningBootMode
}

$driverInstall = [ordered]@{
    attempted = $false
    succeeded = $false
    exitCode = 0
    message = 'Driver install step skipped.'
}
if ($InstallDriverPackage) {
    $driverInstall.attempted = $true
    $installOutput = (& pnputil /add-driver $infPath /install 2>&1 | Out-String)
    $driverInstall.exitCode = $LASTEXITCODE
    $pnputilSaysAdded = $installOutput -match 'Driver package added successfully'
    if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 3010 -or $pnputilSaysAdded) {
        $driverInstall.succeeded = $true
        $driverInstall.message = $installOutput.Trim()
    }
    else {
        $driverInstall.message = $installOutput.Trim()
    }
}

$serviceRepair = Ensure-MinifilterServiceEnabled -ServiceName $ExpectedServiceName

$serviceState = Get-Service -Name $ExpectedServiceName -ErrorAction SilentlyContinue
$serviceStatus = if ($null -ne $serviceState) { [string]$serviceState.Status } else { 'NotInstalled' }

$report = [pscustomobject]@{
    generatedAtUtc = [DateTime]::UtcNow.ToString('o')
    driverPackageRoot = $driverPackageRootFull
    stageDriverRoot = $stageDriverRootFull
    certificate = [pscustomobject]@{
        subject = [string]$certificate.Subject
        thumbprint = [string]$certificate.Thumbprint
        notAfter = $certificate.NotAfter.ToString('o')
    }
    signatureStatus = [pscustomobject]@{
        sys = [string]$signatureSys.Status
        cat = [string]$signatureCat.Status
        sysSigner = if ($signatureSys.SignerCertificate) { [string]$signatureSys.SignerCertificate.Subject } else { '' }
        catSigner = if ($signatureCat.SignerCertificate) { [string]$signatureCat.SignerCertificate.Subject } else { '' }
    }
    bootConfig = $bootConfig
    driverInstall = [pscustomobject]$driverInstall
    serviceRepair = $serviceRepair
    serviceState = $serviceStatus
}

$reportPath = Join-Path $driverPackageRootFull 'local-test-mode-report.json'
[System.IO.File]::WriteAllText($reportPath, ($report | ConvertTo-Json -Depth 8), $utf8NoBom)

Write-Host 'Fenrir local minifilter test-mode setup complete.'
Write-Host "Certificate: $($certificate.Subject) [$($certificate.Thumbprint)]"
Write-Host "Boot config: $($bootConfig.message)"
if ($InstallDriverPackage) {
    Write-Host "Driver install attempted: $($driverInstall.succeeded) (exit code $($driverInstall.exitCode))"
}
Write-Host "Service repair: $($serviceRepair.message)"
Write-Host "Service state: $serviceStatus"
Write-Host "Report: $reportPath"
