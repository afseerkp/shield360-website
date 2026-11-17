#Requires -Version 5.1
<#
.SYNOPSIS
    Downloads and installs Shield360 Endpoint Advanced (preview) from shield360.biz.

.DESCRIPTION
    1. Reads the current release from shield360.biz/advanced/download/latest.json.
    2. Downloads the package and verifies its SHA-256 checksum.
    3. Asks whether to install PostgreSQL here or which existing database to use (unless -Connection or
       -InstallPostgreSql is given, or this is an upgrade).
    4. Extracts the package to a temporary folder and runs the Install-Shield360Server.ps1 inside it,
       which installs the "Shield360 Server" and "Shield360 Worker" services and opens the firewall port.

    Installing PostgreSQL here downloads PostgreSQL 17 from EnterpriseDB and sets it up for this server only. An
    existing database must be PostgreSQL 16 or newer, empty, with a login that owns it.
    On an upgrade the stored connection string is reused and nothing is asked.

    Run from an elevated Windows PowerShell.

.EXAMPLE
    irm https://shield360.biz/advanced/install.ps1 | iex

.EXAMPLE
    & ([scriptblock]::Create((irm https://shield360.biz/advanced/install.ps1))) -InstallPostgreSql

.EXAMPLE
    & ([scriptblock]::Create((irm https://shield360.biz/advanced/install.ps1))) -Connection 'Host=localhost;Database=shield360;Username=shield360;Password=...'

.EXAMPLE
    & ([scriptblock]::Create((irm https://shield360.biz/advanced/install.ps1))) -Port 8443 -CertificatePath C:\certs\shield360.pfx -CertificatePassword ...

.EXAMPLE
    & ([scriptblock]::Create((irm https://shield360.biz/advanced/install.ps1))) -CheckOnly
#>
[CmdletBinding()]
param(
    # The PostgreSQL connection string. Asked for when missing on a fresh install.
    [string]$Connection,
    # Install PostgreSQL 17 on this server for Shield360 instead of using an existing database.
    [switch]$InstallPostgreSql,
    [int]$Port = 8080,
    [string]$CertificatePath,
    [string]$CertificatePassword,
    # Where the server goes; the default is "Program Files\Shield360 Server".
    [string]$InstallDir,
    # Keep the services running as SYSTEM instead of their own low-privilege accounts.
    [switch]$RunAsLocalSystem,
    # Download and verify the package, then stop. Changes nothing on this machine.
    [switch]$CheckOnly,
    [string]$BaseUrl = 'https://shield360.biz'
)

# Everything runs inside a function so that a failure stops the installer
# without closing the caller's window (this script is usually run through iex).
function Install-Shield360Advanced {
    param($Connection, $InstallPostgreSql, $Port, $CertificatePath, $CertificatePassword, $InstallDir, $RunAsLocalSystem, $CheckOnly, $BaseUrl)

    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $BaseUrl = $BaseUrl.TrimEnd('/')

    function Step($text) { Write-Host "  > $text" -ForegroundColor Cyan }

    Write-Host ''
    Write-Host '  Shield360 Endpoint Advanced (preview) - server installer' -ForegroundColor DarkYellow
    Write-Host ''

    if (-not $CheckOnly) {
        $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw 'Run this installer from an elevated (Administrator) PowerShell.'
        }
        if (-not [Environment]::Is64BitOperatingSystem) { throw 'Shield360 Endpoint Advanced needs 64-bit Windows.' }
        if ($CertificatePath -and -not (Test-Path $CertificatePath)) { throw "Certificate not found: $CertificatePath" }

        # This installer runs through iex, which the execution policy does not block, but the .ps1 it
        # calls below is blocked under the Windows default 'Restricted' policy. Allow scripts for this
        # PowerShell session only; the machine's policy is left unchanged.
        try { Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction Stop } catch { }
        if ((Get-ExecutionPolicy) -in 'Restricted', 'AllSigned', 'Default') {
            throw ("PowerShell scripts are blocked by an execution policy set through Group Policy ($(Get-ExecutionPolicy)). " +
                   'Ask your administrator to allow RemoteSigned for this server, then run the installer again.')
        }
    }

    # ---- The database ------------------------------------------------------------
    # Asked before the download, so a 100 MB download never waits on a question.
    if (-not $CheckOnly -and -not $Connection -and -not $InstallPostgreSql) {
        # An existing installation: where -InstallDir says, the default folder, or where an early preview put it.
        $places = @($InstallDir, (Join-Path $env:ProgramFiles 'Shield360 Server'), (Join-Path $env:ProgramFiles 'Shield360')) | Where-Object { $_ }
        $settings = $places | ForEach-Object { Join-Path $_ 'api\appsettings.Production.json' } | Where-Object { Test-Path $_ } | Select-Object -First 1
        if ($settings) {
            $Connection = (Get-Content $settings -Raw | ConvertFrom-Json).ConnectionStrings.Shield360
            if ($Connection) { Step 'Upgrade: keeping the database connection already configured' }
        }
        function Ask($label, $default) { $a = Read-Host "    $label [$default]"; if ($a) { $a.Trim() } else { $default } }
        if (-not $Connection) {
            $pgService = Get-Service -Name 'postgresql*' -ErrorAction SilentlyContinue | Select-Object -First 1
            Write-Host '  The server keeps its data in PostgreSQL.'
            if (-not $pgService) {
                $answer = Ask 'Install PostgreSQL 17 on this server for Shield360? (Y = install it, N = use an existing database)' 'Y'
                if ($answer -match '^(y|yes)$') { $InstallPostgreSql = $true }
                Write-Host ''
            } else {
                Write-Host "  PostgreSQL is already installed here (service $($pgService.Name))."
            }
        }
        if (-not $Connection -and -not $InstallPostgreSql) {
            Write-Host '  Use PostgreSQL 16 or newer: create an empty database and a login that owns it first,'
            Write-Host '  then answer these (Enter accepts the value in brackets).'
            Write-Host ''
            $dbHost = Ask 'PostgreSQL server' 'localhost'
            $dbPort = Ask 'Port' '5432'
            $dbName = Ask 'Database' 'shield360'
            $dbUser = Ask 'Login' 'shield360'
            $secure = Read-Host '    Password' -AsSecureString
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
            try { $dbPass = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
            if (-not $dbPass) { throw 'A password is required.' }
            # The builder quotes values, so a password with ; or = in it stays one value.
            $builder = New-Object System.Data.Common.DbConnectionStringBuilder
            $builder['Host'] = $dbHost; $builder['Port'] = $dbPort; $builder['Database'] = $dbName
            $builder['Username'] = $dbUser; $builder['Password'] = $dbPass
            $Connection = $builder.ConnectionString
            Write-Host ''
        }
    }

    # ---- Download and verify -----------------------------------------------------
    # A unique query string makes the website's CDN return the current latest.json instead of a cached copy.
    Step "Fetching release information from $BaseUrl"
    $release = Invoke-RestMethod -Uri "$BaseUrl/advanced/download/latest.json?t=$([DateTime]::UtcNow.Ticks)" -UseBasicParsing
    if ($release.sha256 -notmatch '^[0-9a-fA-F]{64}$' -or $release.file -notmatch '^[\w.\-]+\.zip$') { throw 'The release information is not readable. Nothing was installed.' }
    $url = if ($release.url) { [string]$release.url } else { "$BaseUrl/advanced/download/$($release.file)" }
    if ($url -notmatch '^https://') { throw "The release's download address is not HTTPS: $url" }
    Write-Host "    Shield360 Endpoint Advanced $($release.version) ($([math]::Round($release.size / 1MB)) MB)"

    $tmp = Join-Path $env:TEMP ("shield360-advanced-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory $tmp | Out-Null
    try {
        Step 'Downloading package (this can take a few minutes)'
        $zip = Join-Path $tmp $release.file
        Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
        $hash = (Get-FileHash $zip -Algorithm SHA256).Hash
        if ($hash -ne $release.sha256.ToUpper()) {
            throw "Checksum mismatch for $($release.file). Expected $($release.sha256), got $hash. Nothing was installed."
        }
        Write-Host '    SHA-256 verified'

        if ($CheckOnly) {
            Write-Host ''
            Write-Host '  Check only: the package downloaded and its checksum matches. Nothing was changed.' -ForegroundColor Green
            Write-Host ''
            return
        }

        Step 'Extracting'
        $extract = Join-Path $tmp 'pkg'
        Expand-Archive -Path $zip -DestinationPath $extract -Force
        $installer = Join-Path $extract 'Install-Shield360Server.ps1'
        if (-not (Test-Path $installer)) { throw 'The package has no Install-Shield360Server.ps1. Nothing was installed.' }
        Get-ChildItem $extract -Recurse -File | Unblock-File

        Step 'Installing'
        $installArgs = @{ PackageDir = (Join-Path $extract 'package'); Port = $Port }
        if ($Connection) { $installArgs.Connection = $Connection }
        elseif ($InstallPostgreSql) {
            if (-not (Select-String -Path $installer -Pattern 'InstallPostgreSql' -SimpleMatch -Quiet)) { throw 'This release cannot install PostgreSQL. Give -Connection for an existing database.' }
            $installArgs.InstallPostgreSql = $true
        }
        if ($InstallDir) { $installArgs.InstallDir = $InstallDir }
        if ($CertificatePath) { $installArgs.CertificatePath = (Resolve-Path $CertificatePath).Path }
        if ($CertificatePassword) { $installArgs.CertificatePassword = $CertificatePassword }
        if ($RunAsLocalSystem) { $installArgs.RunAsLocalSystem = $true }
        & $installer @installArgs
    } finally {
        Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Host ''
    Write-Host '  Done. Sign in with the account above; you will be asked to set your own password.' -ForegroundColor Green
    Write-Host '  To remove it later, download the package and run .\Install-Shield360Server.ps1 -Uninstall.'
    Write-Host ''
}

$previousPolicy = Get-ExecutionPolicy -Scope Process
try {
    Install-Shield360Advanced -Connection $Connection -InstallPostgreSql $InstallPostgreSql -Port $Port -CertificatePath $CertificatePath -CertificatePassword $CertificatePassword `
        -InstallDir $InstallDir -RunAsLocalSystem $RunAsLocalSystem -CheckOnly $CheckOnly -BaseUrl $BaseUrl
} finally {
    # Put the session's policy back so the caller's window behaves as before.
    try { Set-ExecutionPolicy -Scope Process -ExecutionPolicy $previousPolicy -Force -ErrorAction Stop } catch { }
}
