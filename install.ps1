#Requires -Version 5.1
<#
.SYNOPSIS
    Downloads and installs the Shield360 Endpoint management server from shield360.biz.

.DESCRIPTION
    1. Checks for Node.js 22.13+ (installs the LTS with winget if it is missing).
    2. Downloads the latest server package and verifies its SHA-256 checksum.
    3. Extracts it to -InstallDir. On upgrade, config.json and the data folder are kept.
    4. Creates a self-signed HTTPS certificate (fresh installs, unless -NoTls).
    5. Registers the server as a SYSTEM scheduled task and opens the firewall port.

    Run from an elevated Windows PowerShell.

.EXAMPLE
    irm https://shield360.biz/install.ps1 | iex

.EXAMPLE
    & ([scriptblock]::Create((irm https://shield360.biz/install.ps1))) -DnsName shield360.corp.local, shield360

.EXAMPLE
    & ([scriptblock]::Create((irm https://shield360.biz/install.ps1))) -InstallDir 'D:\Shield360 Endpoint' -NoTls
#>
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:SystemDrive 'Shield360 Endpoint'),
    [string[]]$DnsName,
    [int]$Port = 8443,
    [switch]$NoTls,
    [switch]$SkipNodeInstall,
    [string]$BaseUrl = 'https://shield360.biz'
)

# Everything runs inside a function so that a failure stops the installer
# without closing the caller's window (this script is usually run through iex).
function Install-Shield360Server {
    param($InstallDir, $DnsName, $Port, $NoTls, $SkipNodeInstall, $BaseUrl)

    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $BaseUrl = $BaseUrl.TrimEnd('/')

    function Step($text) { Write-Host "  > $text" -ForegroundColor Cyan }

    Write-Host ''
    Write-Host '  Shield360 Endpoint - server installer' -ForegroundColor DarkYellow
    Write-Host ''

    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this installer from an elevated (Administrator) PowerShell.'
    }

    # ---- Node.js ---------------------------------------------------------------
    Step 'Checking Node.js'
    $node = (Get-Command node.exe -ErrorAction SilentlyContinue).Source
    $nodeOk = $false
    if ($node) {
        $v = [version]((& $node --version).TrimStart('v'))
        $nodeOk = $v -ge [version]'22.13.0'
        if (-not $nodeOk) { Write-Host "    Found Node.js $v; 22.13 or later is required." -ForegroundColor Yellow }
    }
    if (-not $nodeOk) {
        $winget = (Get-Command winget.exe -ErrorAction SilentlyContinue).Source
        if ($SkipNodeInstall -or -not $winget) {
            throw 'Node.js 22.13+ is required. Install the LTS from https://nodejs.org and run this installer again.'
        }
        Step 'Installing Node.js LTS with winget'
        & $winget install --id OpenJS.NodeJS.LTS --exact --silent --accept-package-agreements --accept-source-agreements
        $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
        $node = (Get-Command node.exe -ErrorAction SilentlyContinue).Source
        if (-not $node) { throw 'Node.js was installed but node.exe is not on PATH yet. Open a new elevated PowerShell and run the installer again.' }
    }
    Write-Host "    Node.js $(& $node --version)"

    # ---- Download and verify ---------------------------------------------------
    Step "Fetching release information from $BaseUrl"
    $release = Invoke-RestMethod -Uri "$BaseUrl/download/latest.json" -UseBasicParsing
    Write-Host "    Shield360 Endpoint $($release.version) ($([math]::Round($release.size / 1KB)) KB)"

    $tmp = Join-Path $env:TEMP ("shield360-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory $tmp | Out-Null
    try {
        $zip = Join-Path $tmp $release.file
        Step 'Downloading package'
        Invoke-WebRequest -Uri "$BaseUrl/download/$($release.file)" -OutFile $zip -UseBasicParsing
        $hash = (Get-FileHash $zip -Algorithm SHA256).Hash
        if ($hash -ne $release.sha256.ToUpper()) {
            throw "Checksum mismatch for $($release.file). Expected $($release.sha256), got $hash. Nothing was installed."
        }
        Write-Host '    SHA-256 verified'

        # ---- Extract (keeps config.json and data on upgrade) -------------------
        $serverDir = Join-Path $InstallDir 'server'
        $upgrade = Test-Path (Join-Path $serverDir 'src\server.js')
        if ($upgrade) {
            Step "Upgrading existing installation in $InstallDir"
            Stop-ScheduledTask -TaskName 'Shield360 Server' -TaskPath '\Shield360\' -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        } else {
            Step "Installing to $InstallDir"
        }
        $extract = Join-Path $tmp 'pkg'
        Expand-Archive -Path $zip -DestinationPath $extract -Force
        if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory $InstallDir | Out-Null }
        # The package never contains config.json or data\, so copying over keeps them.
        Copy-Item -Path (Join-Path $extract '*') -Destination $InstallDir -Recurse -Force
        Get-ChildItem $InstallDir -Recurse -Include *.ps1 | Unblock-File
    } finally {
        Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }

    # ---- HTTPS -----------------------------------------------------------------
    $configPath = Join-Path $serverDir 'config.json'
    $hasTls = $false
    if (Test-Path $configPath) {
        $cfg = Get-Content $configPath -Raw | ConvertFrom-Json
        $hasTls = [bool]($cfg.tls -and ($cfg.tls.pfx -or $cfg.tls.cert))
    }
    if (-not $NoTls -and -not $hasTls) {
        Step 'Creating self-signed HTTPS certificate'
        $certArgs = @{ Port = $Port }
        if ($DnsName) { $certArgs.DnsName = $DnsName }
        & (Join-Path $serverDir 'New-Shield360Certificate.ps1') @certArgs
    }

    # ---- Service ---------------------------------------------------------------
    Step 'Registering the server task and firewall rule'
    & (Join-Path $serverDir 'Install-Shield360Server.ps1')

    Write-Host ''
    Write-Host '  Done. Sign in as admin, change the initial password, then delete the password file.' -ForegroundColor Green
    Write-Host '  Next: open Deploy agent in the console to enroll your endpoints.'
    Write-Host ''
}

Install-Shield360Server -InstallDir $InstallDir -DnsName $DnsName -Port $Port -NoTls $NoTls `
    -SkipNodeInstall $SkipNodeInstall -BaseUrl $BaseUrl
