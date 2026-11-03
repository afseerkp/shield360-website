#Requires -Version 5.1
<#
.SYNOPSIS
    Downloads and installs the HOT System Agent (agent and tray) from shield360.biz/hot.

.DESCRIPTION
    1. Downloads the latest HOT System Agent package and verifies its SHA-256 checksum.
    2. Runs the package's Install-FleetPulse.ps1, which installs the agent service and the tray,
       stores the enrollment token and waits for the PC to enroll.

    Asks for the server address and the enrollment token when they are not given. On a PC that is
    already enrolled it asks nothing: it keeps the server address and upgrades in place.

    Run from an elevated Windows PowerShell.

.EXAMPLE
    irm https://shield360.biz/hot/install.ps1 | iex

.EXAMPLE
    & ([scriptblock]::Create((irm https://shield360.biz/hot/install.ps1))) -Server https://agents.contoso.com -Token fpe_xxxx

.EXAMPLE
    & ([scriptblock]::Create((irm https://shield360.biz/hot/install.ps1))) -WhatIf
#>
[CmdletBinding()]
param(
    [string]$Server,
    [string]$Token,
    [string]$InstallDir,
    [string[]]$KillList,
    [string]$CfAccessClientId,
    [string]$CfAccessClientSecret,
    [string]$TrayPublisher,
    [switch]$NoScreenshots,
    [switch]$AllowHttp,
    [switch]$RequireSignedTray,
    [switch]$WhatIf,
    [string]$BaseUrl = 'https://shield360.biz/hot'
)

# Everything runs inside a function so that a failure stops the installer
# without closing the caller's window (this script is usually run through iex).
function Install-FleetPulseFromWeb {
    param($Options)

    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $BaseUrl = $Options.BaseUrl.TrimEnd('/')

    function Step($text) { Write-Host "  > $text" -ForegroundColor Cyan }

    Write-Host ''
    Write-Host '  HOT System Agent - installer' -ForegroundColor DarkYellow
    Write-Host ''

    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -and -not $Options.WhatIf) {
        throw 'Run this installer from an elevated (Administrator) PowerShell.'
    }

    # ---- Server and token ------------------------------------------------------
    # An installed PC keeps its server address and identity, so an upgrade needs no answers.
    $dataDir = Join-Path $env:ProgramData 'FleetPulse'
    $enrolled = Test-Path (Join-Path $dataDir 'agent.key')
    $server = $Options.Server
    if (-not $server) {
        $settings = Join-Path $(if ($Options.InstallDir) { $Options.InstallDir } else { Join-Path $env:ProgramFiles 'FleetPulse' }) 'appsettings.json'
        if (Test-Path $settings) {
            try { $server = (Get-Content $settings -Raw | ConvertFrom-Json).Agent.ServerUrl } catch { }
            if ($server) { Write-Host "    Keeping the server address $server" }
        }
    }
    if (-not $server) { $server = (Read-Host '  Server address (for example https://agents.contoso.com)').Trim() }
    if (-not $server) { throw 'A server address is needed. Ask IT for the HOT System Agent server address.' }

    $token = $Options.Token
    if ($enrolled) {
        Write-Host '    This PC is already enrolled; upgrading in place.'
        $token = $null
    }
    elseif (-not $token) {
        $token = (Read-Host '  Enrollment token (fpe_..., from Admin > Enrollment)').Trim()
        if (-not $token) { throw 'An enrollment token is needed for a new PC. Create one in the dashboard: Admin > Enrollment.' }
    }

    # ---- Download and verify ---------------------------------------------------
    # A unique query string makes the website's CDN fetch current files instead of a cached copy,
    # which could otherwise be a few minutes older than latest.json right after a release.
    function Fresh([string]$Path) { "$BaseUrl/download/$Path`?t=$([DateTime]::UtcNow.Ticks)" }

    Step "Fetching release information from $BaseUrl"
    $release = Invoke-RestMethod -Uri (Fresh 'latest.json') -UseBasicParsing
    Write-Host "    HOT System Agent $($release.version) ($([math]::Round($release.size / 1MB, 1)) MB)"

    $tmp = Join-Path $env:TEMP ('fleetpulse-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory $tmp | Out-Null
    try {
        Step 'Downloading package'
        for ($attempt = 1; ; $attempt++) {
            $zip = Join-Path $tmp $release.file
            Invoke-WebRequest -Uri (Fresh $release.file) -OutFile $zip -UseBasicParsing
            $hash = (Get-FileHash $zip -Algorithm SHA256).Hash
            if ($hash -eq $release.sha256.ToUpper()) { break }
            if ($attempt -ge 2) {
                throw ("Checksum mismatch for $($release.file). Expected $($release.sha256), got $hash. Nothing was installed. " +
                       'If a new version was published in the last few minutes, wait 10 minutes and run the installer again.')
            }
            Write-Host '    Checksum did not match (release may be updating); retrying in 15 seconds...' -ForegroundColor Yellow
            Start-Sleep -Seconds 15
            $release = Invoke-RestMethod -Uri (Fresh 'latest.json') -UseBasicParsing
        }
        Write-Host '    SHA-256 verified'

        $pkg = Join-Path $tmp 'pkg'
        Expand-Archive -Path $zip -DestinationPath $pkg -Force
        Get-ChildItem $pkg -Recurse -File | Unblock-File

        # ---- Install -----------------------------------------------------------
        # A separate powershell.exe with -ExecutionPolicy Bypass runs the package script whatever the
        # machine's policy is, and its exit codes (0 ok, 1 failed, 2 bad parameters) come back here.
        $installArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $pkg 'Install-FleetPulse.ps1'), '-ServerUrl', $server)
        if ($token) { $installArgs += '-EnrollmentToken', $token }
        if ($Options.InstallDir) { $installArgs += '-InstallDir', $Options.InstallDir }
        if ($Options.KillList) { $installArgs += '-KillList', ($Options.KillList -join ',') }
        if ($Options.CfAccessClientId) { $installArgs += '-CfAccessClientId', $Options.CfAccessClientId, '-CfAccessClientSecret', $Options.CfAccessClientSecret }
        if ($Options.TrayPublisher) { $installArgs += '-TrayPublisher', $Options.TrayPublisher }
        if ($Options.NoScreenshots) { $installArgs += '-NoScreenshots' }
        if ($Options.AllowHttp) { $installArgs += '-AllowHttp' }
        # The tray is not code-signed yet, so the agent must accept an unsigned tray unless told otherwise.
        if (-not $Options.RequireSignedTray) { $installArgs += '-AllowUnsignedTray' }
        if ($Options.WhatIf) { $installArgs += '-WhatIf' }

        Step $(if ($Options.WhatIf) { 'Checking the settings (nothing is changed)' } else { 'Installing the agent and tray' })
        & (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') @installArgs
        $code = $LASTEXITCODE
    } finally {
        Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Host ''
    switch ($code) {
        0 {
            if ($Options.WhatIf) { Write-Host '  Checks passed. Run again without -WhatIf to install.' -ForegroundColor Green }
            else { Write-Host '  Done. HOT System Agent is running; the tray icon appears next to the clock.' -ForegroundColor Green }
        }
        2 { throw 'The installer rejected the settings (see the message above). Nothing was installed.' }
        default { throw "The installer failed (exit $code). Log: $(Join-Path $dataDir 'install.log')" }
    }
    Write-Host ''
}

try {
    Install-FleetPulseFromWeb -Options @{
        Server = $Server; Token = $Token; InstallDir = $InstallDir; KillList = $KillList
        CfAccessClientId = $CfAccessClientId; CfAccessClientSecret = $CfAccessClientSecret; TrayPublisher = $TrayPublisher
        NoScreenshots = [bool]$NoScreenshots; AllowHttp = [bool]$AllowHttp; RequireSignedTray = [bool]$RequireSignedTray
        WhatIf = [bool]$WhatIf; BaseUrl = $BaseUrl
    }
} catch {
    Write-Host ''
    Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ''
}
