#Requires -Version 5.1
<#
.SYNOPSIS
    Removes the Shield360 Endpoint agent from this machine and undoes its network, USB and website settings.
    The endpoint is removed from the console automatically (its license seat is freed).

.DESCRIPTION
    If uninstall protection is enabled in the console (Settings > Agent uninstall), a local uninstall needs
    the uninstall code: pass -UninstallCode, or the script asks for it. Uninstalls started from the console
    use a one-time token (-RemoteToken) instead.

.EXAMPLE
    .\Uninstall-Shield360Agent.ps1
    .\Uninstall-Shield360Agent.ps1 -UninstallCode 'Code1234'
#>
[CmdletBinding()]
param(
    [switch]$KeepLogs,
    [string]$UninstallCode,
    [string]$RemoteToken
)

$ErrorActionPreference = 'Stop'
$TaskName = 'Shield360 Agent'
$TaskPath = '\Shield360\'
$InstallDir = Join-Path $env:ProgramFiles 'Shield360'
$DataDir = if ($env:SHIELD360_DATA_DIR) { $env:SHIELD360_DATA_DIR } else { Join-Path $env:ProgramData 'Shield360' }
$remote = [bool]$RemoteToken

function Get-Sha256Hex([string]$Text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }
}

# Returns $null when the uninstall may proceed, otherwise the reason it may not.
function Test-UninstallAuthorized($State, [string]$Code, [string]$Token) {
    $p = $State.uninstallProtection
    if (-not ($p -and $p.enabled)) { return $null }
    if ($Token -and $State.remoteUninstallTokenHash -and (Get-Sha256Hex $Token) -eq $State.remoteUninstallTokenHash) { return $null }
    if ($Code -and (Get-Sha256Hex "$($p.salt):$Code") -eq $p.hash) { return $null }
    if ($Code -or $Token) { return 'The uninstall code is not correct.' }
    return 'Uninstall protection is enabled. An uninstall code from the Shield360 console is required.'
}

if ($remote) { Start-Transcript -Path (Join-Path $env:SystemRoot 'Temp\Shield360-Uninstall.log') -Force | Out-Null }
try {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this uninstaller from an elevated (Administrator) PowerShell.'
    }

    $state = $null
    $stateFile = Join-Path $DataDir 'state.json'
    if (Test-Path $stateFile) { try { $state = Get-Content $stateFile -Raw | ConvertFrom-Json } catch { } }
    if ($state) {
        $denied = Test-UninstallAuthorized $state $UninstallCode $RemoteToken
        if ($denied -and -not $UninstallCode -and -not $remote -and [Environment]::UserInteractive) {
            $secure = Read-Host 'Uninstall protection is enabled. Enter the uninstall code' -AsSecureString
            $UninstallCode = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
            $denied = Test-UninstallAuthorized $state $UninstallCode $null
        }
        if ($denied) { throw "$denied Nothing was removed." }
    }

    # Read the agent identity now; it is needed to tell the server once everything is removed.
    $config = $null
    $configFile = Join-Path $DataDir 'config.json'
    if (Test-Path $configFile) { try { $config = Get-Content $configFile -Raw | ConvertFrom-Json } catch { } }

    $task = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
    if ($task) {
        Stop-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false
        Write-Host 'Scheduled task removed.'
    }

    # Make sure no agent process is left running ("\Shield360Agent.ps1" so this uninstaller never matches itself).
    Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" |
        Where-Object { $_.ProcessId -ne $PID -and $_.CommandLine -like '*\Shield360Agent.ps1*' } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

    # Remove Shield360 firewall rules (blocklist, brute-force blocks, isolation) and hosts-file sections.
    Get-NetFirewallRule -Group 'Shield360', 'Shield360 Isolation' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    $hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    if (Test-Path $hosts) {
        $inside = $false
        $kept = Get-Content $hosts | Where-Object {
            if ($_ -like '# >>> Shield360 *') { $inside = $true; return $false }
            if ($_ -like '# <<< Shield360 *') { $inside = $false; return $false }
            -not $inside
        }
        Set-Content -Path $hosts -Value $kept -Encoding ASCII
    }
    # Undo USB control and website blocking - only what Shield360 itself set (recorded under HKLM\SOFTWARE\Shield360).
    $owner = 'HKLM:\SOFTWARE\Shield360'
    if (Test-Path $owner) {
        $o = Get-ItemProperty $owner
        if ($o.UsbManaged -eq 1) {
            Remove-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices' -Name 'Deny_All' -ErrorAction SilentlyContinue
            Remove-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}' -Name 'Deny_Write' -ErrorAction SilentlyContinue
            Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR' -Name 'Start' -Value 3 -Type DWord
            Write-Host 'USB storage access restored.'
        }
        $browsers = @{
            Web_Edge    = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\URLBlocklist'
            Web_Chrome  = 'HKLM:\SOFTWARE\Policies\Google\Chrome\URLBlocklist'
            Web_Firefox = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\WebsiteFilter\Block'
        }
        foreach ($k in $browsers.Keys) {
            foreach ($n in @($o.$k)) { if ($n) { Remove-ItemProperty $browsers[$k] -Name $n -ErrorAction SilentlyContinue } }
        }
        Remove-Item $owner -Recurse -Force
        Write-Host 'Website block lists removed from Edge, Chrome and Firefox.'
    }
    Write-Host 'Firewall rules and hosts-file entries removed. Defender and hardening settings applied by policy are left in place.'

    if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force }
    if (Test-Path $DataDir) {
        if ($KeepLogs) { Remove-Item $configFile, $stateFile -Force -ErrorAction SilentlyContinue }
        else { Remove-Item $DataDir -Recurse -Force }
    }

    # Tell the console, which removes the endpoint and frees its license seat.
    if ($config -and $config.agentId) {
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            Invoke-RestMethod -Method Post -Uri ($config.serverUrl.TrimEnd('/') + '/api/agent/uninstalled') -UseBasicParsing -TimeoutSec 30 `
                -Headers @{ Authorization = "Agent $($config.agentId):$($config.agentKey)" } -ContentType 'application/json' `
                -Body (ConvertTo-Json @{ remote = $remote }) | Out-Null
            Write-Host 'The endpoint was removed from the Shield360 console.'
        } catch {
            Write-Host "Could not reach the Shield360 server ($($_.Exception.Message)). Remove the endpoint in the console manually." -ForegroundColor Yellow
        }
    }

    # Clean up the one-time task and script used by an uninstall started from the console.
    Unregister-ScheduledTask -TaskName 'Shield360 Uninstall' -TaskPath $TaskPath -Confirm:$false -ErrorAction SilentlyContinue
    if ($remote -and $PSCommandPath -like "$env:SystemRoot\Temp\*") { Remove-Item $PSCommandPath -Force -ErrorAction SilentlyContinue }
    Write-Host 'Shield360 Endpoint agent uninstalled.' -ForegroundColor Green
} finally {
    if ($remote) { Stop-Transcript | Out-Null }
}
