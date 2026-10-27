#Requires -Version 5.1
<#
.SYNOPSIS
    Removes the Shield360 Endpoint agent from this machine.
    Remove the endpoint in the console afterwards to delete its history.
#>
[CmdletBinding()]
param([switch]$KeepLogs)

$ErrorActionPreference = 'Stop'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this uninstaller from an elevated (Administrator) PowerShell.'
}

$TaskName = 'Shield360 Agent'
$TaskPath = '\Shield360\'
$InstallDir = Join-Path $env:ProgramFiles 'Shield360'
$DataDir = Join-Path $env:ProgramData 'Shield360'

$task = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
if ($task) {
    Stop-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false
    Write-Host 'Scheduled task removed.'
}

# Make sure no agent process is left running.
Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" |
    Where-Object { $_.CommandLine -like '*Shield360Agent.ps1*' } |
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
    if ($KeepLogs) { Remove-Item (Join-Path $DataDir 'config.json') -Force -ErrorAction SilentlyContinue }
    else { Remove-Item $DataDir -Recurse -Force }
}
Write-Host 'Shield360 Endpoint agent uninstalled.' -ForegroundColor Green
