#Requires -Version 5.1
<#
.SYNOPSIS
    Uninstalls the Shield360 Endpoint management server from this machine.

.DESCRIPTION
    Stops and removes the server task, firewall rule, HTTPS certificate and program files.
    The database, license and settings are either kept for a later reinstall, or deleted after a
    backup zip is written. Run from an elevated Windows PowerShell, either from the server folder
    or straight from the website:  irm https://shield360.biz/uninstall.ps1 | iex

    Uninstall the agents from the console first (Endpoints > select all > Run > Uninstall agent):
    once the server is gone, agents can no longer be managed or removed remotely.

.PARAMETER KeepData
    Keep server\config.json and server\data (database, license, certificate) for a later reinstall.
.PARAMETER DeleteData
    Delete the database, license and settings too (a backup zip is created first unless -NoBackup).
.PARAMETER Force
    Do not ask questions (with neither -KeepData nor -DeleteData, data is kept).

.EXAMPLE
    .\Uninstall-Shield360Server.ps1
    .\Uninstall-Shield360Server.ps1 -DeleteData -BackupPath D:\Backups -Force
#>
[CmdletBinding()]
param(
    [string]$InstallDir,
    [switch]$KeepData,
    [switch]$DeleteData,
    [string]$BackupPath = $env:SystemDrive + '\',
    [switch]$NoBackup,
    [switch]$RemoveNodeJs,
    [switch]$Force
)

$TaskName = 'Shield360 Server'
$TaskPath = '\Shield360\'
$FirewallRule = 'Shield360 Endpoint Server'
$CertName = 'Shield360 Endpoint Server'

# Finds the server folder: -InstallDir, the server task's working folder, this script's folder, or the default.
function Find-Shield360ServerDir([string]$InstallDir, [string]$ScriptDir) {
    $candidates = @()
    if ($InstallDir) { $candidates += (Join-Path $InstallDir 'server'), $InstallDir }
    $task = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
    if ($task -and $task.Actions[0].WorkingDirectory) { $candidates += $task.Actions[0].WorkingDirectory }
    if ($ScriptDir) { $candidates += $ScriptDir }
    $candidates += Join-Path $env:SystemDrive 'Shield360 Endpoint\server'
    foreach ($c in $candidates) { if ($c -and (Test-Path (Join-Path $c 'src\server.js'))) { return (Resolve-Path $c).Path } }
    return $null
}

# Zips config.json and data\ (without the large virus-definition cache and logs) to restore later.
function New-Shield360Backup([string]$ServerDir, [string]$Destination) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmm'
    $zip = Join-Path $Destination "Shield360-Server-Backup-$stamp.zip"
    $staging = Join-Path $env:TEMP "shield360-backup-$stamp"
    New-Item -ItemType Directory $staging -Force | Out-Null
    try {
        if (Test-Path (Join-Path $ServerDir 'config.json')) { Copy-Item (Join-Path $ServerDir 'config.json') $staging }
        $data = Join-Path $ServerDir 'data'
        if (Test-Path $data) {
            New-Item -ItemType Directory (Join-Path $staging 'data') | Out-Null
            Get-ChildItem $data -Force | Where-Object { $_.Name -notin 'definitions', 'logs' } |
                Copy-Item -Destination (Join-Path $staging 'data') -Recurse -Force
        }
        Compress-Archive -Path (Join-Path $staging '*') -DestinationPath $zip -Force
    } finally {
        Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue
    }
    $zip
}

# Deletes the installation. With -KeepData, server\config.json and server\data stay in place.
function Remove-Shield360Files([string]$InstallRoot, [string]$ServerDir, [bool]$KeepData) {
    if (-not $KeepData) { Remove-Item $InstallRoot -Recurse -Force; return }
    $keep = @((Join-Path $ServerDir 'config.json'), (Join-Path $ServerDir 'data'))
    Get-ChildItem $InstallRoot -Force | Where-Object { $_.FullName -ne $ServerDir } | Remove-Item -Recurse -Force
    Get-ChildItem $ServerDir -Force | Where-Object { $keep -notcontains $_.FullName } | Remove-Item -Recurse -Force
}

function Uninstall-Shield360Server {
    param($InstallDir, $KeepData, $DeleteData, $BackupPath, $NoBackup, $RemoveNodeJs, $Force, $ScriptDir)
    $ErrorActionPreference = 'Stop'

    Write-Host ''
    Write-Host '  Shield360 Endpoint - server uninstaller' -ForegroundColor DarkYellow
    Write-Host ''
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this uninstaller from an elevated (Administrator) PowerShell.'
    }
    if ($KeepData -and $DeleteData) { throw 'Use either -KeepData or -DeleteData, not both.' }

    $serverDir = Find-Shield360ServerDir $InstallDir $ScriptDir
    $task = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
    if (-not $serverDir -and -not $task) { throw 'No Shield360 Endpoint server was found on this machine. Use -InstallDir if it is in another folder.' }
    $installRoot = $(if ($serverDir) { Split-Path $serverDir -Parent } else { $null })
    if ($serverDir) { Write-Host "  Found Shield360 server in $installRoot" }

    $config = $null
    if ($serverDir -and (Test-Path (Join-Path $serverDir 'config.json'))) {
        try { $config = Get-Content (Join-Path $serverDir 'config.json') -Raw | ConvertFrom-Json } catch { }
    }

    # Endpoints still enrolled lose their management server; their agents should be removed first.
    $db = $(if ($serverDir) { Join-Path $serverDir 'data\shield360.db' } else { $null })
    $node = (Get-Command node.exe -ErrorAction SilentlyContinue).Source
    if ($db -and (Test-Path $db) -and $node) {
        $count = & $node --no-warnings -e "try{const{DatabaseSync}=require('node:sqlite');const d=new DatabaseSync(process.argv[1],{readOnly:true});console.log(d.prepare('SELECT COUNT(*) n FROM agents').get().n)}catch{console.log('?')}" $db 2>$null
        if ($count -and $count -ne '0' -and $count -ne '?') {
            Write-Host ''
            Write-Host "  $count endpoint(s) are still enrolled. After the server is removed their agents keep running" -ForegroundColor Yellow
            Write-Host '  but can no longer be managed or uninstalled remotely. To remove them first, sign in to the' -ForegroundColor Yellow
            Write-Host '  console: Endpoints > select all > Run > Uninstall agent, and wait until the list is empty.' -ForegroundColor Yellow
            if (-not $Force -and (Read-Host '  Uninstall the server anyway? (y/N)') -notmatch '^(y|yes)$') { Write-Host '  Cancelled. Nothing was changed.'; return }
        }
    }

    # Keep or delete the database, license and settings.
    if ($serverDir -and -not $KeepData -and -not $DeleteData) {
        if ($Force) { $KeepData = $true }
        else {
            Write-Host ''
            Write-Host '  The data folder holds the database (endpoints, policies, history), the license and the HTTPS certificate.'
            $KeepData = (Read-Host '  Keep it for a later reinstall? (Y/n)') -notmatch '^(n|no)$'
            if (-not $KeepData -and (Read-Host '  Type DELETE to permanently delete the data') -cne 'DELETE') {
                Write-Host '  Cancelled. Nothing was changed.'; return
            }
        }
    }
    $backup = $null
    if ($serverDir -and -not $KeepData -and -not $NoBackup) {
        Write-Host "  > Backing up database, license and settings to $BackupPath"
        $backup = New-Shield360Backup $serverDir $BackupPath
    }

    Write-Host '  > Stopping the server'
    if ($task) {
        Stop-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false
    }
    if ($config -and $config.port) {
        Get-NetTCPConnection -State Listen -LocalPort $config.port -ErrorAction SilentlyContinue |
            ForEach-Object { Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue } |
            Where-Object { $_.ProcessName -eq 'node' } | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }

    Write-Host '  > Removing firewall rule'
    Remove-NetFirewallRule -DisplayName $FirewallRule -ErrorAction SilentlyContinue

    if (-not $KeepData) {
        Write-Host '  > Removing the HTTPS certificate'
        Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.FriendlyName -eq $CertName } | Remove-Item -Force
    }

    if ($installRoot -and (Test-Path $installRoot)) {
        Write-Host "  > Removing $(if ($KeepData) { 'program files (keeping config.json and data)' } else { $installRoot })"
        Set-Location $env:SystemRoot   # never delete the folder we are standing in
        Remove-Shield360Files $installRoot $serverDir ([bool]$KeepData)
    }

    if ($RemoveNodeJs) {
        $winget = (Get-Command winget.exe -ErrorAction SilentlyContinue).Source
        if ($winget) { Write-Host '  > Removing Node.js'; & $winget uninstall --id OpenJS.NodeJS.LTS --exact --silent | Out-Null }
        else { Write-Host '  Node.js was not removed (winget not available). Remove it from Settings > Apps if no longer needed.' }
    }

    Write-Host ''
    Write-Host '  Shield360 Endpoint server uninstalled.' -ForegroundColor Green
    if ($KeepData -and $serverDir) { Write-Host "  Kept for reinstall: $serverDir\config.json and $serverDir\data" }
    if ($backup) { Write-Host "  Backup: $backup" }
    if (-not $RemoveNodeJs) { Write-Host '  Node.js was left installed (other programs may use it; add -RemoveNodeJs to remove it).' }
    Write-Host ''
}

Uninstall-Shield360Server -InstallDir $InstallDir -KeepData $KeepData -DeleteData $DeleteData -BackupPath $BackupPath `
    -NoBackup $NoBackup -RemoveNodeJs $RemoveNodeJs -Force $Force -ScriptDir $PSScriptRoot
