#Requires -Version 5.1
<#
.SYNOPSIS
    Installs the Shield360 Endpoint agent on a Windows server or PC.

.EXAMPLE
    .\Install-Shield360Agent.ps1 -ServerUrl https://shield360.corp.local:8443 -EnrollToken <token>

.PARAMETER CertificateFile
    Optional .cer of the server's self-signed certificate; it is added to the
    machine's Trusted Root store so the agent can verify HTTPS.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ServerUrl,
    [Parameter(Mandatory)][string]$EnrollToken,
    [string]$CertificateFile
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$TaskName = 'Shield360 Agent'
$TaskPath = '\Shield360\'
$InstallDir = Join-Path $env:ProgramFiles 'Shield360'
$DataDir = Join-Path $env:ProgramData 'Shield360'
$AgentPath = Join-Path $InstallDir 'Shield360Agent.ps1'
$ServerUrl = $ServerUrl.TrimEnd('/')

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this installer from an elevated (Administrator) PowerShell.'
}
if ($PSVersionTable.PSVersion.Major -lt 5) { throw 'Windows PowerShell 5.1 or later is required.' }

Write-Host "Installing Shield360 Endpoint agent -> $ServerUrl"

if ($CertificateFile) {
    Import-Certificate -FilePath $CertificateFile -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    Write-Host '  Trusted server certificate imported.'
}

# Stop any running instance before replacing files.
$existing = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
if ($existing) {
    Stop-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
    Write-Host '  Existing installation found; upgrading.'
}

foreach ($dir in $InstallDir, $DataDir) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}
# Only SYSTEM and Administrators may read the agent key or modify the agent. The folder gets inheritable
# grants and everything already inside (on upgrade) is reset to inherit them. (/T together with
# /inheritance:r can leave existing files with no access at all - not even for SYSTEM.)
foreach ($dir in $InstallDir, $DataDir) {
    & icacls.exe $dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to set permissions on $dir" }
    if (Get-ChildItem -LiteralPath $dir -Force | Select-Object -First 1) {
        & icacls.exe (Join-Path $dir '*') /reset /T /C /Q | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Failed to reset permissions inside $dir" }
    }
}

$localAgent = Join-Path $PSScriptRoot 'Shield360Agent.ps1'
if ($PSScriptRoot -and (Test-Path $localAgent)) {
    Copy-Item $localAgent $AgentPath -Force
} else {
    Invoke-WebRequest -Uri "$ServerUrl/download/Shield360Agent.ps1" -OutFile $AgentPath -UseBasicParsing
}
Unblock-File $AgentPath
Write-Host "  Agent installed to $InstallDir"

$ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
& $ps -NoProfile -ExecutionPolicy Bypass -File $AgentPath -Enroll -ServerUrl $ServerUrl -EnrollToken $EnrollToken
if ($LASTEXITCODE -ne 0) { throw "Enrollment failed. See $DataDir\logs\agent.log" }

$action = New-ScheduledTaskAction -Execute $ps -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$AgentPath`""
$triggers = @(
    New-ScheduledTaskTrigger -AtStartup
    # Watchdog: relaunch within 5 minutes if the agent ever exits.
    $(New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5))
)
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
$taskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Action $action -Trigger $triggers -Settings $settings `
    -Principal $taskPrincipal -Description 'Shield360 Endpoint monitoring agent' -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath

Write-Host ''
Write-Host 'Shield360 Endpoint agent installed and running.' -ForegroundColor Green
Write-Host "  The endpoint appears in the console within a minute. Logs: $DataDir\logs\agent.log"
