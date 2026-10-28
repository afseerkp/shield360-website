#Requires -Version 5.1
<#
.SYNOPSIS
    Shield360 Endpoint agent. Reports health, security posture and inventory,
    enforces the protection policy, blocks attacks and runs administrator-approved actions.

.DESCRIPTION
    Normally started by the "Shield360 Agent" scheduled task as SYSTEM.
    Compatible with Windows PowerShell 5.1 (Windows Server 2016+, Windows 10/11).

    -Enroll            Register this machine with the server (used by the installer).
    -Once              Run a single check-in + inventory and exit (troubleshooting).
    -ReleaseIsolation  Break-glass: remove network isolation locally (run as administrator).
#>
[CmdletBinding()]
param(
    [switch]$Enroll,
    [string]$ServerUrl,
    [string]$EnrollToken,
    [switch]$Once,
    [switch]$ReleaseIsolation
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$AgentVersion = '1.5.0'
$DataDir = if ($env:SHIELD360_DATA_DIR) { $env:SHIELD360_DATA_DIR } else { Join-Path $env:ProgramData 'Shield360' }
$ConfigFile = Join-Path $DataDir 'config.json'
$StateFile = Join-Path $DataDir 'state.json'
$QuarantineDir = Join-Path $DataDir 'quarantine'
$LogFile = Join-Path $DataDir 'logs\agent.log'
$InventoryEveryHours = 6
$SecurityCacheMinutes = 5
$EnforceEveryMinutes = 15
$FirewallGroup = 'Shield360'
$HostsFile = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'

[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# ------------------------------------------------------------------ utilities

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $dir = Split-Path $LogFile
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    if ((Test-Path $LogFile) -and (Get-Item $LogFile).Length -gt 5MB) {
        Move-Item $LogFile "$LogFile.1" -Force
    }
    $line = '{0} [{1}] {2}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
    if ($Once -or $Enroll) { Write-Host $line }
}

function ConvertTo-IsoDate($Date) {
    if ($null -eq $Date) { return $null }
    try { return ([datetime]$Date).ToUniversalTime().ToString('o') } catch { return $null }
}

function Invoke-Safely([scriptblock]$Block, $Default = $null) {
    try { & $Block } catch { $Default }
}

function Invoke-S360Api {
    param([string]$Path, $Body, [switch]$NoAuth)
    $headers = @{}
    if (-not $NoAuth) { $headers.Authorization = "Agent $($script:Config.agentId):$($script:Config.agentKey)" }
    $json = ConvertTo-Json -InputObject $Body -Depth 8 -Compress
    $uri = $script:Config.serverUrl.TrimEnd('/') + $Path
    Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType 'application/json; charset=utf-8' `
        -Body ([Text.Encoding]::UTF8.GetBytes($json)) -TimeoutSec 60 -UseBasicParsing
}

# ------------------------------------------------------------------ collectors

function Get-SystemInfo {
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $bios = Get-CimInstance Win32_BIOS
    $cpu = @(Get-CimInstance Win32_Processor)
    $nics = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = True')

    $ips = @($nics | ForEach-Object { $_.IPAddress } | Where-Object { $_ -and $_ -notmatch ':' -and $_ -notlike '169.254.*' })
    $macs = @($nics | ForEach-Object { $_.MACAddress } | Where-Object { $_ } | Select-Object -Unique)

    # Interactive users: console user plus anyone running explorer.exe (RDP sessions).
    $users = @()
    if ($cs.UserName) { $users += $cs.UserName }
    $users += Invoke-Safely {
        Get-CimInstance Win32_Process -Filter "Name = 'explorer.exe'" | ForEach-Object {
            $o = Invoke-CimMethod -InputObject $_ -MethodName GetOwner
            if ($o.User) { "$($o.Domain)\$($o.User)" }
        }
    } @()
    $users = @($users | Where-Object { $_ } | Sort-Object -Unique)

    @{
        hostname      = $env:COMPUTERNAME
        deviceId      = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid
        osName        = $os.Caption
        osVersion     = $os.Version
        osBuild       = '{0}.{1}' -f $os.BuildNumber, (Invoke-Safely { (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR } 0)
        productType   = [int]$os.ProductType   # 1 workstation, 2 domain controller, 3 server
        domain        = $cs.Domain
        manufacturer  = $cs.Manufacturer
        model         = $cs.Model
        serial        = $bios.SerialNumber
        cpuModel      = ($cpu[0].Name -replace '\s+', ' ').Trim()
        cores         = [int]$cs.NumberOfLogicalProcessors
        ramTotalMB    = [math]::Round($cs.TotalPhysicalMemory / 1MB)
        lastBoot      = ConvertTo-IsoDate $os.LastBootUpTime
        loggedOnUsers = $users
        ipAddresses   = $ips
        macAddresses  = $macs
    }
}

function Get-Metrics {
    $os = Get-CimInstance Win32_OperatingSystem
    $cpu = (Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name = '_Total'").PercentProcessorTime
    $totalKB = [double]$os.TotalVisibleMemorySize
    $freeKB = [double]$os.FreePhysicalMemory
    $disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType = 3' | Where-Object { $_.Size -gt 0 } | ForEach-Object {
        @{
            drive   = $_.DeviceID
            sizeGB  = [math]::Round($_.Size / 1GB, 1)
            freeGB  = [math]::Round($_.FreeSpace / 1GB, 1)
            usedPct = [math]::Round((1 - $_.FreeSpace / $_.Size) * 100, 1)
        }
    })
    @{
        cpu          = [double]$cpu
        memPct       = [math]::Round((1 - $freeKB / $totalKB) * 100, 1)
        memUsedMB    = [math]::Round(($totalKB - $freeKB) / 1KB)
        disks        = $disks
        processCount = @(Get-Process).Count
        uptimeSec    = [int]((Get-Date) - $os.LastBootUpTime).TotalSeconds
    }
}

# Threats Defender detected in the last 7 days.
function Get-RecentThreats {
    Invoke-Safely {
        $names = @{}
        Get-MpThreat | ForEach-Object { $names[[string]$_.ThreatID] = $_.ThreatName }
        Get-MpThreatDetection | Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddDays(-7) } |
            Sort-Object InitialDetectionTime -Descending | Select-Object -First 25 | ForEach-Object {
                @{
                    time          = ConvertTo-IsoDate $_.InitialDetectionTime
                    threatId      = [string]$_.ThreatID
                    name          = $(if ($names[[string]$_.ThreatID]) { $names[[string]$_.ThreatID] } else { "Threat $($_.ThreatID)" })
                    resources     = @($_.Resources | Select-Object -First 3)
                    actionSuccess = [bool]$_.ActionSuccess
                }
            }
    } @()
}

function Get-SecurityPosture {
    $sec = @{}

    try {
        $mp = Get-MpComputerStatus
        $sec.defender = @{
            present            = $true
            amServiceEnabled   = [bool]$mp.AMServiceEnabled
            antivirusEnabled   = [bool]$mp.AntivirusEnabled
            realTimeProtection = [bool]$mp.RealTimeProtectionEnabled
            tamperProtected    = [bool]$mp.IsTamperProtected
            signatureAgeDays   = [int]$mp.AntivirusSignatureAge
            signatureVersion   = $mp.AntivirusSignatureVersion
            signatureUpdated   = ConvertTo-IsoDate $mp.AntivirusSignatureLastUpdated
            quickScanAgeDays   = $(if ($mp.QuickScanAge -lt 10000) { [int]$mp.QuickScanAge } else { $null })
            engineVersion      = $mp.AMEngineVersion
            mode               = $mp.AMRunningMode
        }
    } catch {
        $sec.defender = @{ present = $false }
    }

    $sec.threats = @(Get-RecentThreats)

    # Third-party antivirus registered with Security Center (workstations only).
    $sec.antivirus = @(Invoke-Safely {
        Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct | ForEach-Object {
            $state = '{0:X6}' -f $_.productState
            @{
                name     = $_.displayName
                enabled  = @('10', '11') -contains $state.Substring(2, 2)
                upToDate = $state.Substring(4, 2) -eq '00'
            }
        }
    } @())

    $sec.firewall = @(Invoke-Safely {
        Get-NetFirewallProfile | ForEach-Object { @{ name = [string]$_.Name; enabled = ([string]$_.Enabled -eq 'True') } }
    } @())

    $sec.bitlocker = @(Invoke-Safely {
        $sysDrive = $env:SystemDrive
        Get-CimInstance -Namespace 'root/cimv2/security/microsoftvolumeencryption' -ClassName Win32_EncryptableVolume |
            Where-Object { $_.DriveLetter } | ForEach-Object {
                @{ drive = $_.DriveLetter; protected = ($_.ProtectionStatus -eq 1); isOsVolume = ($_.DriveLetter -eq $sysDrive) }
            }
    } @())

    $sec.pendingReboot = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
                         (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')

    $sec.failedLogons1h = Invoke-Safely {
        try {
            @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = (Get-Date).AddHours(-1) } -MaxEvents 2000).Count
        } catch {
            if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { 0 } else { throw }
        }
    }

    $sec.uacEnabled = Invoke-Safely {
        (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA -eq 1
    }
    $sec.rdpEnabled = Invoke-Safely {
        (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections -eq 0
    }
    $sec.rdpNla = Invoke-Safely {
        (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication -eq 1
    }
    $sec.usbStorageState = Invoke-Safely { Get-UsbStorageState }
    # USB drives currently plugged in (shown to the admin; useful when deciding on USB policy).
    $sec.usbDevices = @(Invoke-Safely {
        Get-CimInstance Win32_DiskDrive -Filter "InterfaceType = 'USB'" | ForEach-Object {
            @{ model = $_.Model; sizeGB = [math]::Round($_.Size / 1GB, 1); serial = ([string]$_.SerialNumber).Trim() }
        }
    } @())
    $sec
}

function Get-PendingUpdates {
    # The Windows Update search can take minutes; run it in a job with a timeout.
    $job = Start-Job -ScriptBlock {
        $searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
        $result = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
        $updates = @($result.Updates | ForEach-Object { $_ })
        @{
            count         = $updates.Count
            securityCount = @($updates | Where-Object { @($_.Categories | ForEach-Object { $_.Name }) -contains 'Security Updates' -or $_.MsrcSeverity }).Count
            titles        = @($updates | Select-Object -First 20 | ForEach-Object { $_.Title })
        }
    }
    try {
        if (Wait-Job $job -Timeout 600) {
            $r = Receive-Job $job
            return @{ count = [int]$r.count; securityCount = [int]$r.securityCount; titles = @($r.titles) }
        }
        Write-Log 'Windows Update search timed out' 'WARN'
        return $null
    } finally {
        Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
}

function Get-Inventory {
    $software = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    ) | ForEach-Object { Get-ItemProperty $_ -ErrorAction SilentlyContinue } |
        Where-Object { $_.DisplayName -and -not $_.SystemComponent -and -not $_.ParentKeyName } |
        Sort-Object DisplayName, DisplayVersion -Unique | ForEach-Object {
            @{ name = $_.DisplayName; version = $_.DisplayVersion; publisher = $_.Publisher; installDate = $_.InstallDate }
        }

    $hotfixes = @(Invoke-Safely {
        Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 15 | ForEach-Object {
            @{ id = $_.HotFixID; description = $_.Description; installedOn = ConvertTo-IsoDate $_.InstalledOn }
        }
    } @())

    # Automatic services that are stopped, ignoring ones that are expected to stop (delayed/trigger start).
    $stopped = @(Invoke-Safely {
        $triggered = @{}
        Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue | ForEach-Object {
            if (Test-Path (Join-Path $_.PSPath 'TriggerInfo')) { $triggered[$_.PSChildName] = $true }
        }
        Get-CimInstance Win32_Service -Filter "StartMode = 'Auto' AND State <> 'Running'" |
            Where-Object { -not $triggered[$_.Name] -and -not $_.DelayedAutoStart } | ForEach-Object {
                @{ name = $_.Name; displayName = $_.DisplayName }
            }
    } @())

    $admins = @(Invoke-Safely {
        Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { @{ name = $_.Name; source = [string]$_.PrincipalSource } }
    } @())

    $ports = @(Invoke-Safely {
        $procs = @{}
        Get-Process | ForEach-Object { $procs[$_.Id] = $_.ProcessName }
        $tcp = Get-NetTCPConnection -State Listen | ForEach-Object { @{ protocol = 'TCP'; port = $_.LocalPort; address = $_.LocalAddress; process = $procs[[int]$_.OwningProcess] } }
        # Skip loopback and the dynamic port range (outbound DNS/QUIC sockets, not services).
        $udp = Get-NetUDPEndpoint | Where-Object { $_.LocalAddress -notin '127.0.0.1', '::1' -and $_.LocalPort -lt 49152 } |
            ForEach-Object { @{ protocol = 'UDP'; port = $_.LocalPort; address = $_.LocalAddress; process = $procs[[int]$_.OwningProcess] } }
        @($tcp) + @($udp) | Sort-Object { $_.protocol }, { [int]$_.port }, { $_.address } -Unique | Select-Object -First 150
    } @())

    $shares = @(Invoke-Safely {
        Get-CimInstance Win32_Share | Where-Object { $_.Type -eq 0 } | ForEach-Object { @{ name = $_.Name; path = $_.Path } }
    } @())

    @{
        software        = @($software)
        hotfixes        = $hotfixes
        lastPatchDate   = $(if ($hotfixes.Count) { $hotfixes[0].installedOn } else { $null })
        pendingUpdates  = Get-PendingUpdates
        stoppedServices = $stopped
        localAdmins     = $admins
        listeningPorts  = $ports
        shares          = $shares
        collectedAt     = (Get-Date).ToUniversalTime().ToString('o')
    }
}

# ------------------------------------------------------------------ protection: state & helpers

function Read-AgentState {
    $script:State = @{ policy = $null; iocs = $null; isolated = $false; blockedIps = @(); lastEventScan = $null
                       quarantine = @(); appliedExclusions = @(); appliedCfaApps = @(); appliedCfaFolders = @(); lastQuickScanTrigger = $null
                       isolationReason = $null; serverIps = @(); seenThreats = @(); threatsBaselined = $false
                       lastSignatureAttempt = $null; uninstallProtection = $null; remoteUninstallTokenHash = $null }
    if (Test-Path $StateFile) {
        try {
            $saved = Get-Content $StateFile -Raw | ConvertFrom-Json
            foreach ($k in @($script:State.Keys)) { if ($null -ne $saved.$k) { $script:State[$k] = $saved.$k } }
        } catch { Write-Log "State file unreadable, starting fresh: $($_.Exception.Message)" 'WARN' }
    }
    foreach ($k in 'blockedIps', 'quarantine', 'appliedExclusions', 'appliedCfaApps', 'appliedCfaFolders', 'serverIps', 'seenThreats') { $script:State[$k] = @($script:State[$k] | Where-Object { $_ }) }
}

function Get-Sha256Hex([string]$Text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }
}

function Save-AgentState {
    ConvertTo-Json -InputObject $script:State -Depth 10 | Set-Content -Path $StateFile -Encoding UTF8
}

function New-S360Event {
    param([string]$Type, [string]$Severity, [bool]$Blocked, [string]$Message, $Details = $null, $Time = $null, [string]$Key = $null)
    @{
        type     = $Type
        severity = $Severity
        blocked  = $Blocked
        message  = $(if ($Message.Length -gt 900) { $Message.Substring(0, 900) + '...' } else { $Message })
        details  = $Details
        time     = $(if ($Time) { ConvertTo-IsoDate $Time } else { (Get-Date).ToUniversalTime().ToString('o') })
        key      = $(if ($Key) { "$($script:Config.agentId)|$Key" } else { $null })
    }
}

function Get-EventFields($Event) {
    $xml = [xml]$Event.ToXml()
    $fields = @{}
    foreach ($d in @($xml.Event.EventData.Data)) { if ($d -and $d.Name) { $fields[$d.Name] = [string]$d.'#text' } }
    $fields
}

function Test-IpMatch([string]$Ip, [string]$Rule) {
    if ($Rule -notlike '*/*') { return $Ip -eq $Rule }
    $parts = $Rule.Split('/')
    $bits = [int]$parts[1]
    try { $a = [Net.IPAddress]::Parse($Ip).GetAddressBytes(); $b = [Net.IPAddress]::Parse($parts[0]).GetAddressBytes() } catch { return $false }
    if ($a.Length -ne $b.Length) { return $false }
    for ($i = 0; $i -lt $a.Length; $i++) {
        $m = [math]::Max(0, [math]::Min(8, $bits - 8 * $i))
        if ($m -eq 0) { break }
        $mask = (0xFF -shl (8 - $m)) -band 0xFF
        if (($a[$i] -band $mask) -ne ($b[$i] -band $mask)) { return $false }
    }
    $true
}

# One inbound + one outbound block rule per purpose; an empty list removes them.
function Set-BlockRule([string]$Name, [string[]]$Addresses, [string]$Group = $FirewallGroup) {
    foreach ($dir in 'Inbound', 'Outbound') {
        $display = "$Name ($dir)"
        $rule = Get-NetFirewallRule -DisplayName $display -ErrorAction SilentlyContinue
        if (-not $Addresses -or $Addresses.Count -eq 0) {
            if ($rule) { $rule | Remove-NetFirewallRule }
            continue
        }
        if ($rule) { Set-NetFirewallRule -DisplayName $display -RemoteAddress $Addresses }
        else {
            New-NetFirewallRule -DisplayName $display -Group $Group -Direction $dir -Action Block -Profile Any `
                -RemoteAddress $Addresses -Description 'Managed by Shield360 Endpoint' | Out-Null
        }
    }
}

# Replace (or remove, when $Lines is empty) a marked section of the hosts file.
function Set-HostsSection([string]$Section, [string[]]$Lines) {
    $begin = "# >>> Shield360 $Section (managed, do not edit) >>>"
    $end = "# <<< Shield360 $Section <<<"
    $current = @(Get-Content $HostsFile -ErrorAction SilentlyContinue)
    $kept = New-Object System.Collections.ArrayList
    $inside = $false
    foreach ($l in $current) {
        if ($l -eq $begin) { $inside = $true; continue }
        if ($l -eq $end) { $inside = $false; continue }
        if (-not $inside) { [void]$kept.Add($l) }
    }
    if ($Lines -and $Lines.Count) { [void]$kept.Add($begin); $kept.AddRange([string[]]$Lines); [void]$kept.Add($end) }
    if (($current -join "`n") -ne ($kept -join "`n")) {
        Set-Content -Path $HostsFile -Value $kept -Encoding ASCII
        Invoke-Safely { Clear-DnsClientCache } | Out-Null
    }
}

function Test-ProtectedSystemFile([string]$Path) {
    $sysDirs = @((Join-Path $env:SystemRoot 'System32'), (Join-Path $env:SystemRoot 'SysWOW64'))
    if (-not ($sysDirs | Where-Object { $Path -like "$_\*" })) { return $false }
    $sig = Get-AuthenticodeSignature -LiteralPath $Path
    return ($sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -like '*O=Microsoft Corporation*')
}

function Move-ToQuarantine([string]$Path, [string]$Reason) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "File not found: $Path" }
    if (Test-ProtectedSystemFile $Path) { throw "Refusing to quarantine a Microsoft-signed system file: $Path" }
    if (-not (Test-Path $QuarantineDir)) { New-Item -ItemType Directory -Path $QuarantineDir -Force | Out-Null }
    $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    # Renamed with a non-executable extension inside the SYSTEM/Administrators-only data folder.
    Move-Item -LiteralPath $Path -Destination (Join-Path $QuarantineDir "$hash.quarantine") -Force
    $entry = @{ path = $Path; sha256 = $hash; reason = $Reason; time = (Get-Date).ToUniversalTime().ToString('o') }
    $script:State.quarantine = @(@($entry) + @($script:State.quarantine) | Select-Object -First 100)
    Save-AgentState
    $entry
}

# ------------------------------------------------------------------ protection: policy enforcement

function Add-Check($Checks, [string]$Area, [string]$Setting, $Expected, $Actual, $Ok = $null) {
    if ($null -eq $Ok) { $Ok = ([string]$Expected -eq [string]$Actual) }
    [void]$Checks.Add(@{ area = $Area; setting = $Setting; expected = [string]$Expected; actual = [string]$Actual; ok = [bool]$Ok })
}

function Format-Mode($v) {
    switch ([int]$v) { 0 { 'Off' } 1 { 'Block' } 2 { 'Audit' } 6 { 'Warn' } default { "$v" } }
}

# Brings Defender's virus definitions up to date: first directly from Microsoft, then (if that fails,
# the machine is isolated, or it has no internet) from the Shield360 server's mirror of the official package.
function Update-DefenderSignatures {
    $script:State.lastSignatureAttempt = (Get-Date).ToString('o')
    $before = [string](Get-MpComputerStatus).AntivirusSignatureVersion
    $notes = @()
    $microsoftOk = $false
    if ($script:State.isolated) {
        $notes += 'Isolated: skipping Microsoft update servers.'
    } else {
        try { Update-MpSignature; $microsoftOk = $true }
        catch { $notes += "Microsoft update failed: $($_.Exception.Message)" }
    }
    $now = [string](Get-MpComputerStatus).AntivirusSignatureVersion

    $arch = switch ($env:PROCESSOR_ARCHITECTURE) { 'AMD64' { 'x64' } 'ARM64' { 'arm64' } default { 'x86' } }
    $mirrored = $(if ($script:Definitions) { $script:Definitions.$arch } else { $null })
    $mirrorNewer = $mirrored -and $(if ($mirrored.version) { [version]$mirrored.version -gt [version]$now } else { -not $microsoftOk })

    if ($mirrorNewer) {
        $file = Join-Path $DataDir 'mpam-fe.exe'
        try {
            Invoke-WebRequest -Uri ($script:Config.serverUrl.TrimEnd('/') + "/api/agent/definitions/$arch") -OutFile $file -UseBasicParsing -TimeoutSec 1800 `
                -Headers @{ Authorization = "Agent $($script:Config.agentId):$($script:Config.agentKey)" }
            # Only ever run the package if it is genuinely signed by Microsoft.
            $sig = Get-AuthenticodeSignature -LiteralPath $file
            if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notlike '*O=Microsoft Corporation*') {
                throw "Downloaded package failed Microsoft signature check ($($sig.Status))."
            }
            $p = Start-Process -FilePath $file -ArgumentList '-q' -Wait -PassThru -WindowStyle Hidden
            if ($p.ExitCode -ne 0) { throw "Definition package exited with code $($p.ExitCode)." }
            $now = [string](Get-MpComputerStatus).AntivirusSignatureVersion
            $notes += "Installed definitions from the Shield360 server mirror ($($mirrored.version))."
        } catch {
            $notes += "Server mirror update failed: $($_.Exception.Message)"
        } finally {
            Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
        }
    }
    Save-AgentState

    $status = Get-MpComputerStatus
    $summary = $(if ($now -ne $before) { "Virus definitions updated: $before -> $now" } else { "Virus definitions are $now (unchanged)" })
    $result = "$summary. Last updated $($status.AntivirusSignatureLastUpdated), engine $($status.AMEngineVersion)." +
        $(if ($notes.Count) { "`n" + ($notes -join "`n") } else { '' })
    Write-Log ($result -replace "`n", ' | ')
    if ($now -eq $before -and -not $microsoftOk -and -not $mirrorNewer) { throw $result }
    $result
}

function Invoke-DefenderPolicy($Policy, $Checks, [bool]$Apply) {
    $av = $Policy.antivirus
    try { $status = Get-MpComputerStatus } catch {
        Add-Check $Checks 'Antivirus' 'Microsoft Defender available' 'Yes' 'No'
        return
    }
    if ($status.AMRunningMode -and $status.AMRunningMode -ne 'Normal') {
        Add-Check $Checks 'Antivirus' 'Defender mode' 'Normal' "$($status.AMRunningMode) (another antivirus is primary)" $true
        return
    }

    $modes = @{ off = 0; block = 1; audit = 2 }
    $levels = @{ default = 0; high = 2; highplus = 4; zerotolerance = 6 }
    $onOff = { param($disabled) if ($disabled) { 'Off' } else { 'On' } }
    $specs = @(
        @{ key = 'DisableRealtimeMonitoring'; name = 'Real-time protection'; want = (-not $av.realTimeProtection); show = $onOff }
        @{ key = 'DisableBehaviorMonitoring'; name = 'Behavior monitoring'; want = (-not $av.behaviorMonitoring); show = $onOff }
        @{ key = 'DisableScriptScanning'; name = 'Script scanning'; want = (-not $av.scriptScanning); show = $onOff }
        @{ key = 'DisableIOAVProtection'; name = 'Download & attachment scanning'; want = (-not $av.downloadScanning); show = $onOff }
        @{ key = 'MAPSReporting'; name = 'Cloud-delivered protection'; want = $(if ($av.cloudProtection) { 2 } else { 0 }); show = { param($v) if ([int]$v -gt 0) { 'On' } else { 'Off' } } }
        @{ key = 'SubmitSamplesConsent'; name = 'Automatic sample submission'; want = $(if ($av.cloudProtection) { 1 } else { 2 }); show = { param($v) if ([int]$v -eq 2) { 'Never' } else { 'Safe samples' } } }
        @{ key = 'CloudBlockLevel'; name = 'Cloud block level'; want = $levels[[string]$av.cloudBlockLevel]; show = { param($v) switch ([int]$v) { 0 { 'Default' } 2 { 'High' } 4 { 'High+' } 6 { 'Zero tolerance' } default { "$v" } } } }
        @{ key = 'PUAProtection'; name = 'Potentially unwanted apps'; want = $modes[[string]$av.puaProtection]; show = ${function:Format-Mode} }
        @{ key = 'EnableNetworkProtection'; name = 'Network protection (malicious sites)'; want = $modes[[string]$av.networkProtection]; show = ${function:Format-Mode} }
        @{ key = 'EnableControlledFolderAccess'; name = 'Ransomware protection (controlled folders)'; want = $modes[[string]$av.controlledFolderAccess]; show = ${function:Format-Mode} }
        @{ key = 'SignatureUpdateInterval'; name = 'Signature update interval (hours)'; want = [int]$av.signatureUpdateIntervalHours; show = { param($v) "$v" } }
    )

    $pref = Get-MpPreference
    if ($Apply) {
        foreach ($s in $specs) {
            if ($pref.($s.key) -ne $s.want) {
                try { $splat = @{ $s.key = $s.want }; Set-MpPreference @splat }
                catch { Write-Log "Could not set $($s.key): $($_.Exception.Message)" 'WARN' }
            }
        }
        $isServer = (Get-CimInstance Win32_OperatingSystem).ProductType -ne 1
        if ($isServer -and $modes[[string]$av.networkProtection] -ne 0) {
            Invoke-Safely { Set-MpPreference -AllowNetworkProtectionOnWinServer $true } | Out-Null
        }

        $wantEx = @($av.exclusions | Where-Object { $_ })
        $stale = @($script:State.appliedExclusions | Where-Object { $wantEx -notcontains $_ })
        if ($stale.Count) { Invoke-Safely { Remove-MpPreference -ExclusionPath $stale } | Out-Null }
        if ($wantEx.Count) { Invoke-Safely { Add-MpPreference -ExclusionPath $wantEx } | Out-Null }
        $script:State.appliedExclusions = $wantEx

        # Controlled folder access (ransomware protection): programs allowed to change protected folders,
        # and extra folders to protect. Only entries Shield360 added are ever removed again.
        foreach ($cfa in @(
            @{ want = @($av.cfaAllowedApps | Where-Object { $_ }); state = 'appliedCfaApps'; param = 'ControlledFolderAccessAllowedApplications' }
            @{ want = @($av.cfaProtectedFolders | Where-Object { $_ }); state = 'appliedCfaFolders'; param = 'ControlledFolderAccessProtectedFolders' }
        )) {
            $stale = @($script:State[$cfa.state] | Where-Object { $cfa.want -notcontains $_ })
            if ($stale.Count) { Invoke-Safely { $p = @{ $cfa.param = $stale }; Remove-MpPreference @p } | Out-Null }
            if ($cfa.want.Count) {
                try { $p = @{ $cfa.param = $cfa.want }; Add-MpPreference @p }
                catch { Write-Log "Could not set $($cfa.param): $($_.Exception.Message)" 'WARN' }
            }
            $script:State[$cfa.state] = $cfa.want
        }

        # Attack surface reduction rules: 0 off, 1 block, 2 audit.
        $current = @{}
        $ids = @($pref.AttackSurfaceReductionRules_Ids); $acts = @($pref.AttackSurfaceReductionRules_Actions)
        for ($i = 0; $i -lt $ids.Count; $i++) { if ($ids[$i]) { $current[$ids[$i].ToLower()] = [int]$acts[$i] } }
        foreach ($rule in $Policy.asr.PSObject.Properties) {
            $want = $modes[[string]$rule.Value]
            $have = $(if ($current.ContainsKey($rule.Name)) { $current[$rule.Name] } else { 0 })
            if ($have -ne $want) {
                try { Add-MpPreference -AttackSurfaceReductionRules_Ids $rule.Name -AttackSurfaceReductionRules_Actions $want }
                catch { Write-Log "Could not set ASR rule $($rule.Name): $($_.Exception.Message)" 'WARN' }
            }
        }
        $pref = Get-MpPreference
    }

    foreach ($s in $specs) {
        $have = $pref.($s.key)
        Add-Check $Checks 'Antivirus' $s.name (& $s.show $s.want) (& $s.show $have) ($have -eq $s.want)
    }
    if ($av.realTimeProtection) {
        $rtp = (Get-MpComputerStatus).RealTimeProtectionEnabled
        Add-Check $Checks 'Antivirus' 'Real-time protection (effective)' 'On' $(if ($rtp) { 'On' } else { 'Off' })
    }
    foreach ($cfa in @(
        @{ want = @($av.cfaAllowedApps | Where-Object { $_ }); have = @($pref.ControlledFolderAccessAllowedApplications); name = 'Ransomware protection: allowed apps' }
        @{ want = @($av.cfaProtectedFolders | Where-Object { $_ }); have = @($pref.ControlledFolderAccessProtectedFolders); name = 'Ransomware protection: extra protected folders' }
    )) {
        if (-not $cfa.want.Count) { continue }
        $missing = @($cfa.want | Where-Object { $cfa.have -notcontains $_ })
        Add-Check $Checks 'Antivirus' $cfa.name "$($cfa.want.Count) configured" $(if ($missing.Count) { "$($missing.Count) missing" } else { "$($cfa.want.Count) configured" })
    }
    $current = @{}
    $ids = @($pref.AttackSurfaceReductionRules_Ids); $acts = @($pref.AttackSurfaceReductionRules_Actions)
    for ($i = 0; $i -lt $ids.Count; $i++) { if ($ids[$i]) { $current[$ids[$i].ToLower()] = [int]$acts[$i] } }
    foreach ($rule in $Policy.asr.PSObject.Properties) {
        $want = $modes[[string]$rule.Value]
        $have = $(if ($current.ContainsKey($rule.Name)) { $current[$rule.Name] } else { 0 })
        $label = $(if ($Policy.asrNames -and $Policy.asrNames.($rule.Name)) { $Policy.asrNames.($rule.Name) } else { $rule.Name })
        Add-Check $Checks 'Attack surface reduction' $label (Format-Mode $want) (Format-Mode $have) ($have -eq $want)
    }

    $maxHours = [math]::Max(1, [int]$av.signatureUpdateIntervalHours)
    $sigAgeHours = $(if ($status.AntivirusSignatureLastUpdated) { ((Get-Date) - $status.AntivirusSignatureLastUpdated).TotalHours } else { 9999 })
    if ($Apply -and $av.autoUpdateSignatures -and $sigAgeHours -ge $maxHours) {
        $lastTry = $(if ($script:State.lastSignatureAttempt) { [datetime]$script:State.lastSignatureAttempt } else { [datetime]::MinValue })
        if (((Get-Date) - $lastTry).TotalMinutes -ge 30) {
            try { Update-DefenderSignatures | Out-Null } catch { Write-Log "Automatic definition update failed: $($_.Exception.Message)" 'WARN' }
            $status = Get-MpComputerStatus
            $sigAgeHours = ((Get-Date) - $status.AntivirusSignatureLastUpdated).TotalHours
        }
    }
    # Allow one missed cycle before flagging, since Microsoft publishes several updates a day.
    Add-Check $Checks 'Antivirus' "Virus definitions updated within $(2 * $maxHours) hours" 'Yes' $(
        if ($sigAgeHours -le 2 * $maxHours) { 'Yes' } else { "$([math]::Round($sigAgeHours)) hours old" })

    if ($av.dailyQuickScan) {
        $age = [int]$status.QuickScanAge
        $lastTrigger = $(if ($script:State.lastQuickScanTrigger) { [datetime]$script:State.lastQuickScanTrigger } else { [datetime]::MinValue })
        if ($Apply -and $age -ge 1 -and ((Get-Date) - $lastTrigger).TotalHours -ge 20) {
            Start-Process -FilePath (Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe') -ArgumentList '-Scan', '-ScanType', '1' -WindowStyle Hidden
            $script:State.lastQuickScanTrigger = (Get-Date).ToString('o')
            Write-Log 'Started scheduled daily quick scan'
        }
        Add-Check $Checks 'Antivirus' 'Quick scan in the last 2 days' 'Yes' $(if ($age -le 2) { 'Yes' } else { "$age days ago" })
    }
}

function Invoke-FirewallPolicy($Fw, $Checks, [bool]$Apply) {
    foreach ($p in Get-NetFirewallProfile) {
        if ($Fw.enforceOn) {
            if ($Apply -and [string]$p.Enabled -ne 'True') { Set-NetFirewallProfile -Name $p.Name -Enabled True }
        }
        if ($Fw.blockInboundByDefault) {
            if ($Apply -and [string]$p.DefaultInboundAction -eq 'Allow') { Set-NetFirewallProfile -Name $p.Name -DefaultInboundAction Block }
        }
    }
    foreach ($p in Get-NetFirewallProfile) {
        if ($Fw.enforceOn) { Add-Check $Checks 'Firewall' "$($p.Name) profile" 'On' $(if ([string]$p.Enabled -eq 'True') { 'On' } else { 'Off' }) }
        if ($Fw.blockInboundByDefault) {
            Add-Check $Checks 'Firewall' "$($p.Name) default inbound" 'Block' $(if ([string]$p.DefaultInboundAction -eq 'Allow') { 'Allow' } else { 'Block' })
        }
    }
}

function Get-RegValue([string]$Path, [string]$Name) {
    try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

function Invoke-HardeningPolicy($H, $Checks, [bool]$Apply) {
    $items = @(
        @{ on = $H.disableLlmnr; name = 'LLMNR disabled (blocks name-poisoning attacks)'; path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; value = 'EnableMulticast'; want = 0 }
        @{ on = $H.disableWdigest; name = 'WDigest plain-text credentials disabled'; path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'; value = 'UseLogonCredential'; want = 0 }
        @{ on = $H.requireRdpNla; name = 'RDP requires Network Level Authentication'; path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; value = 'UserAuthentication'; want = 1 }
        @{ on = $H.powershellLogging; name = 'PowerShell script block logging'; path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; value = 'EnableScriptBlockLogging'; want = 1 }
        @{ on = $H.lsaProtection; name = 'LSA protection (needs restart)'; path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; value = 'RunAsPPL'; want = 1 }
    )
    foreach ($i in $items | Where-Object { $_.on }) {
        if ($Apply -and (Get-RegValue $i.path $i.value) -ne $i.want) {
            try {
                if (-not (Test-Path $i.path)) { New-Item -Path $i.path -Force | Out-Null }
                Set-ItemProperty -Path $i.path -Name $i.value -Value $i.want -Type DWord
            } catch { Write-Log "Could not set $($i.value): $($_.Exception.Message)" 'WARN' }
        }
        $have = Get-RegValue $i.path $i.value
        Add-Check $Checks 'Hardening' $i.name 'Yes' $(if ($have -eq $i.want) { 'Yes' } else { 'No' })
    }
    if ($H.disableSmb1) {
        $smb1 = Invoke-Safely { (Get-SmbServerConfiguration).EnableSMB1Protocol }
        if ($Apply -and $smb1) {
            try { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false; $smb1 = $false }
            catch { Write-Log "Could not disable SMBv1: $($_.Exception.Message)" 'WARN' }
        }
        Add-Check $Checks 'Hardening' 'SMBv1 server disabled (WannaCry/EternalBlue)' 'Yes' $(if ($smb1) { 'No' } elseif ($null -eq $smb1) { 'Unknown' } else { 'Yes' })
    }
}

# Applies the whole policy (or only measures it in report-only mode) and returns compliance checks.
# Settings Shield360 changed are recorded here (outside ProgramData) so allow-mode and the
# uninstaller only undo Shield360's own changes, never settings made by Group Policy.
$OwnerKey = 'HKLM:\SOFTWARE\Shield360'

function Get-OwnedList([string]$Name) { @(Get-RegValue $OwnerKey $Name | Where-Object { $_ }) }

function Set-OwnedValue([string]$Name, $Value, [string]$Type = 'String') {
    if (-not (Test-Path $OwnerKey)) { New-Item -Path $OwnerKey -Force | Out-Null }
    if ($null -eq $Value -or (@($Value).Count -eq 0)) { Remove-ItemProperty -Path $OwnerKey -Name $Name -ErrorAction SilentlyContinue }
    else { New-ItemProperty -Path $OwnerKey -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null }
}

function Set-DwordValue([string]$Path, [string]$Name, [int]$Value) {
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord
}

# ------------------------------------------------------------------ device control (USB storage)

$RemovableKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices'
$RemovableDiskKey = "$RemovableKey\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}"   # removable disks class
$UsbStorKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR'

function Get-UsbStorageState {
    if ((Get-RegValue $RemovableKey 'Deny_All') -eq 1 -or (Get-RegValue $UsbStorKey 'Start') -eq 4) { return 'Blocked' }
    if ((Get-RegValue $RemovableDiskKey 'Deny_Write') -eq 1) { return 'Read-only' }
    'Allowed'
}

function Invoke-UsbPolicy([string]$Mode, $Checks, [bool]$Apply) {
    if (-not $Mode) { $Mode = 'allow' }
    $managed = (Get-RegValue $OwnerKey 'UsbManaged') -eq 1
    if ($Apply) {
        switch ($Mode) {
            'block' {
                # Deny all removable storage classes (USB drives, phones/MTP, CD) and stop the USB storage driver loading.
                Set-DwordValue $RemovableKey 'Deny_All' 1
                Set-DwordValue $UsbStorKey 'Start' 4
                Set-OwnedValue 'UsbManaged' 1 'DWord'
            }
            'readonly' {
                Remove-ItemProperty -Path $RemovableKey -Name 'Deny_All' -ErrorAction SilentlyContinue
                Set-DwordValue $RemovableDiskKey 'Deny_Write' 1
                Set-DwordValue $UsbStorKey 'Start' 3
                Set-OwnedValue 'UsbManaged' 1 'DWord'
            }
            default {
                if ($managed) {
                    Remove-ItemProperty -Path $RemovableKey -Name 'Deny_All' -ErrorAction SilentlyContinue
                    Remove-ItemProperty -Path $RemovableDiskKey -Name 'Deny_Write' -ErrorAction SilentlyContinue
                    Set-DwordValue $UsbStorKey 'Start' 3
                    Set-OwnedValue 'UsbManaged' $null
                }
            }
        }
    }
    $expected = @{ allow = 'Allowed'; readonly = 'Read-only'; block = 'Blocked' }[$Mode]
    Add-Check $Checks 'Device control' 'USB storage (drives, phones)' $expected (Get-UsbStorageState)
}

# ------------------------------------------------------------------ website blocking

$BrowserBlocklists = @(
    @{ name = 'Edge'; key = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\URLBlocklist'; entries = { param($d) @($d) } }
    @{ name = 'Chrome'; key = 'HKLM:\SOFTWARE\Policies\Google\Chrome\URLBlocklist'; entries = { param($d) @($d) } }
    @{ name = 'Firefox'; key = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\WebsiteFilter\Block'; entries = { param($d) @("*://$d/*", "*://*.$d/*") } }
)

# Browser list policies are numbered values ("1", "2", ...). Entries Shield360 does not own are kept
# and the list is renumbered contiguously, with Shield360's entries after them.
function Set-BrowserBlocklist($Browser, [string[]]$Domains) {
    $wanted = @($Domains | ForEach-Object { & $Browser.entries $_ })
    $ownedNames = Get-OwnedList "Web_$($Browser.name)"
    $current = @{}
    if (Test-Path $Browser.key) {
        $item = Get-Item $Browser.key
        foreach ($n in $item.Property) { $current[$n] = [string]$item.GetValue($n) }
    }
    $ours = @($ownedNames | Where-Object { $current.ContainsKey($_) } | ForEach-Object { $current[$_] })
    if (($ours -join "`n") -eq ($wanted -join "`n") -and $ownedNames.Count -eq $ours.Count) { return }

    $foreign = @($current.Keys | Where-Object { $ownedNames -notcontains $_ } | Sort-Object { [int]($_ -as [int]) } | ForEach-Object { $current[$_] })
    if (Test-Path $Browser.key) { foreach ($n in @($current.Keys)) { Remove-ItemProperty -Path $Browser.key -Name $n -ErrorAction SilentlyContinue } }
    if (-not ($foreign.Count + $wanted.Count)) { Set-OwnedValue "Web_$($Browser.name)" $null; return }
    if (-not (Test-Path $Browser.key)) { New-Item -Path $Browser.key -Force | Out-Null }
    $i = 1
    foreach ($v in $foreign) { New-ItemProperty -Path $Browser.key -Name "$i" -Value $v -PropertyType String -Force | Out-Null; $i++ }
    $names = @()
    foreach ($v in $wanted) { New-ItemProperty -Path $Browser.key -Name "$i" -Value $v -PropertyType String -Force | Out-Null; $names += "$i"; $i++ }
    Set-OwnedValue "Web_$($Browser.name)" ([string[]]$names) 'MultiString'
}

function Invoke-WebFilterPolicy([string[]]$Sites, $Checks, [bool]$Apply) {
    $Sites = @($Sites | Where-Object { $_ })
    if ($Apply) {
        foreach ($b in $BrowserBlocklists) {
            try { Set-BrowserBlocklist $b $Sites } catch { Write-Log "Could not update $($b.name) block list: $($_.Exception.Message)" 'WARN' }
        }
        # System-wide fallback for other apps and browsers (exact names only; browsers above also cover subdomains).
        Set-HostsSection 'websites' @($Sites | ForEach-Object { "0.0.0.0 $_"; "0.0.0.0 www.$_"; "0.0.0.0 m.$_" })
    }
    if (-not $Sites.Count) { return }
    $edge = @(Get-OwnedList 'Web_Edge').Count
    $hosts = @(Get-Content $HostsFile -ErrorAction SilentlyContinue | Where-Object { $_ -match '^0\.0\.0\.0 (\S+)$' -and $Sites -contains $Matches[1] }).Count
    Add-Check $Checks 'Web filtering' 'Blocked websites in browsers (Edge, Chrome, Firefox)' "$($Sites.Count) sites" "$edge sites"
    Add-Check $Checks 'Web filtering' 'Blocked websites system-wide (hosts file)' "$($Sites.Count) sites" "$hosts sites"
}

function Invoke-PolicyEnforcement {
    $policy = $script:State.policy
    if (-not $policy) { return }
    $apply = [bool]$policy.enforce
    $checks = New-Object System.Collections.ArrayList
    foreach ($step in @(
        @{ name = 'antivirus'; run = { Invoke-DefenderPolicy $policy $checks $apply } }
        @{ name = 'firewall'; run = { Invoke-FirewallPolicy $policy.firewall $checks $apply } }
        @{ name = 'hardening'; run = { Invoke-HardeningPolicy $policy.hardening $checks $apply } }
        @{ name = 'USB control'; run = { Invoke-UsbPolicy ([string]$policy.deviceControl.usbStorage) $checks $apply } }
        @{ name = 'website blocking'; run = { Invoke-WebFilterPolicy @($policy.webFilter.blockedSites | Where-Object { $_ }) $checks $apply } }
    )) {
        try { & $step.run } catch { Write-Log "Policy step '$($step.name)' failed: $($_.Exception.Message)" 'ERROR' }
    }
    if ($script:State.isolated) { Invoke-Safely { Enable-Isolation } | Out-Null }   # self-heal isolation rules
    $script:Compliance = @($checks)
    $script:LastEnforced = Get-Date
    Save-AgentState
    $bad = @($checks | Where-Object { -not $_.ok }).Count
    Write-Log ("Policy '{0}' {1}: {2}/{3} settings compliant" -f $policy.name, $(if ($apply) { 'enforced' } else { 'checked (report only)' }), ($checks.Count - $bad), $checks.Count)
}

# ------------------------------------------------------------------ protection: blocklists (IOCs)

function Invoke-IocEnforcement {
    $iocs = $script:State.iocs
    $enabled = $script:State.policy -and $script:State.policy.iocEnforcement -and $script:State.policy.enforce
    if (-not $iocs) { return }
    try {
        Set-BlockRule 'Shield360 - Blocklisted IPs' $(if ($enabled) { @($iocs.ips) } else { @() })
        $lines = $(if ($enabled) { @($iocs.domains | ForEach-Object { "0.0.0.0 $_"; "0.0.0.0 www.$_" }) } else { @() })
        Set-HostsSection 'blocklist' $lines
    } catch { Write-Log "Blocklist enforcement failed: $($_.Exception.Message)" 'ERROR' }
}

$script:HashCache = @{}
# Kills and quarantines running programs whose SHA-256 is on the blocklist.
function Find-BlocklistedProcesses {
    $hashes = @($script:State.iocs.hashes | Where-Object { $_ })
    if (-not $hashes.Count -or -not ($script:State.policy.iocEnforcement -and $script:State.policy.enforce)) { return @() }
    $bad = @{}
    foreach ($h in $hashes) { $bad[[string]$h] = $true }
    if ($script:HashCache.Count -gt 5000) { $script:HashCache = @{} }
    $events = @()
    foreach ($grp in Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath } | Group-Object ExecutablePath) {
        $path = $grp.Name
        try { $fi = Get-Item -LiteralPath $path -Force } catch { continue }
        $key = "$path|$($fi.LastWriteTimeUtc.Ticks)|$($fi.Length)"
        if (-not $script:HashCache.ContainsKey($key)) {
            $script:HashCache[$key] = Invoke-Safely { (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash } ''
        }
        $hash = $script:HashCache[$key]
        if (-not $hash -or -not $bad[$hash]) { continue }
        foreach ($p in $grp.Group) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }
        Start-Sleep -Milliseconds 500
        $quarantined = $true
        try { Move-ToQuarantine $path "Blocklisted SHA-256 $hash" | Out-Null } catch { $quarantined = $false; Write-Log "Quarantine failed for ${path}: $($_.Exception.Message)" 'ERROR' }
        Write-Log "Blocked blocklisted process $path ($hash)" 'WARN'
        $events += New-S360Event 'blocklisted_file' 'critical' $true (
            "Killed blocklisted program $(Split-Path $path -Leaf) ($($grp.Count) process(es)); file " +
            $(if ($quarantined) { 'quarantined' } else { 'could NOT be quarantined' }) + ": $path") @{ sha256 = $hash; path = $path }
    }
    $events
}

# ------------------------------------------------------------------ protection: brute-force blocking

function Invoke-BruteForceProtection {
    $bf = $script:State.policy.bruteForce
    $now = Get-Date
    $before = @($script:State.blockedIps)
    $active = @($before | Where-Object { [datetime]$_.until -gt $now })
    $events = @()

    if ($bf -and $bf.enabled -and $script:State.policy.enforce) {
        $fails = @{}
        $users = @{}
        try {
            Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $now.AddMinutes(-[int]$bf.windowMinutes) } -MaxEvents 5000 |
                ForEach-Object {
                    $f = Get-EventFields $_
                    $ip = $f['IpAddress']
                    if ($ip -and $ip -ne '-' -and $ip -notin '127.0.0.1', '::1') {
                        $fails[$ip] = [int]$fails[$ip] + 1
                        if (-not $users[$ip]) { $users[$ip] = @{} }
                        $users[$ip][$f['TargetUserName']] = $true
                    }
                }
        } catch {
            if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { Write-Log "Failed-logon scan failed: $($_.Exception.Message)" 'WARN' }
        }
        $ownIps = @(Get-SystemInfo).ipAddresses
        foreach ($ip in $fails.Keys) {
            if ($fails[$ip] -lt [int]$bf.threshold) { continue }
            if ($active | Where-Object { $_.ip -eq $ip }) { continue }
            if ($ownIps -contains $ip) { continue }
            if (@($bf.allowlist) | Where-Object { $_ -and (Test-IpMatch $ip $_) }) { continue }
            $accounts = (@($users[$ip].Keys) | Select-Object -First 5) -join ', '
            $active += @{ ip = $ip; until = $now.AddMinutes([int]$bf.blockMinutes).ToString('o'); blockedAt = $now.ToString('o')
                          reason = "$($fails[$ip]) failed logons in $($bf.windowMinutes) min (accounts: $accounts)" }
            Write-Log "Brute force: blocking $ip ($($fails[$ip]) failures)" 'WARN'
            $events += New-S360Event 'bruteforce_blocked' 'high' $true (
                "Blocked attacker $ip for $($bf.blockMinutes) min after $($fails[$ip]) failed logons (accounts tried: $accounts)") @{ ip = $ip; attempts = $fails[$ip] }
        }
    }

    if ($active.Count -ne $before.Count -or $events.Count) {
        $script:State.blockedIps = @($active)
        Set-BlockRule 'Shield360 - Brute-force blocks' @($active | ForEach-Object { $_.ip })
        Save-AgentState
    }
    $events
}

function Remove-BlockedIp([string]$Ip) {
    $script:State.blockedIps = @($script:State.blockedIps | Where-Object { $_.ip -ne $Ip })
    Set-BlockRule 'Shield360 - Brute-force blocks' @($script:State.blockedIps | ForEach-Object { $_.ip })
    Save-AgentState
}

# ------------------------------------------------------------------ protection: network isolation

function ConvertTo-UInt32([string]$Ip) {
    $b = [Net.IPAddress]::Parse($Ip).GetAddressBytes(); [Array]::Reverse($b); [BitConverter]::ToUInt32($b, 0)
}
function ConvertFrom-UInt32([uint64]$N) {
    $b = [BitConverter]::GetBytes([uint32]$N); [Array]::Reverse($b); (New-Object Net.IPAddress (, $b)).IPAddressToString
}
# Every IPv4 range except the given addresses (Windows Firewall block rules override allow rules).
function Get-ComplementRanges([string[]]$Allowed) {
    $ranges = @()
    [uint64]$start = 0
    foreach ($n in ($Allowed | ForEach-Object { [uint64](ConvertTo-UInt32 $_) } | Sort-Object -Unique)) {
        if ($n -gt $start) { $ranges += '{0}-{1}' -f (ConvertFrom-UInt32 $start), (ConvertFrom-UInt32 ($n - 1)) }
        $start = $n + 1
    }
    if ($start -le 4294967295) { $ranges += '{0}-255.255.255.255' -f (ConvertFrom-UInt32 $start) }
    $ranges
}

# Blocks all network traffic except to the Shield360 server, so the admin keeps control.
function Enable-Isolation([string]$Reason = $null) {
    $uri = [uri]$script:Config.serverUrl
    $serverIps = @(Invoke-Safely {
        [Net.Dns]::GetHostAddresses($uri.Host) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.IPAddressToString }
    } @())
    # Fall back to the last known address so an attack during a DNS outage can still be contained.
    if (-not $serverIps.Count) { $serverIps = @($script:State.serverIps) }
    if (-not $serverIps.Count) { throw 'Cannot resolve the server IPv4 address; isolation not applied.' }
    $script:State.serverIps = $serverIps
    if ($Reason) { $script:State.isolationReason = $Reason }
    if ($uri.HostNameType -eq 'Dns') { Set-HostsSection 'isolation' @($serverIps | ForEach-Object { "$_ $($uri.Host)" }) }
    $ranges = @(Get-ComplementRanges $serverIps) + '0:0:0:0:0:0:0:0-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
    Set-BlockRule 'Shield360 - Network isolation' $ranges 'Shield360 Isolation'
    $script:State.isolated = $true
    Save-AgentState
    "Network isolation active. Only $($serverIps -join ', ') ($($uri.Host)) is reachable."
}

function Disable-Isolation {
    Set-BlockRule 'Shield360 - Network isolation' @() 'Shield360 Isolation'
    Set-HostsSection 'isolation' @()
    $script:State.isolated = $false
    $script:State.isolationReason = $null
    Save-AgentState
    'Network isolation released.'
}

# Decides whether this cycle's detections mean the machine is compromised, and if so isolates it
# immediately on the endpoint (no round trip to the server, works even while the server is down).
function Invoke-AutoIsolation($Events) {
    $policy = $script:State.policy
    $ai = $(if ($policy) { $policy.autoIsolate } else { $null })
    $out = @()

    # New Defender detections since the last cycle.
    $seen = @{}
    foreach ($k in @($script:State.seenThreats)) { $seen[[string]$k] = $true }
    $newThreats = @()
    foreach ($t in @(Get-RecentThreats)) {
        $key = "$($t.threatId)|$($t.time)"
        if (-not $seen[$key]) { $newThreats += $t; $script:State.seenThreats = @(@($key) + @($script:State.seenThreats) | Select-Object -First 200) }
    }
    # First run after install: detections from before the agent existed only form the baseline.
    if (-not $script:State.threatsBaselined) { $newThreats = @(); $script:State.threatsBaselined = $true }
    Save-AgentState
    if (-not $ai -or -not $ai.enabled -or $script:State.isolated) { return $out }

    $reasons = @()
    foreach ($t in $newThreats) {
        if ($ai.malwareAny -or ($ai.malwareNotRemediated -and -not $t.actionSuccess)) {
            $reasons += "malware $($t.name)$(if (-not $t.actionSuccess) { ' could not be removed' })"
        }
    }
    foreach ($e in @($Events)) {
        if ($ai.blocklistedFile -and $e.type -eq 'blocklisted_file') { $reasons += 'blocklisted program was running' }
        if ($ai.ransomware -and $e.type -eq 'ransomware_blocked') { $reasons += 'ransomware activity' }
        if ($ai.antivirusDisabled -and $e.type -eq 'av_disabled') { $reasons += 'antivirus was turned off' }
        if ($ai.logCleared -and $e.type -eq 'log_cleared' -and $e.severity -eq 'critical') { $reasons += 'Security event log was cleared' }
        if ($ai.attackPowerShell -and $e.type -eq 'suspicious_powershell' -and $e.severity -eq 'high') { $reasons += 'attack-like PowerShell executed' }
    }
    if (-not $reasons.Count) { return $out }
    $reason = (@($reasons | Select-Object -Unique) -join '; ')

    $isServer = (Get-CimInstance Win32_OperatingSystem).ProductType -ne 1
    if (-not $policy.enforce -or ($isServer -and $ai.excludeServers)) {
        $why = $(if (-not $policy.enforce) { 'policy is in report-only mode' } else { 'servers are excluded from automatic isolation' })
        Write-Log "Compromise detected ($reason) but not isolating: $why" 'WARN'
        return @(New-S360Event 'compromise_detected' 'critical' $false "Compromise indicators: $reason. Not isolated automatically because $why; isolate manually if confirmed.")
    }
    try {
        Enable-Isolation $reason | Out-Null
        Write-Log "AUTO-ISOLATED: $reason" 'WARN'
        $out += New-S360Event 'auto_isolated' 'critical' $true "Endpoint automatically isolated from the network: $reason"
    } catch {
        Write-Log "Automatic isolation FAILED: $($_.Exception.Message)" 'ERROR'
        $out += New-S360Event 'compromise_detected' 'critical' $false "Compromise indicators: $reason. Automatic isolation failed: $($_.Exception.Message)"
    }
    $out
}

# ------------------------------------------------------------------ protection: attack detection (event logs)

$SuspiciousImage = '(?i)\\(temp|appdata|users\\public|perflogs)\\|\\programdata\\[^\\]+\.exe|powershell|pwsh|cmd(\.exe)?\s+/c|mshta|rundll32|regsvr32|wscript|cscript|certutil|bitsadmin|\s-e(nc|ncodedcommand)?\s|^\\\\'

# Techniques common in PowerShell attacks (download cradles, AMSI bypass, in-memory loading, credential theft).
# Stored reversed: written out literally, these keywords make Defender's script scanner (AMSI) block this agent.
$AttackPowerShell = '(?i)' + ((@(
    'ztakimim', 'aslrukes', 'gnirtSdaolnwoD', 'ataDdaolnwoD', 'tneilCbeW.teN', 'slitUismA', 'deliaFtinIisma',
    'gnirtS46esaBmorF', 'daoL::]ylbmessA.noitcelfeR', 'collAlautriV', 'daerhTetomeRetaerC', 'yromeMssecorPetirW',
    'edocllehS-ekovnI', 'noitcejnIEPevitcelfeR-ekovnI', 'drowssaPPPG-teG', 'tsaorebreK-ekovnI', 'roxb-', 'tiolpSrewoP', '(xei', '( xei'
) | ForEach-Object { $c = $_.ToCharArray(); [Array]::Reverse($c); [regex]::Escape(-join $c) }) -join '|')

function ConvertTo-AttackEvent($E) {
    $f = Get-EventFields $E
    $key = "$($E.LogName)|$($E.RecordId)"
    switch ("$($E.LogName)|$($E.Id)") {
        'Security|1102' {
            $user = Invoke-Safely { ([xml]$E.ToXml()).Event.UserData.LogFileCleared.SubjectUserName } '?'
            return New-S360Event 'log_cleared' 'critical' $false "Security event log was cleared by $user (common attacker anti-forensics)" $null $E.TimeCreated $key
        }
        'System|104' {
            return New-S360Event 'log_cleared' 'high' $false "Event log '$($f['Channel'])' was cleared" $null $E.TimeCreated $key
        }
        'Security|4720' {
            return New-S360Event 'account_created' 'warning' $false "User account '$($f['TargetUserName'])' created by $($f['SubjectUserName'])" $null $E.TimeCreated $key
        }
        { $_ -in 'Security|4728', 'Security|4732', 'Security|4756' } {
            $group = $f['TargetUserName']
            $privileged = $f['TargetSid'] -in 'S-1-5-32-544', 'S-1-5-32-555' -or $group -match 'Admins|Administrators'
            $member = $(if ($f['MemberName'] -and $f['MemberName'] -ne '-') { $f['MemberName'] } else { $f['MemberSid'] })
            return New-S360Event 'privileged_group_change' $(if ($privileged) { 'high' } else { 'info' }) $false (
                "$member was added to group '$group' by $($f['SubjectUserName'])") $null $E.TimeCreated $key
        }
        'System|7045' {
            $img = $f['ImagePath']
            $sus = $img -match $SuspiciousImage
            return New-S360Event $(if ($sus) { 'suspicious_service' } else { 'service_installed' }) $(if ($sus) { 'high' } else { 'info' }) $false (
                "New service '$($f['ServiceName'])' installed: $img (account $($f['AccountName']))") $null $E.TimeCreated $key
        }
        'Microsoft-Windows-Windows Defender/Operational|1121' {
            return New-S360Event 'asr_blocked' 'warning' $true "Attack surface reduction blocked $($f['Process Name']) -> $($f['Path'])" @{ rule = $f['ID'] } $E.TimeCreated $key
        }
        'Microsoft-Windows-Windows Defender/Operational|1123' {
            return New-S360Event 'ransomware_blocked' 'high' $true "Ransomware protection blocked $($f['Process Name']) from modifying $($f['Path'])" $null $E.TimeCreated $key
        }
        'Microsoft-Windows-Windows Defender/Operational|1124' {
            # Audit mode: nothing was blocked. If the program is legitimate, add it to the policy's allowed apps.
            return New-S360Event 'ransomware_audit' 'warning' $false (
                "Ransomware protection (audit) would have blocked $($f['Process Name']) from modifying $($f['Path'])") @{ process = $f['Process Name'] } $E.TimeCreated $key
        }
        'Microsoft-Windows-Windows Defender/Operational|1126' {
            $target = @($f['Domain'], $f['Remote Address'], $f['Path']) | Where-Object { $_ } | Select-Object -First 1
            return New-S360Event 'network_blocked' 'warning' $true "Network protection blocked a connection to $target from $($f['Process Name'])" $null $E.TimeCreated $key
        }
        'Microsoft-Windows-Windows Defender/Operational|1015' {
            return New-S360Event 'suspicious_behavior' 'high' $true "Defender behavior monitoring flagged $($f['Threat Name']) in $($f['Process Name'])" $null $E.TimeCreated $key
        }
        { $_ -in 'Microsoft-Windows-Windows Defender/Operational|5001', 'Microsoft-Windows-Windows Defender/Operational|5010', 'Microsoft-Windows-Windows Defender/Operational|5012' } {
            return New-S360Event 'av_disabled' 'critical' $false "Microsoft Defender protection was turned off (event $($E.Id))" $null $E.TimeCreated $key
        }
        'Microsoft-Windows-PowerShell/Operational|4104' {
            $raw = [string]$f['ScriptBlockText']
            # Skip continuation parts of long scripts, Windows' generated CDXML module code, and this agent.
            if ($f['MessageNumber'] -and $f['MessageNumber'] -ne '1') { return $null }
            if ($raw -match '__cmdletization' -or $f['Path'] -like '*Shield360*') { return $null }
            $strong = $raw -match $AttackPowerShell
            $text = $raw -replace '\s+', ' '
            if ($text.Length -gt 300) { $text = $text.Substring(0, 300) + '...' }
            return New-S360Event 'suspicious_powershell' $(if ($strong) { 'high' } else { 'warning' }) $false (
                "$(if ($strong) { 'Attack-like' } else { 'Suspicious' }) PowerShell code ran$(if ($f['Path']) { " ($($f['Path']))" }): $text") @{ path = $f['Path'] } $E.TimeCreated $key
        }
    }
    $null
}

function Get-AttackEvents {
    $since = $(if ($script:State.lastEventScan) { [datetime]$script:State.lastEventScan } else { (Get-Date).AddHours(-1) })
    $until = Get-Date
    $events = New-Object System.Collections.ArrayList
    $queries = @(
        @{ LogName = 'Security'; Id = 1102, 4720, 4728, 4732, 4756 }
        @{ LogName = 'System'; Id = 104, 7045 }
        @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1015, 1121, 1123, 1124, 1126, 5001, 5010, 5012 }
        # Level 3 = script blocks Windows/AMSI itself flagged as suspicious.
        @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104; Level = 3 }
    )
    foreach ($q in $queries) {
        $filter = $q.Clone()
        $filter.StartTime = $since
        $filter.EndTime = $until
        try { $found = @(Get-WinEvent -FilterHashtable $filter -MaxEvents 200) } catch { continue }
        foreach ($e in $found) {
            $evt = Invoke-Safely { ConvertTo-AttackEvent $e }
            if ($evt) { [void]$events.Add($evt) }
        }
    }
    $script:State.lastEventScan = $until.ToString('o')
    @($events)
}

# ------------------------------------------------------------------ actions

$CriticalProcesses = 'System', 'Idle', 'smss', 'csrss', 'wininit', 'winlogon', 'services', 'lsass', 'lsaiso', 'MsMpEng'

function Invoke-AgentAction([string]$Action, $Params) {
    $mpCmd = Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
    switch ($Action) {
        'refresh_inventory' {
            Send-Inventory
            return 'Inventory collected and uploaded.'
        }
        'apply_policy' {
            Invoke-PolicyEnforcement
            Invoke-IocEnforcement
            $bad = @($script:Compliance | Where-Object { -not $_.ok })
            return "Policy '$($script:State.policy.name)' applied: $($script:Compliance.Count - $bad.Count)/$($script:Compliance.Count) settings compliant." +
                $(if ($bad.Count) { "`nNot compliant:`n" + (($bad | ForEach-Object { " - $($_.setting): expected $($_.expected), is $($_.actual)" }) -join "`n") } else { '' })
        }
        'remove_threats' {
            $active = @(Get-MpThreat | Where-Object { $_.IsActive -or -not $_.DidThreatExecute })
            Remove-MpThreat
            return "Remove-MpThreat completed ($($active.Count) threat record(s) were present)."
        }
        'scan_path' {
            $path = [string]$Params.path
            if (-not (Test-Path -LiteralPath $path)) { throw "Path not found: $path" }
            $out = Join-Path $env:TEMP "s360-scan-$([guid]::NewGuid()).txt"
            $p = Start-Process -FilePath $mpCmd -ArgumentList '-Scan', '-ScanType', '3', '-File', "`"$path`"" `
                -NoNewWindow -PassThru -RedirectStandardOutput $out
            $null = $p.Handle   # PowerShell 5.1 only records ExitCode if the handle was opened
            if (-not $p.WaitForExit(300000)) { return "Scan of $path is still running in the background." }
            $text = (Get-Content $out -Raw -ErrorAction SilentlyContinue)
            Remove-Item $out -ErrorAction SilentlyContinue
            $verdict = $(if ($p.ExitCode -eq 2) { 'THREATS FOUND (Defender is remediating)' } elseif ($p.ExitCode -eq 0) { 'No threats found' } else { "exit code $($p.ExitCode)" })
            return "Scan of ${path}: $verdict`n$text".Trim()
        }
        'quarantine_file' {
            $entry = Move-ToQuarantine ([string]$Params.path) 'Quarantined by administrator'
            return "Quarantined $($entry.path) (SHA-256 $($entry.sha256))."
        }
        'kill_process' {
            $procId = [int]$Params.pid
            if ($procId -eq $PID) { throw 'Refusing to stop the Shield360 agent itself.' }
            $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
            if (-not $proc) { throw "No process with ID $procId." }
            if ($CriticalProcesses -contains $proc.ProcessName) { throw "Refusing to stop critical system process $($proc.ProcessName)." }
            $path = $proc.Path
            Stop-Process -Id $procId -Force
            return "Stopped $($proc.ProcessName) (PID $procId)$(if ($path) { " - $path" })."
        }
        'unblock_ip' {
            Remove-BlockedIp ([string]$Params.ip)
            return "Removed $($Params.ip) from the brute-force block list."
        }
        'uninstall_agent' {
            # Runs the uninstaller as a separate one-time SYSTEM task in 20 seconds, so this agent can report
            # the result first and the uninstaller is not stopped together with the agent's own task.
            $uninstaller = Join-Path $env:SystemRoot 'Temp\Shield360-Uninstall.ps1'
            $local = Join-Path $PSScriptRoot 'Uninstall-Shield360Agent.ps1'
            if (Test-Path $local) { Copy-Item $local $uninstaller -Force }
            else {
                Invoke-WebRequest -Uri ($script:Config.serverUrl.TrimEnd('/') + '/download/Uninstall-Shield360Agent.ps1') -OutFile $uninstaller -UseBasicParsing
            }
            # One-time token: lets this console-initiated uninstall pass uninstall protection.
            $token = [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')
            $script:State.remoteUninstallTokenHash = Get-Sha256Hex $token
            Save-AgentState
            $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
            $taskAction = New-ScheduledTaskAction -Execute $ps -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$uninstaller`" -RemoteToken $token"
            Register-ScheduledTask -TaskName 'Shield360 Uninstall' -TaskPath '\Shield360\' -Action $taskAction `
                -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(20)) `
                -Principal (New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest) -Force | Out-Null
            return 'Uninstall started. The agent removes itself within a minute, restores USB, network and website settings, and the endpoint then disappears from the console.'
        }
        'isolate' { return Enable-Isolation }
        'release_isolation' { return Disable-Isolation }
        'defender_quick_scan' {
            Start-Process -FilePath $mpCmd -ArgumentList '-Scan', '-ScanType', '1' -WindowStyle Hidden
            return 'Microsoft Defender quick scan started. Detections will appear under Security.'
        }
        'defender_full_scan' {
            Start-Process -FilePath $mpCmd -ArgumentList '-Scan', '-ScanType', '2' -WindowStyle Hidden
            return 'Microsoft Defender full scan started. This can take several hours.'
        }
        'defender_update_signatures' { return Update-DefenderSignatures }
        'list_processes' {
            return (Get-Process | Sort-Object CPU -Descending | Select-Object -First 40 `
                    Id, ProcessName, @{ n = 'CPU(s)'; e = { [math]::Round($_.CPU, 1) } }, @{ n = 'Memory(MB)'; e = { [math]::Round($_.WorkingSet64 / 1MB) } }, Path |
                Format-Table -AutoSize | Out-String -Width 220).Trim()
        }
        'list_connections' {
            $procs = @{}
            Get-Process | ForEach-Object { $procs[$_.Id] = $_.ProcessName }
            return (Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notin '127.0.0.1', '::1' } |
                Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, @{ n = 'Process'; e = { $procs[[int]$_.OwningProcess] } } |
                Sort-Object Process | Format-Table -AutoSize | Out-String -Width 220).Trim()
        }
        'restart' {
            & shutdown.exe /r /t 120 /c 'Shield360: your administrator has scheduled a restart in 2 minutes. Please save your work.' /d p:4:1
            if ($LASTEXITCODE -ne 0) { throw "shutdown.exe exited with code $LASTEXITCODE" }
            return 'Restart scheduled in 2 minutes.'
        }
        'cancel_restart' {
            & shutdown.exe /a
            if ($LASTEXITCODE -ne 0) { throw 'No restart was pending.' }
            return 'Pending restart cancelled.'
        }
        default { throw "Unsupported action '$Action'." }
    }
}

# ------------------------------------------------------------------ main flows

function Save-Config($cfg) {
    if (-not (Test-Path $DataDir)) { New-Item -ItemType Directory -Path $DataDir -Force | Out-Null }
    ConvertTo-Json -InputObject $cfg | Set-Content -Path $ConfigFile -Encoding UTF8
}

function Invoke-Enrollment {
    if (-not $ServerUrl -or -not $EnrollToken) { throw '-ServerUrl and -EnrollToken are required with -Enroll.' }
    $script:Config = @{ serverUrl = $ServerUrl.TrimEnd('/') }
    Write-Log "Enrolling with $ServerUrl"
    $resp = Invoke-S360Api -Path '/api/agent/enroll' -NoAuth -Body @{
        enrollToken  = $EnrollToken
        agentVersion = $AgentVersion
        system       = Get-SystemInfo
    }
    Save-Config @{ serverUrl = $script:Config.serverUrl; agentId = $resp.agentId; agentKey = $resp.agentKey }
    Write-Log "Enrolled as $($resp.agentId)"
}

function Send-Inventory {
    Write-Log 'Collecting inventory'
    $inv = Get-Inventory
    Invoke-S360Api -Path '/api/agent/inventory' -Body $inv | Out-Null
    Write-Log "Inventory sent ($($inv.software.Count) applications)"
}

function Start-AgentLoop {
    if (-not (Test-Path $ConfigFile)) { throw "Agent is not enrolled ($ConfigFile missing). Run the installer." }
    $script:Config = Get-Content $ConfigFile -Raw | ConvertFrom-Json
    Read-AgentState
    Write-Log "Shield360 agent $AgentVersion starting (server $($script:Config.serverUrl))"

    $interval = 60
    $nextInventory = Get-Date
    $security = $null
    $securityAt = [datetime]::MinValue
    $failures = 0
    $script:Compliance = @()
    $script:LastEnforced = $null
    # Events are kept until the server has accepted them, so nothing is lost while offline.
    $pendingEvents = New-Object System.Collections.ArrayList
    if ($script:State.policy) { Invoke-PolicyEnforcement; Invoke-IocEnforcement }

    while ($true) {
        # Prevention runs every cycle, even when the server is unreachable.
        $cycleEvents = New-Object System.Collections.ArrayList
        foreach ($source in @(
            @{ name = 'attack detection'; run = { Get-AttackEvents } }
            @{ name = 'brute-force protection'; run = { Invoke-BruteForceProtection } }
            @{ name = 'blocklist scan'; run = { Find-BlocklistedProcesses } }
            @{ name = 'automatic isolation'; run = { Invoke-AutoIsolation @($cycleEvents) } }
        )) {
            try { foreach ($e in @(& $source.run)) { if ($e) { [void]$cycleEvents.Add($e); [void]$pendingEvents.Add($e) } } }
            catch { Write-Log "$($source.name) failed: $($_.Exception.Message)" 'ERROR' }
        }
        if ($pendingEvents.Count -gt 1000) { $pendingEvents.RemoveRange(0, $pendingEvents.Count - 1000) }
        if ($script:State.policy -and (-not $script:LastEnforced -or ((Get-Date) - $script:LastEnforced).TotalMinutes -ge $EnforceEveryMinutes)) {
            Invoke-PolicyEnforcement
            Invoke-IocEnforcement
        }

        try {
            if (((Get-Date) - $securityAt).TotalMinutes -ge $SecurityCacheMinutes) {
                $security = Get-SecurityPosture
                $securityAt = Get-Date
            }
            $sending = @($pendingEvents | Select-Object -First 200)
            $resp = Invoke-S360Api -Path '/api/agent/checkin' -Body @{
                agentVersion = $AgentVersion
                system       = Get-SystemInfo
                metrics      = Get-Metrics
                security     = $security
                events       = $sending
                protection   = @{
                    policyVersion = $(if ($script:State.policy) { $script:State.policy.version } else { $null })
                    policyName    = $(if ($script:State.policy) { $script:State.policy.name } else { $null })
                    enforce       = $(if ($script:State.policy) { [bool]$script:State.policy.enforce } else { $null })
                    iocVersion    = $(if ($script:State.iocs) { $script:State.iocs.version } else { $null })
                    compliance    = @($script:Compliance)
                    lastEnforced  = ConvertTo-IsoDate $script:LastEnforced
                    isolated      = [bool]$script:State.isolated
                    isolationReason = $script:State.isolationReason
                    blockedIps    = @($script:State.blockedIps)
                    quarantine    = @($script:State.quarantine | Select-Object -First 25)
                }
            }
            if ($sending.Count) { $pendingEvents.RemoveRange(0, $sending.Count) }
            if ($failures) { Write-Log "Connection restored after $failures failed attempt(s)" }
            $failures = 0
            if ($resp.interval) { $interval = [math]::Max(15, [int]$resp.interval) }
            $script:Definitions = $resp.definitions
            # The uninstaller reads this from state.json to decide whether a local uninstall needs the code.
            if ($resp.uninstallProtection -and (ConvertTo-Json $resp.uninstallProtection -Compress) -ne (ConvertTo-Json $script:State.uninstallProtection -Compress)) {
                $script:State.uninstallProtection = $resp.uninstallProtection
                Save-AgentState
            }

            if ($resp.policy) {
                Write-Log "Received protection policy '$($resp.policy.name)' ($($resp.policy.version))"
                $script:State.policy = $resp.policy
                Invoke-PolicyEnforcement
                Invoke-IocEnforcement
            }
            if ($resp.iocs) {
                Write-Log ("Received blocklist: {0} hashes, {1} IPs, {2} domains" -f @($resp.iocs.hashes).Count, @($resp.iocs.ips).Count, @($resp.iocs.domains).Count)
                $script:State.iocs = $resp.iocs
                Save-AgentState
                Invoke-IocEnforcement
            }

            foreach ($cmd in @($resp.commands)) {
                if (-not $cmd) { continue }
                Write-Log "Running action '$($cmd.action)' (#$($cmd.id))"
                try {
                    $out = Invoke-AgentAction $cmd.action $cmd.params
                    $result = @{ success = $true; output = [string]$out }
                    if ($cmd.action -like 'defender_*' -or $cmd.action -eq 'remove_threats') { $securityAt = [datetime]::MinValue }
                } catch {
                    $result = @{ success = $false; output = $_.Exception.Message }
                    Write-Log "Action '$($cmd.action)' failed: $($_.Exception.Message)" 'ERROR'
                }
                Invoke-S360Api -Path "/api/agent/commands/$($cmd.id)/result" -Body $result | Out-Null
            }

            if ((Get-Date) -ge $nextInventory) {
                Send-Inventory
                $nextInventory = (Get-Date).AddHours($InventoryEveryHours)
            }
        } catch {
            $failures++
            $status = $null
            if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
            if ($status -eq 401) {
                Write-Log 'Server rejected agent credentials. The endpoint may have been removed; reinstall to re-enroll.' 'ERROR'
            } elseif ($failures -le 3 -or $failures % 30 -eq 0) {
                Write-Log "Check-in failed: $($_.Exception.Message)" 'ERROR'
            }
        }
        if ($Once) { break }
        # Back off up to 5 minutes while the server is unreachable.
        Start-Sleep -Seconds ([math]::Min(300, $interval * [math]::Max(1, [math]::Min($failures, 5))))
    }
}

if ($Enroll) {
    try { Invoke-Enrollment } catch { Write-Log "Enrollment failed: $($_.Exception.Message)" 'ERROR'; exit 1 }
} elseif ($ReleaseIsolation) {
    Read-AgentState
    Disable-Isolation
    Write-Log 'Network isolation released locally (break-glass).' 'WARN'
} else {
    Start-AgentLoop
}
