#Requires -Version 5.1
<#
.SYNOPSIS
    Builds the files served from https://shield360.biz/advanced/download/.

.DESCRIPTION
    Packages the Advanced edition (the .NET server, worker, console and agent) into
    advanced\download\shield360-advanced-<version>-<fingerprint>.zip and writes latest.json,
    latest.js and SHA256SUMS.txt next to it. The zip holds Install-Shield360Server.ps1 and the
    package\ folder it installs, so extracting it and running the installer is the whole install.

    By default it first runs ..\deploy\Publish-Shield360.ps1 to build the package. The standard
    edition's files (download\, install.ps1) are not touched: use Build-Downloads.ps1 for those.

    Never packaged: appsettings.Development.json, appsettings.Production.json (connection string)
    and anything under a data folder. The build fails if one would end up in the zip.

.EXAMPLE
    .\Build-Advanced.ps1 -Version 2.0.0-preview.1
    .\Build-Advanced.ps1 -Version 2.0.0-preview.1 -SkipPublish
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$')][string]$Version,
    # Reuse deploy\package as it is instead of building it again.
    [switch]$SkipPublish
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem

$root = Split-Path $PSScriptRoot -Parent
$deploy = Join-Path $root 'deploy'
$package = Join-Path $deploy 'package'
$out = Join-Path $PSScriptRoot 'advanced\download'
# GitHub Pages refuses a file of 100 MB or more.
$maxBytes = 99MB

if (-not $SkipPublish) {
    & (Join-Path $deploy 'Publish-Shield360.ps1')
    if ($LASTEXITCODE) { throw 'Publish-Shield360.ps1 failed' }
}
foreach ($need in 'api\Shield360.Api.exe', 'api\wwwroot\index.html', 'worker\Shield360.Worker.exe', 'agent\Shield360Agent.ps1') {
    if (-not (Test-Path (Join-Path $package $need))) { throw "Package incomplete: $need not found in $package" }
}

$files = @(Get-Item (Join-Path $deploy 'Install-Shield360Server.ps1')) + @(Get-ChildItem $package -File -Recurse) | Sort-Object FullName
foreach ($f in $files) {
    $rel = $f.FullName.Substring($deploy.Length + 1)
    if ($rel -match '(^|\\)appsettings\.(Development|Production)\.json$' -or $rel -match '(^|\\)(data|\.dev-data)\\' -or $rel -match '\.(pfx|key|pem)$') {
        throw "Refusing to package $rel"
    }
}

# Keep the newest previous package: a browser or CDN may still serve the old latest.json for a few
# minutes after a release, and its download link must keep working.
$previous = Get-ChildItem $out -Filter 'shield360-advanced-*.zip' -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
$keep = $null
if ($previous) { $keep = Join-Path $env:TEMP $previous.Name; Copy-Item $previous.FullName $keep -Force }

if (Test-Path $out) { Remove-Item $out -Recurse -Force }
New-Item -ItemType Directory $out -Force | Out-Null

$buildPath = Join-Path $out 'build.zip'
$zip = [IO.Compression.ZipFile]::Open($buildPath, 'Create')
try {
    foreach ($f in $files) {
        # Forward slashes so the archive extracts correctly everywhere.
        $entry = $f.FullName.Substring($deploy.Length + 1).Replace('\', '/')
        [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $f.FullName, $entry, 'Optimal') | Out-Null
    }
} finally { $zip.Dispose() }

if ((Get-Item $buildPath).Length -ge $maxBytes) {
    $mb = [math]::Round((Get-Item $buildPath).Length / 1MB, 1)
    Remove-Item $buildPath -Force
    throw "The package is $mb MB; the website host takes files under 99 MB. Host it elsewhere or make it smaller."
}

# Every build gets a unique name (version + content fingerprint), so a cached package can never
# be served under a name that latest.json gives a different checksum for.
$fingerprint = (Get-FileHash $buildPath -Algorithm SHA256).Hash.Substring(0, 8).ToLower()
$zipName = "shield360-advanced-$Version-$fingerprint.zip"
$zipPath = Join-Path $out $zipName
Move-Item $buildPath $zipPath
if ($keep -and (Split-Path $keep -Leaf) -ne $zipName) { Move-Item $keep (Join-Path $out (Split-Path $keep -Leaf)) }
elseif ($keep) { Remove-Item $keep -Force }

$sums = Get-ChildItem $out -File | Sort-Object Name | ForEach-Object {
    '{0}  {1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.Name
}
[IO.File]::WriteAllLines((Join-Path $out 'SHA256SUMS.txt'), $sums)

$zipItem = Get-Item $zipPath
$latest = [ordered]@{
    version  = $Version
    file     = $zipName
    size     = $zipItem.Length
    sha256   = (Get-FileHash $zipPath -Algorithm SHA256).Hash.ToLower()
    released = (Get-Date).ToString('yyyy-MM-dd')
}
[IO.File]::WriteAllText((Join-Path $out 'latest.json'), ($latest | ConvertTo-Json))

# Lets the page show the current version and checksum without a build step.
$js = "window.SHIELD360_ADVANCED_RELEASE = $($latest | ConvertTo-Json -Compress);"
[IO.File]::WriteAllText((Join-Path $out 'latest.js'), $js)

Write-Host "Built $zipName ($([math]::Round($zipItem.Length / 1MB, 1)) MB, $($files.Count) files) in $out" -ForegroundColor Green
