#Requires -Version 5.1
<#
.SYNOPSIS
    Builds the files served from https://shield360.biz/download/.

.DESCRIPTION
    Packages the server and agent into download\shield360-endpoint-<version>-<fingerprint>.zip,
    copies the agent scripts for offline download, and writes latest.json and
    SHA256SUMS.txt. install.ps1 reads latest.json to find and verify the package.

    Never packaged: server\config.json (enrollment token, TLS passphrase),
    server\data\ (database, admin password, certificates, definitions) and node_modules.

    Run it after every release, then upload the whole Website folder.

.EXAMPLE
    .\Build-Downloads.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem

$root = Split-Path $PSScriptRoot -Parent
$out = Join-Path $PSScriptRoot 'download'
$version = (Get-Content (Join-Path $root 'server\package.json') -Raw | ConvertFrom-Json).version

$include = @(
    'README.md', 'TESTING.md',
    'agent\*.ps1',
    'server\package.json', 'server\*.ps1',
    'server\src\*', 'server\public\*'
)

# Keep the newest previous package: a browser or CDN may still serve the old latest.json for a few
# minutes after a release, and its download link must keep working.
$previous = Get-ChildItem $out -Filter 'shield360-endpoint-*.zip' -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
$keep = $null
if ($previous) { $keep = Join-Path $env:TEMP $previous.Name; Copy-Item $previous.FullName $keep -Force }

if (Test-Path $out) { Remove-Item $out -Recurse -Force }
New-Item -ItemType Directory (Join-Path $out 'agent') -Force | Out-Null

$files = foreach ($pattern in $include) {
    Get-ChildItem (Join-Path $root $pattern) -File -Recurse:($pattern -like '*\*\*')
}
$files = $files | Sort-Object FullName -Unique
foreach ($f in $files) {
    $rel = $f.FullName.Substring($root.Length + 1)
    if ($rel -match '^server\\(data|node_modules)\\' -or $rel -eq 'server\config.json') { throw "Refusing to package $rel" }
}

$buildPath = Join-Path $out 'build.zip'
$zip = [IO.Compression.ZipFile]::Open($buildPath, 'Create')
try {
    foreach ($f in $files) {
        # Forward slashes so the archive extracts correctly everywhere.
        $entry = $f.FullName.Substring($root.Length + 1).Replace('\', '/')
        [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $f.FullName, $entry, 'Optimal') | Out-Null
    }
} finally { $zip.Dispose() }

# Every build gets a unique name (version + content fingerprint). A file name is never reused for
# different content, so a CDN can never serve a cached package that doesn't match latest.json.
$fingerprint = (Get-FileHash $buildPath -Algorithm SHA256).Hash.Substring(0, 8).ToLower()
$zipName = "shield360-endpoint-$version-$fingerprint.zip"
$zipPath = Join-Path $out $zipName
Move-Item $buildPath $zipPath
if ($keep -and (Split-Path $keep -Leaf) -ne $zipName) { Move-Item $keep (Join-Path $out (Split-Path $keep -Leaf)) }
elseif ($keep) { Remove-Item $keep -Force }

Copy-Item (Join-Path $root 'agent\*.ps1') (Join-Path $out 'agent')

$sums = Get-ChildItem $out -File -Recurse | Sort-Object FullName | ForEach-Object {
    $rel = $_.FullName.Substring($out.Length + 1).Replace('\', '/')
    '{0}  {1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $rel
}
$sums += '{0}  ../install.ps1' -f (Get-FileHash (Join-Path $PSScriptRoot 'install.ps1') -Algorithm SHA256).Hash.ToLower()
[IO.File]::WriteAllLines((Join-Path $out 'SHA256SUMS.txt'), $sums)

$zipItem = Get-Item $zipPath
$latest = [ordered]@{
    version  = $version
    file     = $zipName
    size     = $zipItem.Length
    sha256   = (Get-FileHash $zipPath -Algorithm SHA256).Hash.ToLower()
    released = (Get-Date).ToString('yyyy-MM-dd')
}
[IO.File]::WriteAllText((Join-Path $out 'latest.json'), ($latest | ConvertTo-Json))

# Lets the website show the current version and checksum without a build step.
$js = "window.SHIELD360_RELEASE = $($latest | ConvertTo-Json -Compress);"
[IO.File]::WriteAllText((Join-Path $out 'latest.js'), $js)

Write-Host "Built $zipName ($([math]::Round($zipItem.Length / 1KB)) KB, $($files.Count) files) in $out" -ForegroundColor Green
