#Requires -Version 5.1
<#
.SYNOPSIS
    Builds the Advanced edition package and the files served from https://shield360.biz/advanced/download/.

.DESCRIPTION
    Packages the Advanced edition (the .NET server, worker, console and agent) into
    advanced\release\shield360-advanced-<version>-<fingerprint>.zip. The zip holds
    Install-Shield360Server.ps1 and the package\ folder it installs, so extracting it and
    running the installer is the whole install.

    The zip is too large for the website host, so it is published as a GitHub release of the
    website repository (tag advanced-<version>) and advanced\release\ is not uploaded with the
    site. advanced\download\ gets latest.json, latest.js and SHA256SUMS.txt, which give the
    release's download address and the zip's checksum.

    By default it first runs ..\deploy\Publish-Shield360.ps1 to build the package. The standard
    edition's files (download\, install.ps1) are not touched: use Build-Downloads.ps1 for those.

    Never packaged: appsettings.Development.json, appsettings.Production.json (connection string),
    certificates and anything under a data folder. The build fails if one would end up in the zip.

.EXAMPLE
    .\Build-Advanced.ps1 -Version 2.0.0-preview.2 -Publish
    .\Build-Advanced.ps1 -Version 2.0.0-preview.2 -SkipPublish     # reuse deploy\package, no upload
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$')][string]$Version,
    # Reuse deploy\package as it is instead of building it again.
    [switch]$SkipPublish,
    # Create the GitHub release and upload the zip (needs the gh CLI, signed in). Without it, upload the zip yourself.
    [switch]$Publish,
    [string]$Repository = 'afseerkp/shield360-website'
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem

$root = Split-Path $PSScriptRoot -Parent
$deploy = Join-Path $root 'deploy'
$package = Join-Path $deploy 'package'
$out = Join-Path $PSScriptRoot 'advanced\download'
$staging = Join-Path $PSScriptRoot 'advanced\release'
$tag = "advanced-$Version"
# A GitHub release takes files under 2 GB.
$maxBytes = 2000MB

if (-not $SkipPublish) {
    & (Join-Path $deploy 'Publish-Shield360.ps1') -Version $Version
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

foreach ($dir in $out, $staging) {
    if (Test-Path $dir) { Remove-Item $dir -Recurse -Force }
    New-Item -ItemType Directory $dir -Force | Out-Null
}

$buildPath = Join-Path $staging 'build.zip'
$zip = [IO.Compression.ZipFile]::Open($buildPath, 'Create')
try {
    foreach ($f in $files) {
        # Forward slashes so the archive extracts correctly everywhere.
        $entry = $f.FullName.Substring($deploy.Length + 1).Replace('\', '/')
        [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $f.FullName, $entry, 'Optimal') | Out-Null
    }
} finally { $zip.Dispose() }

if ((Get-Item $buildPath).Length -ge $maxBytes) {
    Remove-Item $buildPath -Force
    throw 'The package is 2 GB or more, which a GitHub release does not take.'
}

# Every build gets a unique name (version + content fingerprint), so a file name is never reused for different content.
$sha = (Get-FileHash $buildPath -Algorithm SHA256).Hash.ToLower()
$zipName = "shield360-advanced-$Version-$($sha.Substring(0, 8)).zip"
$zipPath = Join-Path $staging $zipName
Move-Item $buildPath $zipPath
$zipItem = Get-Item $zipPath

$latest = [ordered]@{
    version  = $Version
    file     = $zipName
    url      = "https://github.com/$Repository/releases/download/$tag/$zipName"
    size     = $zipItem.Length
    sha256   = $sha
    released = (Get-Date).ToString('yyyy-MM-dd')
}
[IO.File]::WriteAllText((Join-Path $out 'latest.json'), ($latest | ConvertTo-Json))
# Lets the page show the current version and checksum without a build step.
[IO.File]::WriteAllText((Join-Path $out 'latest.js'), "window.SHIELD360_ADVANCED_RELEASE = $($latest | ConvertTo-Json -Compress);")
[IO.File]::WriteAllLines((Join-Path $out 'SHA256SUMS.txt'), @("$sha  $zipName"))

Write-Host "Built $zipName ($([math]::Round($zipItem.Length / 1MB, 1)) MB, $($files.Count) files) in $staging" -ForegroundColor Green

if ($Publish) {
    # An earlier build of the same version keeps its file: a cached latest.json may still point at it.
    & gh release view $tag --repo $Repository *> $null
    if ($LASTEXITCODE -eq 0) { & gh release upload $tag $zipPath --repo $Repository }
    else {
        & gh release create $tag $zipPath --repo $Repository --title "Shield360 Endpoint Advanced $Version" --prerelease --latest=false `
            --notes "Shield360 Endpoint Advanced $Version (preview). Install steps: https://shield360.biz/advanced/`n`nSHA-256: $sha"
    }
    if ($LASTEXITCODE) { throw 'The GitHub release upload failed' }
    Write-Host "Published $($latest.url). Now upload advanced\ (the site) so the page points at it." -ForegroundColor Green
} else {
    Write-Host "Not uploaded. Run again with -Publish, or upload the zip to release '$tag' of $Repository, then upload advanced\."
}
