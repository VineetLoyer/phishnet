# Package PhishNet AI for Splunk install / Splunkbase upload.
#
# Usage:
#   .\scripts\package_app.ps1
#   .\scripts\package_app.ps1 -Version 1.0.0
#
# Output: dist/phishnet_ai-<version>.tar.gz

param(
    [string]$Version = "1.0.0",
    [string]$OutDir = "dist"
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$appDir = Join-Path $repoRoot "phishnet_ai"
$outPath = Join-Path $repoRoot $OutDir
$tarName = "phishnet_ai-$Version.tar.gz"
$tarPath = Join-Path $outPath $tarName

if (-not (Test-Path $appDir)) {
    throw "App directory not found: $appDir"
}

New-Item -ItemType Directory -Force -Path $outPath | Out-Null

Push-Location $appDir
try {
    if (Test-Path $tarPath) {
        Remove-Item -Force $tarPath
    }
    tar -czf $tarPath `
        --exclude="__pycache__" `
        --exclude="*.pyc" `
        --exclude="*.pyo" `
        .
} finally {
    Pop-Location
}

Write-Host "Packaged PhishNet AI"
Write-Host "  Archive : $tarPath"
Write-Host "  Manifest: $appDir\app.manifest"
Write-Host ""
Write-Host "Install locally:"
Write-Host "  splunk install app `"$tarPath`" -auth user:password"
Write-Host ""
Write-Host "Splunkbase:"
Write-Host "  Upload $tarName at https://splunkbase.splunk.com/submit (include app.manifest in package root)"
