# PhishNet AI - Deploy app to local Splunk Enterprise (Windows)
#
# Splunk is installed at "C:\Program Files\Splunk" which requires admin rights
# to write into etc\apps. Run this script from an ELEVATED PowerShell prompt.
#
# It copies the phishnet_ai app into Splunk's apps directory and restarts Splunk.
#
# Usage (elevated):
#   .\scripts\deploy_to_splunk.ps1
#   .\scripts\deploy_to_splunk.ps1 -NoRestart

param(
    [string]$SplunkHome = "C:\Program Files\Splunk",
    [switch]$NoRestart
)

$ErrorActionPreference = "Stop"

# Resolve repo root (parent of this script's folder)
$repoRoot = Split-Path -Parent $PSScriptRoot
$appSource = Join-Path $repoRoot "phishnet_ai"
$appDest   = Join-Path $SplunkHome "etc\apps\phishnet_ai"

if (-not (Test-Path $appSource)) {
    throw "App source not found at $appSource"
}

Write-Host "Deploying PhishNet AI app..."
Write-Host "  From: $appSource"
Write-Host "  To  : $appDest"

# Copy app (excluding dev-only artifacts)
if (Test-Path $appDest) {
    Write-Host "  Removing existing deployment..."
    Remove-Item -Recurse -Force $appDest
}
Copy-Item -Recurse -Force $appSource $appDest

# Remove any __pycache__ that snuck in
Get-ChildItem -Path $appDest -Recurse -Directory -Filter "__pycache__" |
    ForEach-Object { Remove-Item -Recurse -Force $_.FullName }

Write-Host "  Copy complete."

if (-not $NoRestart) {
    $splunkExe = Join-Path $SplunkHome "bin\splunk.exe"
    Write-Host "  Restarting Splunk..."
    & $splunkExe restart
} else {
    Write-Host "  Skipped restart (-NoRestart). Restart Splunk manually to load changes."
}

Write-Host "Done. Open http://localhost:8000 and look for 'PhishNet AI' in the app list."
