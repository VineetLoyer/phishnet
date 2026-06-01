# PhishNet AI - Lower Splunk's minimum free disk space floor (DEV ONLY)
#
# Splunk halts search/indexing when free disk space drops below
# server.conf [diskUsage] minFreeSpace (default 5000 MB). On a tight dev
# laptop this freezes Splunk. This script lowers it to 1000 MB so dev can
# continue. NOT for production — low disk genuinely risks data loss.
#
# Run from an ELEVATED PowerShell prompt.
#
# Usage (elevated):
#   .\scripts\lower_disk_threshold.ps1
#   .\scripts\lower_disk_threshold.ps1 -MinFreeMB 800

param(
    [string]$SplunkHome = "C:\Program Files\Splunk",
    [int]$MinFreeMB = 1000
)

$ErrorActionPreference = "Stop"

$serverConf = Join-Path $SplunkHome "etc\system\local\server.conf"

Write-Host "Setting [diskUsage] minFreeSpace = $MinFreeMB MB in:"
Write-Host "  $serverConf"

# Read existing content (file may or may not exist)
$content = ""
if (Test-Path $serverConf) {
    $content = Get-Content $serverConf -Raw
}

if ($content -match "(?ms)^\[diskUsage\]") {
    if ($content -match "(?m)^\s*minFreeSpace\s*=") {
        # Replace existing minFreeSpace value
        $content = $content -replace "(?m)^\s*minFreeSpace\s*=.*$", "minFreeSpace = $MinFreeMB"
    } else {
        # Add minFreeSpace under existing [diskUsage] stanza
        $content = $content -replace "(?ms)(^\[diskUsage\]\s*\r?\n)", "`$1minFreeSpace = $MinFreeMB`r`n"
    }
} else {
    # Append a fresh [diskUsage] stanza
    if ($content -and -not $content.EndsWith("`n")) { $content += "`r`n" }
    $content += "`r`n[diskUsage]`r`nminFreeSpace = $MinFreeMB`r`n"
}

Set-Content -Path $serverConf -Value $content -Encoding ASCII
Write-Host "  Written."

$splunkExe = Join-Path $SplunkHome "bin\splunk.exe"
Write-Host "Restarting Splunk to apply..."
& $splunkExe restart

Write-Host "Done. Splunk minFreeSpace is now $MinFreeMB MB."
Write-Host "NOTE: This is a dev-only workaround. Free real disk space when you can."
