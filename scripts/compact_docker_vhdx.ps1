# PhishNet AI - Compact the Docker/WSL2 virtual disk to reclaim freed space
#
# Docker's docker_data.vhdx is dynamically EXPANDING but never auto-SHRINKS.
# After `docker system prune` frees space inside it, the .vhdx file on Windows
# stays large. This script compacts it via diskpart, returning the freed space
# to your C: drive. It only removes EMPTY space — no Docker data is lost.
#
# Safe to run when Docker Desktop is NOT running.
# Run from an ELEVATED PowerShell prompt.
#
# Usage (elevated):
#   .\scripts\compact_docker_vhdx.ps1

param(
    [string]$VhdxPath = "$env:LOCALAPPDATA\Docker\wsl\disk\docker_data.vhdx"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $VhdxPath)) {
    throw "vhdx not found at $VhdxPath. Adjust -VhdxPath if Docker stores it elsewhere."
}

$before = [math]::Round((Get-Item $VhdxPath).Length/1GB, 2)
$freeBefore = [math]::Round((Get-PSDrive C).Free/1GB, 2)
Write-Host "vhdx size before : $before GB"
Write-Host "C: free before   : $freeBefore GB"

Write-Host "Shutting down WSL (closes Docker's WSL distros)..."
wsl --shutdown
Start-Sleep -Seconds 5

# Build a diskpart script. 'compact vdisk' reclaims empty space.
$dp = @"
select vdisk file="$VhdxPath"
attach vdisk readonly
compact vdisk
detach vdisk
exit
"@

$tmp = Join-Path $env:TEMP "phishnet_compact.txt"
Set-Content -Path $tmp -Value $dp -Encoding ASCII

Write-Host "Running diskpart compact (this can take a few minutes)..."
diskpart /s $tmp

Remove-Item $tmp -Force -ErrorAction SilentlyContinue

$after = [math]::Round((Get-Item $VhdxPath).Length/1GB, 2)
$freeAfter = [math]::Round((Get-PSDrive C).Free/1GB, 2)
Write-Host ""
Write-Host "vhdx size after  : $after GB   (was $before GB)"
Write-Host "C: free after    : $freeAfter GB   (was $freeBefore GB)"
Write-Host ("Reclaimed        : {0:N2} GB" -f ($freeAfter - $freeBefore))
