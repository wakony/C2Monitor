<#
.SYNOPSIS
    C2 Monitor - Uninstaller
.DESCRIPTION
    Completely removes C2 Monitor from the system.
    Run as Administrator:
      powershell -ExecutionPolicy Bypass -File Uninstall-C2Monitor.ps1
#>

#Requires -RunAsAdministrator
$ErrorActionPreference = "SilentlyContinue"

Write-Host ""
Write-Host "Uninstalling C2 Monitor..." -ForegroundColor Yellow
Write-Host ""

# Stop notifier processes
Write-Host "  Stopping notifier processes..."
Get-Process powershell | Where-Object {$_.CommandLine -like "*C2AlertNotifier*"} | Stop-Process -Force
Get-Process wscript | Where-Object {$_.CommandLine -like "*LaunchNotifier*"} | Stop-Process -Force

# Remove scheduled tasks
Write-Host "  Removing scheduled tasks..."
schtasks.exe /Delete /TN "C2Monitor-DeepScan" /F 2>&1 | Out-Null
schtasks.exe /Delete /TN "C2Monitor-QuickWatch" /F 2>&1 | Out-Null

# Remove auto-start registry entry
Write-Host "  Removing auto-start entry..."
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "C2AlertNotifier" -ErrorAction SilentlyContinue

# Uninstall Sysmon
Write-Host "  Uninstalling Sysmon..."
if (Test-Path "C:\Windows\Sysmon64.exe") {
    & "C:\Windows\Sysmon64.exe" -u force 2>&1 | Out-Null
} elseif (Test-Path "$env:TEMP\C2Monitor-Sysmon\Sysmon64.exe") {
    & "$env:TEMP\C2Monitor-Sysmon\Sysmon64.exe" -u force 2>&1 | Out-Null
}

# Remove event log source
Write-Host "  Removing event log source..."
Remove-EventLog -Source "C2Monitor" -ErrorAction SilentlyContinue

# Ask about log preservation
$keepLogs = Read-Host "  Keep alert logs for review? (y/n)"
if ($keepLogs -eq "y") {
    $archiveDir = Join-Path $env:USERPROFILE "C2Monitor-Logs-Archive"
    New-Item -Path $archiveDir -ItemType Directory -Force | Out-Null
    Copy-Item -Path "C:\ProgramData\C2Monitor\alerts*.log" -Destination $archiveDir -ErrorAction SilentlyContinue
    Copy-Item -Path "C:\ProgramData\C2Monitor\connection-history.json" -Destination $archiveDir -ErrorAction SilentlyContinue
    Write-Host "  Logs saved to: $archiveDir" -ForegroundColor Cyan
}

# Remove install directory
Write-Host "  Removing install directory..."
Remove-Item -Path "C:\ProgramData\C2Monitor" -Recurse -Force -ErrorAction SilentlyContinue

# Clean up temp files
Remove-Item -Path "$env:TEMP\C2Monitor-Sysmon" -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "C2 Monitor has been uninstalled." -ForegroundColor Green
Write-Host ""
