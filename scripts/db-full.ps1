# db-full.ps1 - show both users and sessions
$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir\..

powershell -ExecutionPolicy Bypass -File .\db-users.ps1
Write-Host ""
powershell -ExecutionPolicy Bypass -File .\db-sessions.ps1
