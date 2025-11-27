# docker-clean.ps1 - remove container and image if present
$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir\..

Write-Host "Cleaning Docker artifacts..."
& docker rm -f zkp-framework-dev 2>$null || $null
& docker rmi zkp-framework 2>$null || $null
Write-Host "Docker clean completed."
