# docker-build.ps1 - build docker image
$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir\..

Write-Host "Building Docker image..."
& docker build -t zkp-framework .
