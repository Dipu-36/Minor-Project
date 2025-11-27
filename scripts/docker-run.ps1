# docker-run.ps1 - run docker container
$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir\..

Write-Host "Running Docker container on port 8443..."
& docker run --rm -p 8443:8443 --name zkp-framework-dev zkp-framework
