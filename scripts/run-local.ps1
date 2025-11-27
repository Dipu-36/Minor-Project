# run-local.ps1 - run the Python HTTPS server via venv python
$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir\..

$VENV_PY = Join-Path "venv" "Scripts\python.exe"
if (-not (Test-Path $VENV_PY)) {
    Write-Host "Virtualenv not found. Running venv creation first..."
    powershell -ExecutionPolicy Bypass -File .\venv.ps1
}

Write-Host "Running local HTTPS server..."
& $VENV_PY -m zkp_server.server
