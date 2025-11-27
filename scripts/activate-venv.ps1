# activate-venv.ps1 — Activate venv and keep shell open
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location "$ScriptDir\.."

$VENV_ACT = ".\venv\Scripts\Activate.ps1"

if (-not (Test-Path $VENV_ACT)) {
    Write-Host "venv not found. Creating a new virtual environment..."
    python -m venv venv
}

Write-Host "Activating virtual environment..."
. $VENV_ACT

Write-Host "✔ venv activated."
Write-Host "To exit type: exit"
