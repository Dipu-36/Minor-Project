# activate-venv.ps1 — Activate venv and KEEP the shell open

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location "$ScriptDir\.."

$VENV_ACT = ".\venv\Scripts\Activate.ps1"

if (-not (Test-Path $VENV_ACT)) {
    Write-Host "Virtual environment not found. Creating it..."
    python -m venv venv
}

Write-Host "Activating venv..."
. $VENV_ACT

Write-Host "✔ Virtual environment activated."
Write-Host "You can now run Python inside this shell."
Write-Host ""
Write-Host "To exit: type 'exit'"
