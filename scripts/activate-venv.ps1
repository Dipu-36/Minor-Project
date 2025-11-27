# activate-venv.ps1 â€” Activate venv (ASCII-safe)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location "$ScriptDir\.."

$VENV_ACT = ".\venv\Scripts\Activate.ps1"

if (-not (Test-Path $VENV_ACT)) {
    Write-Host "Virtual environment not found. Please run: make -f Makefile.win venv"
    exit 1
}

Write-Host "Activating virtual environment..."
. $VENV_ACT

Write-Host "venv activated."
Write-Host "To exit type: exit"
