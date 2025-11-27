# venv.ps1 - create virtualenv, install packages, and ACTIVATE it
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location "$ScriptDir\.."

$VENV_DIR = "venv"
$VENV_ACT = Join-Path $VENV_DIR "Scripts\Activate.ps1"
$PIP      = Join-Path $VENV_DIR "Scripts\pip.exe"

Write-Host "=== Setting up Virtual Environment ==="

# Create if needed
if (-not (Test-Path $VENV_DIR)) {
    Write-Host "Creating virtual environment..."
    python -m venv $VENV_DIR
} else {
    Write-Host "Virtual environment already exists."
}

# Verify creation
if (-not (Test-Path $PIP)) {
    Write-Error "pip not found in $VENV_DIR — virtualenv creation failed!"
    exit 1
}

Write-Host "Upgrading pip..."
& $PIP install --upgrade pip

Write-Host "Installing required packages..."
& $PIP install flask pynacl argon2-cffi

# 🔥 **ACTIVATE THE VENV NOW**
if (Test-Path $VENV_ACT) {
    Write-Host "Activating virtual environment..."
    . $VENV_ACT
    Write-Host "✔ venv activated (PowerShell session updated)"
} else {
    Write-Error "Could not find Activate.ps1 — activation failed!"
    exit 1
}

Write-Host "=== venv setup & activation complete! ==="
