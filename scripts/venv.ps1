# venv.ps1 - create virtualenv and install required packages
$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir\..

$VENV_DIR = "venv"
$REQ_PKGS = @("flask","pynacl","argon2-cffi")

if (-not (Test-Path $VENV_DIR)) {
    Write-Host "Creating virtual environment..."
    python -m venv $VENV_DIR
} else {
    Write-Host "Virtual environment exists."
}

$PIP = Join-Path $VENV_DIR "Scripts\pip.exe"

if (-not (Test-Path $PIP)) {
    Write-Error "pip not found in $VENV_DIR. Did venv creation fail?"
    exit 1
}

Write-Host "Upgrading pip..."
& $PIP install --upgrade pip

Write-Host "Installing required packages..."
& $PIP install $REQ_PKGS
Write-Host "venv ready."
