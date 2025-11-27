# clean-venv.ps1 — remove ALL virtual environment data safely

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location "$ScriptDir\.."

$VENV_DIR = "venv"

Write-Host "=== Cleaning Python Virtual Environment ==="

# Delete venv directory completely
if (Test-Path $VENV_DIR) {
    Write-Host "Removing virtual environment folder..."
    Remove-Item -Recurse -Force $VENV_DIR
} else {
    Write-Host "No venv directory found — nothing to delete."
}

# Delete Python caches
Write-Host "Removing __pycache__ directories..."
Get-ChildItem -Recurse -Directory "__pycache__" -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

# Optional: remove build artifacts
Write-Host "Cleaning WASM cache files..."
Get-ChildItem -Path "wasm_crypto" -Include *.wasm,*.js,*.sig -File -ErrorAction SilentlyContinue | Remove-Item -Force

Write-Host "=== Virtual environment fully removed ==="
