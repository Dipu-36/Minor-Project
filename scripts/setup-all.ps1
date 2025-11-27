# setup-all.ps1 - convenience wrapper to run the full setup
$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir\..

Write-Host "Running full setup: venv, gen-tls, init-db, build-wasm, gen-keys"
powershell -ExecutionPolicy Bypass -File .\venv.ps1
powershell -ExecutionPolicy Bypass -File .\gen-tls.ps1
powershell -ExecutionPolicy Bypass -File .\init-db.ps1
powershell -ExecutionPolicy Bypass -File .\build-wasm.ps1
powershell -ExecutionPolicy Bypass -File .\gen-keys.ps1

Write-Host "Full environment setup complete!"
