# init-db.ps1 - initialize local sqlite DB using venv python
$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir\..

$VENV_PY = Join-Path "venv" "Scripts\python.exe"

if (-not (Test-Path $VENV_PY)) {
    Write-Host "Virtualenv not found. Creating..."
    powershell -ExecutionPolicy Bypass -File .\venv.ps1
}

Write-Host "Initializing local database..."
& $VENV_PY -c "from zkp_server.storage import init_db; init_db(); print('DB initialized ✔')"
