# reset-db.ps1 - remove DB and re-init
$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir\..

$db = ".\zkp_server\zkp_auth.db"
if (Test-Path $db) {
    Remove-Item $db -Force
    Write-Host "Removed existing DB."
} else {
    Write-Host "DB not present; creating new DB."
}

$VENV_PY = Join-Path "venv" "Scripts\python.exe"
& $VENV_PY -c "from zkp_server.storage import init_db; init_db(); print('DB initialized ✔')"
