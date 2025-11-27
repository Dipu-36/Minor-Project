# db-users.ps1 - show users table
$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir\..

# Prefer sqlite3 CLI if available
$sqlite = Get-Command sqlite3 -ErrorAction SilentlyContinue
if ($sqlite) {
    & sqlite3 ".\zkp_server\zkp_auth.db" "SELECT user_id, salt, verifier FROM users;"
} else {
    # Fallback: use venv python to query
    $VENV_PY = Join-Path "venv" "Scripts\python.exe"
    & $VENV_PY - <<'PY'
import sqlite3,sys
db='./zkp_server/zkp_auth.db'
con=sqlite3.connect(db)
for r in con.execute("SELECT user_id, salt, verifier FROM users;"): print(r)
con.close()
PY
}
