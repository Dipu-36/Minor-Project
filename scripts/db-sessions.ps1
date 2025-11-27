# db-sessions.ps1 - show sessions table
$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir\..

$sqlite = Get-Command sqlite3 -ErrorAction SilentlyContinue
if ($sqlite) {
    & sqlite3 ".\zkp_server\zkp_auth.db" "SELECT session_id, user_id, used, datetime(expires_at, 'unixepoch') FROM sessions;"
} else {
    $VENV_PY = Join-Path "venv" "Scripts\python.exe"
    & $VENV_PY - <<'PY'
import sqlite3,sys
db='./zkp_server/zkp_auth.db'
con=sqlite3.connect(db)
for r in con.execute("SELECT session_id, user_id, used, datetime(expires_at, 'unixepoch') FROM sessions;"): print(r)
con.close()
PY
}
  