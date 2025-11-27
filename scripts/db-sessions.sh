#!/bin/bash
# db-sessions.sh - show sessions table

set -e
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.."

DB="./zkp_server/zkp_auth.db"

if command -v sqlite3 &> /dev/null; then
    sqlite3 "$DB" "SELECT session_id, user_id, used, datetime(expires_at, 'unixepoch') FROM sessions;"
else
    VENV_PY="./venv/bin/python"
    "$VENV_PY" - <<PY
import sqlite3,sys
db='$DB'
con=sqlite3.connect(db)
for r in con.execute("SELECT session_id, user_id, used, datetime(expires_at, 'unixepoch') FROM sessions;"): print(r)
con.close()
PY
fi
