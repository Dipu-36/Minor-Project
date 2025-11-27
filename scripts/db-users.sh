#!/bin/bash
# db-users.sh - show users table

set -e
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.."

DB="./zkp_server/zkp_auth.db"

if command -v sqlite3 &> /dev/null; then
    sqlite3 "$DB" "SELECT user_id, salt, verifier FROM users;"
else
    VENV_PY="./venv/bin/python"
    "$VENV_PY" - <<PY
import sqlite3,sys
db='$DB'
con=sqlite3.connect(db)
for r in con.execute("SELECT user_id, salt, verifier FROM users;"): print(r)
con.close()
PY
fi
