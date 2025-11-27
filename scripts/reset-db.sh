#!/bin/bash
# reset-db.sh - remove DB and re-init

set -e
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.."

DB="./zkp_server/zkp_auth.db"
if [ -f "$DB" ]; then
    rm "$DB"
    echo "Removed existing DB."
else
    echo "DB not present; creating new DB."
fi

VENV_PY="./venv/bin/python"
"$VENV_PY" -c "from zkp_server.storage import init_db; init_db(); print('DB initialized ✔')"
