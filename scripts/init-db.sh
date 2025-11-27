#!/bin/bash
# init-db.sh - initialize local sqlite DB using venv python

set -e
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.."

VENV_PY="./venv/bin/python"

if [ ! -f "$VENV_PY" ]; then
    echo "Virtualenv not found. Creating..."
    ./scripts/venv.sh
fi

echo "Initializing local database..."
"$VENV_PY" -c "from zkp_server.storage import init_db; init_db(); print('DB initialized ✔')"
