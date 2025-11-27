#!/bin/bash
# run-local.sh - run the Python HTTPS server via venv python

set -e
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.."

VENV_PY="./venv/bin/python"
if [ ! -f "$VENV_PY" ]; then
    echo "Virtualenv not found. Running venv creation first..."
    ./scripts/venv.sh
fi

echo "Running local HTTPS server..."
"$VENV_PY" -m zkp_server.server
