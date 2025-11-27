#!/bin/bash
# activate-venv.sh — Activate venv and KEEP the shell open

set -e
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.."

VENV_ACT="./venv/bin/activate"

if [ ! -f "$VENV_ACT" ]; then
    echo "Virtual environment not found. Creating it..."
    python3 -m venv venv
fi

echo "Activating venv..."
# We cannot "keep shell open" in the same way as PS1 if we just run this script.
# The user must source this script.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "WARNING: You are running this script. It should be sourced to activate the venv in your current shell."
    echo "Usage: source ./scripts/activate-venv.sh"
    # We can try to spawn a new shell with venv activated
    source "$VENV_ACT"
    echo "✔ Virtual environment activated."
    echo "Spawning a new shell with venv activated..."
    exec "$SHELL"
else
    source "$VENV_ACT"
    echo "✔ Virtual environment activated."
fi
