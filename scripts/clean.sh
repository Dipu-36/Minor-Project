#!/bin/bash
# clean.sh - create virtualenv, install packages, and ACTIVATE it
# NOTE: This script mirrors clean.ps1 which appears to be a setup script.

set -e
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.."

VENV_DIR="venv"
VENV_ACT="$VENV_DIR/bin/activate"
PIP="$VENV_DIR/bin/pip"

echo "=== Setting up Virtual Environment ==="

# Create if needed
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
else
    echo "Virtual environment already exists."
fi

# Verify creation
if [ ! -f "$PIP" ]; then
    echo "pip not found in $VENV_DIR — virtualenv creation failed!"
    exit 1
fi

echo "Upgrading pip..."
"$PIP" install --upgrade pip

echo "Installing required packages..."
"$PIP" install flask pynacl argon2-cffi

# Activate
if [ -f "$VENV_ACT" ]; then
    echo "Activating virtual environment..."
    if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
        echo "WARNING: You are running this script. It should be sourced to activate the venv."
        echo "Spawning a new shell with venv activated..."
        source "$VENV_ACT"
        exec "$SHELL"
    else
        source "$VENV_ACT"
        echo "✔ venv activated"
    fi
else
    echo "Could not find activate script — activation failed!"
    exit 1
fi

echo "=== venv setup & activation complete! ==="
