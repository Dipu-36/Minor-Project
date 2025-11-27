#!/bin/bash
# venv.sh - create virtualenv and install required packages

set -e
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.."

VENV_DIR="venv"
REQ_PKGS="flask pynacl argon2-cffi"

if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment..."
    if ! python3 -m venv "$VENV_DIR"; then
        echo "Warning: venv creation reported failure (likely missing ensurepip)."
        if [ -f "$VENV_DIR/bin/python3" ]; then
            echo "Python binary exists. Attempting to install pip manually..."
            curl -sS https://bootstrap.pypa.io/get-pip.py -o get-pip.py
            "$VENV_DIR/bin/python3" get-pip.py
            rm get-pip.py
        else
            echo "Error: Failed to create venv and python binary is missing."
            exit 1
        fi
    fi
else
    echo "Virtual environment exists."
fi

PIP="$VENV_DIR/bin/pip"

if [ ! -f "$PIP" ]; then
    echo "pip not found in $VENV_DIR. Checking if we can repair..."
    if [ -f "$VENV_DIR/bin/python3" ]; then
        echo "Python binary exists. Attempting to install pip manually..."
        curl -sS https://bootstrap.pypa.io/get-pip.py -o get-pip.py
        "$VENV_DIR/bin/python3" get-pip.py
        rm get-pip.py
    fi
fi

if [ ! -f "$PIP" ]; then
    echo "pip still not found in $VENV_DIR. Setup failed."
    exit 1
fi

echo "Upgrading pip..."
"$PIP" install --upgrade pip

echo "Installing required packages..."
"$PIP" install $REQ_PKGS
echo "venv ready."
