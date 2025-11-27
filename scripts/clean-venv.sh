#!/bin/bash
# clean-venv.sh — remove ALL virtual environment data safely

set -e
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.."

VENV_DIR="venv"

echo "=== Cleaning Python Virtual Environment ==="

# Delete venv directory completely
if [ -d "$VENV_DIR" ]; then
    echo "Removing virtual environment folder..."
    rm -rf "$VENV_DIR"
else
    echo "No venv directory found — nothing to delete."
fi

# Delete Python caches
echo "Removing __pycache__ directories..."
find . -type d -name "__pycache__" -exec rm -rf {} +

# Optional: remove build artifacts
echo "Cleaning WASM cache files..."
find wasm_crypto -name "*.wasm" -o -name "*.js" -o -name "*.sig" -delete 2>/dev/null || true

echo "=== Virtual environment fully removed ==="
