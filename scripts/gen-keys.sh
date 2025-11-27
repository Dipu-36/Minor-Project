#!/bin/bash
# gen-keys.sh - run the sign_wasm.sh script

set -e
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.."

SIGN_SCRIPT="./scripts/sign_wasm.sh"

if [ ! -f "$SIGN_SCRIPT" ]; then
    echo "sign_wasm.sh not found in scripts/."
    exit 1
fi

echo "Running sign_wasm.sh..."
chmod +x "$SIGN_SCRIPT"

# Check if WASM file exists before trying to sign
WASM_FILE="./wasm_crypto/crypto.wasm"
if [ ! -f "$WASM_FILE" ]; then
    echo "WARNING: WASM file not found ($WASM_FILE). Skipping key generation/signing."
    exit 0
fi

"$SIGN_SCRIPT"
