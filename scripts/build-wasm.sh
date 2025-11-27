#!/bin/bash
# build-wasm.sh - build wasm

set -e
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.."

WASM_DIR="wasm_crypto"
if [ ! -d "$WASM_DIR" ]; then
    echo "Directory wasm_crypto not found."
    exit 1
fi

echo "Building WebAssembly module..."

if ! command -v emcc &> /dev/null; then
    echo "WARNING: 'emcc' (Emscripten) not found. Skipping WASM build."
    echo "       The application may not function correctly without the WASM module."
    exit 0
fi

cd wasm_crypto && ./build.sh
