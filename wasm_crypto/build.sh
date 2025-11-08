#!/bin/bash
set -e

echo "Building ZKP WASM crypto core..."

# Build with Emscripten - include all necessary files
emcc -O3 -s WASM=1 \
    -s EXPORTED_FUNCTIONS="['_compute_v_from_password', '_initiate_login_from_password', '_compute_response_from_state', '_free_state', '_malloc', '_free']" \
    -s EXPORTED_RUNTIME_METHODS="['ccall', 'cwrap']" \
    -s MODULARIZE=1 \
    -s ENVIRONMENT=web,node \
    -s SINGLE_FILE=0 \
    -s ALLOW_MEMORY_GROWTH=1 \
    -I. \
    -o crypto.js \
    crypto.c state.c ed25519_ref/ed25519.c

echo "Build complete: crypto.wasm and crypto.js"