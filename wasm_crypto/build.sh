#!/usr/bin/env bash
set -e
# Build script for wasm_crypto module using Emscripten (emcc)

# Adjust this list to match the exact ed25519_ref source filenames in your repo.
ED_SOURCES="ed25519_ref/ed25519.c ed25519_ref/fe.c ed25519_ref/ge.c ed25519_ref/sc.c ed25519_ref/sha512.c"

OUTPUT_JS="crypto.js"
OUTPUT_WASM="crypto.wasm"

echo "Building WASM (crypto.js + crypto.wasm)..."

emcc -O3 \
  -s WASM=1 \
  -s MODULARIZE=1 -s EXPORT_ES6=1 \
  -s EXPORTED_FUNCTIONS="['_compute_v_from_scalar','_initiate_login_from_scalar','_compute_response_from_state','_free_state','_malloc','_free']" \
  -s EXPORTED_RUNTIME_METHODS="['ccall','cwrap','UTF8ToString','getValue','setValue']" \
  -o ${OUTPUT_JS} \
  crypto.c ${ED_SOURCES}

# wasm-opt optional (if binaryen/wasm-opt available)
if command -v wasm-opt >/dev/null 

