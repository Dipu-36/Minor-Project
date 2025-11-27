#!/bin/bash

set -e

echo "[BUILD] Cleaning old build..."
rm -f crypto.wasm crypto.js

echo "[BUILD] Compiling WebAssembly..."

emcc \
  crypto.c \
  state.c \
  rand_bridge.c \
  ed25519_ref/fe.c \
  ed25519_ref/ge.c \
  ed25519_ref/sc.c \
  ed25519_ref/sha512.c \
  \
  -O3 \
  -s WASM=1 \
  -s MODULARIZE=1 \
  -s EXPORT_NAME="createCryptoModule" \
  -s EXPORTED_FUNCTIONS="['_compute_v_from_scalar','_initiate_login_from_scalar','_compute_response_from_state','_malloc','_free']" \
  -s EXPORTED_RUNTIME_METHODS="['HEAPU8']" \
  -o crypto.js

echo "[BUILD] Build complete: crypto.js + crypto.wasm"
