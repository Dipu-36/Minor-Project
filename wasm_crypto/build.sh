#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$SCRIPT_DIR"
JS_OUT="$OUT_DIR/crypto.js"

ED_SRCS=(
  "$SCRIPT_DIR/ed25519_ref/fe.c"
  "$SCRIPT_DIR/ed25519_ref/ge.c"
  "$SCRIPT_DIR/ed25519_ref/sc.c"
  "$SCRIPT_DIR/ed25519_ref/sha512.c"
  "$SCRIPT_DIR/ed25519_ref/sign.c"
  "$SCRIPT_DIR/ed25519_ref/verify.c"
  "$SCRIPT_DIR/ed25519_ref/keypair.c"
  "$SCRIPT_DIR/ed25519_ref/key_exchange.c"
  "$SCRIPT_DIR/ed25519_ref/add_scalar.c"
)

WRAPPER_SRCS=(
  "$SCRIPT_DIR/crypto.c"
  "$SCRIPT_DIR/rand_bridge.c"
)
ALL_SRCS=("${WRAPPER_SRCS[@]}" "${ED_SRCS[@]}")

emcc "${ALL_SRCS[@]}" \
  -O3 \
  -s WASM=1 \
  -s ALLOW_MEMORY_GROWTH=1 \
  -s MODULARIZE=1 \
  -s EXPORT_NAME=createCryptoModule \
  -s EXPORTED_FUNCTIONS="['_compute_v_from_scalar','_initiate_login_from_scalar','_compute_response_from_state','_free_state','_malloc','_free']" \
  -s EXPORTED_RUNTIME_METHODS='["cwrap","ccall","UTF8ToString"]' \
  -o "$JS_OUT"

echo "Build complete: $JS_OUT and crypto.wasm"
