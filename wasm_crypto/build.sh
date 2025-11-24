#!/usr/bin/env bash
set -euo pipefail

# Path variables (adjust if your tree differs)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WASM_OUT="$SCRIPT_DIR/crypto.wasm"
JS_OUT="$SCRIPT_DIR/crypto.js"

echo "Building wasm in: $SCRIPT_DIR"

# List of source files - include all ed25519_ref .c files you added
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

# Add wrapper sources (crypto.c, rand_bridge.c, etc.)
WRAPPER_SRCS=(
  "$SCRIPT_DIR/crypto.c"            # your top-level wasm wrapper functions
  "$SCRIPT_DIR/rand_bridge.c"       # contains EM_JS-based randombytes wrapper
  # if you have a separate sha512_standalone.c, include it, otherwise ed25519_ref/sha512.c covers it
)

# Join arrays into a single space-separated string
ALL_SRCS="${WRAPPER_SRCS[*]} ${ED_SRCS[*]}"

# EMCC flags
EMCC_FLAGS=(
  -O3                            # optimization
  -s WASM=1
  -s ALLOW_MEMORY_GROWTH=1       # optional but handy during development
  -s ENVIRONMENT='web,node'      # ensure works in both web worker and node
  -s NO_EXIT_RUNTIME=1
  -s MODULARIZE=1                # emit JS module factory function (clean)
  -s EXPORT_NAME="createCryptoModule" # name of factory
  -s EXPORTED_FUNCTIONS='["_compute_v_from_scalar","_initiate_login_from_scalar","_compute_response_from_state","_free_state","_malloc","_free"]'
  -s EXTRA_EXPORTED_RUNTIME_METHODS='["ccall","cwrap","allocate","UTF8ToString"]'
  --memory-init-file 0
)

# Build command (produces JS glue + wasm)
emcc ${ALL_SRCS} "${EMCC_FLAGS[@]}" -o "$JS_OUT"

echo "Build finished. Outputs:"
echo " - JS glue: $JS_OUT"
echo " - WASM binary: ${WASM_OUT}"
