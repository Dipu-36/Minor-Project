#!/usr/bin/env bash
set -e

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

WASM="$repo_root/wasm_crypto/crypto.wasm"
SIG="$repo_root/wasm_crypto/crypto.wasm.sig"
PRIV="$script_dir/private_key.pem"
PUB="$script_dir/public_key.pem"

# generate keys if missing
if [ ! -f "$PRIV" ]; then
  echo "Generating RSA keypair..."
  openssl genpkey -algorithm RSA -out "$PRIV" -pkeyopt rsa_keygen_bits:2048
  openssl rsa -in "$PRIV" -pubout -out "$PUB"
fi

# Create sha256 digest
openssl dgst -sha256 -binary -out /tmp/wasm.sha256 "$WASM"

# Sign with RSA-PSS (saltLength=32)
openssl pkeyutl -sign \
  -inkey "$PRIV" \
  -in /tmp/wasm.sha256 \
  -out "$SIG" \
  -pkeyopt digest:sha256 \
  -pkeyopt rsa_padding_mode:pss \
  -pkeyopt rsa_pss_saltlen:32

echo "WASM signed -> $SIG"
