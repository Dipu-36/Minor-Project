#!/bin/bash
# setup-all.sh - convenience wrapper to run the full setup

set -e
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.."

echo "Running full setup: venv, gen-tls, init-db, build-wasm, gen-keys"
./scripts/venv.sh
./scripts/gen-tls.sh
./scripts/init-db.sh
./scripts/build-wasm.sh
./scripts/gen-keys.sh

echo "Full environment setup complete!"
