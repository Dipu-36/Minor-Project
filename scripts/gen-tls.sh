#!/bin/bash
# gen-tls.sh - generate TLS cert (using openssl)

set -e
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.."

CERT="./zkp_server/server.crt"
KEY="./zkp_server/server.key"

if [ -f "$CERT" ] && [ -f "$KEY" ]; then
    echo "✔ TLS cert already exists."
    exit 0
fi

# Check for openssl
if ! command -v openssl &> /dev/null; then
    echo "OpenSSL not found on PATH. Please install OpenSSL."
    exit 1
fi

echo "Generating self-signed TLS certificate..."
openssl req -x509 -nodes -newkey rsa:2048 -keyout "$KEY" -out "$CERT" -days 365 -subj "/CN=localhost"
echo "✔ TLS Certificates ready at zkp_server/"
