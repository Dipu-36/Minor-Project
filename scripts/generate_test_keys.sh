#!/bin/bash

# Generate test keys for development
# Usage: ./generate_test_keys.sh [key_size]

set -e

KEY_SIZE="${1:-2048}"
PRIVATE_KEY="private_key.pem"
PUBLIC_KEY="verify_wasm_public_key.pem"

echo "Generating test RSA key pair..."
echo "Key size: $KEY_SIZE bits"

# Generate private key
openssl genrsa -out "$PRIVATE_KEY" "$KEY_SIZE"

# Generate public key
openssl rsa -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY"

# Display key information
echo ""
echo "Generated keys:"
echo "Private key: $PRIVATE_KEY"
echo "Public key:  $PUBLIC_KEY"
echo ""

# Show key details
echo "Private key details:"
openssl rsa -in "$PRIVATE_KEY" -noout -text | head -10

echo ""
echo "Public key details:"
openssl rsa -in "$PUBLIC_KEY" -pubin -noout -text

# Set proper permissions
chmod 600 "$PRIVATE_KEY"
chmod 644 "$PUBLIC_KEY"

echo ""
echo "✓ Key generation complete"
echo "🔒 Private key permissions set to 600"