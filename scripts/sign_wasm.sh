#!/bin/bash

# Script to sign the WASM binary for integrity verification
# Usage: ./sign_wasm.sh [wasm_file] [private_key]

set -e

WASM_FILE="${1:-../wasm_crypto/crypto.wasm}"
PRIVATE_KEY="${2:-../scripts/private_key.pem}"
SIGNATURE_FILE="${WASM_FILE}.sig"
PUBLIC_KEY_FILE="../scripts/verify_wasm_public_key.pem"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}ZKP WASM Signing Script${NC}"
echo "=========================="

# Check if WASM file exists
if [ ! -f "$WASM_FILE" ]; then
    echo -e "${RED}Error: WASM file not found: $WASM_FILE${NC}"
    echo "Please build the WASM first: cd wasm_crypto && ./build.sh"
    exit 1
fi

# Generate key pair if it doesn't exist
if [ ! -f "$PRIVATE_KEY" ]; then
    echo -e "${YELLOW}Generating new RSA key pair...${NC}"
    mkdir -p "$(dirname "$PRIVATE_KEY")"
    openssl genrsa -out "$PRIVATE_KEY" 2048
    openssl rsa -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY_FILE"
    echo -e "${GREEN}Generated new key pair:${NC}"
    echo "  Private key: $PRIVATE_KEY"
    echo "  Public key:  $PUBLIC_KEY_FILE"
fi

# Sign the WASM file
echo -e "${YELLOW}Signing WASM file: $WASM_FILE${NC}"
openssl dgst -sha256 -sign "$PRIVATE_KEY" -out "$SIGNATURE_FILE" "$WASM_FILE"

# Verify the signature
echo -e "${YELLOW}Verifying signature...${NC}"
openssl dgst -sha256 -verify "$PUBLIC_KEY_FILE" -signature "$SIGNATURE_FILE" "$WASM_FILE"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Signature created and verified successfully${NC}"
    echo "Signature file: $SIGNATURE_FILE"
    
    # Display file info
    WASM_SIZE=$(stat -f%z "$WASM_FILE" 2>/dev/null || stat -c%s "$WASM_FILE")
    SIG_SIZE=$(stat -f%z "$SIGNATURE_FILE" 2>/dev/null || stat -c%s "$SIGNATURE_FILE")
    echo "WASM size: $WASM_SIZE bytes"
    echo "Signature size: $SIG_SIZE bytes"
else
    echo -e "${RED}✗ Signature verification failed${NC}"
    exit 1
fi

# Create a verification test script
cat > "$(dirname "$WASM_FILE")/verify_wasm.html" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>WASM Signature Verification</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .success { color: green; }
        .error { color: red; }
        .info { background: #f0f0f0; padding: 10px; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>WASM Signature Verification Test</h1>
    <div id="status">Loading...</div>
    <div id="info" class="info" style="display: none;"></div>
    
    <script>
        async function verifyWasmSignature() {
            const status = document.getElementById('status');
            const info = document.getElementById('info');
            
            try {
                // Load WASM and signature
                const [wasmResponse, sigResponse, keyResponse] = await Promise.all([
                    fetch('crypto.wasm'),
                    fetch('crypto.wasm.sig'),
                    fetch('../scripts/verify_wasm_public_key.pem')
                ]);
                
                if (!wasmResponse.ok || !sigResponse.ok || !keyResponse.ok) {
                    throw new Error('Failed to load required files');
                }
                
                const wasmBuffer = await wasmResponse.arrayBuffer();
                const signature = await sigResponse.arrayBuffer();
                const pemText = await keyResponse.text();
                
                // Convert PEM to ArrayBuffer
                const pemContents = pemText
                    .replace(/-----BEGIN PUBLIC KEY-----/g, '')
                    .replace(/-----END PUBLIC KEY-----/g, '')
                    .replace(/\s/g, '');
                
                const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));
                
                // Import public key
                const publicKey = await crypto.subtle.importKey(
                    'spki',
                    binaryDer,
                    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
                    false,
                    ['verify']
                );
                
                // Compute WASM hash
                const wasmHash = await crypto.subtle.digest('SHA-256', wasmBuffer);
                
                // Verify signature
                const isValid = await crypto.subtle.verify(
                    'RSASSA-PKCS1-v1_5',
                    publicKey,
                    signature,
                    wasmHash
                );
                
                if (isValid) {
                    status.innerHTML = '<span class="success">✓ WASM signature verification PASSED</span>';
                    info.style.display = 'block';
                    info.innerHTML = `
                        <strong>Verification Details:</strong><br>
                        • WASM file: crypto.wasm (${wasmBuffer.byteLength} bytes)<br>
                        • Signature: crypto.wasm.sig (${signature.byteLength} bytes)<br>
                        • Hash algorithm: SHA-256<br>
                        • Signature algorithm: RSASSA-PKCS1-v1_5<br>
                        • Timestamp: ${new Date().toLocaleString()}
                    `;
                } else {
                    status.innerHTML = '<span class="error">✗ WASM signature verification FAILED</span>';
                }
                
            } catch (error) {
                status.innerHTML = `<span class="error">✗ Error: ${error.message}</span>`;
            }
        }
        
        verifyWasmSignature();
    </script>
</body>
</html>
EOF

echo -e "\n${GREEN}Verification test page created: wasm_crypto/verify_wasm.html${NC}"
echo -e "${YELLOW}To test signature verification, open wasm_crypto/verify_wasm.html in a browser${NC}"