#!/bin/bash

# Development environment setup script
# Usage: ./setup_dev_env.sh

set -e

echo "Setting up ZKP Authentication Framework development environment..."
echo "================================================================"

# Check for required tools
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo "❌ $1 is not installed. Please install it first."
        return 1
    else
        echo "✓ $1 found: $(which $1)"
        return 0
    fi
}

echo ""
echo "Checking required tools..."

REQUIRED_TOOLS=("python3" "emcc" "openssl" "node" "make")

for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! check_tool "$tool"; then
        MISSING_TOOLS+=("$tool")
    fi
done

if [ ${#MISSING_TOOLS[@]} -ne 0 ]; then
    echo ""
    echo "The following tools are missing: ${MISSING_TOOLS[*]}"
    echo "Please install them before continuing."
    exit 1
fi

echo ""
echo "All required tools are available."

# Create necessary directories
echo ""
echo "Creating directory structure..."
mkdir -p ../wasm_crypto/ed25519_ref
mkdir -p ../tests/test_data
mkdir -p ../frontend/lib

# Generate development keys if they don't exist
echo ""
echo "Setting up cryptographic keys..."
if [ ! -f "private_key.pem" ]; then
    ./generate_test_keys.sh
else
    echo "✓ Existing keys found"
fi

# Build WASM crypto core
echo ""
echo "Building WASM crypto core..."
cd ../wasm_crypto
if [ -f "build.sh" ]; then
    ./build.sh
else
    echo "❌ build.sh not found in wasm_crypto directory"
    exit 1
fi

# Sign the WASM binary
echo ""
echo "Signing WASM binary..."
cd ../scripts
./sign_wasm.sh

# Create a test configuration
echo ""
echo "Creating test configuration..."
cat > ../tests/test_config.py << 'EOF'
# Test configuration
import os

TEST_DB_PATH = "test_zkp_auth.db"
TEST_HOST = "127.0.0.1"
TEST_PORT = 8444  # Different port for tests
TEST_USER_ID = "testuser@example.com"
TEST_PASSWORD = "testpassword123"

# Ed25519 test vectors (for reference)
TEST_SCALAR = "4866741023562595627518202893235797367275721234296765159652624010143563065360"
TEST_POINT = "15112221349535400772501151409588531511454012693041857206046113283949847762202"

def cleanup_test_db():
    """Remove test database file"""
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)
EOF

# Create a simple test runner
echo ""
echo "Creating test runner..."
cat > ../tests/run_tests.sh << 'EOF'
#!/bin/bash

# Test runner script for ZKP Authentication Framework
# Usage: ./run_tests.sh [test_file]

set -e

cd "$(dirname "$0")"

TEST_FILE="${1:-}"

echo "Running ZKP Authentication Framework Tests"
echo "=========================================="

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

run_test() {
    local test_file="$1"
    echo -e "${YELLOW}Running $test_file...${NC}"
    if python3 -m pytest "$test_file" -v; then
        echo -e "${GREEN}✓ $test_file passed${NC}"
        return 0
    else
        echo -e "${RED}✗ $test_file failed${NC}"
        return 1
    fi
}

# Run specific test file or all tests
if [ -n "$TEST_FILE" ]; then
    run_test "$TEST_FILE"
else
    echo "Running all test suites..."
    echo ""
    
    # Run unit tests
    run_test "test_server.py"
    run_test "test_wasm_math.py"
    
    # Run integration tests
    run_test "integration_test.py"
    
    echo ""
    echo -e "${GREEN}All test suites completed${NC}"
fi
EOF

chmod +x ../tests/run_tests.sh

echo ""
echo "Development environment setup complete! 🎉"
echo ""
echo "Next steps:"
echo "1. Review the generated keys in scripts/"
echo "2. Check the WASM build in wasm_crypto/"
echo "3. Run tests: cd tests && ./run_tests.sh"
echo "4. Start the server: cd zkp_server && python server.py"
echo "5. Serve the frontend: cd frontend && python -m http.server 8080"
echo ""
echo "For more information, see README.md"