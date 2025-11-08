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