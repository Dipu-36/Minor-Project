"""
config.py
----------
Central configuration for the ZKP server.
This file holds constants, paths, and security configuration.

Includes:
- HTTPS setup (certificate, key)
- Server fingerprint computation for challenge binding
- Database location
"""

import os
import ssl
from hashlib import sha512

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ===============================
# Server & TLS Configuration
# ===============================
HOST = "127.0.0.1"
PORT = 8443  # Use HTTPS port
CERT_FILE = os.path.join(BASE_DIR, "server.crt")
KEY_FILE = os.path.join(BASE_DIR, "server.key")

# ===============================
# Database Configuration
# ===============================
DB_PATH = os.path.join(BASE_DIR, "zkp_auth.db")

# ===============================
# Challenge/Session Settings
# ===============================
CHALLENGE_TTL = 30  # seconds
MAX_SESSIONS = 10000

# ===============================
# Compute server certificate fingerprint
# ===============================
def get_server_fingerprint(cert_path: str = CERT_FILE) -> bytes:
    """
    Computes SHA-512 fingerprint of the server certificate (DER format).
    Used to bind challenges to a specific server instance to prevent relay MITM.
    """
    if not os.path.exists(cert_path):
        print("[WARN] Server certificate not found — challenge binding disabled.")
        return b""
    with open(cert_path, "rb") as f:
        pem = f.read()
    try:
        der = ssl.PEM_cert_to_DER_cert(pem.decode())
    except Exception:
        # Already DER
        der = pem
    return sha512(der).digest()

SERVER_FINGERPRINT = get_server_fingerprint()

