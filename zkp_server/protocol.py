"""
protocol.py
------------
Implements the core Schnorr Zero Knowledge Proof protocol flow:
- Challenge generation
- Proof verification

Uses Ed25519 curve math via PyNaCl bindings.
"""

import base64
import os
import time
from hashlib import sha512
from nacl.bindings import (
    crypto_scalarmult_ed25519_base_noclamp,
    crypto_scalarmult_ed25519_noclamp,
    crypto_core_ed25519_add,
)
from zkp_server import storage, config


# ===========================================================
# Helper: Generate challenge bound to server identity
# ===========================================================
def generate_challenge(user_id: str, t_b64: str, session_id: str, expires_at: int) -> bytes:
    """
    Generates challenge c = SHA512(t || user_id || session_id || server_fp || expires_at)
    Binds challenge to server fingerprint for MITM resistance.
    """
    t_bytes = base64.urlsafe_b64decode(t_b64 + "==")
    server_fp = config.SERVER_FINGERPRINT or b""
    data = t_bytes + user_id.encode() + session_id.encode() + server_fp + str(expires_at).encode()
    return sha512(data).digest()[:32]  # 32-byte challenge


# ===========================================================
# Proof verification: g^s == t * v^c
# ===========================================================
def verify_proof(v_b64: str, t_b64: str, c_bytes: bytes, s_b64: str) -> bool:
    """
    Verifies Schnorr proof for Ed25519 curve:
      g^s == t * v^c
    """
    try:
        v = base64.urlsafe_b64decode(v_b64 + "==")
        t = base64.urlsafe_b64decode(t_b64 + "==")
        s = base64.urlsafe_b64decode(s_b64 + "==")

        # g^s
        gs = crypto_scalarmult_ed25519_base_noclamp(s)

        # v^c
        vc = crypto_scalarmult_ed25519_noclamp(c_bytes, v)

        # expected = t * v^c
        expected = crypto_core_ed25519_add(t, vc)

        return gs == expected
    except Exception as e:
        print(f"[verify_proof] Verification error: {e}")
        return False


# ===========================================================
# Main login flow (server-side)
# ===========================================================
def initiate_login(user_id: str, t_b64: str):
    """
    Called when client sends t = g^r.
    Stores session with challenge c and expiration.
    """
    session_id = os.urandom(16).hex()
    expires_at = int(time.time()) + config.CHALLENGE_TTL
    c_bytes = generate_challenge(user_id, t_b64, session_id, expires_at)
    storage.store_session(user_id, session_id, t_b64, c_bytes, expires_at)
    return {"challenge": base64.urlsafe_b64encode(c_bytes).decode(), "session_id": session_id}


def complete_login(user_id: str, session_id: str, s_b64: str) -> bool:
    """
    Called when client responds with s.
    Verifies stored session, loads v, t, c, checks proof.
    """
    session = storage.load_session(session_id)
    if not session:
        return False

    v_b64, t_b64, c_bytes, expires_at = session

    if int(time.time()) > expires_at:
        print("[complete_login] Challenge expired.")
        return False

    ok = verify_proof(v_b64, t_b64, c_bytes, s_b64)
    if ok:
        storage.mark_session_used(session_id)
    return ok

