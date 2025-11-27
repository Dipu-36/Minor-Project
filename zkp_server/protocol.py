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


# ------------------------
# Helpers: base64url utils
# ------------------------
def b64url_to_bytes(s: str) -> bytes:
    """
    Decode a URL-safe base64 string which may have its padding stripped.
    """
    if s is None:
        return b""
    if isinstance(s, bytes):
        s = s.decode()
    # Restore padding
    padding_needed = (-len(s)) % 4
    if padding_needed:
        s += "=" * padding_needed
    return base64.urlsafe_b64decode(s)


def bytes_to_b64url(b: bytes) -> str:
    """
    Encode bytes to URL-safe base64 with padding stripped (transport form).
    """
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


# ===========================================================
# Helper: Generate challenge bound to server identity
# ===========================================================
def generate_challenge(user_id: str, t_b64: str, session_id: str, expires_at: int) -> bytes:
    """
    Generates challenge c = SHA512(t || user_id || session_id || server_fp || expires_at)
    Binds challenge to server fingerprint for MITM resistance.
    """
    t_bytes = b64url_to_bytes(t_b64)
    server_fp = config.SERVER_FINGERPRINT or b""
    if isinstance(server_fp, str):
        server_fp = server_fp.encode()
    data = t_bytes + user_id.encode() + session_id.encode() + server_fp + str(expires_at).encode()
    return sha512(data).digest()[:32]  # 32-byte challenge


# ===========================================================
# Proof verification: g^s == t * v^c
# ===========================================================
def verify_proof(v_b64: str, t_b64: str, c_bytes: bytes, s_b64: str) -> bool:
    """
    Verifies Schnorr proof for Ed25519 curve:
      g^s == t * v^c
    This function reduces scalars to canonical form before using the noclamp APIs.
    """
    try:
        from nacl.bindings import crypto_core_ed25519_scalar_reduce
    except Exception:
        crypto_core_ed25519_scalar_reduce = None

    try:
        v = b64url_to_bytes(v_b64)
        t = b64url_to_bytes(t_b64)
        s = b64url_to_bytes(s_b64)

        # reduce challenge c_bytes and s to canonical scalars
        if crypto_core_ed25519_scalar_reduce:
            c_red = crypto_core_ed25519_scalar_reduce(c_bytes)
            s_red = crypto_core_ed25519_scalar_reduce(s)
        else:
            # fallback: if binding missing, assume c_bytes and s are already reduced
            c_red = c_bytes
            s_red = s

        # g^s
        gs = crypto_scalarmult_ed25519_base_noclamp(s_red)

        # v^c
        vc = crypto_scalarmult_ed25519_noclamp(c_red, v)

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
    # store c_bytes as raw bytes in storage layer (storage implementation may accept raw bytes)
    storage.store_session(user_id, session_id, t_b64, c_bytes, expires_at)
    # return urlsafe base64 WITHOUT padding (client expects this form)
    return {"challenge": bytes_to_b64url(c_bytes), "session_id": session_id}


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
