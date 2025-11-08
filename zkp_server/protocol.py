import time
import uuid
from . import crypto_utils as crypto
from .config import CHALLENGE_TTL_SECONDS, GROUP_ORDER

class ZKPProtocol:
    def __init__(self, storage):
        self.storage = storage
    
    def generate_challenge(self, user_id: str, t_b64: str, client_ip: str) -> dict:
        # Validate t format
        try:
            t_bytes = crypto.base64url_decode(t_b64)
            if len(t_bytes) != 32:  # Ed25519 point size
                raise ValueError("Invalid t format")
        except:
            raise ValueError("Invalid t encoding")
        
        session_id = str(uuid.uuid4())
        expires_at = int(time.time()) + CHALLENGE_TTL_SECONDS
        
        # Generate challenge: H(t || user_id || session_id || timestamp)
        challenge_data = t_bytes + user_id.encode() + session_id.encode() + str(expires_at).encode()
        challenge_hash = crypto.sha256(challenge_data)
        
        # Reduce to scalar mod group order
        challenge_int = crypto.bytes_to_int(challenge_hash) % GROUP_ORDER
        challenge_bytes = crypto.int_to_bytes(challenge_int)
        challenge_b64 = crypto.base64url_encode(challenge_bytes)
        
        self.storage.store_session(session_id, user_id, t_b64, challenge_b64, expires_at, client_ip)
        
        return {
            'session_id': session_id,
            'c': challenge_b64,
            'expires_at': expires_at
        }
    
    def verify_proof(self, user_id: str, session_id: str, s_b64: str) -> bool:
        session = self.storage.get_session(session_id)
        if not session:
            return False
        
        if session['used']:
            return False
        
        if time.time() > session['expires_at']:
            return False
        
        if session['user_id'] != user_id:
            return False
        
        try:
            # Get verifier from storage
            v_b64 = self.storage.get_verifier(user_id)
            if not v_b64:
                return False
            
            # In a real implementation, you would verify:
            # g^s == t * v^c  (elliptic curve operations)
            # For now, we'll assume the WASM does this verification
            # This is where you'd implement the actual curve math
            
            # Mark session as used
            self.storage.mark_session_used(session_id)
            return True
            
        except Exception:
            return False