"""
compat.py
---------
Compatibility layer so tests and external integrations
can use a clean interface:

    from zkp_server.compat import ZKPServer, Storage, ZKPProtocol
"""

from zkp_server import storage, protocol


class Storage:
    """Thin wrapper around storage.py to expose a clean API."""

    def init_db(self):
        return storage.init_db()

    def store_user(self, user_id, verifier, salt):
        return storage.store_user(user_id, verifier, salt)

    def get_user(self, user_id):
        return storage.get_user(user_id)

    def store_session(self, user_id, session_id, t_b64, c_bytes, expires_at):
        return storage.store_session(user_id, session_id, t_b64, c_bytes, expires_at)

    def load_session(self, session_id):
        return storage.load_session(session_id)

    def mark_session_used(self, session_id):
        return storage.mark_session_used(session_id)


class ZKPProtocol:
    """Wrapper for protocol functions."""

    def initiate(self, user_id, t_b64):
        return protocol.initiate_login(user_id, t_b64)

    def verify(self, user_id, session_id, s_b64):
        return protocol.complete_login(user_id, session_id, s_b64)

    def generate_challenge(self, user_id, t_b64, session_id, expires_at):
        return protocol.generate_challenge(user_id, t_b64, session_id, expires_at)


class ZKPServer:
    """
    Wrapper around server-side logic so tests
    or external tools can call the ZKP login flow without HTTP.
    """

    def __init__(self):
        self.storage = Storage()
        self.protocol = ZKPProtocol()
        self.storage.init_db()

    # Registration
    def register(self, user_id, verifier, salt):
        self.storage.store_user(user_id, verifier, salt)
        return {"status": "ok"}

    # Login start
    def login_start(self, user_id, t_b64):
        return self.protocol.initiate(user_id, t_b64)

    # Login finish
    def login_finish(self, user_id, session_id, s_b64):
        ok = self.protocol.verify(user_id, session_id, s_b64)
        return {"status": "success"} if ok else {"status": "failed"}
