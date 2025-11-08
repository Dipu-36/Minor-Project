import sqlite3
import time
from typing import Optional

class Storage:
    def __init__(self, db_path: str = "zkp_auth.db"):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    v TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                )
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    t_data TEXT NOT NULL,
                    challenge TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    client_ip TEXT NOT NULL,
                    used INTEGER DEFAULT 0
                )
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS rate_limits (
                    key TEXT PRIMARY KEY,
                    attempts INTEGER NOT NULL,
                    window_start INTEGER NOT NULL
                )
            ''')
            conn.commit()
    
    def store_verifier(self, user_id: str, v: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO users (user_id, v, created_at) VALUES (?, ?, ?)",
                (user_id, v, int(time.time()))
            )
            conn.commit()
    
    def get_verifier(self, user_id: str) -> Optional[str]:
        with sqlite3.connect(self.db_path) as conn:
            result = conn.execute(
                "SELECT v FROM users WHERE user_id = ?", (user_id,)
            ).fetchone()
            return result[0] if result else None
    
    def store_session(self, session_id: str, user_id: str, t_data: str, challenge: str, 
                     expires_at: int, client_ip: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                '''INSERT INTO sessions 
                   (session_id, user_id, t_data, challenge, created_at, expires_at, client_ip)
                   VALUES (?, ?, ?, ?, ?, ?, ?)''',
                (session_id, user_id, t_data, challenge, int(time.time()), expires_at, client_ip)
            )
            conn.commit()
    
    def get_session(self, session_id: str) -> Optional[dict]:
        with sqlite3.connect(self.db_path) as conn:
            result = conn.execute(
                "SELECT user_id, t_data, challenge, expires_at, used FROM sessions WHERE session_id = ?",
                (session_id,)
            ).fetchone()
            if not result:
                return None
            return {
                'user_id': result[0],
                't_data': result[1],
                'challenge': result[2],
                'expires_at': result[3],
                'used': bool(result[4])
            }
    
    def mark_session_used(self, session_id: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE sessions SET used = 1 WHERE session_id = ?",
                (session_id,)
            )
            conn.commit()