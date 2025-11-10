"""
storage.py
-----------
Manages persistence for:
- Registered users (user_id, verifier v, salt)
- Active sessions (session_id, t, c, expiration)
"""

import sqlite3
import base64
from zkp_server import config

def _get_conn():
    conn = sqlite3.connect(config.DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db():
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            verifier TEXT NOT NULL,
            salt TEXT NOT NULL
        );
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            t_b64 TEXT NOT NULL,
            c_bytes BLOB NOT NULL,
            expires_at INTEGER NOT NULL,
            used INTEGER DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(user_id)
        );
    """)
    conn.commit()
    conn.close()

def store_user(user_id, verifier, salt):
    conn = _get_conn()
    conn.execute(
        "INSERT OR REPLACE INTO users (user_id, verifier, salt) VALUES (?, ?, ?);",
        (user_id, verifier, salt)
    )
    conn.commit()
    conn.close()

def get_user(user_id):
    conn = _get_conn()
    cur = conn.execute("SELECT verifier, salt FROM users WHERE user_id=?;", (user_id,))
    row = cur.fetchone()
    conn.close()
    return row if row else None

def store_session(user_id, session_id, t_b64, c_bytes, expires_at):
    conn = _get_conn()
    conn.execute(
        "INSERT INTO sessions (session_id, user_id, t_b64, c_bytes, expires_at) VALUES (?, ?, ?, ?, ?);",
        (session_id, user_id, t_b64, c_bytes, expires_at)
    )
    conn.commit()
    conn.close()

def load_session(session_id):
    conn = _get_conn()
    cur = conn.execute(
        "SELECT u.verifier, s.t_b64, s.c_bytes, s.expires_at "
        "FROM sessions s JOIN users u ON s.user_id = u.user_id WHERE s.session_id=? AND s.used=0;",
        (session_id,)
    )
    row = cur.fetchone()
    conn.close()
    return row

def mark_session_used(session_id):
    conn = _get_conn()
    conn.execute("UPDATE sessions SET used=1 WHERE session_id=?;", (session_id,))
    conn.commit()
    conn.close()

