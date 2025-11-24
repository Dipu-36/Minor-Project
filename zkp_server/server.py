"""
server.py
----------
Flask web server exposing registration and login endpoints for ZKP authentication.

Endpoints:
- POST /register         : register user (store verifier)
- POST /login/start      : start login, receive challenge
- POST /login/finish     : submit proof, verify
- GET  /user_salt        : return a user's salt

Also serves the frontend (index.html + WASM/JS files) from ../frontend.
Everything runs over HTTPS.
"""

import ssl
import os
from flask import Flask, request, jsonify, send_from_directory
from zkp_server import storage, protocol, config

# ==========================================================
# Static Frontend Serving
# ==========================================================

# Static folder is project-root/frontend (one level above zkp_server/)
FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")

@app.route("/")
def serve_index():
    """Serve the main frontend page."""
    return send_from_directory(FRONTEND_DIR, "index.html")

# Optional explicit route for accessing frontend paths
@app.route("/frontend/<path:path>")
def serve_frontend(path):
    """Serve any file inside the frontend directory."""
    return send_from_directory(FRONTEND_DIR, path)


# ==========================================================
# ZKP Authentication Endpoints
# ==========================================================

@app.route("/register", methods=["POST"])
def register():
    """
    Register a new user.
    Body: { "user_id": str, "v": str (base64url), "salt": str }
    """
    data = request.get_json(force=True)
    user_id = data.get("user_id")
    v = data.get("v")
    salt = data.get("salt")

    if not user_id or not v or not salt:
        return jsonify({"error": "Missing fields"}), 400

    storage.store_user(user_id, v, salt)
    return jsonify({"status": "ok"})


@app.route("/login/start", methods=["POST"])
def login_start():
    """
    Begin login.
    Body: { "user_id": str, "t": str (base64url) }
    """
    data = request.get_json(force=True)
    user_id = data.get("user_id")
    t = data.get("t")

    if not user_id or not t:
        return jsonify({"error": "Missing fields"}), 400

    res = protocol.initiate_login(user_id, t)
    return jsonify(res)


@app.route("/login/finish", methods=["POST"])
def login_finish():
    """
    Complete login.
    Body: { "user_id": str, "session_id": str, "s": str (base64url) }
    """
    data = request.get_json(force=True)
    user_id = data.get("user_id")
    session_id = data.get("session_id")
    s = data.get("s")

    if not (user_id and session_id and s):
        return jsonify({"error": "Missing fields"}), 400

    ok = protocol.complete_login(user_id, session_id, s)

    if ok:
        return jsonify({"status": "success"})
    return jsonify({"status": "failed"}), 403


@app.route("/user_salt", methods=["GET"])
def user_salt():
    """
    Return the salt for a given user.
    Query: /user_salt?user=<user_id>
    Response: { "salt": "<base64 salt>" } or 404
    """
    user = request.args.get("user") or request.args.get("user_id")

    if not user:
        return jsonify({"error": "missing user"}), 400

    row = storage.get_user(user)
    if not row:
        return jsonify({"error": "not found"}), 404

    verifier, salt = row
    return jsonify({"salt": salt})


# ==========================================================
# HTTPS Server Startup
# ==========================================================

if __name__ == "__main__":
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=config.CERT_FILE, keyfile=config.KEY_FILE)

    print(f"[INFO] Serving frontend from: {FRONTEND_DIR}")
    print(f"[INFO] Using DB at: {storage.config.DB_PATH}")

    app.run(host=config.HOST, port=config.PORT, ssl_context=ctx)
