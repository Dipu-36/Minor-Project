"""
server.py
----------
Flask web server exposing registration and login endpoints for ZKP authentication.

Endpoints:
- POST /register : register user (store verifier)
- POST /login/start : start login, receive challenge
- POST /login/finish : submit proof, verify
- GET  /user_salt : return a user's salt

All served over HTTPS.
"""

import base64
import ssl
from flask import Flask, request, jsonify, send_from_directory
from zkp_server import storage, protocol, config

# Serve files from the project-level "frontend" directory without moving it.
# server.py is in zkp_server/, so ../frontend points to the frontend folder at project root.
app = Flask(__name__, static_folder="../frontend", static_url_path="")

# Serve index.html at site root
@app.route("/")
def root_index():
    return send_from_directory(app.static_folder, "index.html")


# Optionally allow direct access to any file under frontend via normal URLs,
# e.g. /worker.js, /crypto.js, /crypto.wasm, /zkp-loader.js, etc. Flask will
# automatically serve static files from `app.static_folder` because static_url_path=""
# maps direct requests to the files in that folder.


@app.route("/register", methods=["POST"])
def register():
    """
    Register new user with verifier v.
    Body: { "user_id": str, "v": str (base64url), "salt": str (base64) }
    """
    data = request.get_json() or {}
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
    data = request.get_json() or {}
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
    Body: { "user_id": str, "session_id": str, "s": str }
    """
    data = request.get_json() or {}
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


if __name__ == "__main__":
    # Start Flask app with HTTPS context (uses paths from config)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=config.CERT_FILE, keyfile=config.KEY_FILE)
    # app.run will serve static files from app.static_folder (../frontend)
    app.run(host=config.HOST, port=config.PORT, ssl_context=ctx)
