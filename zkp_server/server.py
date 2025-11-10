"""
server.py
----------
Flask web server exposing registration and login endpoints for ZKP authentication.

Endpoints:
- POST /register : register user (store verifier)
- POST /login/start : start login, receive challenge
- POST /login/finish : submit proof, verify

All served over HTTPS.
"""

from flask import Flask, request, jsonify
from zkp_server import storage, protocol, config
import base64
import ssl

app = Flask(__name__)

@app.route("/register", methods=["POST"])
def register():
    """
    Register new user with verifier v.
    Body: { "user_id": str, "v": str (base64url), "salt": str (base64) }
    """
    data = request.get_json()
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
    data = request.get_json()
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
    data = request.get_json()
    user_id = data.get("user_id")
    session_id = data.get("session_id")
    s = data.get("s")
    if not (user_id and session_id and s):
        return jsonify({"error": "Missing fields"}), 400

    ok = protocol.complete_login(user_id, session_id, s)
    if ok:
        return jsonify({"status": "success"})
    return jsonify({"status": "failed"}), 403


if __name__ == "__main__":
    # Start Flask app with HTTPS context
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=config.CERT_FILE, keyfile=config.KEY_FILE)
    app.run(host=config.HOST, port=config.PORT, ssl_context=ctx)

