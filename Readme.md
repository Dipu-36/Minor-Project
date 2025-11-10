# Zero Knowledge Proof (ZKP) Authentication Framework

## 1. Overview

This project implements a Zero Knowledge Proof (ZKP) based authentication framework using the **Schnorr protocol** on the **Ed25519 elliptic curve**.  
The goal is to provide a secure, passwordless authentication system that eliminates the risks of **MITM (Man-in-the-Middle)** and **Replay Attacks**.

The framework is designed so that it can be used as the **backend authentication layer** for any web or REST API application.  
Developers can build their own applications on top of this framework without needing to manually handle cryptographic details.

The project includes:
- A **Python Flask backend** for REST endpoints (`register`, `login/start`, `login/finish`)
- A **C/WebAssembly module** that performs client-side cryptographic operations (Schnorr ZKP)
- Integration with **Argon2id** for password hashing (KDF)
- A **Docker setup** for easy build and deployment
- A minimal **frontend** for registration and login testing

## 2. What This Framework Does

This framework implements a complete passwordless authentication flow based on Zero Knowledge Proofs.

1. **Registration Phase**:
   - A user chooses a password.
   - The password is converted into a secure scalar value using **Argon2id**.
   - The WebAssembly module computes a public verifier `v = g^x`, where `x` is the scalar derived from the password.
   - The verifier `v` and the salt are sent to the server and stored.

2. **Login Phase**:
   - The client picks a random number `r` and computes `t = g^r`.
   - The server responds with a random challenge `c`.
   - The client computes `s = r + c*x mod L`.
   - The server verifies the proof using `g^s == t * v^c`.
   - If the equation holds, the authentication is successful.

3. **Security Features**:
   - No password is ever sent to the server.
   - Each login session uses a fresh random challenge.
   - The challenge is bound to the server’s certificate fingerprint to prevent MITM attacks.
   - HTTPS (TLS) is used for transport security.

## 3. Directory Structure

```
minor-project/
├── zkp_server/
│   ├── config.py
│   ├── crypto_utils.py
│   ├── protocol.py
│   ├── server.py
│   ├── storage.py
├── wasm_crypto/
│   ├── crypto.c
│   ├── crypto.h
│   ├── build.sh
│   ├── ed25519_ref/
├── frontend/
│   ├── index.html
│   ├── zkp-loader.js
│   ├── worker.js
├── tests/
├── Dockerfile
├── Makefile
└── README.md
```

## 4. How to Build and Run the Framework

### Option 1: Using Docker (Recommended)

**Steps:**
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/minor-project.git
   cd minor-project
   ```

2. Build the Docker image:
   ```bash
   make docker-build
   ```

3. Run the container:
   ```bash
   make docker-run
   ```

4. Once running, open:
   ```
   https://127.0.0.1:8443/frontend/index.html
   ```

### Option 2: Local Setup (Without Docker)

**Requirements:**
- Python 3.10+
- Node.js and npm
- Emscripten SDK (emcc)
- GCC and make

**Steps:**
1. Create a Python virtual environment:
   ```bash
   make setup
   ```

2. Build the WebAssembly module:
   ```bash
   make build
   ```

3. Initialize the database:
   ```bash
   make initdb
   ```

4. Run the Flask server:
   ```bash
   make run
   ```

Then open:
```
https://127.0.0.1:8443/frontend/index.html
```

## 5. How to Build Applications Using This Framework

Once the framework is built, it can be imported into other Python projects as a module.

### Steps to Use It in a New Project

1. Install the framework locally:
   ```bash
   pip install ../minor-project
   ```

2. Import and use it in your app:
   ```python
   from zkp_server.protocol import verify_proof
   ```

3. Example REST API:
   ```python
   from flask import Flask, request, jsonify
   from zkp_server.protocol import verify_proof
   import base64

   app = Flask(__name__)

   @app.route("/api/login", methods=["POST"])
   def zkp_login():
       data = request.get_json()
       proof = data.get("proof")
       if not proof:
           return jsonify({"error": "No proof provided"}), 400

       c_bytes = base64.urlsafe_b64decode(proof["c"] + "==")
       valid = verify_proof(proof["v"], proof["t"], c_bytes, proof["s"])

       if valid:
           return jsonify({"status": "authenticated"})
       else:
           return jsonify({"status": "denied"}), 403

   if __name__ == "__main__":
       app.run(port=5000)
   ```
