# ============================================================
# Dockerfile for the ZKP Authentication Framework
# ============================================================

FROM ubuntu:22.04

# -----------------------------
# Install base dependencies
# -----------------------------
RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-venv \
    sqlite3 openssl \
    git curl build-essential cmake \
    nodejs npm pkg-config \
    && apt-get clean

# -----------------------------
# Install Emscripten (for WASM)
# -----------------------------
RUN git clone https://github.com/emscripten-core/emsdk.git /opt/emsdk
WORKDIR /opt/emsdk
RUN ./emsdk install latest && ./emsdk activate latest
ENV PATH="/opt/emsdk:/opt/emsdk/upstream/emscripten:${PATH}"

# -----------------------------
# Setup working directory
# -----------------------------
WORKDIR /app
COPY . /app

# -----------------------------
# Python environment setup
# -----------------------------
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"
RUN pip install --upgrade pip && pip install flask pynacl argon2-cffi

# -----------------------------
# Build WebAssembly module
# -----------------------------
WORKDIR /app/wasm_crypto
RUN bash build.sh

# Copy wasm + glue into frontend
RUN cp crypto.wasm /app/frontend/crypto.wasm && \
    cp crypto.js /app/frontend/crypto.js

# -----------------------------
# Generate TLS Certificates
# -----------------------------
WORKDIR /app/zkp_server
RUN test -f server.crt || openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout server.key \
        -out server.crt \
        -days 365 \
        -subj "/CN=localhost"

# -----------------------------
# Generate WASM signature keys
# -----------------------------
WORKDIR /app/scripts
RUN bash sign_wasm.sh

# Copy public key to frontend so browser can verify it
RUN cp wasm_pub.pem /app/frontend/wasm_pub.pem && \
    cp /app/wasm_crypto/crypto.wasm.sig /app/frontend/crypto.wasm.sig

# -----------------------------
# Initialize database
# -----------------------------
WORKDIR /app/zkp_server
RUN python3 -c "from storage import init_db; init_db(); print('DB Initialized ✔')"

# -----------------------------
# Expose HTTPS port
# -----------------------------
EXPOSE 8443

# -----------------------------
# Entrypoint
# -----------------------------
WORKDIR /app/zkp_server
CMD ["python3", "server.py"]
