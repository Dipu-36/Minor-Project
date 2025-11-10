# ============================================================
# Dockerfile for the ZKP Authentication Framework
# ============================================================

FROM ubuntu:22.04

# -----------------------------
# Install base dependencies
# -----------------------------
RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-venv \
    git curl build-essential cmake nodejs npm openssl pkg-config \
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
RUN bash build.sh || echo "Skipping build if already compiled"

# -----------------------------
# Initialize database
# -----------------------------
WORKDIR /app/zkp_server
RUN python3 -c "from storage import init_db; init_db(); print('DB Initialized ✅')"

# -----------------------------
# Expose HTTPS port
# -----------------------------
EXPOSE 8443

# -----------------------------
# Entrypoint
# -----------------------------
WORKDIR /app/zkp_server
CMD ["python3", "server.py"]

