# ============================================================
# Dockerfile – ZKP Authentication Framework
# ============================================================

FROM ubuntu:22.04

# -----------------------------
# Install base dependencies
# -----------------------------
RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-venv \
    git curl build-essential cmake openssl pkg-config \
    nodejs npm sqlite3 \
    && apt-get clean

# -----------------------------
# Install Emscripten (for WASM)
# -----------------------------
RUN git clone https://github.com/emscripten-core/emsdk.git /opt/emsdk
WORKDIR /opt/emsdk
RUN ./emsdk install latest && ./emsdk activate latest

ENV EMSDK="/opt/emsdk"
ENV PATH="/opt/emsdk:/opt/emsdk/upstream/emscripten:${PATH}"

# -----------------------------
# Copy project
# -----------------------------
WORKDIR /app
COPY . /app

# -----------------------------
# Python environment
# -----------------------------
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"
RUN pip install --upgrade pip && pip install flask pynacl argon2-cffi

# -----------------------------
# Build WASM module
# -----------------------------
WORKDIR /app/wasm_crypto
RUN bash build.sh

# -----------------------------
# Sign WASM (RSA-PSS)
# -----------------------------
WORKDIR /app/scripts
RUN bash sign_wasm.sh || echo "Signing skipped (first build)."

# -----------------------------
# Initialize DB
# -----------------------------
WORKDIR /app/zkp_server
RUN python3 - <<'PY'
from storage import init_db
init_db()
print("DB Initialized ✔")
PY

# -----------------------------
# Expose HTTPS port
# -----------------------------
EXPOSE 8443

# -----------------------------
# Entrypoint
# -----------------------------
WORKDIR /app/zkp_server
CMD ["python3", "server.py"]
