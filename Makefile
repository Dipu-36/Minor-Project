# Makefile — Linux-only helper for ZKP Auth Framework

IMAGE_NAME := zkp-framework
CONTAINER_NAME := zkp-framework-dev
PORT := 8443

WASM_DIR := wasm_crypto
SCRIPT_DIR := scripts
SERVER_DIR := zkp_server

DB_PATH := $(SERVER_DIR)/zkp_auth.db
CERT := $(SERVER_DIR)/server.crt
KEY  := $(SERVER_DIR)/server.key

REQ_PKGS := flask pynacl argon2-cffi

VENV_DIR := venv
VENV_PY := $(VENV_DIR)/bin/python
VENV_PIP := $(VENV_DIR)/bin/pip

.PHONY: all venv init-db gen-tls gen-keys build-wasm setup-all run-local \
        docker-build docker-run docker-shell docker-clean clean reset-db \
        db-users db-sessions db-full

# Default
all: setup-all

# Create virtualenv + install dependencies
venv:
	@test -d $(VENV_DIR) || python3 -m venv $(VENV_DIR)
	@$(VENV_PIP) install --upgrade pip
	@$(VENV_PIP) install $(REQ_PKGS)

# Initialize SQLite DB
init-db: venv
	@echo "Initializing DB..."
	@$(VENV_PY) -c "from zkp_server.storage import init_db; init_db(); print('DB initialized ✔')"

# Generate TLS certificate with OpenSSL
gen-tls:
	@test -f $(CERT) && echo "✔ TLS cert already exists" || ( \
	  openssl req -x509 -nodes -newkey rsa:2048 \
	    -keyout $(KEY) -out $(CERT) -days 365 \
	    -subj "/CN=localhost" && \
	  echo "✔ TLS Certificates ready at $(SERVER_DIR)/" )

# Generate keys using bash script
gen-keys:
	@echo "Generating WASM signature keys..."
	@bash $(SCRIPT_DIR)/sign_wasm.sh

# Build WASM module
build-wasm:
	@echo "🛠 Building WebAssembly module..."
	cd $(WASM_DIR) && bash build.sh

# One-command full setup
setup-all: venv gen-tls init-db build-wasm gen-keys
	@echo "Full environment setup complete!"

# Run local HTTPS server
run-local: setup-all
	@echo "Running local HTTPS server..."
	@$(VENV_PY) -m zkp_server.server

# Docker
docker-build:
	@echo "Building Docker image: $(IMAGE_NAME)"
	docker build -t $(IMAGE_NAME) .

docker-run:
	@echo "Running Docker container on port $(PORT)..."
	docker run --rm -p $(PORT):8443 --name $(CONTAINER_NAME) $(IMAGE_NAME)

docker-shell:
	@echo "Opening shell in container..."
	-docker exec -it $(CONTAINER_NAME) /bin/bash || \
	  docker run -it --rm --entrypoint /bin/bash $(IMAGE_NAME)

docker-clean:
	@echo "Cleaning Docker images..."
	-docker rm -f $(CONTAINER_NAME) 2>/dev/null || true
	-docker rmi $(IMAGE_NAME) 2>/dev/null || true

# Inspect DB contents
db-users:
	@echo "👤 Users in ZKP DB:"
	@sqlite3 $(DB_PATH) "SELECT user_id, salt, verifier FROM users;"

db-sessions:
	@echo "Session records:"
	@sqlite3 $(DB_PATH) "SELECT session_id, user_id, used, datetime(expires_at, 'unixepoch') FROM sessions;"

db-full:
	@echo "================ USERS ================"
	@$(MAKE) db-users
	@echo ""
	@echo "=============== SESSIONS =============="
	@$(MAKE) db-sessions

# Reset DB
reset-db:
	@echo "Resetting DB..."
	@rm -f $(DB_PATH)
	@$(VENV_PY) -c "from zkp_server.storage import init_db; init_db(); print('DB initialized ✔')"

# Cleanup temp files
clean:
	@echo "Cleaning project..."
	@rm -rf $(VENV_DIR) \
	         $(WASM_DIR)/*.wasm $(WASM_DIR)/*.js $(WASM_DIR)/*.sig
	@rm -rf $(SERVER_DIR)/__pycache__ $(WASM_DIR)/__pycache__ */__pycache__
