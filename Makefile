# Makefile — cross-platform helper for ZKP Auth Framework

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

.PHONY: all venv init-db gen-tls gen-keys build-wasm setup-all run-local \
        docker-build docker-run docker-shell docker-clean clean reset-db \
        db-users db-sessions db-full

# Detect Windows
ifeq ($(OS),Windows_NT)
  IS_WINDOWS := true
  VENV_DIR := venv
  VENV_PY := $(VENV_DIR)\Scripts\python.exe
  VENV_PIP := $(VENV_DIR)\Scripts\pip.exe
else
  IS_WINDOWS := false
  VENV_DIR := venv
  VENV_PY := $(VENV_DIR)/bin/python
  VENV_PIP := $(VENV_DIR)/bin/pip
endif

# Default
all: setup-all

# Create virtualenv and install required packages
venv:
ifeq ($(IS_WINDOWS),true)
	@if not exist "$(VENV_DIR)\" ( python -m venv "$(VENV_DIR)" && echo "Created virtual environment" ) else ( echo "Virtual environment exists" )
	@"$(VENV_PIP)" install --upgrade pip
	@"$(VENV_PIP)" install $(REQ_PKGS)
else
	@test -d $(VENV_DIR) || python3 -m venv $(VENV_DIR)
	@$(VENV_PIP) install --upgrade pip
	@$(VENV_PIP) install $(REQ_PKGS)
endif

# Init DB (use venv python if available)
init-db: venv
	@echo " Initializing local database..."
	@$(VENV_PY) -c "from zkp_server.storage import init_db; init_db(); print('DB initialized ✔')"

# Generate TLS cert (platform-appropriate check)
gen-tls:
ifeq ($(IS_WINDOWS),true)
	@if exist "$(CERT)" ( echo "✔ TLS cert already exists" ) else ( \
	  where openssl >nul 2>&1 || ( echo "OpenSSL not found; install or run from WSL/Git Bash"; exit 1 ); \
	  openssl req -x509 -nodes -newkey rsa:2048 -keyout "$(KEY)" -out "$(CERT)" -days 365 -subj "/CN=localhost"; \
	  echo "✔ TLS Certificates ready at $(SERVER_DIR)/" )
else
	@test -f $(CERT) && echo "✔ TLS cert already exists" || ( \
	  openssl req -x509 -nodes -newkey rsa:2048 -keyout $(KEY) -out $(CERT) -days 365 -subj "/CN=localhost"; \
	  echo "✔ TLS Certificates ready at $(SERVER_DIR)/" )
endif

# Generate keys using script (requires bash)
gen-keys:
	@echo " Generating WASM signature keys..."
ifeq ($(IS_WINDOWS),true)
	@if not exist "$(SCRIPT_DIR)\sign_wasm.sh" ( echo "sign_wasm.sh not found"; exit 1 ) else ( \
	  if not defined COMSPEC ( echo "Bash required to run script; use WSL/Git Bash"; exit 1 ); \
	  bash -lc '"$(SCRIPT_DIR)/sign_wasm.sh"' )
else
	@bash $(SCRIPT_DIR)/sign_wasm.sh
endif

# Build WASM (requires bash)
build-wasm:
	@echo "🛠 Building WebAssembly module..."
ifeq ($(IS_WINDOWS),true)
	@bash -lc "cd $(WASM_DIR) && ./build.sh"
else
	cd $(WASM_DIR) && bash build.sh
endif

# Convenience: run full setup
setup-all: venv gen-tls init-db build-wasm gen-keys
	@echo " Full environment setup complete!"

# Run local HTTPS server
run-local: setup-all
	@echo " Running local HTTPS server..."
	@$(VENV_PY) -m zkp_server.server

# Docker targets
docker-build:
	@echo " Building Docker image: $(IMAGE_NAME)"
	docker build -t $(IMAGE_NAME) .

docker-run:
	@echo " Running Docker container on port $(PORT)..."
	docker run --rm -p $(PORT):8443 --name $(CONTAINER_NAME) $(IMAGE_NAME)

docker-shell:
	@echo " Opening shell in container..."
	-docker exec -it $(CONTAINER_NAME) /bin/bash || docker run -it --rm --entrypoint /bin/bash $(IMAGE_NAME)

docker-clean:
	@echo " Cleaning Docker images..."
	-docker rm -f $(CONTAINER_NAME) || true
	-docker rmi $(IMAGE_NAME) || true

# Database helpers (use sqlite3 if available)
db-users:
	@echo "👤 Users in ZKP DB:"
ifeq ($(IS_WINDOWS),true)
	@$(VENV_PY) - <<PY
import sqlite3, sys
db='$(DB_PATH)'
con=sqlite3.connect(db)
for r in con.execute("SELECT user_id, salt, verifier FROM users;"): print(r)
con.close()
PY
else
	@sqlite3 $(DB_PATH) "SELECT user_id, salt, verifier FROM users;"
endif

db-sessions:
	@echo " Session records:"
ifeq ($(IS_WINDOWS),true)
	@$(VENV_PY) - <<PY
import sqlite3
db='$(DB_PATH)'
con=sqlite3.connect(db)
for r in con.execute("SELECT session_id, user_id, used, datetime(expires_at, 'unixepoch') FROM sessions;"): print(r)
con.close()
PY
else
	@sqlite3 $(DB_PATH) "SELECT session_id, user_id, used, datetime(expires_at, 'unixepoch') FROM sessions;"
endif

db-full:
	@echo "================ USERS ================"
	@$(MAKE) db-users
	@echo ""
	@echo "=============== SESSIONS =============="
	@$(MAKE) db-sessions

reset-db:
	@echo " Resetting DB..."
	@rm -f $(DB_PATH) || if [ -f "$(DB_PATH)" ]; then rm -f "$(DB_PATH)"; fi
	@$(VENV_PY) -c "from zkp_server.storage import init_db; init_db(); print('DB initialized ✔')"

# Clean
clean:
	@echo " Cleaning project..."
	@rm -rf $(VENV_DIR) $(WASM_DIR)/*.wasm $(WASM_DIR)/*.js $(WASM_DIR)/*.sig
	@rm -rf $(SERVER_DIR)/__pycache__ $(WASM_DIR)/__pycache__ */__pycache__ || true
