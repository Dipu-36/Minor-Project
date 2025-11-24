# ==========================================================
# Makefile – Automated Build System for ZKP Auth Framework
# ==========================================================

IMAGE_NAME := zkp-framework
CONTAINER_NAME := zkp-framework-dev
PORT := 8443

WASM_DIR := wasm_crypto
SCRIPT_DIR := scripts
SERVER_DIR := zkp_server

DB := zkp_auth.db

# ==========================================================
# Local Development
# ==========================================================

venv:
	@echo "🐍 Creating virtual environment..."
	@test -d venv || python3 -m venv venv
	@venv/bin/pip install --upgrade pip
	@venv/bin/pip install flask pynacl argon2-cffi

init-db: venv
	@echo "🗃 Initializing local database..."
	@echo "from zkp_server.storage import init_db; init_db(); print('DB initialized locally ✔')" | venv/bin/python3

gen-keys:
	@echo "🔑 Generating RSA keys for WASM signature..."
	@bash $(SCRIPT_DIR)/sign_wasm.sh

build-wasm:
	@echo "🛠 Building WebAssembly module..."
	cd $(WASM_DIR) && bash build.sh

run-local: venv init-db build-wasm gen-keys
	@echo "🚀 Running local HTTPS server..."
	cd $(SERVER_DIR) && ../venv/bin/python3 server.py

# ==========================================================
# Docker Build & Run
# ==========================================================

docker-build:
	@echo "🐳 Building Docker image: $(IMAGE_NAME)"
	docker build -t $(IMAGE_NAME) .

docker-run:
	@echo "🐳 Running Docker container on port $(PORT)..."
	docker run --rm -p $(PORT):8443 --name $(CONTAINER_NAME) $(IMAGE_NAME)

docker-shell:
	@echo "🐚 Opening shell in container..."
	docker exec -it $(CONTAINER_NAME) /bin/bash || \
	docker run -it --rm --entrypoint /bin/bash $(IMAGE_NAME)

docker-clean:
	@echo "🧹 Cleaning Docker images..."
	-docker rm -f $(CONTAINER_NAME) || true
	-docker rmi $(IMAGE_NAME) || true

# ==========================================================
# Cleanup
# ==========================================================

clean:
	@echo "🧽 Cleaning project..."
	rm -rf venv $(WASM_DIR)/*.wasm $(WASM_DIR)/*.js $(WASM_DIR)/*.sig
	rm -rf $(SERVER_DIR)/__pycache__
	rm -rf $(WASM_DIR)/__pycache__
	rm -rf */__pycache__

.PHONY: venv run-local docker-build docker-run docker-shell docker-clean clean init-db gen-keys build-wasm
