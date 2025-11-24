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
CERT := $(SERVER_DIR)/server.crt
KEY  := $(SERVER_DIR)/server.key

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
	@echo "from zkp_server.storage import init_db; init_db(); print('DB initialized ✔')" | venv/bin/python3

gen-tls:
	@echo "🔐 Generating TLS certificates..."
	@test -f $(CERT) && echo "✔ TLS cert already exists" || \
	openssl req -x509 -nodes -newkey rsa:2048 \
	    -keyout $(KEY) \
	    -out $(CERT) \
	    -days 365 \
	    -subj "/CN=localhost"
	@echo "✔ TLS Certificates ready at $(SERVER_DIR)/"

gen-keys:
	@echo "🔑 Generating RSA keys for WASM signature..."
	@bash $(SCRIPT_DIR)/sign_wasm.sh

build-wasm:
	@echo "🛠 Building WebAssembly module..."
	cd $(WASM_DIR) && bash build.sh

setup-all: venv gen-tls init-db build-wasm gen-keys
	@echo "🎉 Full environment setup complete!"

run-local: setup-all
	@echo "🚀 Running local HTTPS server..."
	# run as a package module so imports like `from zkp_server import ...` succeed
	@./venv/bin/python3 -m zkp_server.server

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

.PHONY: venv run-local docker-build docker-run docker-shell docker-clean clean \
        init-db gen-keys build-wasm gen-tls setup-all
