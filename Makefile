# ==========================================================
# Makefile for Dockerized ZKP Authentication Framework
# ==========================================================

IMAGE_NAME := zkp-framework
CONTAINER_NAME := zkp-framework-dev
PORT := 8443

# ==========================================================
# Local Development (non-Docker)
# ==========================================================
venv:
	@echo "🐍 Creating virtual environment..."
	@test -d venv || python3 -m venv venv
	@venv/bin/pip install --upgrade pip
	@venv/bin/pip install flask pynacl argon2-cffi

run-local: venv
	@echo "🚀 Running local HTTPS server..."
	cd zkp_server && ../venv/bin/python server.py

# ==========================================================
# Docker Build & Run
# ==========================================================
docker-build:
	@echo " Building Docker image: $(IMAGE_NAME)"
	docker build -t $(IMAGE_NAME) .

docker-run:
	@echo "Running Docker container on port $(PORT)..."
	docker run --rm -p $(PORT):8443 --name $(CONTAINER_NAME) $(IMAGE_NAME)

docker-shell:
	@echo " Opening interactive shell in container..."
	docker exec -it $(CONTAINER_NAME) /bin/bash || \
	docker run -it --rm --entrypoint /bin/bash $(IMAGE_NAME)

docker-clean:
	@echo " Removing old Docker images..."
	-docker rm -f $(CONTAINER_NAME) || true
	-docker rmi $(IMAGE_NAME) || true

# ==========================================================
# Utility
# ==========================================================
clean:
	@echo " Cleaning up..."
	rm -rf venv wasm_crypto/*.wasm wasm_crypto/*.js
	find . -type d -name "__pycache__" -exec rm -rf {} +

.PHONY: venv run-local docker-build docker-run docker-shell docker-clean clean

