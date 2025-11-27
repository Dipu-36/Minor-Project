# Makefile for ZKP Framework (Windows/Linux/WSL)

.PHONY: help setup run clean venv gen-tls init-db build-wasm gen-keys

help:
	@echo "Available targets:"
	@echo "  make setup      - Run full environment setup (venv, tls, db, wasm, keys)"
	@echo "  make run        - Run the local development server"
	@echo "  make clean      - Clean up venv, db, and build artifacts"
	@echo "  make venv       - Create virtual environment only"
	@echo "  make gen-tls    - Generate TLS certificates"
	@echo "  make init-db    - Initialize database"
	@echo "  make build-wasm - Build WebAssembly module"
	@echo "  make gen-keys   - Generate signing keys"

setup:
	@echo "Running full setup..."
	@bash scripts/setup-all.sh

run:
	@echo "Starting server..."
	@bash scripts/run-local.sh

clean:
	@echo "Cleaning project..."
	@bash scripts/clean-venv.sh
	@bash scripts/docker-clean.sh
	@bash scripts/reset-db.sh

venv:
	@bash scripts/venv.sh

gen-tls:
	@bash scripts/gen-tls.sh

init-db:
	@bash scripts/init-db.sh

build-wasm:
	@bash scripts/build-wasm.sh

gen-keys:
	@bash scripts/gen-keys.sh
