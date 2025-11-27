# ZKP Framework — Quick Start (Makefile)

This file explains how to use the **Makefile** helper and the accompanying `scripts/*.sh` Bash scripts to setup, run, and maintain the ZKP Auth Framework.

> **Note**: This project now uses standard `Makefile` and Bash scripts (`.sh`). You can run these on Linux, macOS, WSL, or Git Bash on Windows.

---

## Prerequisites

1. **Bash** (WSL, Git Bash, or native Linux/macOS).
2. **Make** (GNU Make).
3. **Python 3** installed and available in your bash environment.
4. **Docker** (optional, for docker targets).

---

## Commands

Run the following commands from the project root:

### Setup
```bash
make setup
```
Runs the full setup sequence:
- Creates virtual environment (`venv`)
- Generates TLS certificates
- Initializes the database
- Builds WebAssembly module (requires `emcc`)
- Generates signing keys

### Run
```bash
make run
```
Starts the local HTTPS server on port 8443.

### Clean
```bash
make clean
```
Removes the virtual environment, database, and build artifacts.

### Individual Steps
You can also run individual steps if needed:
- `make venv`
- `make gen-tls`
- `make init-db`
- `make build-wasm`
- `make gen-keys`

---

## Troubleshooting
If you encounter issues with `make`, ensure you are running it from a bash-compatible shell (like Git Bash or WSL) and that `make` is installed.
