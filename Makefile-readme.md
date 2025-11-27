# RUNNING_PROJECT.md

# ZKP Authentication Framework — How to Run the Project

This guide explains the exact sequence of commands required to set up and run the ZKP Authentication Framework on:

- **Linux / macOS (Unix-like)**
- **Windows (PowerShell)**

The goal: **You should be able to clone the repo and run the server successfully by following this file only.**

---

# ✅ 1. Prerequisites

## Linux / macOS
You must have:
- Python 3.8+
- `make`
- `bash`
- `openssl`
- `sqlite3` (optional)

## Windows
You must have:
- Python 3.8+
- PowerShell
- Git Bash **OR** WSL (required for building WebAssembly)
- OpenSSL (via Git Bash or WSL)
- Docker (optional)

> **Note:** You can run the Python server fully on Windows, but WASM building requires Git Bash or WSL.

---

# ✅ 2. First-Time Setup (Full Project Setup)

Run these commands **once** after cloning.

## **Linux / macOS**
```bash
make setup-all
```

This automatically performs:
1. Environment setup (virtualenv)
2. TLS certificate generation
3. Database initialization
4. WASM build
5. WASM signing key generation

---

## **Windows (PowerShell)**
```powershell
make win-setup-all
```

Equivalent to the Unix setup but using Windows commands.

---

# ✅ 3. Running the Local HTTPS Server

## **Linux / macOS**
```bash
make run-local
```

## **Windows**
```powershell
make win-run-local
```

Server runs at:
```
https://localhost:8443
```

You may see a self-signed certificate warning — this is expected.

---

# ✅ 4. Daily Development Workflow

## Step 1: Activate the virtual environment  
### Linux/macOS:
```bash
source venv/bin/activate
```

### Windows:
```powershell
.\venv\Scripts\activate
```

## Step 2: Rebuild WASM if crypto code changed:
```bash
make build-wasm
```

## Step 3: Run the server:
```bash
make run-local
```

---

# ✅ 5. Database Management (SQLite)

## View all users:
### Linux/macOS:
```bash
make db-users
```

### Windows:
```powershell
make win-db-users
```

## View session records:
```bash
make db-sessions   # Unix
make win-db-sessions   # Windows
```

## View users + sessions:
```bash
make db-full
```

## Reset the entire database:
⚠ **Deletes and recreates the DB**
```bash
make reset-db        # Unix
make win-reset-db    # Windows
```

---

# ✅ 6. Docker Support (Optional)

## Build the Docker image:
```bash
make docker-build
```

## Run container:
```bash
make docker-run
```

Page available at:
```
https://localhost:8443
```

## Shell inside the container:
```bash
make docker-shell
```

## Clean images/containers:
```bash
make docker-clean
```

---

# ✨ 7. Useful Commands Summary

| Purpose | Linux/macOS | Windows |
|--------|--------------|---------|
| Full setup | `make setup-all` | `make win-setup-all` |
| Run server | `make run-local` | `make win-run-local` |
| Build WASM | `make build-wasm` | `make win-build-wasm` |
| Reset DB | `make reset-db` | `make win-reset-db` |
| View users | `make db-users` | `make win-db-users` |
| View sessions | `make db-sessions` | `make win-db-sessions` |
| Docker build | `make docker-build` | `make win-docker-build` |

---

# 🎉 Done!

This document provides everything needed to:

- Build the WebAssembly module  
- Initialize the ZKP database  
- Set up TLS certificates  
- Run the secure HTTPS server  
- Inspect or reset/auth DB  
- Use Docker if needed  

If you need, I can also create:

✅ A full `README.md`  
✅ A developer onboarding guide  
✅ Diagrams for architecture, WASM flow, or ZKP protocol  
