# ZKP Framework — Windows Quick Start (Makefile.win)

This file explains how to use the **Makefile.win** helper and the accompanying `scripts/*.ps1` PowerShell scripts to setup, run, and maintain the ZKP Auth Framework on **Windows**.  
Everything below assumes you are in the project root (the directory that contains `Makefile.win` and the `scripts/` folder).

> **Important**: `Makefile.win` is not automatically discovered by `make`. You must invoke `make` with `-f Makefile.win` and the target name:
>
> ```
> make -f Makefile.win <target>
> ```
>
> Replace `<target>` with the actual target name from the list shown below.

---

## Prerequisites (Windows)

1. **PowerShell** (modern Windows includes it).  
2. **Python 3** on PATH.  
3. A `make` implementation (GNU Make). Options:
   - Install **Git for Windows** and use **Git Bash** (recommended).
   - Install **MSYS2** / `pacman -S make`.
   - Use **WSL** (Ubuntu) and run `make` inside WSL (you can still call PowerShell scripts).
4. **Optional but required for some steps**:
   - **OpenSSL** on PATH (or run TLS generation from WSL/Git Bash).
   - **Bash (WSL / Git Bash)** for building the WASM (`build-wasm`) and running `sign_wasm.sh`.
   - **Docker** if you plan to use the docker targets.

If `make` is not available, you can run the PowerShell scripts directly from `scripts\*.ps1`.

---

## High-level recommended sequence

Run the following targets in order to set up the development environment and start the local server:

1. **make -f Makefile.win venv**  
   Creates the virtual environment, installs Python dependencies, then opens a **new  
   run - **make -f Makefile.win activate-venv** to activate the venv
     ```

2. **make -f Makefile.win gen-tls**  
   Generates a self-signed TLS certificate at `zkp_server/server.crt` and `zkp_server/server.key` (requires `openssl`).

3. **make -f Makefile.win init-db**  
   Initializes the local SQLite database using the project `venv` Python.

4. **make -f Makefile.win build-wasm**  
   Builds the WebAssembly module (invokes `wasm_crypto/build.sh` via bash). Bash/WSL required.

5. **make -f Makefile.win gen-keys**  
   Runs the `sign_wasm.sh` script (via bash/WSL) to create signing keys for the WASM.

6. **make -f Makefile.win setup-all**  
   Equivalent convenience target that runs the full setup: `venv`, `gen-tls`, `init-db`, `build-wasm`, `gen-keys`. (Note: `venv` will open a new interactive PowerShell session — after finishing the rest, you may need to re-run `setup-all` from that session or run the individual steps as shown above.)

7. **make -f Makefile.win run-local**  
   Starts the local HTTPS server using the virtual environment python.

---

## Single-command setup (convenience)

If you prefer one command that runs everything (and you accept it will spawn a persistent venv shell), do:

