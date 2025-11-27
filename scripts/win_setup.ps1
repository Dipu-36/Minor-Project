#!/usr/bin/env pwsh
<#
  scripts/win_setup.ps1
  Windows setup script for the ZKP project. Run from the repo root.

  Usage examples:
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\win_setup.ps1
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\win_setup.ps1 -SkipWasm
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\win_setup.ps1 -SkipCerts -SkipSigning
#>

param(
    [switch]$SkipWasm,
    [switch]$SkipCerts,
    [switch]$SkipSigning
)

Set-StrictMode -Version Latest

$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $RepoRoot

$VENV_DIR = 'venv'
$VENV_PY = Join-Path $VENV_DIR 'Scripts\python.exe'
$VENV_PIP = Join-Path $VENV_DIR 'Scripts\pip.exe'
$REQ_PKGS = 'flask pynacl argon2-cffi'.Split(' ')
$CERT = 'zkp_server/server.crt'
$KEY = 'zkp_server/server.key'
$WASM_DIR = 'wasm_crypto'
$SCRIPT_DIR = 'scripts'

function Fail($msg, $code=1) {
    Write-Error $msg
    exit $code
}

Write-Host "Starting Windows setup in: $(Get-Location)"

if (-not (Test-Path $VENV_DIR)) {
    Write-Host "Creating virtual environment: $VENV_DIR"
    python -m venv $VENV_DIR | Out-Null
    Write-Host "Created virtual environment $VENV_DIR"
} else {
    Write-Host "Virtual environment already exists: $VENV_DIR"
}

if (-not (Test-Path $VENV_PY)) {
    Fail "Python executable not found inside venv at $VENV_PY"
}

Write-Host "Upgrading pip..."
& $VENV_PY -m pip install --upgrade pip || Fail "Failed to upgrade pip"

# Install required Python packages if missing
$missing = @()
foreach ($p in $REQ_PKGS) {
    try { & $VENV_PIP show $p > $null } catch { $missing += $p }
}
if ($missing.Count -gt 0) {
    Write-Host "Installing missing packages: $($missing -join ', ')"
    & $VENV_PY -m pip install $missing || Fail "Failed to install required Python packages"
} else {
    Write-Host "All required Python packages are already installed."
}

Write-Host "Initializing database..."
& $VENV_PY -c "from zkp_server.storage import init_db; init_db(); print('DB initialized ✔')" || Fail "DB init failed"

if (-not $SkipCerts) {
    if (Test-Path $CERT) {
        Write-Host '✔ TLS cert already exists'
    } else {
        if (-not (Get-Command openssl -ErrorAction SilentlyContinue)) {
            Fail 'OpenSSL not found; please install OpenSSL or run this script inside WSL/Git Bash.' 2
        }
        openssl req -x509 -nodes -newkey rsa:2048 -keyout $KEY -out $CERT -days 365 -subj "/CN=localhost" || Fail 'OpenSSL failed to generate certificates'
        Write-Host "✔ TLS Certificates ready at zkp_server/"
    }
} else {
    Write-Host "Skipping certificate generation (SkipCerts)"
}

if (-not $SkipWasm) {
    Write-Host "Building WASM module..."
    if (Get-Command bash -ErrorAction SilentlyContinue) {
        bash -lc "cd $WASM_DIR && ./build.sh" || Fail "WASM build failed"
    } else {
        Fail 'Bash not found; cannot build WASM on native Windows. Use WSL or Git Bash.' 3
    }
} else {
    Write-Host "Skipping WASM build (SkipWasm)"
}

if (-not $SkipSigning) {
    Write-Host "Signing WASM..."
    if (Get-Command bash -ErrorAction SilentlyContinue) {
        bash -lc "'$SCRIPT_DIR/sign_wasm.sh'" || Fail "WASM signing failed"
    } else {
        Fail 'Bash not available; cannot run sign_wasm.sh. Use WSL/Git Bash or run the script manually.' 4
    }
} else {
    Write-Host "Skipping WASM signing (SkipSigning)"
}

Write-Host "Full environment setup complete!"
