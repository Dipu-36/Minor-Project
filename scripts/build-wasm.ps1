# build-wasm.ps1 - build wasm (tries bash / WSL)
$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir\..

$wasmDir = "wasm_crypto"
if (-not (Test-Path $wasmDir)) {
    Write-Error "Directory wasm_crypto not found."
    exit 1
}

$bash = Get-Command bash -ErrorAction SilentlyContinue
if ($bash) {
    Write-Host "Building WebAssembly module via bash..."
    & bash -lc "cd wasm_crypto && ./build.sh"
} else {
    Write-Host "Bash/WSL not detected. To build the WASM module on Windows, run this script from WSL or Git Bash:"
    Write-Host "  (from project root) bash -lc 'cd wasm_crypto && ./build.sh'"
    exit 1
}
