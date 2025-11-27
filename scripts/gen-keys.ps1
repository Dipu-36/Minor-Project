# gen-keys.ps1 - run the sign_wasm.sh script via bash if available, else show instructions
$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir\..

$signScript = Join-Path $ScriptDir "sign_wasm.sh"

if (-not (Test-Path $signScript)) {
    Write-Error "sign_wasm.sh not found in scripts/."
    exit 1
}

# Prefer WSL / bash if available
$bash = Get-Command bash -ErrorAction SilentlyContinue
if ($bash) {
    Write-Host "Running sign_wasm.sh with bash..."
    # Use -lc so WSL/git-bash can run the script; adjust quoting for Windows
    & bash -lc "./scripts/sign_wasm.sh"
} else {
    Write-Host "Bash not found. You can run the script from WSL or Git Bash:"
    Write-Host "  bash ./scripts/sign_wasm.sh"
    exit 1
}
