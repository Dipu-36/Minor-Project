# gen-tls.ps1 - generate TLS cert (using openssl if available)
$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir\..

$CERT = ".\zkp_server\server.crt"
$KEY = ".\zkp_server\server.key"

if (Test-Path $CERT -and Test-Path $KEY) {
    Write-Host "✔ TLS cert already exists."
    exit 0
}

# Check for openssl
$openssl = Get-Command openssl -ErrorAction SilentlyContinue
if (-not $openssl) {
    Write-Host "OpenSSL not found on PATH. If you have WSL or Git Bash, run gen-tls from there or install OpenSSL for Windows."
    exit 1
}

Write-Host "Generating self-signed TLS certificate..."
& openssl req -x509 -nodes -newkey rsa:2048 -keyout $KEY -out $CERT -days 365 -subj "/CN=localhost"
Write-Host "✔ TLS Certificates ready at zkp_server/"
