# docker-shell.ps1 - open shell in container or run a temporary container shell
$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir\..

try {
    Write-Host "Opening shell in running container..."
    & docker exec -it zkp-framework-dev /bin/bash
} catch {
    Write-Host "Container not running. Spawning temporary shell container..."
    & docker run -it --rm --entrypoint /bin/bash zkp-framework
}
