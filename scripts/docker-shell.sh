#!/bin/bash
# docker-shell.sh - open shell in container or run a temporary container shell

set -e
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.."

if docker ps | grep -q zkp-framework-dev; then
    echo "Opening shell in running container..."
    docker exec -it zkp-framework-dev /bin/bash
else
    echo "Container not running. Spawning temporary shell container..."
    docker run -it --rm --entrypoint /bin/bash zkp-framework
fi
