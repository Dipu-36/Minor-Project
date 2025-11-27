#!/bin/bash
# docker-clean.sh - remove container and image if present

set -e
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.."

echo "Cleaning Docker artifacts..."
docker rm -f zkp-framework-dev 2>/dev/null || true
docker rmi zkp-framework 2>/dev/null || true
echo "Docker clean completed."
