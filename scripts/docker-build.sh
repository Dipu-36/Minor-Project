#!/bin/bash
# docker-build.sh - build docker image

set -e
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.."

echo "Building Docker image..."
docker build -t zkp-framework .
