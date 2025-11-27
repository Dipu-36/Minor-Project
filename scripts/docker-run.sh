#!/bin/bash
# docker-run.sh - run docker container

set -e
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.."

echo "Running Docker container on port 8443..."
docker run --rm -p 8443:8443 --name zkp-framework-dev zkp-framework
