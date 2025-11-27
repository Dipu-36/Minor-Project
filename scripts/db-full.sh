#!/bin/bash
# db-full.sh - show both users and sessions

set -e
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.."

./scripts/db-users.sh
echo ""
./scripts/db-sessions.sh
