#!/usr/bin/env bash
# Stop the complete Docker Compose environment without deleting database data.
# Usage: ./scripts/dev-stop.sh
set -euo pipefail

cd "$(dirname "$0")/.."

# `stop` preserves the PostgreSQL bind-mounted data directory. A destructive
# reset must always be an explicit, separate action.
docker compose stop
echo "Environment stopped. Database data was preserved."
