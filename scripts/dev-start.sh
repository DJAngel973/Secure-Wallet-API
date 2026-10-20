#!/usr/bin/env bash
# Start the complete local environment declared in docker-compose.yml.
# Usage: ./scripts/dev-start.sh
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ ! -f .env ]]; then
  echo "ERROR: .env not found. Copy .env.example to .env and set private values."
  exit 1
fi

# Docker Compose reads .env itself. Do not source it in Bash: passwords may
# contain characters such as $, / or ! that should remain literal values.
docker compose up -d --build
docker compose ps

echo "Environment started. Inspect API logs with: docker compose logs -f wallet-api"
