#!/bin/bash
# ================================================================
# dev-start.sh — Start local development environment
# Usage: ./script/dev-start.sh
# ================================================================

# Move to project root regardless of where script is called from
cd "$(dirname "$0")/.." || exit 1

# 1. Load .env FIRST — Docker Compose needs these variables to start
# set -a exports ALL variables defined after it
# source .env reads the file
# set +a stops auto-exporting
if [ ! -f .env ]; then
  echo "ERROR: .env file not found. Copy .env.example and fill in your values."
  exit 1
fi
set -a && source .env && set +a
echo "Environment variables loaded."

# 2. Start PostgreSQL container
echo "Starting PostgreSQL..."
docker compose up -d postgres

# 3. Wait for PostgreSQL to be healthy (uses healthcheck defined in docker-compose.yml)
echo "Waiting for PostgreSQL to be ready..."
until docker compose exec -T postgres pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB" 2>/dev/null; do
  sleep 1
done
echo "PostgreSQL is ready."

# 4. Start Spring Boot with dev profile (background + PID)
# WHY background + PID file: allows dev-stop.sh to kill only THIS process,
# not any other Java project running on the same machine.
echo "Starting Spring Boot on port ${SERVER_PORT:-8080}..."
./mvnw spring-boot:run -Dspring-boot.run.profiles=dev &
SPRING_PID=$!
echo "$SPRING_PID" > .spring-boot.pid
echo "Spring Boot PID: $SPRING_PID (saved to .spring-boot.pid)"

# Wait keeps the script alive so you can see logs — Ctrl+C to stop
wait
