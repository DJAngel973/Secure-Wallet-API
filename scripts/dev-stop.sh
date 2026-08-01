#!/bin/bash
# ================================================================
# dev-stop.sh — Stop local development environment
# Usage: ./script/dev-stop.sh
# ================================================================

cd "$(dirname "$0")/.." || exit 1

# 1. Stop Spring Boot using PID file
# WHY PID file instead of pkill: isolates THIS project — won't kill other Java apps.
echo "Stopping Spring Boot..."
if [ -f .spring-boot.pid ]; then
  PID=$(cat .spring-boot.pid)
  if kill "$PID" 2>/dev/null; then
    echo "Spring Boot stopped (PID $PID)."
  else
    echo "Spring Boot process (PID $PID) was not running."
  fi
  rm -f .spring-boot.pid
else
  echo "No .spring-boot.pid found. Spring Boot may not be running."
fi

echo "Stopping PostgreSQL container..."
docker compose stop postgres
echo "PostgreSQL stopped."

echo "Done. All services stopped."
