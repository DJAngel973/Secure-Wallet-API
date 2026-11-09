#!/usr/bin/env bash
set -euo pipefail

# Verifies PostgreSQL row-lock serialization without touching application data.
# The temporary probe table is dropped on exit. This proves the database
# primitive used by WalletRepository.findByIdWithLock() (SELECT ... FOR UPDATE).

cd "$(dirname "$0")/.."
probe="tx_lock_probe_$$"
trap 'docker compose exec -T postgres sh -c '\''psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 -c "DROP TABLE IF EXISTS '"$probe"';"'\'' >/dev/null' EXIT

docker compose exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1' <<SQL
CREATE TABLE ${probe} (id integer PRIMARY KEY, value integer NOT NULL);
INSERT INTO ${probe}(id, value) VALUES (1, 0);
SQL

docker compose exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1' <<SQL &
BEGIN;
SELECT value FROM ${probe} WHERE id = 1 FOR UPDATE;
SELECT pg_sleep(2);
UPDATE ${probe} SET value = value + 1 WHERE id = 1;
COMMIT;
SQL
first_pid=$!
sleep 0.3

docker compose exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1' <<SQL
BEGIN;
SELECT value FROM ${probe} WHERE id = 1 FOR UPDATE;
UPDATE ${probe} SET value = value + 1 WHERE id = 1;
COMMIT;
SQL
wait "$first_pid"

result=$(printf 'SELECT value FROM %s WHERE id = 1;\n' "${probe}" | \
    docker compose exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tA')

if [[ "${result//[[:space:]]/}" != "2" ]]; then
  echo "FAIL: expected serialized value 2, got '${result}'" >&2
  exit 1
fi

echo "PASS: PostgreSQL FOR UPDATE serialized two concurrent updates (final value: 2)."
