#!/usr/bin/env bash
# Run the same Maven verification gate used by the CI build-and-test job.
# Usage: ./scripts/test.sh
set -euo pipefail

cd "$(dirname "$0")/.."

# `clean` prevents stale compiled classes from hiding errors. Tests use the
# `test` Spring profile and H2; Docker/PostgreSQL are not required.
SPRING_PROFILES_ACTIVE=test ./mvnw clean test --no-transfer-progress
