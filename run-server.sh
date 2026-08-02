#!/usr/bin/env bash
set -euo pipefail
# Resolve repo root (directory containing this script) so the DB path is stable.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
JAR="${SCRIPT_DIR}/target/aauth-java-person-server-0.1.0-SNAPSHOT.jar"
[ -f "$JAR" ] || (cd "$SCRIPT_DIR" && mvn -q -DskipTests package)

# Single SQLite file for Person Server + Agent Server (same env contract as the Python server).
export AAUTH_DATABASE_URL="sqlite:///${SCRIPT_DIR}/aauth.db"
export AAUTH_PS_SIGNING_KEY_PATH="${SCRIPT_DIR}/.aauth/ps-signing-key.pem"
export AAUTH_AS_SIGNING_KEY_PATH="${SCRIPT_DIR}/.aauth/as-signing-key.pem"

AAUTH_PS_PUBLIC_ORIGIN=http://127.0.0.1:8765 \
AAUTH_AS_PUBLIC_ORIGIN=http://127.0.0.1:8765 \
AAUTH_PS_ADMIN_TOKEN=mytoken \
AAUTH_AS_PERSON_TOKEN=mytoken \
AAUTH_PS_INSECURE_DEV=false \
AAUTH_AS_INSECURE_DEV=false \
exec java -jar "$JAR" --server.port=8765
