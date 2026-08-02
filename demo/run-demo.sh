#!/usr/bin/env bash
# Start the unified portal in demo mode: in-memory state, insecure-dev signatures
# (so demo.sh can act as an agent with curl + openssl), and fixed demo tokens.
# Runs in the foreground — Ctrl-C stops it. State resets on every start.
set -euo pipefail

DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$DEMO_DIR")"
JAR="${REPO_DIR}/target/aauth-java-person-server-0.1.0-SNAPSHOT.jar"

PORT="${PORT:-8765}"
ORIGIN="http://127.0.0.1:${PORT}"

if [ ! -f "$JAR" ]; then
  echo "Building ${JAR##*/} (first run only)…"
  (cd "$REPO_DIR" && mvn -q -DskipTests package)
fi

cat <<BANNER

  AAuth Person Portal — demo mode
  ─────────────────────────────────────────────────────
  Portal UI      ${ORIGIN}/ui/
  Console        ${ORIGIN}/ui/portal.html
  Consent page   ${ORIGIN}/ui/consent.html
  Console token  demo-admin      (paste into the top-bar Token box)
  User token     demo-user
  ─────────────────────────────────────────────────────
  Insecure-dev mode: signatures are parsed but not verified,
  so demo.sh can play the agent with plain curl. State is
  in-memory and resets on restart. Never expose this mode.

  Next: in another terminal, run  demo/demo.sh

BANNER

AAUTH_PS_PUBLIC_ORIGIN="$ORIGIN" \
  AAUTH_AS_PUBLIC_ORIGIN="$ORIGIN" \
  AAUTH_PS_INSECURE_DEV=true \
  AAUTH_AS_INSECURE_DEV=true \
  AAUTH_PS_ADMIN_TOKEN=demo-admin \
  AAUTH_AS_PERSON_TOKEN=demo-admin \
  AAUTH_PS_USER_TOKEN=demo-user \
  AAUTH_PS_AUTO_APPROVE_TOKEN=false \
  AAUTH_PS_MISSION_EVALUATOR=keyword \
  AAUTH_PS_SIGNING_KEY_PATH="${DEMO_DIR}/.demo-keys/ps-signing-key.pem" \
  AAUTH_AS_SIGNING_KEY_PATH="${DEMO_DIR}/.demo-keys/as-signing-key.pem" \
  exec java -jar "$JAR" --server.port="$PORT"
