#!/usr/bin/env bash
# Start the unified portal in SECURE demo mode: real RFC 9421 signature verification on
# every agent route, scheme=jwt required on POST /token, real Ed25519-signed aa-auth+jwt
# issuance. In-memory state, fixed demo tokens. Companion: demo/secure-demo.sh.
# Reached through the shared local HTTPS front (caddy/Caddyfile), like demo/run-demo.sh.
set -euo pipefail

DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$DEMO_DIR")"
JAR="${REPO_DIR}/target/aauth-java-person-server-0.1.0-SNAPSHOT.jar"

PORT=8765
ORIGIN="https://ps.uma.lab"
AS_ORIGIN="${AS_ORIGIN:-https://as.uma.lab}"
TLS_DIR="${HOME}/.local/share/uma-lab-tls"

[ -f "${TLS_DIR}/truststore.p12" ] || "${REPO_DIR}/scripts/setup-tls.sh"
"${REPO_DIR}/scripts/run-caddy.sh"

if [ ! -f "$JAR" ]; then
  echo "Building ${JAR##*/} (first run only)…"
  (cd "$REPO_DIR" && mvn -q -DskipTests package)
fi

cat <<BANNER

  AAuth Person Portal — SECURE demo mode
  ─────────────────────────────────────────────────────
  Portal UI      ${ORIGIN}/ui/
  Console        ${ORIGIN}/ui/portal.html
  Console token  demo-admin
  ─────────────────────────────────────────────────────
  Signatures are verified for real: unsigned or stub
  requests get 401, POST /token demands scheme=jwt with
  an aa-agent+jwt, and issued auth tokens are genuine
  Ed25519-signed aa-auth+jwt (see the Issued tokens tab).
  State is in-memory and resets on restart.

  Next: in another terminal, run  demo/secure-demo.sh

BANNER

AAUTH_PS_PUBLIC_ORIGIN="$ORIGIN" \
  AAUTH_AS_PUBLIC_ORIGIN="$AS_ORIGIN" \
  AAUTH_PS_EGRESS_ALLOW_HOSTS="*.uma.lab" \
  AAUTH_PS_INSECURE_DEV=false \
  AAUTH_AS_INSECURE_DEV=false \
  AAUTH_PS_ADMIN_TOKEN=demo-admin \
  AAUTH_AS_PERSON_TOKEN=demo-admin \
  AAUTH_PS_USER_TOKEN=demo-user \
  AAUTH_PS_SIGNING_KEY_PATH="${DEMO_DIR}/.demo-keys/secure-ps-signing-key.pem" \
  AAUTH_AS_SIGNING_KEY_PATH="${DEMO_DIR}/.demo-keys/secure-as-signing-key.pem" \
  exec java \
  -Djavax.net.ssl.trustStore="${TLS_DIR}/truststore.p12" -Djavax.net.ssl.trustStorePassword=changeit \
  -jar "$JAR" --server.address=127.0.0.1 --server.port="$PORT"
