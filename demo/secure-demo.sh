#!/usr/bin/env bash
# Draft-11 walkthrough against the secure-mode portal started by demo/run-secure-demo.sh.
# demo/Draft11Walkthrough.java plays the agent and a calendar resource at https://rs.uma.lab
# with the io.github.marcofanti:aauth library: registration at the Agent Server, a mission
# with a person token, a resource challenge, POST /auth-token, the resource call, and a
# binding revocation that cascades Agent Server → Person Server → resource. Every signature
# and token is verified for real.
#
# One-time setup beyond demo/run-secure-demo.sh: rs.uma.lab must resolve to 127.0.0.1
# (/etc/hosts), and Caddy must route it (caddy/Caddyfile; reload a running Caddy).
#
# Usage:
#   demo/secure-demo.sh          # interactive: you approve and revoke in the console
#   AUTO=1 demo/secure-demo.sh   # unattended: the person's steps go through the API
set -euo pipefail

DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$DEMO_DIR")"
PS="${PS:-https://ps.uma.lab}"
TLS_DIR="${HOME}/.local/share/uma-lab-tls"
CLASSPATH_FILE="${REPO_DIR}/target/demo-classpath.txt"
RS_PORT=9997

fail() {
  printf '  \033[31m✗ %s\033[0m\n' "$*" >&2
  exit 1
}

[ -f "${TLS_DIR}/truststore.p12" ] || fail "no truststore at ${TLS_DIR} — run scripts/setup-tls.sh"
curl -sf --cacert "$(mkcert -CAROOT)/rootCA.pem" -o /dev/null "${PS}/.well-known/aauth-person.json" ||
  fail "server not reachable at ${PS} — run demo/run-secure-demo.sh first"
python3 -c 'import socket; socket.gethostbyname("rs.uma.lab")' 2>/dev/null ||
  fail "rs.uma.lab does not resolve — add it to /etc/hosts: 127.0.0.1 rs.uma.lab"
if lsof -nP -iTCP:"${RS_PORT}" -sTCP:LISTEN >/dev/null 2>&1; then
  fail "port ${RS_PORT} (the walkthrough's resource) is already in use"
fi

if [ ! -s "$CLASSPATH_FILE" ]; then
  echo "Resolving the walkthrough's classpath (first run only)…"
  (cd "$REPO_DIR" && mvn -q org.apache.maven.plugins:maven-dependency-plugin:3.10.0:build-classpath \
    -Dmdep.outputFile="$CLASSPATH_FILE" -Dmdep.includeScope=runtime)
fi

exec java \
  -Djavax.net.ssl.trustStore="${TLS_DIR}/truststore.p12" -Djavax.net.ssl.trustStorePassword=changeit \
  -cp "$(cat "$CLASSPATH_FILE")" "${DEMO_DIR}/Draft11Walkthrough.java"
