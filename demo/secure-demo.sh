#!/usr/bin/env bash
# Secure-mode companion to demo/demo.sh, against the server started by
# demo/run-secure-demo.sh. Where the main demo uses insecure-dev shortcuts, this one
# shows the real thing: stub identities get 401, registrations carry genuine RFC 9421
# signatures, and POST /token (scheme=jwt) returns an Ed25519-signed aa-auth+jwt that
# lands in the console's Issued tokens tab.
#
# The signing agents are the Python reference repo's client scripts, run unchanged —
# which doubles as a live interop proof. Requires a sibling clone of
# https://github.com/christian-posta/aauth-person-server (default ../aauth-person-server;
# override with PS_REPO=…); its virtualenv is created on first run.
#
# Usage:
#   demo/secure-demo.sh          # interactive: you approve one registration in the UI
#   AUTO=1 demo/secure-demo.sh   # unattended: approval via API (smoke test)
#   OPEN=1 demo/secure-demo.sh   # also open UI pages in the browser (macOS)
set -euo pipefail

DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$DEMO_DIR")"
BASE="${BASE:-http://127.0.0.1:8765}"
BASE="${BASE%/}"
ADMIN_TOKEN="${ADMIN_TOKEN:-demo-admin}"
PS_REPO="${PS_REPO:-${REPO_DIR}/../aauth-person-server}"
AUTO="${AUTO:-0}"
OPEN="${OPEN:-0}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
act() { printf '\n\033[1;36m═══ %s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
ok() { printf '  \033[32m✓\033[0m %s\n' "$*"; }
fail() {
  printf '  \033[31m✗ %s\033[0m\n' "$*" >&2
  exit 1
}

pause() {
  [ "$AUTO" = "1" ] && return 0
  printf '\n'
  read -r -p "  ⏎ continue… " _
}

your_turn() {
  if [ "$AUTO" = "1" ]; then
    note "(AUTO) $1"
    return 0
  fi
  printf '\n  \033[1;33m▶ YOUR TURN:\033[0m %s\n' "$1"
  printf '    \033[4m%s\033[0m\n' "$2"
  if [ "$OPEN" = "1" ] && command -v open >/dev/null 2>&1; then
    open "$2"
  fi
}

show_json() { python3 -m json.tool <"$1" | sed 's/^/    /'; }

req() {
  local method="$1" path="$2"
  shift 2
  curl -sS -o "$WORK/body" -w '%{http_code}' -X "$method" "${BASE}${path}" "$@"
}

PY="${PS_REPO}/.venv/bin/python"

# ═══════════════════════════════════════════════════════════════════ Act 0
act "Act 0 — Prove the server is actually secure"
status=$(req GET /.well-known/aauth-person.json) || true
[ "$status" = "200" ] || fail "server not reachable at ${BASE} — run demo/run-secure-demo.sh first"
ok "Server is up at ${BASE}"

status=$(req POST /mission -H 'Content-Type: application/json' -H 'X-AAuth-Agent-Id: impostor' \
  -d '{"description":"let me in"}')
if [ "$status" = "401" ]; then
  ok "The insecure-dev stub identity header is rejected — 401:"
  show_json "$WORK/body"
else
  fail "expected 401 for a stub identity, got HTTP ${status} — is this server in secure mode?"
fi

if [ ! -d "$PS_REPO" ]; then
  fail "Python reference repo not found at ${PS_REPO} — clone christian-posta/aauth-person-server there (or set PS_REPO)"
fi
if [ ! -x "$PY" ]; then
  note "Setting up the Python reference repo's virtualenv (one-time)…"
  (cd "$PS_REPO" && uv venv .venv && uv pip install --python .venv/bin/python -e ".[dev]") \
    >"$WORK/venv-setup.log" 2>&1 || {
    tail -5 "$WORK/venv-setup.log"
    fail "virtualenv setup failed"
  }
  ok "virtualenv ready"
fi
note "The agents in this demo are the Python reference repo's own signing clients,"
note "run unchanged against the Java server — a live interop proof."
your_turn "Open the console and paste the token (demo-admin)." "${BASE}/ui/portal.html"
pause

# ═══════════════════════════════════════════════════════════════════ Act 1
act "Act 1 — Signed registration, approval, and jkt-jwt refresh"
note "agent-server-signed-walkthrough.py registers with a real hwk signature,"
note "approves via the person API, collects its aa-agent+jwt, then refreshes it"
note "with the jkt-jwt scheme signed by the stable key."
"$PY" "${PS_REPO}/scripts/agent-server-signed-walkthrough.py" \
  --base "$BASE" --person-token "$ADMIN_TOKEN" --pending-prefix /register/pending \
  --no-show-curl 2>&1 | sed 's/^/    /'
ok "Registration → approval → agent token → refresh, all with verified signatures."
note "(Console → Bindings tab: the walkthrough agent is there with its device key.)"
pause

# ═══════════════════════════════════════════════════════════════════ Act 2
act "Act 2 — A real aa-auth+jwt, with you in the approval path"
note "ps-token-mode3.py plays a full mode-3 agent: it registers (hwk-signed), then"
note "serves its own resource-server metadata + JWKS, mints a resource token, and"
note "calls POST /token with scheme=jwt. It is now polling — its registration"
note "needs a person's approval before it gets an identity."

"$PY" "${PS_REPO}/scripts/ps-token-mode3.py" --base "$BASE" >"$WORK/mode3.log" 2>&1 &
mode3_pid=$!

REG_ID=""
for _ in $(seq 1 30); do
  status=$(req GET /person/registrations -H "Authorization: Bearer ${ADMIN_TOKEN}")
  [ "$status" = "200" ] || fail "GET /person/registrations → HTTP ${status}"
  REG_ID=$(
    python3 - "$WORK/body" <<'PYEOF'
import json, sys
rows = [r for r in json.load(open(sys.argv[1]))
        if r.get("agent_name") == "ps-token-mode3 demo" and r.get("status") == "pending"]
print(rows[-1]["id"] if rows else "")
PYEOF
  )
  [ -n "$REG_ID" ] && break
  sleep 1
done
[ -n "$REG_ID" ] || fail "mode-3 registration never appeared (see its log below)
$(tail -5 "$WORK/mode3.log")"
ok "Pending registration '${REG_ID}' is waiting in the Registrations tab."

your_turn "Registrations tab → Approve 'ps-token-mode3 demo'." "${BASE}/ui/portal.html"
if [ "$AUTO" = "1" ]; then
  status=$(req POST "/person/registrations/${REG_ID}/approve" -H "Authorization: Bearer ${ADMIN_TOKEN}")
  [ "$status" = "200" ] || fail "approve registration → HTTP ${status}"
fi

note "Waiting for the agent to collect its identity and finish the token exchange…"
for _ in $(seq 1 300); do
  kill -0 "$mode3_pid" 2>/dev/null || break
  sleep 1
done
if kill -0 "$mode3_pid" 2>/dev/null; then
  kill "$mode3_pid" 2>/dev/null
  fail "mode-3 agent did not finish (see log)
$(tail -10 "$WORK/mode3.log")"
fi
wait "$mode3_pid" 2>/dev/null || {
  tail -10 "$WORK/mode3.log" | sed 's/^/    /'
  fail "mode-3 agent exited with an error"
}
ok "POST /token returned a real Ed25519-signed aa-auth+jwt. Its claims:"
sed -n '/^{/,$p' "$WORK/mode3.log" | sed 's/^/    /'
pause

# ═══════════════════════════════════════════════════════════════════ Act 3
act "Act 3 — The Issued tokens tab is no longer theoretical"
status=$(req GET /admin/issued-tokens -H "Authorization: Bearer ${ADMIN_TOKEN}")
[ "$status" = "200" ] || fail "GET /admin/issued-tokens → HTTP ${status}"
ok "Every real issuance is on the record:"
show_json "$WORK/body"
note "(Console → Issued tokens tab shows the same row: agent, resource, scope, JTI.)"

act "Finale"
ok "Same routes, same flows as the main demo — but every signature verified,"
note "  every token genuine, and the audit trail backed by real crypto."
bold ""
bold "  fin."
