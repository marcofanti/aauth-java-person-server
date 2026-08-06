#!/usr/bin/env bash
# Guided AAuth demo against the Java Person Portal started by demo/run-demo.sh.
#
# The script plays the agent ("Concierge", a restaurant-booking assistant) with
# curl + openssl; you play the person in the portal UI. Each act pauses so a
# presenter can narrate and click; AUTO=1 performs the person's approvals over
# the API instead, turning the whole demo into a self-checking smoke test.
#
# Usage:
#   demo/demo.sh                 # interactive: you approve in the UI
#   AUTO=1 demo/demo.sh          # unattended: approvals via API
#   OPEN=1 demo/demo.sh          # also open UI pages in the browser (macOS)
#   BASE=http://127.0.0.1:8765 ADMIN_TOKEN=demo-admin demo/demo.sh
#
# Requires: curl, openssl, python3.
set -euo pipefail

BASE="${BASE:-http://127.0.0.1:8765}"
BASE="${BASE%/}"
ADMIN_TOKEN="${ADMIN_TOKEN:-demo-admin}"
AUTO="${AUTO:-0}"
OPEN="${OPEN:-0}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ---------------------------------------------------------------- presentation
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
  # $1: instruction, $2: URL to visit
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

# ------------------------------------------------------------------- plumbing
jget() {
  # jget <file> <key> — top-level string/number field, empty if absent
  python3 - "$1" "$2" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    value = json.load(f).get(sys.argv[2], "")
print(value if value is not None else "")
PY
}

jwt_payload() {
  python3 - "$1" <<'PY'
import base64, json, sys
part = sys.argv[1].split(".")[1]
part += "=" * (-len(part) % 4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(part)), indent=2))
PY
}

b64url_sha256_of_file() {
  openssl dgst -sha256 -binary "$1" | base64 | tr '+/' '-_' | tr -d '='
}

ed25519_pub_x() {
  # base64url x coordinate of an Ed25519 private key's public half
  openssl pkey -in "$1" -pubout -outform DER 2>/dev/null | tail -c 32 | base64 | tr '+/' '-_' | tr -d '='
}

req() {
  # req <method> <path> [curl args…] → status code on stdout, body in $WORK/body
  local method="$1" path="$2"
  shift 2
  curl -sS -o "$WORK/body" -w '%{http_code}' -X "$method" "${BASE}${path}" "$@"
}

# Insecure-dev signature headers: the server parses Signature-Key but skips
# cryptographic verification, so the signature value itself is a placeholder.
sig_headers() {
  # $1: base64url x of the signing (ephemeral) public key
  SIG_INPUT="sig=(\"@method\" \"@authority\" \"@path\" \"signature-key\");created=$(date +%s)"
  SIG="sig=:$(head -c 64 /dev/zero | base64 | tr -d '\n'):"
  SIG_KEY="sig=hwk;kty=\"OKP\";crv=\"Ed25519\";x=\"$1\""
}

agent_req() {
  # Agent-authenticated PS request via the insecure-dev stub header.
  local method="$1" path="$2"
  shift 2
  req "$method" "$path" -H "X-AAuth-Agent-Id: ${AGENT_ID}" "$@"
}

consent_decision() {
  # AUTO-mode stand-in for the person: fetch context by code, post a decision.
  local code="$1" decision="$2" status
  status=$(req GET "/consent?code=${code}")
  [ "$status" = "200" ] || fail "GET /consent?code=… → HTTP ${status}"
  local pid
  pid=$(jget "$WORK/body" pending_id)
  status=$(req POST "/consent/${pid}/decision" -H 'Content-Type: application/json' -d "$decision")
  [ "$status" = "200" ] || fail "POST /consent/${pid}/decision → HTTP ${status}"
}

poll_until_done() {
  # Poll a URL with the given curl args until it stops answering 202.
  # $1: path; remaining args passed to req. Result: status in POLL_STATUS.
  local path="$1" status tries=0
  shift
  while :; do
    status=$(req GET "$path" "$@")
    if [ "$status" != "202" ]; then
      POLL_STATUS="$status"
      return 0
    fi
    tries=$((tries + 1))
    [ "$tries" -ge 150 ] && fail "still pending after $((tries * 2))s: GET ${path}"
    sleep 2
  done
}

# ═══════════════════════════════════════════════════════════════════ Act 0
act "Act 0 — A fresh Person Portal"
note "Server:  ${BASE}   (started by demo/run-demo.sh, in-memory, insecure-dev)"
note "Cast:    'Concierge' — an agent that books restaurants for its person."
note "         You — the person, working the portal UI."

status=$(req GET /.well-known/aauth-person.json) || true
[ "$status" = "200" ] || fail "server not reachable at ${BASE} — run demo/run-demo.sh first"
ok "Person Server metadata (agents discover endpoints here):"
show_json "$WORK/body"
status=$(req GET /.well-known/aauth-agent.json)
[ "$status" = "200" ] || fail "agent metadata missing"
ok "Agent Server metadata on the same origin — that's the unified portal."
your_turn "Open the portal and paste the console token (demo-admin)." "${BASE}/ui/portal.html"
pause

# ═══════════════════════════════════════════════════════════════════ Act 1
act "Act 1 — Registration: the agent asks for an identity"
note "Concierge generates two Ed25519 keys: a stable identity key and a"
note "per-device ephemeral key, then registers the stable public key."

openssl genpkey -algorithm ed25519 -out "$WORK/stable.pem" 2>/dev/null
openssl genpkey -algorithm ed25519 -out "$WORK/ephemeral.pem" 2>/dev/null
STABLE_X=$(ed25519_pub_x "$WORK/stable.pem")
EPH_X=$(ed25519_pub_x "$WORK/ephemeral.pem")
ok "stable key x=${STABLE_X:0:16}…   ephemeral key x=${EPH_X:0:16}…"

sig_headers "$EPH_X"
status=$(curl -sS -D "$WORK/headers" -o "$WORK/body" -w '%{http_code}' \
  -X POST "${BASE}/register" \
  -H 'Content-Type: application/json' \
  -H "Signature-Input: ${SIG_INPUT}" -H "Signature: ${SIG}" -H "Signature-Key: ${SIG_KEY}" \
  -d "{\"stable_pub\":{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"${STABLE_X}\"},\"agent_name\":\"Concierge (laptop)\"}")
[ "$status" = "202" ] || {
  show_json "$WORK/body"
  fail "POST /register → HTTP ${status} (expected 202)"
}
POLL_PATH=$(tr -d '\r' <"$WORK/headers" | awk 'tolower($1)=="location:" {print $2}')
REG_ID="${POLL_PATH##*/}"
ok "202 Accepted — registration is pending, poll at ${POLL_PATH}"
show_json "$WORK/body"

your_turn "Console → Registrations tab → Approve 'Concierge (laptop)'." "${BASE}/ui/portal.html"
if [ "$AUTO" = "1" ]; then
  status=$(req POST "/person/registrations/${REG_ID}/approve" -H "Authorization: Bearer ${ADMIN_TOKEN}")
  [ "$status" = "200" ] || fail "approve registration → HTTP ${status}"
fi

note "Concierge keeps polling while you decide…"
poll_until_done "$POLL_PATH" \
  -H "Signature-Input: ${SIG_INPUT}" -H "Signature: ${SIG}" -H "Signature-Key: ${SIG_KEY}"
[ "$POLL_STATUS" = "200" ] || {
  show_json "$WORK/body"
  fail "registration poll → HTTP ${POLL_STATUS}"
}
AGENT_TOKEN=$(jget "$WORK/body" agent_token)
ok "Approved! The Agent Server minted an agent token (aa-agent+jwt):"
jwt_payload "$AGENT_TOKEN" | sed 's/^/    /'
AGENT_ID=$(jwt_payload "$AGENT_TOKEN" | python3 -c 'import json,sys; print(json.load(sys.stdin)["sub"])')
ok "agent_id: ${AGENT_ID}"
note "(Check the Bindings tab — the agent now has a binding with one device key.)"
pause

# ═══════════════════════════════════════════════════════════════════ Act 2
act "Act 2 — Mission: the agent states what it's for"
note "Before touching anything, Concierge proposes a mission — a human-readable"
note "contract listing its purpose and the tools it intends to use."

cat >"$WORK/mission-req.json" <<JSON
{
  "description": "Find and book a table for two at a quiet restaurant on Friday evening",
  "tools": [
    {"name": "search_restaurants", "description": "Search restaurants by area and cuisine"},
    {"name": "book_table", "description": "Reserve a table at a chosen restaurant"}
  ]
}
JSON
status=$(agent_req POST /mission -H 'Content-Type: application/json' --data-binary "@$WORK/mission-req.json")
[ "$status" = "200" ] || {
  show_json "$WORK/body"
  fail "POST /mission → HTTP ${status}"
}
cp "$WORK/body" "$WORK/mission-blob.json"
MISSION_S256=$(b64url_sha256_of_file "$WORK/mission-blob.json")
ok "Mission approved. The canonical mission blob:"
show_json "$WORK/mission-blob.json"
ok "s256 = base64url(SHA-256(exact response bytes)) = ${MISSION_S256}"

status=$(req GET /missions -H "Authorization: Bearer ${ADMIN_TOKEN}")
[ "$status" = "200" ] || fail "GET /missions → HTTP ${status}"
python3 - "$WORK/body" "$MISSION_S256" <<'PY'
import json, sys
missions = json.load(open(sys.argv[1]))
match = [m for m in missions if m.get("s256") == sys.argv[2]]
assert match, "computed s256 not found in /missions"
print(f"    server agrees: state={match[0]['state']}  agent={match[0]['agent']}")
PY
ok "Same hash on the Missions tab — agent and person point at identical bytes."
MISSION_REF="{\"approver\":\"${BASE}\",\"s256\":\"${MISSION_S256}\"}"
pause

# ═══════════════════════════════════════════════════════════════════ Act 3
act "Act 3 — Token request: governance defers to you"
note "Concierge asks the PS to broker an access token, citing its mission."
note "Layer 1 (keyword evaluator) inspects the request; anything it can't"
note "confidently allow escalates to the person — deny by default, not allow."

status=$(agent_req POST /token -H 'Content-Type: application/json' -d "{
  \"resource_token\": \"demo-resource-token-for-bookings-api\",
  \"justification\": \"Confirm Friday reservation at the restaurant chosen by my person\",
  \"mission\": ${MISSION_REF}
}")
[ "$status" = "202" ] || {
  show_json "$WORK/body"
  fail "POST /token → HTTP ${status} (expected 202 deferred)"
}
TOKEN_PENDING=$(jget "$WORK/body" pending_id)
TOKEN_CODE=$(jget "$WORK/body" code)
ok "202 deferred — requirement=interaction, interaction code ${TOKEN_CODE}"
show_json "$WORK/body"

your_turn "Review the request on the consent page and Approve it." \
  "${BASE}/ui/consent.html?code=${TOKEN_CODE}"
[ "$AUTO" = "1" ] && consent_decision "$TOKEN_CODE" '{"approved": true}'

note "Concierge polls the pending request…"
poll_until_done "/pending/${TOKEN_PENDING}" -H "X-AAuth-Agent-Id: ${AGENT_ID}"
[ "$POLL_STATUS" = "200" ] || {
  show_json "$WORK/body"
  fail "token poll → HTTP ${POLL_STATUS}"
}
ok "Consent granted → token delivered:"
show_json "$WORK/body"
note "(Insecure-dev issues a fake federated token; in secure mode this is a"
note " real Ed25519-signed aa-auth+jwt and appears under Issued tokens.)"
pause

# ═══════════════════════════════════════════════════════════════════ Act 4
act "Act 4 — The agent asks a question mid-mission"
note "Consent is a two-way street: agents can pause and ask their person."

status=$(agent_req POST /interaction -H 'Content-Type: application/json' -d "{
  \"type\": \"question\",
  \"question\": \"Two options fit: 7pm at Lucia's or 8pm at The Anchor. Which one?\",
  \"description\": \"Need a decision before booking\",
  \"mission\": ${MISSION_REF}
}")
[ "$status" = "202" ] || {
  show_json "$WORK/body"
  fail "POST /interaction → HTTP ${status}"
}
QUESTION_PENDING=$(jget "$WORK/body" pending_id)
QUESTION_CODE=$(jget "$WORK/body" code)
ok "202 deferred — the question is waiting on the consent page."

your_turn "Answer the agent's question, then Send answer." \
  "${BASE}/ui/consent.html?code=${QUESTION_CODE}"
[ "$AUTO" = "1" ] && consent_decision "$QUESTION_CODE" \
  '{"approved": true, "answer_text": "7pm at Lucia'\''s, please"}'

poll_until_done "/pending/${QUESTION_PENDING}" -H "X-AAuth-Agent-Id: ${AGENT_ID}"
[ "$POLL_STATUS" = "200" ] || {
  show_json "$WORK/body"
  fail "question poll → HTTP ${POLL_STATUS}"
}
ok "The person's answer, delivered to the agent:"
show_json "$WORK/body"
pause

# ═══════════════════════════════════════════════════════════════════ Act 5
act "Act 5 — Permission gating: approved tools vs. everything else"
note "Layer 2: actions named in the mission's approved_tools are granted"
note "immediately; anything else defers through the same consent machinery."

status=$(agent_req POST /permission -H 'Content-Type: application/json' -d "{
  \"action\": \"book_table\",
  \"description\": \"Reserve Friday 7pm at Lucia's\",
  \"mission\": ${MISSION_REF}
}")
[ "$status" = "200" ] || {
  show_json "$WORK/body"
  fail "POST /permission (book_table) → HTTP ${status}"
}
ok "book_table is an approved tool → granted on the spot:"
show_json "$WORK/body"

status=$(agent_req POST /permission -H 'Content-Type: application/json' -d "{
  \"action\": \"charge_credit_card\",
  \"description\": \"Prepay a £50 deposit to hold the table\",
  \"parameters\": {\"amount\": \"£50\", \"merchant\": \"Lucia's\"},
  \"mission\": ${MISSION_REF}
}")
[ "$status" = "202" ] || {
  show_json "$WORK/body"
  fail "POST /permission (charge) → HTTP ${status} (expected 202)"
}
CHARGE_PENDING=$(jget "$WORK/body" pending_id)
CHARGE_CODE=$(jget "$WORK/body" code)
ok "charge_credit_card is NOT in the mission → 202 deferred."

your_turn "This one deserves a 'no' — Deny it on the consent page." \
  "${BASE}/ui/consent.html?code=${CHARGE_CODE}"
[ "$AUTO" = "1" ] && consent_decision "$CHARGE_CODE" '{"approved": false}'

poll_until_done "/pending/${CHARGE_PENDING}" -H "X-AAuth-Agent-Id: ${AGENT_ID}"
VERDICT=$([ "$POLL_STATUS" = "200" ] && jget "$WORK/body" permission || echo "error-${POLL_STATUS}")
if [ "$VERDICT" = "denied" ]; then
  ok "Denied — the agent gets a clean, auditable refusal, not a token:"
else
  note "(Outcome: ${VERDICT})"
fi
show_json "$WORK/body"
pause

# ═══════════════════════════════════════════════════════════════════ Act 6
act "Act 6 — Audit: the mission remembers everything"
status=$(agent_req POST /audit -H 'Content-Type: application/json' -d "{
  \"mission\": ${MISSION_REF},
  \"action\": \"book_table\",
  \"description\": \"Booked Friday 7pm for two at Lucia's\",
  \"result\": {\"confirmation\": \"LUC-4417\", \"time\": \"Friday 19:00\"}
}")
[ "$status" = "201" ] || {
  show_json "$WORK/body"
  fail "POST /audit → HTTP ${status}"
}
ok "Audit entry recorded (201)."

status=$(req GET "/missions/${MISSION_S256}" -H "Authorization: Bearer ${ADMIN_TOKEN}")
[ "$status" = "200" ] || fail "GET /missions/{s256} → HTTP ${status}"
ok "The mission log — evaluator verdicts, consent, and audits in one trail:"
python3 - "$WORK/body" <<'PY'
import json, sys
detail = json.load(open(sys.argv[1]))
for entry in detail.get("log", []):
    payload = entry.get("payload") or {}
    extra = payload.get("decision") or payload.get("action") or ""
    print(f"    {entry['ts']}  {entry['kind']:<16} {extra}")
PY
note "(Also visible in the console: Missions tab → Detail.)"
pause

# ═══════════════════════════════════════════════════════════════════ Finale
act "Finale"
ok "One origin served: discovery, registration, mission, brokered consent,"
note "  a mid-mission question, permission gating, and a complete audit trail —"
note "  with the person in the loop at every escalation."
note ""
note "Where to go next:"
note "  • Secure mode: demo/run-secure-demo.sh + demo/secure-demo.sh — same flows"
note "    with real RFC 9421 signatures and a genuine aa-auth+jwt."
note "  • Persistence: set AAUTH_DATABASE_URL (SQLite/Postgres) and restart —"
note "    missions and bindings survive."
note "  • Consoles: ${BASE}/ui/portal.html (token: demo-admin)"
bold ""
bold "  fin."
