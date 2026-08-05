# Demo

A guided, presentable walkthrough of the AAuth Java Person Server: one origin
serving the Person Server, the Agent Server, and the portal UI, with a scripted
agent on one side and you (the person) on the other.

## Run it

Two terminals:

```bash
# Terminal 1 — the server (in-memory, insecure-dev, fixed demo tokens)
demo/run-demo.sh

# Terminal 2 — the show
demo/demo.sh            # interactive: you approve things in the UI
OPEN=1 demo/demo.sh     # same, and macOS opens each UI page for you
AUTO=1 demo/demo.sh     # unattended: approvals happen over the API (smoke test)
```

Browser: `http://127.0.0.1:8765/ui/portal.html`, console token `demo-admin`.

Requirements: JDK 26 + Maven (first run builds the jar), `curl`, `openssl`,
`python3`. State is in-memory — restart `run-demo.sh` for a clean slate.

## The story ("Concierge")

An agent that books restaurants, walked through every AAuth touchpoint:

| Act | What happens | What to say |
|---|---|---|
| 0 | Fetch both `/.well-known` docs | One origin, two roles: Agent Server (identity) + Person Server (authority). Agents bootstrap from metadata, no out-of-band config. |
| 1 | Ed25519 keys → `POST /register` → 202 → **you approve in Registrations** → poll → agent token | Agents don't get accounts, they get *bindings*: a human vouches for a key. The 202/poll pattern repeats everywhere — agents wait, humans decide. |
| 2 | `POST /mission` → canonical blob; script recomputes `s256` and matches the Missions tab | The mission is a human-readable contract. Its identity is the hash of the exact bytes — agent, server, and UI all point at the same thing. |
| 3 | `POST /token` + mission → keyword evaluator escalates → **you approve on the consent page** → poll → token | Governance layer 1. Default-deny: what the evaluator can't confidently allow goes to the person. The consent page shows mission, justification, and the evaluator's note. |
| 4 | `POST /interaction` (question) → **you type an answer** → poll returns it | Consent is two-way — agents can stop and ask. The answer travels back through the same pending machinery. |
| 5 | `POST /permission`: `book_table` granted instantly; `charge_credit_card` defers → **you deny it** | Governance layer 2. Tools named in the mission are pre-approved; everything else needs a human. Denial is a first-class, auditable outcome. |
| 6 | `POST /audit` → mission log shows evaluator verdicts, consents, audits | Every decision in one trail, queryable by mission hash — also in the console under Missions → Detail. |

Presenter tips: the script pauses (⏎) between acts and prints a highlighted
**YOUR TURN** line with the exact URL whenever the UI is needed. Keep the
console open on the Pending tab — new requests appear there as the script
creates them.

## Demo mode vs. secure mode

`run-demo.sh` sets `AAUTH_PS_INSECURE_DEV=true` / `AAUTH_AS_INSECURE_DEV=true`
so the scripted agent can use placeholder signatures and a stub identity
header, and brokered tokens come from the fake federator (`aa-auth.fake.*`).
The flows, routes, status codes, and UI are identical to secure mode.
Never expose insecure-dev beyond localhost.

## Secure mode

The same two-terminal shape, everything verified for real:

```bash
demo/run-secure-demo.sh            # terminal 1: secure server (both INSECURE_DEV=false)
demo/secure-demo.sh                # terminal 2: four acts; you approve one registration
AUTO=1 demo/secure-demo.sh         # unattended smoke test
```

Acts: prove stub identities get 401 → real hwk-signed registration, approval,
and jkt-jwt refresh → a mode-3 agent (own resource metadata + JWKS, `scheme=jwt`
`POST /token`) waits for **your** approval and receives a genuine Ed25519-signed
`aa-auth+jwt` → the console's Issued tokens tab shows the record.

The signing agents are the Python reference repo's client scripts run unchanged
(live interop proof), so this mode needs a sibling clone of
[aauth-person-server](https://github.com/christian-posta/aauth-person-server) at
`../aauth-person-server` (or `PS_REPO=…`); its virtualenv is created on first
run. `PORT=…` / `BASE=…` relocate both scripts if 8765 is taken.

## Slides

`slides/aauth-java-person-server.pptx` — deck for presenting the project and
this demo (source HTML in `slides/`).
