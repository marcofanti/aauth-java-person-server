# AAuth Person Server (Java)

[![ci](https://github.com/marcofanti/aauth-java-person-server/actions/workflows/ci.yml/badge.svg)](https://github.com/marcofanti/aauth-java-person-server/actions/workflows/ci.yml)

Java port of Christian Posta's
[aauth-person-server](https://github.com/christian-posta/aauth-person-server) reference
implementation (Apache-2.0, as is this port): a Person Server, an Agent Server, and a
unified portal per the AAuth
protocol ([github.com/dickhardt/AAuth](https://github.com/dickhardt/AAuth)), built on
[aauth-java-library](https://github.com/marcofanti/aauth-java-library) for all
RFC 9421 / Signature-Key / JWT work.
Route surface, error bodies, env vars, and pending/consent semantics mirror the Python
reference; its walkthrough scripts run unchanged against this server.

Plan: [docs/PLAN.md](docs/PLAN.md) · status and deviations: [docs/PROGRESS.md](docs/PROGRESS.md)

## Build and test

```bash
mvn verify          # tests, JaCoCo 80% line gate, Spotless check
```

## Run

One jar, three apps, selected by Spring profile (default = unified portal):

```bash
./run-server.sh     # portal on 127.0.0.1:8765, SQLite persistence, real signatures
```

Dev mode (in-memory state, stub agent identification):

```bash
AAUTH_PS_PUBLIC_ORIGIN=http://127.0.0.1:8765 AAUTH_AS_PUBLIC_ORIGIN=http://127.0.0.1:8765 \
AAUTH_PS_ADMIN_TOKEN=mytoken AAUTH_AS_PERSON_TOKEN=mytoken \
AAUTH_PS_INSECURE_DEV=true AAUTH_AS_INSECURE_DEV=true \
java -jar target/aauth-java-person-server-0.1.0-SNAPSHOT.jar --server.port=8765
```

Standalone servers: add `--spring.profiles.active=ps` (Person Server only, original PS
console under `/ui/`) or `--spring.profiles.active=agent-server` (Agent Server only, poll
path `GET /pending/{id}`, AS console under `/ui/`).

Environment variables are the Python server's, unchanged: `AAUTH_PS_*`, `AAUTH_AS_*`, and
`AAUTH_DATABASE_URL` (SQLAlchemy-style `sqlite:///…` or `postgresql+psycopg://…`). See the
[Python README](https://github.com/christian-posta/aauth-person-server#readme) for the
full tables.

Portal UI: `http://127.0.0.1:8765/ui/index.html` (sign in with the admin/person token).

## Demo

A guided, presentable walkthrough — a scripted agent on one side, you approving in the
portal UI on the other — plus a slide deck. See [demo/README.md](demo/README.md):

```bash
demo/run-demo.sh          # terminal 1: the server (in-memory, demo tokens)
demo/demo.sh              # terminal 2: seven acts, pauses for your UI turns
AUTO=1 demo/demo.sh       # unattended smoke test
```

Slides: `demo/slides/aauth-java-person-server.pptx` (source: `demo/slides/slides.html`).

## Interop with the Python repo (verified 2026-07-30; re-verified 2026-08-06 on draft-10)

Draft-10 note: `ps-token-mode3.py` needs aauth-java-library ≥ 0.2.3 — earlier 0.2.x
reject the script's legacy `alg: EdDSA` resource JWKS (fixed by
[aauth-java-library#15](https://github.com/marcofanti/aauth-java-library/pull/15),
first shipped in 0.2.3). This repo pins 0.2.3, so the full suite passes.

Run from a sibling clone of
[aauth-person-server](https://github.com/christian-posta/aauth-person-server) at
`../aauth-person-server`, with this server on 8765:

- `BASE_URL=http://127.0.0.1:8765 ./scripts/ps-demo.sh` — insecure-dev PS flow ✓
- `.venv/bin/python scripts/agent-server-signed-walkthrough.py --base http://127.0.0.1:8765
  --person-token mytoken --pending-prefix /register/pending` — real-signature registration,
  approval, agent token, jkt-jwt refresh ✓ (`AAUTH_AS_INSECURE_DEV=false`)
- `.venv/bin/python scripts/ps-token-mode3.py --base http://127.0.0.1:8765` — mode-3 secure
  `POST /token` returning a real `aa-auth+jwt` ✓ (`AAUTH_PS_INSECURE_DEV=false`,
  `AAUTH_AS_INSECURE_DEV=true`; approve the registration via UI or API)
- `./scripts/hwk-ps-client.sh --base-url http://127.0.0.1:8765 --permission-action WebSearch
  --audit` — HWK-signed `/mission`, `/permission`, `/audit` ✓; `POST /token` returns the
  documented 401 (`scheme=jwt` required in secure mode), identical to the Python server
- `./scripts/agent-server-walkthrough.sh` — stale upstream: it sends `label` instead of the
  now-required `agent_name` and fails identically against the Python server
