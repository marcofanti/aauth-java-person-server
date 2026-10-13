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

## Protocol version

The `draft11` branch speaks AAuth draft-11 (Signature-Keys draft-09) and still accepts
draft-10 clients, so the Python walkthroughs below keep working. Draft-11 clients discover
`auth_token_endpoint` (`/auth-token`), `person_token_endpoint` (`/person-token`),
`mission_endpoint` (`/agent-missions`) and `revocation_endpoint` (`/revoke`); draft-10
clients keep `/token` and `/mission`. Four-party federation, call chaining and the
revocation cascade are draft-11 only. Status per checklist item:
[docs/PLAN-draft11.md](docs/PLAN-draft11.md). The branch builds against
aauth-java-library `0.3.0-SNAPSHOT` (install it locally from the library's `draft11`
branch); CI stays red until that version is released.

## Build and test

```bash
mvn verify          # tests, JaCoCo 80% line gate, Spotless check
```

## Run

One jar, three apps, selected by Spring profile (default = unified portal):

```bash
./run-server.sh     # https://ps.uma.lab + https://as.uma.lab, SQLite persistence, real signatures
```

### Local HTTPS (required for draft-11)

Draft-11 server identifiers are HTTPS origins without a port, so the portal listens on
`127.0.0.1:8765` behind a local Caddy front on `:443`. The Caddyfile in `caddy/` is shared
byte-for-byte with aauth-full-java-demo, and both repos use the same hostnames:

| Hostname | Upstream | Serves |
| --- | --- | --- |
| `ps.uma.lab` | `127.0.0.1:8765` | Person Server |
| `as.uma.lab` | `127.0.0.1:8765` | the portal's Agent Server (same process, own identifier) |
| `sca.uma.lab`, `maa.uma.lab` | `127.0.0.1:9999`, `:9998` | demo resources (aauth-full-java-demo) |

One-time setup:

1. Add `127.0.0.1 ps.uma.lab as.uma.lab sca.uma.lab maa.uma.lab` to `/etc/hosts` (sudo).
2. `brew install caddy mkcert && mkcert -install` (trusts mkcert's local CA).
3. `scripts/setup-tls.sh` creates the `*.uma.lab` certificate and a JVM truststore in
   `~/.local/share/uma-lab-tls/`.

`run-server.sh` and `demo/run-demo.sh` start Caddy through `scripts/run-caddy.sh`, which does
nothing if a Caddy admin API already answers on `localhost:2019` (the other repo may own it).
Stop only the listener (`lsof -ti tcp:8765 -sTCP:LISTEN`); killing every process on the port
also kills Caddy's upstream connections. Don't run the javauma4agents Docker stack at the same
time: its Envoy also binds `:443`. Clients outside the JVM trust the certificate with
`curl --cacert "$(mkcert -CAROOT)/rootCA.pem"` or `SSL_CERT_FILE="$(mkcert -CAROOT)/rootCA.pem"`.

Dev mode (in-memory state, stub agent identification):

```bash
scripts/run-caddy.sh
AAUTH_PS_PUBLIC_ORIGIN=https://ps.uma.lab AAUTH_AS_PUBLIC_ORIGIN=https://as.uma.lab \
AAUTH_PS_ADMIN_TOKEN=mytoken AAUTH_AS_PERSON_TOKEN=mytoken \
AAUTH_PS_INSECURE_DEV=true AAUTH_AS_INSECURE_DEV=true \
java -jar target/aauth-java-person-server-0.1.0-SNAPSHOT.jar --server.address=127.0.0.1 --server.port=8765
```

Standalone servers: add `--spring.profiles.active=ps` (Person Server only, original PS
console under `/ui/`) or `--spring.profiles.active=agent-server` (Agent Server only, poll
path `GET /pending/{id}`, AS console under `/ui/`).

Environment variables are the Python server's, unchanged: `AAUTH_PS_*`, `AAUTH_AS_*`, and
`AAUTH_DATABASE_URL` (SQLAlchemy-style `sqlite:///…` or `postgresql+psycopg://…`). See the
[Python README](https://github.com/christian-posta/aauth-person-server#readme) for the
full tables.

Portal UI: `https://ps.uma.lab/ui/index.html` (sign in with the admin/person token).

## Demo

A guided, presentable walkthrough — a scripted agent on one side, you approving in the
portal UI on the other — plus a slide deck. See [demo/README.md](demo/README.md):

```bash
demo/run-demo.sh          # terminal 1: the server (in-memory, demo tokens)
demo/demo.sh              # terminal 2: seven acts, pauses for your UI turns
AUTO=1 demo/demo.sh       # unattended smoke test
```

Slides: `demo/slides/aauth-java-person-server.pptx` (source: `demo/slides/slides.html`).

## Interop with the Python repo (verified 2026-07-30; re-verified 2026-08-06 on draft-10 and 2026-10-12 on the dual-stack draft-11 branch)

Draft-10 note: `ps-token-mode3.py` needs aauth-java-library ≥ 0.2.3 — earlier 0.2.x
reject the script's legacy `alg: EdDSA` resource JWKS (fixed by
[aauth-java-library#15](https://github.com/marcofanti/aauth-java-library/pull/15),
first shipped in 0.2.3). This repo pins 0.2.3, so the full suite passes.

Run from a sibling clone of
[aauth-person-server](https://github.com/christian-posta/aauth-person-server) at
`../aauth-person-server`, with this server behind the local HTTPS front (see Run) and
`export SSL_CERT_FILE="$(mkcert -CAROOT)/rootCA.pem"` (re-verified over HTTPS 2026-10-12):

- `BASE_URL=https://ps.uma.lab ./scripts/ps-demo.sh` — insecure-dev PS flow ✓
- `.venv/bin/python scripts/agent-server-signed-walkthrough.py --base https://ps.uma.lab
  --person-token mytoken --pending-prefix /register/pending` — real-signature registration,
  approval, agent token, jkt-jwt refresh ✓ (`AAUTH_AS_INSECURE_DEV=false`)
- `.venv/bin/python scripts/ps-token-mode3.py --base https://ps.uma.lab` — mode-3 secure
  `POST /token` returning a real `aa-auth+jwt` ✓ (`AAUTH_PS_INSECURE_DEV=false`,
  `AAUTH_AS_INSECURE_DEV=true`; approve the registration via UI or API)
- `./scripts/hwk-ps-client.sh --base-url https://ps.uma.lab --permission-action WebSearch
  --audit` — HWK-signed `/mission`, `/permission`, `/audit` ✓; `POST /token` returns the
  documented 401 (`scheme=jwt` required in secure mode), identical to the Python server
- `./scripts/agent-server-walkthrough.sh` — stale upstream: it sends `label` instead of the
  now-required `agent_name` and fails identically against the Python server
