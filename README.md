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

This server speaks AAuth draft-11 (Signature-Keys draft-09) and still accepts draft-10
clients that use fully-specified keys. The Python reference's signed draft-10 scripts are
refused until it moves to `aauth` 0.5.x; see Interop below. Draft-11 clients discover
`auth_token_endpoint` (`/auth-token`), `person_token_endpoint` (`/person-token`),
`mission_endpoint` (`/agent-missions`) and `revocation_endpoint` (`/revoke`); draft-10
clients keep `/token` and `/mission`. Four-party federation, call chaining and the
revocation cascade are draft-11 only. Status per checklist item:
[docs/PLAN-draft11.md](docs/PLAN-draft11.md). Built on aauth-java-library `0.3.0`
(strict draft-11).

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

One variable is Java-only. `AAUTH_PS_EGRESS_ALLOW_HOSTS` takes comma-separated host names or
`*.suffix` wildcards. Outbound fetches (metadata, JWKS, federation, revocation) go only to
HTTPS URLs whose host does not resolve to a loopback, private, link-local, CGNAT or
unique-local address. Listed hosts skip that check. The run scripts set `*.uma.lab` for the
local HTTPS setup.

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

## Interop with the Python repo

**Status since library 0.3.0 (2026-10-13):** this server builds on the strict draft-11
library (`0.3.0`). That library accepts only fully-specified `Ed25519`/`ES256`/`ES384` keys and
JWTs. The Python reference server's scripts use the Python `aauth` 0.3.0 library, which labels
Ed25519 keys and JWTs `alg: EdDSA`, so its signed scripts are now refused:

| Script | Result |
| --- | --- |
| `scripts/ps-demo.sh` (insecure-dev, unsigned) | passes |
| `scripts/agent-server-signed-walkthrough.py` | registration signature refused (401) |
| `scripts/hwk-ps-client.sh` | `/mission` signature refused (401) |
| `scripts/ps-token-mode3.py` | registration key refused (400, `EdDSA`) |

Draft-10 requests from clients with fully-specified keys still work, including `demo/demo.sh`.
The signed scripts work again once the Python reference moves to `aauth` 0.5.x. With
library 0.2.3 (before draft-11), all four passed, as verified 2026-07-30 and again 2026-08-06.

Run from a sibling clone of
[aauth-person-server](https://github.com/christian-posta/aauth-person-server) at
`../aauth-person-server`, with this server behind the local HTTPS front (see Run) and
`export SSL_CERT_FILE="$(mkcert -CAROOT)/rootCA.pem"`:

- `BASE_URL=https://ps.uma.lab ./scripts/ps-demo.sh`
- `.venv/bin/python scripts/agent-server-signed-walkthrough.py --base https://ps.uma.lab
  --person-token mytoken --pending-prefix /register/pending` (`AAUTH_AS_INSECURE_DEV=false`)
- `.venv/bin/python scripts/ps-token-mode3.py --base https://ps.uma.lab`
  (`AAUTH_PS_INSECURE_DEV=false`, `AAUTH_AS_INSECURE_DEV=true`)
- `./scripts/hwk-ps-client.sh --base-url https://ps.uma.lab --permission-action WebSearch --audit`
