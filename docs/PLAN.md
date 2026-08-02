# AAuth Java Person Server — Implementation Plan

Approved 2026-07-30. Port of [aauth-person-server](../../aauth-person-server) — the reference
Person Server + Agent Server + unified portal for the AAuth protocol
([github.com/dickhardt/AAuth](https://github.com/dickhardt/AAuth)). Follows the porting
conventions established by [aauth-java-library](../../aauth-java-library) (phased TDD port,
PROGRESS.md decision log, final security review).

## Why

[aauth-full-java-demo](../../aauth-full-java-demo) is all-Java except the Person Server, which
is still the Python `aauth-person-server`. This port completes the all-Java stack; the demo's
mode-cycling integration suite is the acceptance test.

## Coordinates and layout

Single-module Maven project (`io.github.marcofanti:aauth-java-person-server`), JDK 26,
Spring Boot WebMVC — same stack and guardrails as the demo backend (Spotless/Palantir,
JaCoCo 80% line gate, enforcer, `-Xlint:all,-serial,-processing -Werror`).

Java packages under `io.github.marcofanti.aauth.personserver` mirror the Python layout:

| Java package | Python source | Responsibility |
|---|---|---|
| `.model` | `ps/models.py`, `agent_server/models.py` | records + store interfaces + exceptions |
| `.ps` | `ps/impl`, `ps/service` | mission lifecycle, pending/consent, governance, token broker |
| `.ps.web` | `ps/api`, `ps/http` | PS controllers, settings, error mapping, signature auth |
| `.agentserver` | `agent_server/impl`, `agent_server/service` | registrations, bindings, token factory |
| `.agentserver.web` | `agent_server/api`, `agent_server/http` | AS controllers, settings |
| `.portal` | `portal/http` | unified app wiring, merged JWKS |
| `.persistence` | `persistence/` | Flyway schema, JPA stores, dual-mode wiring |

Static UI (`portal/ui`, `ps/http/static`, `agent_server/ui`) is copied verbatim into
`src/main/resources/static/...` and served path-compatibly.

## Design decisions

- **Same env vars.** `AAUTH_PS_*` / `AAUTH_AS_*` / `AAUTH_DATABASE_URL` bind via
  `@ConfigurationProperties` with exact Python parity so the walkthrough scripts and
  `run-demo.sh` work unchanged.
- **All crypto via aauth-java-library.** RFC 9421 verification, Signature-Key schemes
  (`hwk`, `jkt-jwt`, `jwt`), JWK/JWKS, JWT create/verify come from
  `io.github.marcofanti:aauth`; nothing is reimplemented.
- **One jar, three apps.** The unified portal is the default; standalone PS-only and AS-only
  modes are Spring profiles selecting which controller sets load (parity with the three
  uvicorn entrypoints).
- **Dual-mode state.** In-memory store implementations by default; when a database URL is
  set, JPA stores against one shared schema (`ps_*` / `as_*` tables, Flyway-managed).
  H2 (file) for local dev, PostgreSQL optional. Replay protection is always in-process.
- **Wire parity over Java taste.** Error bodies, status codes (202 deferred flows, 401
  challenges), pending polling semantics, and JWT claim shapes must match the Python server
  byte-for-byte where scripts assert on them.
- **Portal path split preserved.** Registration polling is `GET /register/pending/{id}` on
  the portal, `GET /pending/{id}` standalone; PS consent polling owns `/pending/{id}`.

## Governance layers (MISSIONS.md)

Both PS-local layers are in scope:

1. `MissionEvaluator` interface + keyword implementation gating `POST /token`
   (allow / escalate / clarify / deny).
2. Approved-tools gating on `POST /permission` — actions in the mission's `approved_tools`
   grant immediately; others defer through the same pending/consent machinery.

## Phases

1. **Scaffolding + guardrails** — POM, quality gates, docs, git, smoke test.
2. **Domain model** — records, store interfaces, exception hierarchy with Python error codes.
3. **PS core (in-memory)** — missions, pending/consent state machine, governance,
   keyword evaluator, token broker (`aa-auth+jwt` issuance).
4. **PS HTTP** — all PS routes, insecure-dev vs real HWK/`scheme=jwt` verification,
   `.well-known/aauth-person.json`, JWKS, trust registry.
5. **Agent Server** — registration flow, stable-key bindings, `hwk` register / `jkt-jwt`
   refresh, person admin routes, agent token factory with `cnf.jwk` rotation.
6. **Unified portal** — both stacks on one origin, merged JWKS, copied UI, pending-path split.
7. **Persistence** — Flyway schema, JPA stores, dual-mode wiring, engine shutdown.
8. **Interop + acceptance** — run `ps-demo.sh`, `hwk-ps-client.sh`,
   `agent-server-walkthrough.sh`, `agent-server-signed-walkthrough.py` unchanged against the
   Java portal in both security modes; port the 7 pytest suites; point aauth-full-java-demo
   at the Java PS and run `run-tests.sh`; java-reviewer security pass; README.

Each phase is TDD-ordered: port the corresponding Python tests first, then implement.

Deferred (not in scope unless requested): OTel/Jaeger instrumentation; SQLite DB-file
compatibility with the Python server; Alembic interop.

Progress and deviations are tracked in [PROGRESS.md](PROGRESS.md).
