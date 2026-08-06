# Progress Log

Status of each phase from [PLAN.md](PLAN.md). Updated as work lands.

| Phase | Scope | Status |
|---|---|---|
| 1 | Scaffolding: POM, quality gates, docs, git | done |
| 2 | Domain model, store interfaces, exceptions | done |
| 3 | PS core: missions, pending/consent, governance, token broker | done — 83 tests; real aa-auth+jwt round-trip vs library |
| 4 | PS HTTP: routes, signature verification, metadata, trust | done — smoke + mode-3 signed suites pass (108 tests) |
| 5 | Agent Server: registration, bindings, refresh | done — signed register/approve/poll/refresh (jkt-jwt) suites pass |
| 6 | Unified portal + static UI | done — merged JWKS, /register/pending split, cross-token auth, full register→consent→aa-auth+jwt flow test |
| 7 | Persistence: JDBC dual-mode (SQLite/Postgres) | done — restart-survival tests over one SQLite file |
| 8 | Interop scripts, ported tests, demo acceptance, review | done — acceptance run green 2026-08-02 (see below) |

## Acceptance run (2026-08-02)

The aauth-full-java-demo mode-cycling suite ran against this Java Person Server —
`AAUTH_PS_IMPL=java scripts/run-tests.sh all` (the switch was added to that repo's
`scripts/run-person-server.sh`; Python remains its default). All five modes passed:
off, hwk, jwt, auth-token, and consent — covering registration + approval, aa-agent+jwt
issuance, autonomous resource-token exchange, and deferred require:user consent, all in
secure mode (real RFC 9421 signatures, real signed tokens). The Java run uses its own
SQLite file (`aauth-demo.db`) and signing keys, since the Python repo's Alembic DB and
key layout are not byte-compatible. With this, every phase of PLAN.md is complete.
Rerun 2026-08-02 after the aauth-java-library 0.1.1 bump: all five modes pass on the
0.1.1-built jar as well.

## Security review (2026-07-30)

A java-reviewer pass compared every security-critical path against the Python reference
(auth dispatch, token issuance, broker/consent secure branches, pending semantics,
registration/binding flows, JDBC stores). Verdict: line-for-line parity, no CRITICAL
findings, no injection/scheme-confusion/info-leak divergences. One MEDIUM finding, fixed
in the same session:

1. **MEDIUM — `MemoryPendingStore` thread-safety**: Python's store is safe under
   uvicorn's single-threaded event loop; under Tomcat's thread pool, `getPending`,
   `checkTtl`, `setCallbackUrl`, `replaceTokenRequest`, and `getRecord` were
   unsynchronized while sharing mutable `PendingRecord` state with synchronized
   mutators, and brokers write fields on records returned by `getRecord`. Fixed:
   those methods are now synchronized, all mutable `PendingRecord` fields are
   `volatile`, and `clarificationResponses` is a `CopyOnWriteArrayList`.

Noted, not a divergence: bearer-token comparisons are not constant-time in either
implementation (shared characteristic of the reference).

## UI rewrite (2026-07-31)

The `ui-portal/`, `ui-ps/`, `ui-as/` resources — previously copied verbatim from the
unlicensed upstream Python repo — were replaced with an original implementation. Method:
the browser-facing API surface was documented in [UI-CONTRACT.md](UI-CONTRACT.md) by
reading this repo's own controllers (not the upstream markup), and every page, stylesheet,
JS helper, and SVG mark was authored fresh from that contract. Load-bearing filenames
(`index.html`, `consent.html`, `portal.html`) and `/ui/**` paths are unchanged.

While extracting the contract, a parity gap surfaced and was fixed: the Python portal's
`GET /admin/issued-tokens` had never been ported. It now exists as the portal-only
`PortalAdminController` (admin bearer auth, `IssuedTokenStore.listIssued()`), covered by
`PortalHttpTest` including an end-of-flow assertion that a real issuance appears there.

Verified: `mvn verify` green (tests, JaCoCo 80%, Spotless), plus a live browser pass —
portal console pending/missions tabs, then a full agent `question` interaction answered
through `/ui/consent.html` and picked up by the agent's `GET /pending/{id}` poll.

## Demo package (2026-08-02)

`demo/` adds a presentable end-to-end walkthrough: `run-demo.sh` starts the portal in
insecure-dev with fixed tokens and the keyword evaluator; `demo.sh` plays a curl+openssl
agent ("Concierge") through seven acts — discovery, registration, mission (with client-side
s256 verification), evaluator-escalated token consent, a mid-mission question, approved-tools
permission gating with a denial, and the audit trail. Interactive mode pauses for UI
approvals; `AUTO=1` performs them over the API as a self-checking smoke test (verified
green). `demo/slides/` holds a 12-slide deck: `slides.html` (authored source, Adobe Fonts)
and the derived `aauth-java-person-server.pptx`.

## Decision log

- **2026-08-05 — Licensing resolved**: this repo relicensed MIT → Apache-2.0
  (`LICENSE` + `NOTICE`), and upstream `christian-posta/aauth-person-server` added
  Apache-2.0 the same day (agreed by email). The behavioral-port caveat that had
  gated publishing is retired; the repo is public at
  github.com/marcofanti/aauth-java-person-server.
- **2026-08-02 — aauth-java-library 0.1.1**: bumped from the `0.1.0-SNAPSHOT` local
  snapshot to the released `0.1.1` (`../aauth-java-library` tag `release: 0.1.1`).
  `mvn verify` green: 132 tests, no source changes needed.
- **2026-07-30 — Stack**: Spring Boot 4.1.0 (WebMVC) on JDK 26 (Corretto local), matching
  aauth-full-java-demo's parent POM; depends on locally installed
  `io.github.marcofanti:aauth:0.1.0-SNAPSHOT`.
- **2026-07-30 — Single module**: the Python repo is one installable package with four
  subpackages; a Maven multi-module split adds ceremony without a consumer for the pieces.
  Revisit only if someone needs the PS core as a library.

## Deviations from the Python server

- **Union types → sealed interfaces**: Python's `TokenOutcome`/`MissionOutcome`/
  `PendingPollOutcome`/`PendingStoreValue` `Union`s become sealed marker interfaces so
  route handlers can switch exhaustively.
- **kwargs-heavy dataclasses → builders**: `TokenRequest`, `DeferredResponse`,
  `ConsentContext` get builders; `DeferredResponse.toBuilder()` replaces
  `dataclasses.replace`.
- **Mutable dataclasses → records with withers**: `PendingRegistration.withStatus`,
  `Binding.withRevoked` / `withAddedThumbprint`, `Mission.withState` — stores replace rows
  instead of mutating them.
- **AS exception names**: Python's AS `PendingNotFoundError`/`PendingExpiredError`/
  `PendingDeniedError` collide with PS names only via module paths; Java renames them
  `Registration{NotFound,Expired,Denied}Exception` in the `agentserver` package.
- **PS signing key needs a `.pub` sibling**: the JDK cannot derive an Ed25519 public key
  from a PKCS#8 private key, so `PsSigningService` writes `<path>.pem` (kid comment +
  PKCS#8 PEM, Python-compatible layout) plus `<path>.pem.pub` (base64 X.509). A
  Python-written PEM without the sibling triggers regeneration of a fresh pair.
- **Pending-store port folds in impl extras**: Python splits `PendingRequestStore` (ABC)
  from `MemoryPendingStore` extras (`get_record`, `lookup_code`, create-variants, admin
  lists); the Java `PendingRequestStore` interface includes them so the SQL store swaps in
  everywhere.
- **Canonical mission blob via Jackson**: `Json.CANONICAL` (sorted keys, compact,
  ESCAPE_NON_ASCII) reproduces `json.dumps(obj, sort_keys=True, separators=(",",":"))`
  byte-for-byte for s256 parity.
- **Poll rate-limit clock**: Python uses `time.monotonic()` per record; Java uses
  `System.nanoTime()` with the same 50 ms minimum interval.
- **Settings read env vars directly**: `PsSettings.fromEnv(System.getenv())` with exact
  `AAUTH_PS_*` names — Spring relaxed binding is deliberately not used (underscore/dash
  mapping would silently miss `AAUTH_PS_PUBLIC_ORIGIN`-style names).
- **Raw-body controllers**: agent routes take `byte[]` bodies and parse JSON after
  signature verification (RFC 9421 needs the exact bytes); FastAPI/Pydantic validation
  errors map to the same 400 `invalid_request` on agent paths, 422 `detail` elsewhere.
- **bleach → regex sanitizer**: `Sanitize.markdown` strips disallowed HTML tags (keeping
  text) and removes script/style blocks; same allowlist as the Python bleach call, without
  a new dependency. Plain-text inputs (all demo traffic) pass through unchanged.
- **Spring Boot 4 MockMvc**: `@AutoConfigureMockMvc` moved to
  `spring-boot-webmvc-test` (`org.springframework.boot.webmvc.test.autoconfigure`).
- **One jar, three apps via Spring profiles**: PS web components load on
  `default`/`portal`/`ps`, AS components on `default`/`portal`/`agent-server`; the
  standalone AS-only poll path `GET /pending/{id}` and AS-only JWKS live in an
  `agent-server`-profile controller. `SPRING_PROFILES_ACTIVE=ps|agent-server` selects a
  standalone server; default is the portal.
- **`AgentTokenFactory` folded into `AsSigningService`**: the Python factory is a
  one-method wrapper; Java issues tokens directly from the signing service.
- **Python `datetime.isoformat()` timestamps** (`+00:00` offset, microseconds) are
  reproduced by `PyIso.format` for registration/binding rows and `expires_at`.
- **JDBC instead of SQLAlchemy/JPA, `init_db` instead of Flyway/Alembic**: plain
  JdbcTemplate stores over the same `ps_*`/`as_*` table split, schema created with
  idempotent DDL on startup (the Python dev-mode `create_all` path). The DB file is not
  byte-compatible with the Python server's Alembic schema (out of scope per PLAN);
  pending rows serialize the whole record as JSON (`record_json`), like the Python serde.
  SQLAlchemy-style `AAUTH_DATABASE_URL` values (`sqlite:///…`, `postgresql+psycopg://…`)
  are translated to JDBC; SQLite runs with a single-connection pool.
- **SQL mode keeps memory brokers** (Python parity): `getRecord` returns detached
  snapshots, so post-create field mutations (verified claims, evaluator reason) are not
  persisted — consent re-verifies the resource token, matching the Python behavior.
- **Boot `DataSourceAutoConfiguration` excluded**: database mode is driven by
  `AAUTH_DATABASE_URL`, not `spring.datasource.*`.
