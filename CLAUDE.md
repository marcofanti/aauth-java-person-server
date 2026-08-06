# aauth-java-person-server

Java port of `../aauth-person-server` (AAuth Person Server + Agent Server + unified portal).
The Python server is the reference implementation — mirror its behavior, route surface,
error bodies, env vars, and pending/consent semantics. Wire parity beats Java idiom when
they conflict: the Python repo's walkthrough scripts must pass unchanged against this server.

## Structure

Single Maven module `io.github.marcofanti:aauth-java-person-server`, packages under
`io.github.marcofanti.aauth.personserver` (`.model`, `.ps`, `.ps.web`, `.agentserver`,
`.agentserver.web`, `.portal`, `.persistence`). Static UI under
`src/main/resources/ui-portal/`, `ui-ps/`, `ui-as/` (served per Spring profile) is an
original implementation authored against `docs/UI-CONTRACT.md` — keep that contract in
sync with the controllers, and never copy upstream UI markup into these directories.

## License

Apache-2.0 (`LICENSE` + `NOTICE`, Copyright 2026 Marco Fanti; the POM's `<licenses>`
block declares the same), switched from MIT on 2026-08-05 to match the license the
upstream author agreed to adopt for the Python reference. Note `../aauth-java-library`
and `../aauth-full-java-demo` are still MIT — the licenses are compatible in both
directions. The upstream `christian-posta/aauth-person-server` is Apache-2.0 as of
2026-08-05, so the long-standing behavioral-port caveat is retired: both sides of the
port are now cleanly licensed. The verbatim-copied `ui-*` files were
replaced on 2026-07-31 with an original UI authored from `docs/UI-CONTRACT.md` (derived
from this repo's own controllers). Published 2026-08-02 to
github.com/marcofanti/aauth-java-person-server as a squashed single-root history so the
copied UI never appears in public history; the pre-publish full history lives only on
the local `pre-publish-history` branch — never push it.

## Rules

- JDK 26 (`--release 26`), Spring Boot WebMVC, same stack as `../aauth-full-java-demo`.
- All RFC 9421 / Signature-Key / JWT work goes through `io.github.marcofanti:aauth`
  (0.1.1, locally installed from `../aauth-java-library`) — never reimplement crypto.
- Build: `mvn verify` (tests, JaCoCo 80% line gate, Spotless check).
- Format: `mvn spotless:apply` (Palantir) before committing.
- Zero warnings: `-Xlint:all,-serial,-processing -Werror`.
- Immutable records for domain values; interfaces + in-memory impls for stores.
- Env vars must match the Python server exactly (`AAUTH_PS_*`, `AAUTH_AS_*`,
  `AAUTH_DATABASE_URL`).
- TDD: port the corresponding Python tests first, then implement.

## Docs to keep current

- `docs/PLAN.md` — the approved implementation plan.
- `docs/PROGRESS.md` — phase status, decision log, deviations from the Python server.
  Update both when completing a phase or making a design decision.
