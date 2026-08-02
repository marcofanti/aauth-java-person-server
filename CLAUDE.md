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

MIT (`LICENSE`, Copyright © 2026 Marco Fanti), matching `../aauth-java-library` and
`../aauth-full-java-demo`; the POM's `<licenses>` block declares the same. The upstream
Python `../aauth-person-server` has **no license file** (unlike Christian Posta's
MIT-licensed `aauth-python-library`). The verbatim-copied `ui-*` files were replaced
on 2026-07-31 with an original UI authored from `docs/UI-CONTRACT.md` (derived from
this repo's own controllers), which removes the clearest copying concern. Published
2026-08-02 to github.com/marcofanti/aauth-java-person-server as a squashed single-root
history so the copied UI never appears in public history; the pre-publish full history
lives only on the local `pre-publish-history` branch — never push it. Remaining caveat:
the server is a behavioral port of an unlicensed upstream; getting upstream permission
or an upstream license is still the cleanest path for anything beyond reference use.

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
