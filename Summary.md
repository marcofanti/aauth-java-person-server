# aauth-java-person-server

**Source:** (authored locally — not cloned)
**Stack:** Java 26 (Maven, Spring Boot WebMVC)

Java port of `aauth-person-server` (the Python reference implementation of the AAuth
Protocol's Person Server + Agent Server + unified portal, IETF draft
`draft-hardt-aauth-protocol`). Built on the local `aauth-java-library` for all RFC 9421 /
Signature-Key / JWT work. Completes the all-Java AAuth stack used by `aauth-full-java-demo`,
which previously required the Python Person Server. Plan: `docs/PLAN.md`; status:
`docs/PROGRESS.md`.

## Running it

```bash
cd aauth-java-person-server
mvn verify          # build + tests + coverage gate
./run-server.sh     # unified portal on 127.0.0.1:8765 (SQLite, real signatures)
```

Portal UI at `http://127.0.0.1:8765/ui/index.html`; the Python repo's walkthrough
scripts run unchanged against it (see README § Interop).
