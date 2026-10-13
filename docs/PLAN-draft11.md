# AAuth draft-11 Migration Plan (Person Server + Agent Server)

Target: `draft-hardt-oauth-aauth-protocol-11` (2026-09-25) + `draft-hardt-httpbis-signature-key-09`.
Checklist source: upstream [`upgrade-10-to-11/person-server.md`](https://github.com/dickhardt/AAuth/tree/main/upgrade-10-to-11)
(IDs `PS-01`…`PS-115`). Library counterpart: `../aauth-java-library/docs/PLAN-draft11.md`.

## Decisions (2026-10-12)

- **Dual-stack.** Emit draft-11; keep accepting draft-10 requests until the Python reference
  reaches -11, so its walkthrough scripts and `aauth-full-java-demo` keep passing. All draft-10
  handling lives in one package, `io.github.marcofanti.aauth.personserver.compat10`, and is deleted
  as a unit when Python reaches -11 — no -10 branches scattered through the -11 code.
- **Build against the library `0.3.0-SNAPSHOT`** from its local `draft11` branch, absorbing library
  churn as it lands. Nothing merges to `main` until the library releases a -11 version.
- **Full checklist**, optional items included.

## Dual-stack detection

A request is draft-10 when it lacks every -11 marker: no `presented_token`, a resource token
without `ps`/`sub`/`presented_jti`, or a `mission` object instead of `mission_s256`. The library's
-11 `ResourceTokens.verify` is strict (requires `ps`, `sub`, `presented_jti`), so `compat10`
verifies -10 resource tokens with the library's public primitives (`Jwts.parse`,
`Jwts.verifySignature`, `Jwk.toPublicKey`) — no crypto is reimplemented.

Metadata publishes both `auth_token_endpoint` and the legacy `token_endpoint` (same URL);
`POST /token` serves both shapes.

## Phases

Each phase: tests first, `mvn verify` green, one PR into the `draft11` branch.

### Phase 1 — Build, metadata, signatures, error codes
- Switch to library `0.3.0-SNAPSHOT`; fix compile breaks (`AuthTokens.Spec` gains `sub`/`ps`,
  loses `agent`/`act`; `ResourceTokens.Spec` reshaped).
- PS-01/02/03/04/05 metadata: `auth_token_endpoint`, `person_token_endpoint`,
  `revocation_endpoint`, `mission_endpoint` semantics, `accept_signature_algs`.
- PS-100..104: Ed25519 everywhere, body-coverage requirement, `invalid_signature` /
  `clock_skew` / `revoked_jwt` codes, no-skew `exp`, `exp − iat ≤ 1h`, `typ` first, uppercase
  agent locals.
- Token-endpoint error code set (§11.9.3): drop `invalid_agent_token`/`expired_agent_token` for
  -11 requests (`Signature-Error` instead); add the new codes.

### Phase 2 — Directed identifiers + person token endpoint
- PS-20: `sub` stable per (person, resource), unique within the issuer, independent of agent/key.
- PS-10..13: `POST /person_token` (jwt-signed): `resource`, `mission_s256`, `subagent_token`,
  optional params; issue `aa-person+jwt` (no `scope`/`account`, `exp` ≤ 1h and ≤ agent token /
  mission `expires_at`); `202 interaction` for a first-use resource with resource metadata in
  consent; `user_unreachable` without `capabilities`; issuance records + per-agent resource rate
  limit.
- PS-70/71: sub-agent person tokens bound to the sub-agent's key; `invalid_subagent_token`.

### Phase 3 — Auth token endpoint (three-party)
- PS-30..36: require `presented_token`; replace resource-token checks (`aud`, `agent_jkt`, `ps`;
  presented token by `typ`, `jti` = `presented_jti`, `sub`/`mission_s256`/`tenant` match); new
  errors; `login_hint` passthrough; new auth token claims (`ps`, `sub`, `mission_s256`, no
  `agent`/`act`); `exp` caps; updated-request invariants.
- PS-40: consent page separates resource-asserted from agent-asserted content.

### Phase 4 — Missions
- PS-80..86: `mission_s256` on person-token/permission/audit/interaction; no `AAuth-Mission`, no
  `approver` in the blob; new approval response (`s256`, `mission` bytes, `capabilities`,
  `person_tokens`); blob members; `{mission_endpoint}/{s256}` with `action`
  (`completion`, `update`) and indistinguishable `mission_not_found`; terminated is final.
- PS-87..90 (optional): mission update, `approved_resources`, `expires_at`, `termination_reason`.
- PS-95/96: interaction types `interaction|payment|question`; out-of-band completion.

### Phase 5 — Revocation (new endpoint)
- PS-110..115: `POST /revoke` (`{jti, exp}`, issuer = verified `jwks_uri` signer, `(iss, jti)`
  keys, no 404, `unsupported_iss`/`rate_limited`); agent-token cascade with 200/202 + signed
  polling; resource-token revocation → `revoked_resource_token` and pending `revoked`; outbound
  revocation signed as a server; downstream outcome handling; retention until `exp` + skew.

### Phase 6 — Four-party federation + call chaining
- PS-50..55: call the AS `auth_token_endpoint`, sign as a server (`jwks_uri;id=…;dwk=…;kid=…`,
  `content-digest` + `content-type` covered), send `presented_token`, new delivery checks,
  relay errors / `as_unreachable`, no `sub` in `requirement=claims`.
- PS-60..64: person tokens from `upstream_token`; upstream verification rewrite; no `act`; no
  intermediary binding; pending downstream ends on upstream expiry.

### Phase 7 — Agent Server, demo, acceptance
- AS side: agent `local` uppercase support, AP revocation of agent tokens against the PS.
- Update `demo/` scripts and `aauth-full-java-demo` to -11; rerun all acceptance modes in both
  -10 (Python) and -11 shapes.

## Exit criteria

All PS-xx items checked; `mvn verify` green; draft-10 Python walkthroughs still pass; -11 demo
flows pass; `compat10` is the only place -10 shapes are handled.

## Status

| Item | State | Notes |
|---|---|---|
| Build on library SNAPSHOT, dual-stack tokens | done | `compat10.Draft10Tokens`, `ResourceTokenVerifier` |
| PS-01 `auth_token_endpoint` | done | `/auth-token`; legacy `token_endpoint` → `/token` |
| PS-02 `person_token_endpoint` | done | `/person-token` |
| PS-05 `accept_signature_algs` | done | `["Ed25519"]` |
| PS-10..13 person token endpoint | done | first-use consent (`person_token` pending kind), `user_unreachable`, ledger, per-agent cap 100 |
| PS-20 directed `sub` | done | HMAC-SHA256(person, resource); secret beside the PS signing key |
| PS-70/71 sub-agent person tokens | done | `invalid_subagent_token`, `expired_subagent_token` |
| PS-30..36 auth token endpoint | done | `Draft11Checks`; `aud` is this PS (three-party) or the resource's AS (four-party); `ps` must be this PS |
| PS-40 consent attribution | done | consent page: "This request" / "From the resource" / "Stated by the agent" |
| Agent-token failures on -11 endpoints | done | 401 + `Signature-Error` (`invalid_signature`, `expired_jwt`, `invalid_jwt`) |
| PS-32 revocation checks | done | `revoked_presented_token`; a revoked token is reported as revoked even when also expired (§11.12.5) |
| PS-04 mission_endpoint | done | `/agent-missions` (+ `/agent-missions/{s256}`); draft-10 agents keep hardcoded `/mission` |
| PS-80..90 missions | done | `Draft11Missions` (create/update), `Draft11MissionStatus` (active, expiry, reasons in the log) |
| PS-95 interaction types | done | `completion` refused on `/interaction` for `mission_s256` requests |
| PS-96 out-of-band completion | n/a | the PS completes interactions only via its consent page |
| PS-03 `revocation_endpoint` | done | `POST /revoke` |
| PS-102 signature failure codes | done | `revoked_jwt`; `clock_skew` for `created` ahead of the clock on draft-11 paths (draft-10 paths keep `invalid_signature`); `unsupported_scheme` + `Accept-Signature-Scheme` on `/revoke`; `/agent-missions/{s256}` now reports failures with `Signature-Error` |
| PS-110 accept revocations | done | `jwks_uri` callers only; `dwk=aauth-agent.json` must be trusted (else 403 `unsupported_iss`); per-issuer cap 100/min → 429 + `Retry-After`; `exp` beyond 24h + skew → `invalid_request` |
| PS-111 agent-token cascade | done | by the agent's `sub`: live person tokens (at their resource and at each AS they were presented to) and PS-issued auth tokens |
| PS-112 resource-token revocation | done | `revoked_resource_token`; open pendings started for it fail with polling error `revoked` |
| PS-113 outbound revocation | done | signed `jwks_uri;id=<PS>;dwk=aauth-person.json`, body coverage; endpoint from `aauth-resource.json` (resources) or `aauth-access.json` (ASes) |
| PS-114 downstream outcomes | done | no endpoint / `unsupported_iss` → `revocation_unsupported`; unreachable, 5xx, unparseable → `revocation_unavailable`; repeats retry; an AS's `downstream` array is logged |
| PS-115 records | done | agent tokens `(iss, jti, sub, exp)`; person tokens with presentations and upstream `(iss, jti)`; PS-issued auth tokens; agent revocation times by `sub`. The cascade follows person tokens issued on a revoked token as `upstream_token` |
| PS-103 JWT checks | done | library: `exp` without tolerance, `typ` first, person-token `exp − iat` ≤ 1h; PS: presented auth tokens need `iat` and `exp − iat` ≤ 1h. The optional future-`iat` `clock_skew` is not applied |
| PS-104 uppercase agent identifiers | done (PS) | agent ids compared exactly, no case folding; library `Identifiers` still rejects uppercase in `parent_agent` (library finding) |
| PS-50..54 four-party federation | done | `HttpAsFederator`: discovers `aauth-access.json`, POSTs `resource_token`/`agent_token`/`presented_token` (+ `upstream_token`) signed as the PS, follows 202s (claims answered, others polled with a signed GET) within 20 s, verifies the §9.1.3 delivery checks, relays well-formed AS errors, else 502 `as_unreachable`; presentations recorded for revocation. Draft-10 requests keep the fake federator |
| PS-55 claims without `sub` | done | the PS releases no claims (it holds none beyond the directed `sub`, which is never sent) |
| PS-60 person tokens on `upstream_token` | done | issued for the upstream person, `mission_s256` copied from the upstream token, `exp` capped by it; the intermediary sends no `mission_s256`/`subagent_token`; upstream `(iss, jti)` recorded |
| PS-61 upstream verification | done | `UpstreamTokens`: person or auth `typ`; `aud` = the intermediary's agent-token `iss`; person-token `iss` / auth-token `ps` is this PS; auth-token `iss` is this PS or an AS it presented a person token to for that `aud`/`sub`; calling agent and person from the PS's records; `revoked_upstream_token` for a revoked token or an agent whose agent token was revoked after the upstream token was issued |
| PS-62 no `act`, no copied `sub` | done | the downstream `sub` comes from the downstream resource token |
| PS-63 no intermediary binding | done | an intermediary's request neither uses nor establishes a binding |
| PS-64 upstream expiry ends pendings | done | the pending gets a `deadline` at the upstream `exp`, after which it is `expired` whatever its state |

Dual-stack discriminator for the token endpoint: the path. Draft-11 clients discover
`auth_token_endpoint` (`/auth-token`), draft-10 clients `token_endpoint` (`/token`), so
`/auth-token` enforces draft-11 rules (PS-30 `presented_token` REQUIRED, problem+json errors).

Library findings to raise on its `draft11` branch: `PersonTokens.Spec` accepts `scope`,
`account`, and `capabilities`, but §7.1.2 says a person token MUST NOT contain `scope` or
`account` (the PS always passes `null`); `ErrorCodes` lacks the draft-11 token-endpoint codes
(held in `ProblemError` until it has them); the installed SNAPSHOT lacks `ERROR_CLOCK_SKEW` (held in
`SignatureError`); `AuthTokens.verifyToken` does not require `iat` or bound `exp − iat` (PS-103,
checked in `Draft11Checks`); `Identifiers.AAUTH_LOCAL` rejects uppercase locals (PS-104).

Dual-stack safety rule (2026-10-12): a draft-11 resource token (`presented_jti` present) is
refused on the legacy `/token` path, so a draft-11 agent cannot skip the presented-token
cross-check by calling the draft-10 endpoint. Regression test:
`PsTokenEndpointHttpTest.draft11ResourceTokenOnTheLegacyPathIsRejected`.

Library gap: `AuthTokens.Spec` has no `tenant`, so PS-34's "copy `tenant`" into the auth token is
not possible yet (the PS still enforces tenant equality between resource and presented tokens).

Mission dual-stack (2026-10-12): both drafts read the same `mission_endpoint` key, so the draft-11
endpoint lives at a new path (`/agent-missions`). Every draft-10 client (Python scripts, the demo's
`MissionClient`) hardcodes `POST /mission`, and no client discovers `mission_endpoint` from
metadata, so advertising the new path is safe. A mission is draft-11 when its blob has no
`approver`; termination reasons are logged only for draft-11 missions, keeping draft-10 logs
identical to the reference. Known gap: draft-11 mission creation approves immediately (§8.1
deferral is a MAY; draft-10 deferral is not agent-pollable either). New setting:
`AAUTH_PS_MISSION_LIFETIME_SECONDS` sets `expires_at` (unset = no expiry).

Revocation (2026-10-12): the PS answers synchronously. Downstream calls run in parallel with
5-second timeouts, so the cascade finishes inside the ~20 s hold §11.12.3 suggests, and the
PS never answers 202. A downstream 202 counts as `revocation_unavailable` (the PS does not poll
it); a repeated revocation retries. Records are not purged after `exp` (discarding is a MAY).
Fixed alongside: `SqlPendingStore.getRecord` returns a fresh copy, so the broker's in-place writes
(`verifiedResourceClaims`, `tokenAgentCnfJwk`, `evaluatorReason`, clarification rounds) were lost
in SQL mode (the Python reference has the same pattern). `PendingRequestStore.saveRecord` now
persists them; it is a no-op in memory.

Four-party gaps (2026-10-12): an AS `requirement=interaction` or `clarification` is polled until
the 20-second deadline rather than passed down to the agent, and a 402 is `as_unreachable` (no
payment support). A relayed AS error on a deferred request reaches the agent as polling error
`<error>` with 403 (502 for `as_unreachable`), since pending failures carry a code, not a status.

Phase 7 (2026-10-12): the Agent Server records the agent tokens it mints and, when the person
revokes a binding, revokes that agent's live tokens at the PS named in `ps` (signed
`jwks_uri;dwk=aauth-agent.json`, in the background; records are in memory, so tokens minted
before a restart live until `exp`). Uppercase agent locals: the Agent Server mints UUID locals
and validates none (`AgentIds.isValidAgentId` has no callers), so nothing changes there. Python
interop rerun and `demo/demo.sh` pass on this branch. Left for the user:
`aauth-full-java-demo` acceptance on draft-11 (that repo has uncommitted work), and the
library release that lets this branch leave `0.3.0-SNAPSHOT`.

Review hardening (2026-10-12): `/revoke` accepts resource revocations only from issuers whose
resource tokens this PS has verified (403 `unsupported_iss` before any fetch). An agent-token
revocation also fails that agent's open pendings and any pending relying on a token the cascade
revoked (presented or upstream). Sub-agent tokens get the revoked check (`revoked_subagent_token`)
and are recorded so their revocation cascades. Presentations to an AS are recorded before the
request, with the agent's key thumbprint, so an AS-issued upstream token resolves to the agent its
`cnf` names. The federation deadline is checked on every 202 and a pending `Location` must stay on
the AS's origin. Outbound revocation and federation use 5-second timeouts with no redirects;
cascades run on virtual threads, bounded at 20 s. SQL revocation and ledger writes are
`ON CONFLICT DO NOTHING` upserts.

Known, not fixed: the PS still fetches metadata and JWKS from URLs an authenticated agent can
influence (resource `iss`, four-party `aud`, person-token `resource`), as the draft-10 code did
for resource tokens; deployments should restrict egress. Memory-mode revocation records are not
purged after `exp`.
