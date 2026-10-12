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
- PS-110..115: `POST /revocation` (`{jti, exp}`, issuer = verified `jwks_uri` signer, `(iss, jti)`
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
