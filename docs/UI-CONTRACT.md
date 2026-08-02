# UI Contract

The browser consoles under `src/main/resources/ui-*` are original works authored against
this document, which is derived from the Java controllers (not from the upstream Python
repo's UI markup). If a controller changes, update this file first, then the pages.

## Serving model

`UiResourceConfiguration` maps `/ui/**` to one classpath root per Spring profile:

| Profile | Root | Console |
|---|---|---|
| default / `portal` | `classpath:/ui-portal/` | Unified portal (PS + AS) |
| `ps` | `classpath:/ui-ps/` | Standalone Person Server |
| `agent-server` | `classpath:/ui-as/` | Standalone Agent Server |

`/ui` and `/ui/` redirect to `/ui/index.html`.

Load-bearing filenames (referenced by server code, tests, or deferred responses —
do not rename):

- `index.html` — redirect target for `/ui/`.
- `consent.html` — `MemoryPendingStore.CONSENT_UI_PATH` builds every
  `interaction_url` as `<origin>/ui/consent.html`; agents send users there with
  `?code=<interaction code>`.
- `portal.html` — asserted reachable by `PortalHttpTest`.

Everything else (page structure, styling, helper JS, other filenames) is ours to choose.

## Browser auth

All console API calls are plain-bearer: `Authorization: Bearer <token>`. Tokens are
static strings from the environment; the console stores the entered token in
`localStorage` and replays it on every call.

| Token | Env var | Grants |
|---|---|---|
| PS admin | `AAUTH_PS_ADMIN_TOKEN` | `/missions*`, `/admin/*`, `/person/trusted-agent-servers` (unset ⇒ those routes are open) |
| PS user | `AAUTH_PS_USER_TOKEN` | `/user/*` (unset ⇒ standalone `/user/*` returns 503) |
| AS person | `AAUTH_AS_PERSON_TOKEN` (default `changeme`) | `/person/registrations*`, `/person/bindings*` |

Portal cross-acceptance (`PsAuth` with `portalPersonToken`): the AS person token is also
accepted on PS admin routes, and `/user/*` accepts user, admin, or person tokens. So the
portal console needs only one token field.

The consent page (`GET /consent` + decision POST) requires no bearer token — the
interaction `code` is the credential.

## Endpoints by console

### Consent page (all consoles: `consent.html`)

Reads `code` (required) and `callback` (optional) from the query string.

- `GET /consent?code=<code>[&callback=<url>]` → consent context:
  `pending_id`, `scopes` (list), `mission` (mission object or null), and optional
  `pending_kind`, `resource_name`, `justification`, `agent_name`,
  `clarification_responses` (list), `interaction_type`, `summary`, `question`,
  `resource_iss`, `resource_scope`, `resource_mission_s256`, `permission_action`,
  `permission_description`, `permission_parameters` (object), `evaluator_reason`.
  Errors: 404 unknown code, 410 expired/consumed.
- `POST /consent/{pending_id}/decision` with
  `{"approved": bool, "clarification_question"?: str, "answer_text"?: str}` →
  `{}` or `{"redirect_url": str}` (browser should navigate there when present).
  - `approved=false` + `clarification_question` ⇒ ask the agent to clarify instead
    of denying.
  - `answer_text` answers an agent `question` interaction.

`pending_kind` values: `token` (scope consent), `permission` (approved-tools
escalation), `interaction` (agent-initiated: `interaction_type` one of
`interaction`, `payment`, `question`, `completion`).

### Portal console (`ui-portal/`)

Everything below plus the consent page. One bearer token (see above).

Person Server:

- `GET /missions?agent_id=&state=` → list of mission objects:
  blob fields `approver`, `agent`, `approved_at`, `description`,
  `approved_tools`? (`[{name, description}]`), `capabilities`? — plus `s256`,
  `state` (`active`|`terminated`), `owner_id`.
- `GET /missions/{s256}` → `{mission: {...}, log: [{ts, kind, payload}]}`.
- `PATCH /missions/{s256}` body `{"state": "terminated"}` → `{mission: {...}}`.
- `GET /user/missions`, `GET /user/missions/{s256}`, `PATCH /user/missions/{s256}` —
  same shapes, owner-scoped.
- `GET /user/consent` → `[{pending_id, code, kind, agent_id, interaction_url}]` —
  the user's open consent queue; open `interaction_url + "?code=" + code`.
- `GET /admin/pending` → `[{pending_id, kind, status, requirement, agent_id,
  owner_id, code, interaction_url, pending_url, justification, resource_iss,
  resource_scope}]` (`code` non-null only for `requirement=interaction`).
- `GET /admin/issued-tokens` → `[{issued_id, agent_id, owner_id, resource_iss,
  resource_scope, justification, issue_method, token_jti, issued_at, expires_at}]`,
  newest first. Portal-only (matches the Python portal app).
- `GET /admin/consent-scopes` → `{scopes: [str]}`;
  `POST /admin/consent-scopes` `{"scope": str}` → 201 `{scope, added}` (409 dup);
  `DELETE /admin/consent-scopes/{scope}` → 204 (404 missing).
- `GET /person/trusted-agent-servers` → `[{issuer, display_name, jwks_uri,
  jwks_fingerprint, added_at}]`;
  `POST /person/trusted-agent-servers` `{"issuer": str, "display_name"?: str}` → 201;
  `DELETE /person/trusted-agent-servers?issuer=<url>` → 204.

Agent Server (person-facing):

- `GET /person/registrations` → `[{id, agent_name, stable_jkt, created_at,
  expires_at, status}]` (pending only).
- `POST /person/registrations/{id}/approve` → `{agent_id, agent_name}`.
- `POST /person/registrations/{id}/deny` → 200.
- `POST /person/registrations/{id}/link` `{"agent_id": str}` → `{agent_id,
  agent_name}` (adds the new device key to an existing binding).
- `GET /person/bindings` → `[{agent_id, agent_name, created_at, device_count,
  stable_key_thumbprints, revoked}]`.
- `POST /person/bindings/{agent_id}/revoke` → 200.
- `POST /person/bindings` `{"stable_pub": jwk, "agent_name": str}` → 201
  (pre-trust a stable key without a pending registration).

Metadata (no auth): `GET /.well-known/aauth-person.json` (`issuer`,
`token_endpoint`, `mission_endpoint`, `permission_endpoint`, `audit_endpoint`,
`interaction_endpoint`, `mission_control_endpoint`, `jwks_uri`),
`GET /.well-known/aauth-agent.json` (`issuer`, `jwks_uri`, `client_name`,
`registration_endpoint`, `refresh_endpoint`), `GET /.well-known/jwks.json` (merged).

### Standalone PS console (`ui-ps/`)

Pages: `index.html` (overview + metadata), `admin.html` (admin token: missions,
pending, consent scopes, trusted agent servers), `user.html` (user token: own
missions + consent queue), `consent.html`.

Same PS endpoints as the portal minus `/admin/issued-tokens` and all `/person/*`
AS routes (the standalone PS app does not register them).

### Standalone AS console (`ui-as/`)

Pages: `index.html` (overview + `/.well-known/aauth-agent.json`),
`registrations.html` (list / approve / deny / link), `agents.html` (bindings:
list / revoke / pre-trust). Person token auth. AS-only extras: standalone poll
path `GET /pending/{id}` and its own `/.well-known/jwks.json`.

## Error body shape

PS routes return `{"detail": str}` for 4xx (FastAPI parity); agent-signed routes
return `{"error": code, "error_description": str}`. The consoles display `detail`
when present, else `error_description`, else the raw body.
