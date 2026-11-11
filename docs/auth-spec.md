# Auth and access-control spec (multi-user mode, oauth2-proxy)

Status: DESIGN, not built. Needs a new decision in `docs/decisions.md` before any code (section 12; D16 and D17 are taken, use the next free number).
Supersedes the first draft, which had nettrace doing its own OIDC, sessions and password store. Now an existing,
maintained proxy ([oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/)) does the login. nettrace only
verifies who is calling, applies roles, and writes the audit trail.

## 1. Design in one picture

```
Browser --https--> Ingress --> [ Pod ]
                               oauth2-proxy (sidecar, :4180)  --http, pod-local-->  nettrace (127.0.0.1:8765)
                                 |  Entra login, cookie, refresh                      verifies signed ID token
                                 v                                                    applies role
                          Microsoft Entra ID                                          audits by user
```

- oauth2-proxy and nettrace run in the same pod. They share a network namespace, so nettrace keeps binding to
  127.0.0.1 only (rule 7 stays true) and no other pod can reach it.
- oauth2-proxy forwards the user's signed Entra ID token to nettrace. nettrace checks the signature itself and reads
  the roles from the token. It does not trust plain `X-Forwarded-*` headers.
- Why that matters: anyone allowed to `kubectl port-forward` or `exec` into the pod can reach 127.0.0.1:8765 and skip
  the proxy. Without a valid signed token they get 401.

## 2. What is verified and what is not

Verified in oauth2-proxy docs (fetched 2026-11-11):
- Entra ID provider exists (`provider = "entra-id"`), OIDC compliant, supports federated workload identity
  (no client secret), and group overage via Microsoft Graph with `User.Read`.
- `oidc_groups_claim` (default `groups`) picks which claim becomes the groups list.
- `pass_user_headers` (default true) sends `X-Forwarded-User`, `-Groups`, `-Email`, `-Preferred-Username`.
- `pass_authorization_header` sends the OIDC ID token to the upstream as a Bearer token.
- `code_challenge_method` accepts `S256`. `cookie_expire` defaults to 168h. `cookie_secure` defaults to true.
- `insecure_oidc_skip_nonce` defaults to **true**, so nonce is not checked unless you set it false.
- Behind a reverse proxy, leaving `trusted_proxy_ip` unset trusts every source IP for forwarded headers.
- `allowed_groups`, `client_secret_file`, `cookie_secret_file`, and an htpasswd username/password form exist.

Microsoft docs: Entra emits a `roles` claim for each app role granted to the signed-in user.

NOT verified, test in a lab first:
1. That `oidc_groups_claim = "roles"` puts the Entra app roles into `X-Forwarded-Groups`. Likely, not proven.
   The design does not depend on it: nettrace reads `roles` from the signed token. It only matters for
   `allowed_groups` (an optional extra gate).
2. That the ID token forwarded by `pass_authorization_header` is refreshed when oauth2-proxy refreshes the session.
   If it is not, a long session sends an expired token and nettrace returns 401.
3. That `allowed_groups` with role names works as a login gate. If not, rely on Entra "Assignment required".

## 3. Who owns what

| Job | oauth2-proxy | nettrace |
|---|---|---|
| Redirect to Entra, PKCE, state, nonce | yes | no |
| Exchange code, validate ID token at login | yes | no |
| Browser session cookie, refresh, logout | yes | no |
| TLS | ingress | no |
| Verify signed token on every request | no | **yes** (signature, iss, aud, exp, tid) |
| Roles to permissions, owner-only data | no | **yes** |
| CSRF header, Host and Origin checks, body limits | no | **yes** (existing code) |
| Audit by user | proxy logs sign-ins | **yes**, every device request |
| Read-only guards, deadlines, never-guess | no | **yes**, unchanged |

## 4. Modes

| `auth.mode` | Who | Notes |
|---|---|---|
| `local-code` (default) | One person | Today's behaviour. Unchanged. |
| `proxy-oidc` | Many named users | Needs the sidecar. New. |

`proxy-oidc` refuses to start unless: bind is loopback; `oidc.tenant_id`, `client_id`, `public_url` (https) are set;
the JWKS URL is the Entra one for that tenant; at least one role mapping exists; the AWS session policy loads (existing
rule). In this mode the one-time login code and `nettrace_session` cookie are disabled and `X-Nettrace-Token` is
refused, so there is only one way in. Any config error exits 1. Fail closed.

## 5. Identity verification inside nettrace

On every `/api` call and the page load:
1. Read `Authorization: Bearer <id_token>`. Missing or malformed is 401.
2. Verify with a maintained JOSE library (PyJWT with `cryptography`, pinned). Algorithm RS256 only, never `none`.
   Keys come from the JWKS URL in config (fixed, from the tenant), cached, refreshed at most once a minute on an
   unknown `kid`. Fetch with the existing no-redirect rule.
3. Check `iss` equals `https://login.microsoftonline.com/<tenant-id>/v2.0`, `tid` equals the tenant, `aud` equals the
   client ID, `exp` and `nbf` with 2 minutes of skew. (`nonce` was checked by the proxy at login, which is why
   `insecure_oidc_skip_nonce` must be false.)
4. Identity key is `entra:<oid>`. Never use email or UPN as the key.
5. Roles come from the token `roles` claim, filtered to `nettrace.viewer|pilot|admin`. No role is 403 with an
   "ask an admin" page. Highest role wins. Unknown roles are ignored. There is no default admin.
6. Result goes into a per-request context (user, role). Every later audit record reads it.

Reject also: a request with no `Host` equal to the configured `public_url` host; an `Origin` that is not the
public URL; a request that carries `X-Forwarded-*` identity headers but no valid token (the headers are ignored and
logged as `access_denied`).

## 6. Roles and routes

| Role | Who | Can do |
|---|---|---|
| `viewer` | Observers | See own traces and path maps. |
| `pilot` | Pilot engineers | Start, cancel and view own traces. Console only if `console.pilot: true` (default false). |
| `admin` | Owners | All of pilot, plus view all traces, cancel any, use console, read the audit log in the UI. |

| Route | viewer | pilot | admin |
|---|---|---|---|
| `GET /` page, `GET /api/bootstrap` | yes | yes | yes |
| `POST /api/trace` | no | yes | yes |
| `POST /api/trace/cancel` | no | own | any |
| `GET /api/traces`, `/api/traces/<id>` | own | own | all |
| `POST /api/console` | no | if enabled | yes |
| `GET /api/admin/audit` | no | no | yes |
| `GET /auth/me` | yes | yes | yes |
| `GET /healthz` (returns `ok`, no data) | open | open | open |

Logout is the proxy's `/oauth2/sign_out`; the UI links to it. User management is done in Entra, so there are no
`/api/admin/users` routes.

## 7. Entra setup (one app registration, single tenant)

1. Supported account type: this tenant only.
2. Redirect URI (Web): `https://<public_url>/oauth2/callback`. One URI, https.
3. Credential: prefer workload identity federation (`entra_id_federated_token_auth`). Otherwise a client secret in a
   Kubernetes Secret, read by the proxy from a file (`client_secret_file`). Rotate at least yearly.
4. App roles: `nettrace.viewer`, `nettrace.pilot`, `nettrace.admin`, allowed for users/groups.
5. Enterprise application: **Assignment required = yes**, and assign groups to roles. (The oauth2-proxy Terraform
   example sets `app_role_assignment_required = false`. Do not copy that.)
6. Conditional Access for this app: require MFA and a compliant device. Entra enforces it.
7. Emit `roles`, `oid`, `tid` in the ID token (default for v2 tokens with app roles).

## 8. oauth2-proxy configuration (sketch)

```toml
provider = "entra-id"
oidc_issuer_url = "https://login.microsoftonline.com/<tenant-id>/v2.0"
client_id = "<client-id>"
client_secret_file = "/secrets/oidc-client-secret"
scope = "openid"
redirect_url = "https://nettrace.example.internal/oauth2/callback"
code_challenge_method = "S256"
insecure_oidc_skip_nonce = false          # default is true; turn the nonce check on
oidc_groups_claim = "roles"               # verify (section 2, item 1)

upstreams = ["http://127.0.0.1:8765"]     # pod-local
http_address = "0.0.0.0:4180"
reverse_proxy = true
trusted_proxy_ip = ["10.0.0.0/8"]         # ingress controller range only; never leave unset
email_domains = ["*"]                     # single-tenant issuer + Entra assignment is the real gate

pass_authorization_header = true          # signed ID token to nettrace
pass_user_headers = false                 # nettrace must not use plain headers
set_xauthrequest = false

cookie_name = "__Host-nettrace_oauth2"
cookie_secret_file = "/secrets/cookie-secret"
cookie_secure = true
cookie_httponly = true
cookie_samesite = "lax"
cookie_expire = "8h"                      # default is 168h; shorten so removals take effect
cookie_refresh = "1h"                     # verify the forwarded token refreshes (section 2, item 2)
skip_auth_routes = ["^/healthz$"]
```

Run `oauth2-proxy --config-test` in CI. Pin the image by digest. Keep the proxy's own auth log; ship it with the
nettrace audit log.

## 9. nettrace changes

- New `src/nettrace/web/authn.py`: token verification (section 5) and role lookup. No session store, no cookies,
  no password code.
- `server.py`: in `proxy-oidc` mode skip the login-code and token paths, call `authn` first, keep Host, Origin,
  CSRF-header, JSON-only, 64 KiB and the 10 s body deadline. Config `public_url` replaces the loopback Host check.
- `audit.py`: add `user`, `role`, `src_ip` (from the proxy-set `X-Forwarded-For` only if the peer is loopback, which
  is true in a sidecar) to every record in this mode. New event records: `login_seen` (first request of a session),
  `access_denied` (route, role, reason code), `token_rejected` (reason code only). Never log the token.
- History is keyed by owner. `App.history` stays under `history_lock`; listings filter by owner unless admin.
- Limits: 2 running traces per user, 6 overall, 429 above that. Trace deadline and cancel behave as today.
- The console is admin-only by default and keeps its per-device lock, 1 s gap, 60 s idle and 256 KiB cap.
- Maps downloaded by non-admins never include hop evidence.
- Log to stdout as JSON as well as the file (`NETTRACE_AUDIT_STDOUT=1`) so the cluster log agent can ship it.
- New dependency (pinned exact in the lock file): `PyJWT[crypto]`. Nothing else.

## 10. Local user and password options

The first draft had a local password store with argon2 and TOTP. It is dropped. Choose one:

| Option | How | Trade-off |
|---|---|---|
| A. Entra only (recommended) | Pilot users are Entra users or B2B guests in a pilot group | Simplest, MFA by policy, nothing to store |
| B. Break-glass by port-forward | Admin runs `kubectl port-forward` and uses the existing single-user `local-code` mode in a second, non-shared pod | Needs cluster RBAC; no passwords anywhere |
| C. oauth2-proxy htpasswd form | `htpasswd_file` plus the proxy's login form | Users arrive with no ID token, so nettrace cannot verify them. Would need a separate trust path (header trust, mapped users to roles in config). Weaker; avoid unless required |

If the owner insists on user/pass for the pilot, use Option B for admin and Option A with a pilot group for others.
Option C is the only one that reintroduces header trust, so it must be a separate decision.

## 11. Deployment

- One Deployment, two containers (nettrace, oauth2-proxy), one Service on the proxy port 4180 only. Ingress terminates
  TLS with HSTS and only forwards to that Service.
- nettrace container: non-root, read-only root filesystem, writable volume for the audit log only. Device and AWS
  credentials as Secrets via env (rule 4). Cisco known-hosts as a mounted file.
- `NetworkPolicy`: ingress to the pod only from the ingress controller. Egress only to Entra
  (`login.microsoftonline.com`, Graph if overage is used), the devices and Panorama, SCM, and AWS endpoints.
- RBAC: restrict `pods/exec`, `pods/portforward`, and Secret reads in this namespace. They are admin-equivalent.
  Port-forward cannot impersonate a user because the token check still applies.
- Headers on every response: existing strict CSP, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`.
  No CORS.
- Device accounts stay read-only (`docs/value-proposition.md`, section 6).

## 12. Changes to existing rules (new decision)

Record before coding:
- Rule 7 still holds: loopback bind, no `--host`, no CORS, no unauthenticated data route, JSON-only 64 KiB bodies.
- Add: in `proxy-oidc` mode the identity is a verified Entra ID token, and the one-time code and `X-Nettrace-Token`
  paths are disabled. The default mode is unchanged.
- Add: the secret-handling rule (no secret in argv, env of the browser, URL or log) now also covers the ID token and
  the proxy cookie.
- Rule 3 (never guess) and rule 1 (read-only) are untouched. A role never widens what the guards allow.

## 13. Threat model (short)

| Threat | Control |
|---|---|
| Bypass proxy via port-forward or exec | nettrace requires a valid signed token; no token is 401 |
| Forged identity headers | Plain headers ignored; `pass_user_headers = false` |
| Forged or replayed token | Signature, iss, tid, aud, exp; nonce on at the proxy |
| Stolen browser cookie | HttpOnly, Secure, `__Host-` prefix, 8 h life, Conditional Access, refresh every hour |
| Removed user stays signed in | Short `cookie_expire`; Entra assignment required; refresh fails after removal |
| Over-broad trusted proxy range | Narrow `trusted_proxy_ip`; startup check refuses an unset value |
| CSRF | Required custom header, Origin check, SameSite lax |
| Insider reads others' traces | Owner filter; admin read of another user's trace is audited |
| Privilege escalation | Roles only from Entra app roles; no default admin; changes are Entra audit events |
| Compromised pod reads device creds | Read-only device accounts, NetworkPolicy, RBAC on exec and Secrets |
| JWKS fetch abuse (SSRF) | Fixed URL from config; no redirects followed |
| Config error opens the app | Startup checks fail closed |
| Entra outage | Option B break-glass |

Out of scope: a malicious cluster admin; per-user device credentials; SAML; SCIM.

## 14. Test plan

Unit (token verifier uses a locally generated RSA key and a fake JWKS on a transport seam, below the guards, like the
other simulators): good token; wrong `iss`, `tid`, `aud`; expired; `alg: none`; wrong key; unknown `kid`; missing
roles; unknown role; header-only identity ignored; direct hit without token; Host and Origin mismatch; role by route
matrix; owner filtering; cancel of another user's trace is 403; limits give 429.

Guard regression: for every role confirm the read-only guards, audit records and deadlines behave as before, and no
role can reach a command the guards refuse.

Lab (real Entra test tenant and a kind/minikube cluster): login with MFA, wrong-tenant user blocked, unassigned user
blocked, role change takes effect after refresh, removal takes effect within `cookie_expire`, token refresh
(section 2 item 2), `oidc_groups_claim = "roles"` check (item 1), port-forward bypass attempt, logout, pod restart.

## 15. Build phases

1. The new decision record, config schema, startup checks, `authn.py` with the fake JWKS tests. (small)
2. Roles, route matrix, audit fields, owner-scoped history, limits. (medium)
3. Sidecar manifests, NetworkPolicy, stdout audit. (small)
4. Lab run against a real Entra test tenant; close the three unverified items. (small)
5. Pilot with one team. (small)

## 16. Open questions

1. Who owns the Entra app registration and the Conditional Access policy?
2. Is workload identity federation available on the cluster, or must a client secret be used?
3. Do pilot users get the console? Default here is no.
4. Is Option B (break-glass by port-forward) acceptable to the security team?
5. Where does the audit log ship, and who reviews it?
6. Should roles ever limit which devices a user can trace (inventory tags)? Not in v1.
