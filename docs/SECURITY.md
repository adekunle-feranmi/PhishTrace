# Security model

PhishTrace investigates hostile infrastructure, so it treats network responses,
provider payloads and archived page bodies as untrusted input. This document
describes the trust boundaries, the controls that are implemented, and the risks
that remain. Deployment hardening is covered in
[DEPLOYMENT.md](DEPLOYMENT.md); provider-specific controls are in
[PROVIDERS.md](PROVIDERS.md).

## Supported versions

Security fixes are applied to the current `main` branch. There are no maintained
long-term release branches yet.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Send a private report
with the affected version/commit, reproduction steps, impact and any suggested
fix to the maintainers of the deployment you are testing. If you are testing a
third-party deployment, contact that operator, not the upstream project. Allow
time for a fix before disclosure.

## Threat model

| Adversary | Capability | Primary controls |
| --- | --- | --- |
| Unauthenticated network client | Reaches the reverse proxy / app port | Auth required for every route except `/health` and `/login`; bind validation; login throttle; generic login errors |
| Authenticated low-privilege user | Uses the console and API | Per-investigation ownership checks; admin-only audit log; CSRF on state changes |
| Malicious target or phishing kit | Returns hostile HTML, redirects, huge bodies, slow responses | Isolated fetcher: scheme/host/IP policy, DNS pinning, redirect revalidation, byte/time caps, no script execution |
| Compromised or malicious provider | Returns crafted JSON/CSV/text | Bounded parsers, type checks, size caps, evidence hashing; no `eval`/`exec` of provider data |
| Local unprivileged user on the host | Reads process data, files, env | Dedicated service account, `ProtectSystem`/`ProtectHome`, `StateDirectory` mode 0700, env file mode 0640 |
| Operator error | Public bind, missing secret, weak config | Startup refusal without auth/secret; `phishtrace doctor`; redacted config snapshot |

Out of scope for the application itself: a compromised host kernel, a malicious
administrator, and an attacker who can already read the process environment
(which contains provider API keys).

## Implemented controls

**Authentication and sessions**

* Argon2id password hashes, minimum password policy, uniform "invalid username
  or password" response.
* Signed, HttpOnly, SameSite=Lax session cookies with a 12-hour default TTL;
  `Secure` is enabled by `auth.cookie_secure` behind TLS.
* CSRF double-submit token on login, logout and every state-changing API route.
* Login throttling per client IP + username (default 8 attempts / 5 minutes).
* All `/api/*` routes depend on `current_user`; `/health` and `/login` are the
  only public endpoints. Interactive API docs are disabled when auth is on.
* Non-loopback binds are refused unless auth is enabled and the session secret
  is at least 32 characters.

**Request handling**

* Security headers on every response: CSP (`script-src 'self'`, no third-party
  CDN), `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`,
  restrictive `Permissions-Policy`, `no-store` on `/api/*` and `/health`.
* HSTS when `cookie_secure` is enabled.
* Forwarded headers are trusted only from `PHISHTRACE_TRUSTED_PROXIES`
  (loopback by default), so throttling and audit records cannot be spoofed by a
  direct client.
* Evidence downloads resolve the stored path and require it to stay inside the
  evidence or archive directory; symlinks escaping those roots are rejected.
* JSON error responses for API 404s; HTML escaping is enabled in Jinja
  templates and report renderers.

**Secrets**

* API keys and tokens are read only from the environment/`.env`, never from
  `config.yaml`, logs or reports.
* `Config.redacted()` replaces credential-bearing fields (provider cookies,
  MISP/OpenCTI keys, LLM keys) with `[REDACTED]` before the snapshot is returned
  by `/api/config` or persisted with an investigation.
* Evidence URLs for keyed providers are stored with the key removed.
* Reports, STIX/MISP exports and abuse drafts never include credentials.

**Active fetching (opt-in)**

`fetcher.active_fetch` is `false` by default. When enabled:

* Only `http`/`https`; URL userinfo is stripped (the fetcher never authenticates)
  and blocked ports are denied.
* Hostnames are resolved once and the connection is pinned to the validated IP
  (TLS SNI/Host preserved), blocking DNS-rebinding.
* Loopback, private, link-local, multicast and reserved addresses are denied;
  redirects are revalidated hop by hop and capped.
* Response bodies are capped per response and per investigation; downloads run
  with a timeout, in a scratch directory, and can drop to an unprivileged user.
* Page content is parsed as data. JavaScript is never executed, and kit analysis
  reads static files only.

**Wrapped CLI tools**

* argv-only execution (no shell), sanitized environment, scratch working
  directory, output caps and process-group termination on timeout.
* Targets beginning with `-` are rejected to prevent option injection.
* Account-probing tools (`holehe`, `ghunt`) are disabled by default and require
  `legal_acknowledged: true`; their output is treated as PII.

**Data handling**

* Evidence bodies are written to disk with a SHA-256 digest and served from the
  database row, not from a user-supplied path.
* Retention (`retention_days`, `phishtrace purge`) deletes investigations and
  orphaned evidence files; archived sightings and report bundles are bounded.
* Audit log records login, logout, admin creation, investigation and export
  actions with the client IP.

## Residual risks and limitations

* **Single-tenant trust.** Every authenticated administrator can see every
  investigation; ownership checks separate ordinary users, but there is no
  fine-grained RBAC, team scoping or per-provider permission.
* **Session invalidation.** Resetting a password does not revoke already issued
  session cookies; they expire at the configured TTL. Rotate
  `PHISHTRACE_SESSION_SECRET` to invalidate all sessions immediately.
* **In-memory throttle.** Login attempt counters live in the process and reset
  on restart; running multiple workers would require a shared store.
* **SQLite.** One writer at a time. The app is designed for a single process;
  do not run multiple uvicorn workers against the same database file.
* **No encryption at rest.** The database and evidence tree rely on host disk
  encryption (LUKS) and filesystem permissions. Backups contain the same
  sensitive material.
* **Third-party tools.** `dnstwist`, `sherlock`, `maigret`, `holehe`, `ghunt`,
  `phoneinfoga`, `spiderfoot` and `theHarvester` execute as the service account.
  Install them from trusted sources and pin versions; a compromised binary is
  outside the application's sandbox.
* **Provider schemas.** Keyed providers are tested against mocked payloads, not
  live APIs. A vendor schema change can cause a partial result rather than a
  hard failure; check the coverage panel.
* **LLM classifier.** Disabled by default. Enabling it sends indicator context
  to the configured endpoint; review the provider's data handling first.
* **Abuse workflow.** PhishTrace writes draft emails and manifests only. It
  never sends a message. Verify every recipient and claim before contacting a
  host or registrar.

## Hardening checklist

1. Bind loopback and terminate TLS at a reverse proxy.
2. Set a random `PHISHTRACE_SESSION_SECRET` (48+ characters) and
   `auth.cookie_secure: true`.
3. Create a dedicated OS account; keep `.env` mode 0600/0640.
4. Enable the systemd unit's sandboxing (or run the provided Compose file with
   `read_only`, `cap_drop: ALL` and `no-new-privileges`).
5. Restrict outbound egress if active fetching is enabled; use a dedicated
   proxy or egress IP so attacker infrastructure cannot reach your office LAN.
6. Back up the database and evidence tree; test a restore.
7. Schedule `phishtrace purge` according to your retention policy.
8. Review `/api/audit` and provider coverage after each investigation.
9. Keep the host, Python dependencies and wrapped tools patched.

## Authorized use

PhishTrace is built for authorized phishing investigations, brand protection,
incident response and threat intelligence work. Only investigate infrastructure
you are permitted to assess, respect provider terms of service and rate limits,
and handle victim PII according to applicable law and your organisation's
policy.
