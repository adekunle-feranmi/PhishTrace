# PhishTrace build log

Running record of what was built, what broke, and what is intentionally limited.
Newest phase at the bottom of each section; the file is updated at every phase.

Environment observed at build time: Linux (Debian), Python 3.14 in the build
sandbox, Node not required, no outbound network needed for the test suite.

## Phase status

| Phase | Scope | State |
|---|---|---|
| 1 | Skeleton, config, models, storage, auth, HTTP layer, registry, health API, CLI | done |
| 2 | Normalizer + keyless providers + mocked-transport tests | done |
| 3 | Pivot engine, stop-lists, scoring, caps, orchestrator | in progress |
| 4 | Timeline merger, sightings, role classifier, archiver | pending |
| 5 | Isolated fetcher + kit analyzer + mock kit | pending |
| 6 | Web UI (live progress, graph, timeline, evidence browser) | pending |
| 7 | Reports (HTML/PDF/JSON/STIX/MD/CSV), abuse reports, OpenCTI/MISP | pending |
| 8 | Phase B keyed providers and Phase C wrapped tools | pending |
| 9 | Hardening review, load test, docs, Docker, systemd | pending |

## Phase 1 — skeleton

Delivered:

* `pyproject.toml` with pinned ranges, console script `phishtrace`.
* Layered config loader (`config.yaml` + `.env` + environment), strict validation.
* SQLAlchemy models and repositories for investigations, indicators, edges,
  evidence, events, sightings, provider runs, kits, users and audit records.
  Uniqueness constraints guarantee idempotent re-runs (no duplicate nodes or
  sightings for the same seed).
* Provider plugin system: `ProviderMeta`, discovery by package scan, per-provider
  status (`enabled`/`skipped`/`failed`) with machine-readable skip reasons.
* HTTP layer: token-bucket limiter, global + per-provider budget, retries with
  jitter and `Retry-After`, response size caps, TTL cache, and an append-only
  evidence recorder (raw bytes + SHA-256 + retrieval time + redacted request).
* Auth: Argon2id password hashing, signed cookie sessions, CSRF tokens, login
  throttling, audit log. Non-loopback binds refuse to start without auth and a
  session secret.
* FastAPI app (health, auth, providers, investigations, evidence preview/raw,
  stats, audit), minimal templates, CLI (`serve`, `create-admin`, `doctor`,
  `providers`, `version`).

Failures fixed during the phase:

* `networkx` missing in the sandbox venv -> installed project deps editable.
* Size guard in `core/http.py` referenced an undefined `max_bytes` -> rewritten.
* Registry did not detect duplicate provider names when classes were injected
  directly -> duplicate detection added and covered by a test.
* `api/deps.py` first draft was internally inconsistent -> rewritten.

Verification: `29 passed` for the three phase-1 test modules.

## Phase 2 — normalizer and keyless providers

Delivered:

* `phishtrace/normalizer.py`
  * refang/defang (`hxxp`, `[.]`, `(.)`, `[dot]`, `[:]`, `[@]`), unicode NFKC,
    zero-width stripping;
  * URL canonicalisation: lower-case scheme/host, IDNA, default-port removal,
    fragment removal, tracking-parameter removal (utm_*, fbclid, gclid, …),
    sorted query, credential stripping, IPv6 literals;
  * types: url, domain, ip, email, phone (E.164 + national + RFC3966, region
    aware), cert_sha256, file_hash (md5/sha1/sha256), telegram (handle, invite,
    bot ID with token redaction), analytics IDs, nameserver, ASN, JA3,
    username, BTC (Base58Check verified);
  * punycode and mixed-script (homoglyph) detection, public-suffix-aware
    registrable domains;
  * `extract_indicators()` for free text with per-type caps and dedupe.
* 22 keyless providers, all with real documented endpoints and mocked tests:

| Provider | Category | Notes |
|---|---|---|
| crt_sh | certificates | CT log search |
| certspotter | certificates | keyless; optional key raises limits |
| rdap | registration | domain/IP registration events, entities, nameservers |
| dns_intel | dns | DoH A/NS/MX/TXT/CNAME/PTR, SPF includes |
| hackertarget | dns | host search CSV |
| threatminer | threat-intel | passive DNS |
| wayback | archives | CDX index, earliest snapshot |
| memento | archives | TimeTravel timemap |
| urlscan | scanners | historical scans, IPs, ASNs |
| urlhaus | feeds | abuse.ch URL/payload DB |
| threatfox | threat-intel | abuse.ch IOC search |
| openphish | feeds | public feed, local matching |
| phishing_database | feeds | GitHub community feed |
| phishtank | feeds | keyed (`PHISHTANK_API_KEY`) |
| phishstats | feeds | URL/IP search |
| shodan_internetdb | hosting | ports, hostnames, CVEs |
| ipinfo | hosting | ASN/geo, optional `IPINFO_TOKEN` |
| hudsonrock | exposure | aggregate-only by design |
| typosquat | lookalike | local permutation, no network |
| telegram_public | social | t.me public preview, sightings only |
| bluesky | social | public AppView search, sightings only |
| reddit | social | OAuth or public JSON, sightings only |

* `mastodon` is implemented but requires `MASTODON_TOKEN`; without it the
  registry reports it as skipped with an explicit reason.
* Test harness (`tests/providers_harness.py`) wires a provider to
  `httpx.MockTransport`, a temporary SQLite DB and the real evidence recorder,
  so parsing, evidence and degradation behaviour are all exercised offline.

Issues found and fixed:

* `refang` joined sentence punctuation into domains (`example.org. Backup` ->
  `example.org.backup`); whitespace repair is now limited to a single token.
* Mixed-script detection counted the ASCII TLD as Latin; suffix is now excluded.
* MX answers are `"10 mail.example."`, so the numeric preference was parsed as a
  domain; the last token is used now.
* `route()` test helper returned JSON for plain-text feeds; text payloads now
  produce text responses.
* Registry treated the private `_BulkFeedProvider` helper as a plugin; private
  classes are skipped by convention now.

Verification: `82 passed` (phase 1 + 2).

## Known limitations (tracked, not hidden)

* Provider parsers are written against the public API shapes as documented at
  build time; upstream schema changes will surface as `partial` results with a
  note rather than a crash. Live-key validation happens in phase 8/9.
* Mastodon search needs a token; Telegram has no public search API, only the
  public channel preview.
* Hudson Rock results are aggregated (family counts and dates) so no stolen
  credentials or victim hostnames enter the database.
