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
| 3 | Pivot engine, stop-lists, scoring, caps, orchestrator | done |
| 4 | Timeline merger, sightings, role classifier, archiver | done |
| 5 | Isolated fetcher + kit analyzer + mock kit | done |
| 6 | Web UI (live progress, graph, timeline, evidence browser) | done |
| 7 | Reports (HTML/PDF/JSON/STIX/MD/CSV), abuse reports, OpenCTI/MISP | done |
| 8 | Phase B keyed providers and Phase C wrapped tools | done |
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

## Phase 3 — pivot engine, stop-lists, scoring, orchestrator

Added:

* `phishtrace/core/stoplist.py` — CIDR and domain stop-lists for shared
  infrastructure that must never be pivoted: Cloudflare, Akamai, Fastly,
  CloudFront, Google frontends, Sucuri, Imperva, Microsoft edge, plus public
  resolvers (Quad9, OpenDNS, AdGuard). Domain categories cover CDNs, social
  platforms, web archives, URL shorteners and free webmail. Each hit returns a
  `StopDecision` with `expand=False`, the matched category and a human reason;
  those nodes are still recorded as context so the graph shows *why* a pivot
  stopped. Cloud and VPS compute ranges (AWS, GCP, Azure, DigitalOcean) are
  deliberately **not** stop-listed: phishing kits are routinely hosted there and
  blocking them would hide real infrastructure.
* `phishtrace/core/scoring.py` — selector-strength base weights (strong 0.9,
  medium 0.65, weak 0.3), reliability multiplier per provider, corroboration
  bonus (0.06 per extra independent source, capped at 0.18), edge and path
  confidence, observation ranking and the `should_expand` gate.
* `phishtrace/core/pivot.py` — `PivotEngine`: priority queue over selector
  strength, one shared request `Budget` for the whole investigation, per-provider
  token-bucket rate limiting, per-provider timeouts, a circuit breaker that opens
  after 3 consecutive failures, hard caps (`max_depth`, `max_children_per_node`,
  `max_nodes`), normalisation and de-duplication of observations before they are
  persisted, and persistence of indicators, edges, events and provider runs.
  Children of a non-expandable node inherit `context_only`, so a stop-listed seed
  cannot leak expandable children.
* `phishtrace/core/orchestrator.py` — `InvestigationRunner.run_seed()` creates or
  reuses an investigation for the same normalised seed (`--no-reuse` forces a
  fresh one), finalises it as `completed` or `partial` with coverage, stats and a
  summary, and `validate_provider_keys()` health-checks keyed providers without
  ever echoing a secret.
* `phishtrace/cli.py` — `phishtrace run <seed>` with `--type`, `--json`,
  `--no-sightings`, `--no-reuse`, `--verbose`, `--data-dir`, `--owner`,
  `--config`. Prints indicator/edge/event/evidence counts, failed and skipped
  providers, warnings, and uses "earliest observed" wording for the timeline.
* `phishtrace/tests/test_phase3_engine.py` — 16 tests.

Acceptance behaviours proven by tests:

* A Cloudflare-IP seed expands exactly once; its children are context-only.
* `max_children_per_node`, `max_nodes` and `max_depth` are honoured.
* A provider that raises does not abort the investigation.
* Re-running the same seed reuses the completed investigation with identical
  graph counts and zero new edges.
* A URL seed derives the hostname and pivots the hostname.
* Exhausting the global request budget sets `stats.truncated`.
* `validate_provider_keys()` reports presence without leaking the value.

Live zero-key smoke run (`phishtrace run https://example.com`, bounded config:
budget 40 requests, depth 1, 40 nodes, 90 s timeout):

* Completed with exit 0 and wrote investigation, edges, events and evidence.
* `urlhaus` and `threatfox` returned **HTTP 401** — abuse.ch now requires an
  `Auth-Key` header. Both providers were converted to keyed providers reading
  `ABUSECH_AUTH_KEY`, and the header is only sent when a key exists; they now
  report as *skipped* with an explicit reason instead of failing at runtime.
* `phishing_database` returned a 65.8 MB response and was rejected by the
  16 MB response cap; needs a streaming/smaller endpoint (tracked in phase 8).
* `memento` failed with `ConnectError: Name or service not known` —
  `timetravel.mementoweb.org` appears to be defunct; the failure degraded to a
  warning as designed.
* `phishstats` returned HTTP 522 (upstream outage) and degraded to a warning.
* `dns_intel` exhausted its per-provider DoH budget at 4 requests, which is the
  intended budget behaviour, not an error.
* Provider-level HTTP failures call `ctx.partial()`, so the run is recorded as
  `ran` with warnings carrying the reason; the investigation still finishes.

Verification: `98 passed` (phases 1–3).

## Phase 4 — timeline merger, sightings engine, role classifier, archiver

Added:

* `phishtrace/core/timeline.py` — merges every dated observation into one
  chronological timeline. `stage_for()` maps a selector type to a human stage
  (`registration`, `certificate`, `archive`, `social`, `feed`, `infrastructure`,
  `resolution`, ...); `merge_events()` collapses rows that describe the same fact
  on the same day into a single event carrying a `sources` list and a `collapsed`
  count, so five feeds repeating one first-seen date do not produce five bars.
  `build_timeline()` returns `earliest_observed`, per-stage earliest dates,
  gaps (configurable `gap_days`, default 30) with day counts, per-event
  precision (`exact` for timestamps, `day` for date-only evidence), coverage of
  the anchors that were actually checked, and fixed "earliest observed" wording.
  `TimelineMerger(repo, investigation_id).build()` reads the database directly;
  `derive_events_from_sightings()` turns stored social posts into timeline events.
* `phishtrace/core/roles.py` — heuristic role classifier for handles seen in the
  sightings stage. Roles: `victim_reporting`, `researcher`, `threat_actor`,
  `distributor`, `amplifier`, `brand`, `unknown`. Signals are multilingual
  (English, French, Spanish, Portuguese, German, Indonesian, Nigerian pidgin and
  common phishing slang), scored with weights and returned with confidence and a
  rationale string per handle, plus `summarize_roles()` for the summary block.
* `phishtrace/core/sightings.py` — `SightingsEngine.collect(seed, variants)`.
  Runs only providers that implement `sightings()` (`supports_sightings` and not
  `emits`), each with its own timeout, rate-limit bucket, request budget and
  `EvidenceRecorder`, so a slow or hostile platform cannot starve the run. Caps
  output to `limits.max_sightings`, keeps the earliest posts, de-duplicates on
  `(platform, post_id)` so re-runs add nothing, persists via `repo.add_sighting`
  and `repo.record_provider_run(extra={"stage": "sightings"})`, and returns a
  `SightingsSummary` with collected/stored/suppressed counts, providers run /
  skipped / failed, platforms, role counts, earliest observed per platform,
  warnings and duration.
* `phishtrace/core/archiver.py` — `Archiver` resolves Wayback Machine
  availability per URL (`status` = `existing` / `unavailable`), optionally stores
  a gzip, content-addressed local snapshot (requires `fetcher.active_fetch`, i.e.
  the SSRF-guarded fetcher), records every lookup as evidence, and
  `archive_sightings()` writes `archive_snapshot_url` back onto stored sightings.
* `phishtrace/core/pivot.py` — added `note_external_run(provider, requests=...,
  duration_ms=..., error=..., stage=...)` so providers driven outside the engine
  still appear in `coverage()` with the right status and an explicit `stage`
  field, instead of being mislabelled as skipped.
* `phishtrace/core/orchestrator.py` — new `_post_stages()` runs after pivoting:
  sightings collection, external-run accounting, social timeline derivation and
  optional archiving. The investigation summary now carries `sightings`,
  `archive` and `timeline` (`earliest_observed`, `earliest_label`, per-stage
  dates, `event_count`, `precision`, `wording`), warnings are truncated to 50
  entries before finalisation, and `coverage["timeline"]` reports anchor coverage.
* `phishtrace/cli.py` — prints the earliest-observed line and a `Social` stage
  line (collected vs kept, capped marker) in addition to the existing counters.
* `phishtrace/tests/test_phase4_timeline.py` — 34 tests.

Behaviours proven by tests:

* Same-day, same-fact events collapse into one entry with a `sources` list and
  the correct `collapsed` count; distinct stages on the same day stay separate.
* Timeline gaps are detected with a configurable threshold, and gap arithmetic
  uses real day deltas (Jan 1 to Mar 10 = 69 days).
* Date-only evidence is marked `precision="day"`; timestamped evidence is
  `"exact"`; `earliest_observed` is always the minimum across stages.
* Social posts become timeline events at the `social` stage and participate in
  the earliest-observed calculation.
* Role classification separates victim reports, researchers and actors, returns
  confidence and rationale, and `summarize_roles()` counts only stored posts.
* The sightings engine caps to `max_sightings`, keeps the earliest posts,
  de-duplicates on re-run (zero new rows), isolates per-provider failures, and
  records `stage="sightings"` provider runs.
* `note_external_run()` flips a provider from skipped to ran/failed in coverage.
* The archiver records a Wayback lookup as evidence and marks unavailable URLs.

Fixes made while writing these tests: `ProviderContext` exposes `sighting()`, not
`sight()`; timeline events must convert `occurred_at` with `parse_timestamp`
before reaching SQLAlchemy; role counts must be based on stored (capped) posts.

Verification: `132 passed` (phases 1–4).

## Phase 5 — isolated fetcher and static kit analyzer (completed)

Delivered:

* `phishtrace/core/fetcher.py` — `IsolatedFetcher`, the only code path allowed to
  touch attacker infrastructure. It resolves the host once, rejects every
  address that is not `is_global` (loopback, RFC1918, CGNAT 100.64/10, link-local
  169.254.169.254, documentation 192.0.2.0/24, IPv6 loopback), revalidates on
  every redirect hop, pins the connection to the validated IP while keeping the
  real `Host` header and TLS SNI, accepts only `http`/`https`, blocks
  management/database ports (`22,23,25,135,139,445,1433,3306,3389,5432,6379,9200,11211`),
  strips credentials from URLs and proxies, enforces per-response and per-run
  byte caps, never reuses cookies between requests, and records a fetch as
  evidence only when an investigation is bound. `allow_localhost` is an explicit
  test-only gate.
* `phishtrace/analyzers/kit.py` — static phishing-kit analysis, no execution:
  * Gated on `fetcher.active_fetch` plus either a hostile verdict or an explicit
    `force=True`; refuses before making a single request otherwise.
  * Landing page, same-origin scripts/styles/images only (third-party CDN URLs
    are recorded, never fetched), a bounded set of common kit/exposure paths
    (`/logs`, `/results`, `/config.php`, `/.env`, `/admin`, archives, ...) with a
    small probe budget, soft-404 detection and a 403/Cloudflare challenge
    classifier.
  * Extraction of brand lure and confidence, title, form fields/action,
    exfiltration e-mails, Telegram bot IDs + chat IDs (token reduced to bot ID
    plus a truncated SHA-256 fingerprint), Discord/Slack/Telegram/generic
    webhooks (paths redacted), analytics IDs, author handles and redirect chains.
  * Credential exposure reported as count/type/masked local-part only; the same
    dump reachable at `/logs` and `/logs/` is counted once by body hash.
  * ZIP archives inspected in memory with traversal, absolute path, drive letter
    and size-cap rejection; nothing is ever extracted to disk.
  * Deterministic `file_tree_hash`, SHA-256 per file, and fuzzy hashes
    (`ssdeep`/`tlsh` when installed, otherwise a labelled simhash64 fallback).
  * `pivots()` emits normalizer-validated graph candidates and `to_db_dict()`
    persists through `repo.add_kit` when a repository is bound.
* `phishtrace/tests/kit_fixture.py` — harmless loopback mock kit
  (`ThreadingHTTPServer` on `127.0.0.1:0`) serving a Microsoft 365 lure, JS/CSS/PNG
  assets, a PHP source disclosure, open log/CSV dumps, a bot challenge, a safe
  redirect, a metadata-service redirect, a 200 KB body, a ZIP with a zip-slip
  member and an external-CDN reference. No real credentials, no outbound traffic.
* `phishtrace/tests/test_phase5_kit.py` — 21 tests including closed-gate (zero
  requests), verdict gate, full signal extraction, probe classification,
  credential masks, in-memory archives, redirect handling, SSRF denials
  (CGNAT/documentation/link-local/IPv6/protocol), blocked port 22, cookie
  non-reuse, byte-cap truncation, zero probe budget, repository persistence and
  evidence de-duplication, zip-slip/oversize units, simhash stability and
  `kind_for` classification.

Bugs found and fixed while testing:

* Asset text was cached only when an evidence id existed, so runs without a
  repository silently lost script content and webhook/Telegram pivots.
* Telegram redaction missed tokens embedded in `api.telegram.org/bot<id>:<token>`
  URLs because the token has no word boundary after `bot`; the token regex now
  accepts the `bot` prefix and redaction keeps the bot ID only.
* Literal Telegram webhook URLs were echoed in `url_redacted` including the token;
  they are now reduced to `bot<redacted>`.
* Probe credential counts double-counted the same body at `/logs` and `/logs/`.
* The mock server reused the previous instance's request log, which could mask
  probe-budget regressions.
* `kind_for` now prioritises content type and `<?php`/`<html` sniffing before the
  file suffix, so disclosed source and open logs are classified correctly.

Verification: `153 passed` (phases 1–5).

## Phase 6 — live console

Delivered:

* `phishtrace/api/runs.py` — `RunManager`, an in-process supervisor for console
  runs. Each investigation gets a replayable event deque with a monotonic
  cursor, an `RLock`, a daemon worker thread and a cloned provider registry, so
  a run started from HTTP cannot block the event loop or mutate shared provider
  circuit-breaker state. `snapshot()` and `wait()` back both tests and the
  progress endpoints. Durable state stays in SQLite; the manager is only the
  live transport.
* `phishtrace/core/orchestrator.py` — `run_existing()` split out of `run_seed()`
  so an API-created investigation can be executed by the manager. Added
  `run.start`, stage, and `run.finalized` progress events alongside the pivot
  engine's `node.*`, `provider.done` and `run.complete` events. The finalized
  summary now embeds the merged timeline (earliest observed, per-stage
  earliest, event count, precision, gaps and wording) plus sightings, archive
  counters and warnings.
* `phishtrace/api/routes.py` — `POST /api/investigations` (normalized seed,
  explicit or auto-detected kind, length cap, optional reuse of the latest
  completed/partial run, CSRF enforced when auth is on), replayable
  `GET /api/investigations/{id}/progress?after=N`, SSE
  `GET /api/investigations/{id}/progress/stream` with `no-store` and
  `X-Accel-Buffering: no`, kit-lab `POST /api/investigations/{id}/kit` (gated on
  `fetcher.active_fetch`, persisted through `add_kit`), `GET .../kits`, merged
  timeline output, and `/api/stats`.
* Console UI (`phishtrace/ui/index.html`, `static/app.js`, `static/style.css`):
  seed launcher with type override and sightings toggle, investigation sidebar,
  headline counters, "earliest observed" card, replaying live event log with
  polling fallback when SSE is unavailable, radial SVG infrastructure/persona
  graph with per-node inspector, merged first-seen timeline with precision and
  gaps, sightings list, provider coverage with ran/skipped/failed reasons and
  stop-list counts, evidence browser with safe text preview and raw download,
  and kit-lab run/history views. Every API/provider value is inserted with
  `textContent` or DOM properties; links are restricted to http(s) and carry
  `rel="noopener noreferrer"`; no token, cookie or password is written to the
  DOM or logs.
* `phishtrace/tests/test_phase6_ui.py` — 8 tests with a deterministic fixture
  provider: page/asset rendering, start + progress + reuse idempotency, invalid
  seed/kind, terminal SSE replay, sightings/evidence preview and raw download,
  kit gate, auth + CSRF + ownership, and static UI security checks.

Bugs found and fixed while testing:

* The UI security test searched for the literal `innerHTML` and tripped on the
  file's own safety comment; the assertion now looks for actual assignment
  (`.innerHTML =`) so it tests behaviour instead of prose.
* A sighting inserted by the API test used an ISO string for `posted_at` and hit
  SQLAlchemy's `DateTime` type; it now passes an aware `datetime`.
* Coverage row severity classes did not match the CSS (`good`/`warn`/`bad` vs
  `ran`/`skipped`/`failed`), leaving counts unstyled; classes now match.

Verification: `161 passed` (phases 1–6), 1 third-party Starlette/httpx
 deprecation warning. Browser smoke: real console served on loopback with the
 fixture provider, a UI-started run completed, graph/timeline/coverage/evidence
 tabs rendered at 1600x1000, no page errors and no console errors. All API tests
 use FastAPI's TestClient; no network provider was contacted.

Known limits: the live event deque is in memory, so after a server restart a
 run's progress is gone but its durable record, coverage and timeline remain in
 SQLite; SSE reconnects replay from the `after` cursor, and the JS falls back to
 polling. The archiver/sightings path was not exercised in this phase's UI smoke
 (`run_sightings=False`); it is covered by phase 4 tests.

## Known limitations (tracked, not hidden)

* Provider parsers are written against the public API shapes as documented at
  build time; upstream schema changes will surface as `partial` results with a
  note rather than a crash. Live-key validation happens in phase 8/9.
* Mastodon search needs a token; Telegram has no public search API, only the
  public channel preview.
* Hudson Rock results are aggregated (family counts and dates) so no stolen
  credentials or victim hostnames enter the database.

## Phase 7 — reporting, STIX/MISP/OpenCTI, abuse drafting

Built a reporting layer where every renderer consumes one JSON-safe context dict,
so HTML, PDF, Markdown, text, CSV, JSON, STIX 2.1 and MISP cannot drift apart.

* `phishtrace/reports/context.py` — `build_report_data()` merges the durable
  export (indications, edges, sightings, kits, evidence) with the timeline
  merger and the coverage record. Renderers never touch the database or the
  network. Includes `report_filename()` (slugged, fixed extension map) and
  `deterministic_uuid()` (`uuid5` over a fixed namespace) so re-exports are
  idempotent in a TIP.
* `phishtrace/reports/render.py` — HTML (Jinja autoescape, standalone inline
  CSS, CSP `default-src 'none'`), PDF, Markdown, text, CSV (formula-injection
  guarded by a leading apostrophe for `= + - @` cells), JSON, plus the bundle
  writer with a manifest of size and SHA-256 per file.
* `phishtrace/reports/stix.py` — STIX 2.1 bundle with `identity`, `indicator`
  (standard SCO patterns; `x-…` custom SCO names only where no standard
  observable exists), `relationship` per graph edge, a `note` carrying coverage
  and a `report` object referencing every emitted indicator.
* `phishtrace/reports/misp.py`, `opencti.py` — MISP event mapping (`to_ids` is
  false for context-only stop-list nodes, comment says why) and an OpenCTI
  GraphQL bundle push. Both pushes are opt-in, disabled by default, and raise
  `IntegrationError` without echoing the API key on failure.
* `phishtrace/reports/abuse.py` — drafts only, never sends. Hosting, registrar,
  certificate-authority and national-CERT targets are derived from recorded
  evidence plus explicitly configured contacts; addresses are never guessed
  from an organisation name. Emails defang indicators in the body and attach
  the exact-indicator JSON report.
* `phishtrace/reports/templates/` — `report.html.j2`, `report.md.j2`.
* API: `GET /api/investigations/{id}/reports`, `GET …/report?format=…`
  (download or `inline=1` with CSP + `frame-ancestors 'none'`),
  `GET …/abuse` (JSON preview or ZIP), `POST …/export/{misp,opencti}` with
  push gated behind explicit configuration.
* CLI: `phishtrace report`, `phishtrace abuse`, `phishtrace export`.
* UI: report panel in the overview tab with per-format links; `wireReportLinks`
  builds URLs from the investigation id only.
* `phishtrace/tests/test_phase7_reports.py` — 24 tests: context merging and
  coverage precedence, every renderer, CSV injection guard, HTML escaping of a
  hostile indicator, STIX shape/determinism/quote escaping, MISP mapping and
  redaction, OpenCTI gating, abuse target derivation and EML headers, bundle
  manifest integrity, API status codes and CSP.

Bugs found and fixed while testing:

* Coverage reported providers as `enabled` because the static availability row
  won over the run's own `ran`/`skipped`/`failed` lists. The run's lists are now
  authoritative, and an `enabled` row with no recorded request becomes
  `skipped` with a reason instead of pretending it ran.
* STIX custom SCO types were emitted with a trailing hyphen
  (`x-phone-number-:value`), which is not the documented naming. They are now
  `x-phone-number`, `x-telegram-account`, etc.; the test asserts the custom type
  inside the pattern, where STIX actually allows it.
* Abuse targeting picked a stop-listed CDN (`context_only` node) as a hosting
  provider. Context-only nodes are now excluded from target derivation.
* A configured `company` containing CRLF and `Bcc:` survived into the `From`
  display name. Display names are now stripped of control characters and
  address-delimiters before the header is built.
* Certificate authority and national CERT were one target, so a CA draft could
  be addressed to a CERT inbox (or the reverse). They are now separate targets:
  the issuer is manual unless a CA abuse role is configured, and a CERT draft is
  created only for an explicitly configured country contact.
* `build_abuse_package()` produced no attachment unless the caller passed one,
  even with `abuse_include_attachment: true`. It now renders the JSON report
  itself.

Verification: `185 passed` (phases 1–7), one third-party Starlette/httpx
deprecation warning. `node --check` on the UI bundle, `compileall` on the
package, and `git diff --check` are clean. No test contacts a live provider,
MISP or OpenCTI instance; both push paths use `httpx.MockTransport`.

Known limits: the PDF renderer is dependency-light and produces a simple
text-flow document rather than a designed layout; MISP/OpenCTI payloads follow
the documented shapes but were not pushed to a live instance in this phase.

## Phase 8 — keyed providers and wrapped CLI tools

Added the provider classes that need a credential or an external binary, and
taught the registry to label every provider with the phase it belongs to.

* `phishtrace/providers/keyed.py` — ten Phase B providers behind normal
  `ProviderMeta` classes: VirusTotal, Shodan, Censys, SecurityTrails, AlienVault
  OTX, AbuseIPDB, GreyNoise, Hybrid Analysis, MalwareBazaar and WhoisXML. Each
  declares the indicator types it accepts, the credential variables it needs and
  the fields it maps into the normalized indicator/edge model; the API key stays
  in headers except where the vendor only accepts a query parameter, and the
  evidence URL is built with the key redacted so it can be shown in the UI.
* `phishtrace/providers/tool_wrappers.py` — eight Phase C providers that shell
  out to `dnstwist`, `theHarvester`, `sherlock`, `maigret`, `holehe`, `ghunt`,
  `phoneinfoga` and `spiderfoot`. All of them run through the existing bounded
  `ToolRunner`: argv-only (no shell), sanitized environment, scratch working
  directory, process-group kill on timeout, output byte caps and a leading `-`
  guard on targets. Parsers cover JSON, CSV and plain-text output shapes.
* Phase tags on `ProviderMeta` (`phase="A" | "B" | "C"`), surfaced in
  `/api/providers` and the UI so an operator can see which providers are
  keyless, which need a key and which need a binary. The registry now reports
  `loaded 41 errors 0` with `Counter({'A': 23, 'B': 10, 'C': 8})`.
* `config.yaml` providers block rewritten to the real 41 names, with `timeout:`
  at provider level and `path`/`mode`/`max_output` under `options:`. The two
  active account probes (`holehe`, `ghunt`) ship disabled and require
  `legal_acknowledged: true` because they touch third-party accounts; the other
  wrappers only read public data and no longer carry the acknowledgement gate.
  Unimplemented options moved to a commented "planned, not implemented" list.
* `docs/PROVIDERS.md` — discovery model, per-phase tables with credentials,
  binaries and options, the provider behaviour contract (`can_run`, skip reasons,
  evidence, budget), the security controls in the tool runner and the steps for
  adding a provider.
* `phishtrace/tests/test_phase8_providers.py` — 38 tests. Keyed providers are
  exercised through `httpx.MockTransport` payloads (VirusTotal v3, Shodan,
  Censys, SecurityTrails, OTX, AbuseIPDB, GreyNoise, Hybrid Analysis,
  MalwareBazaar, WhoisXML); wrappers are exercised against `/bin/sh` stub
  scripts that emit representative JSON/CSV/text, so no real binary or network
  call is needed.

Bugs found and fixed while testing:

* Shodan, Censys and VirusTotal parsed an ASN label such as `AS64501` with
  `as_int()`, got `0` and emitted `AS0`. A shared `_asn_label()` helper now
  strips the prefix and keeps the digits.
* Censys returning `{"result": null}` was treated as success (the empty dict
  passed the `isinstance(dict)` check and the event was then dropped for a
  missing timestamp), and VirusTotal with an empty `data.attributes` did the
  same. Both now record a partial result with an explicit reason instead of
  reporting a clean run that produced nothing.
* Sherlock's `"available"` state (meaning no profile) was counted as a hit;
  only `"claimed"`/`"found"` are accepted now.
* `belongs_to_domain()` could leak out-of-scope addresses: it compared the
  target against the registrable domain of the host, so `elsewhere.example`
  matched `evil-login.example` because both collapse to `example`. The helper is
  now a strict `host_matches(host, domain)` and theHarvester only keeps
  hostnames inside the investigated domain.
* Evidence URLs for keyed providers embedded the API key in the query string;
  they are now recorded with the secret redacted.

Verification: `223 passed` for the full suite (185 through Phase 7 plus the 38
new tests), one third-party Starlette/httpx deprecation warning. `compileall`
on the package and `git diff --check` are clean.

Known limits: none of the eight wrapped binaries is installed in this
environment, so their tests use stub scripts and the parsers are verified
against documented output shapes rather than live tool versions. Keyed providers
are verified against mocked payloads; live API responses, quota behaviour and
vendor-side schema changes were not exercised in this phase.
