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

## Known limitations (tracked, not hidden)

* Provider parsers are written against the public API shapes as documented at
  build time; upstream schema changes will surface as `partial` results with a
  note rather than a crash. Live-key validation happens in phase 8/9.
* Mastodon search needs a token; Telegram has no public search API, only the
  public channel preview.
* Hudson Rock results are aggregated (family counts and dates) so no stolen
  credentials or victim hostnames enter the database.
