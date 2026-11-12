# API key checklist and live status

Every key below is loaded from `.env` in the repo root at startup
(`BASE_DIR/.env`, see `phishtrace/config.py`). A missing key is never fatal —
that provider just reports `skipped`.

Verify what is live at any time:

```bash
./.venv/Scripts/phishtrace.exe doctor      # api_keys_present + config health
./.venv/Scripts/phishtrace.exe providers   # per-provider status/reason
```

After editing `.env`, restart the service so the config is re-read:

```bash
schtasks /End /TN PhishTrace
schtasks /Run /TN PhishTrace
```

---

## Current status — verified 2026-11-12

Each key was checked with one minimal read-only request against the vendor's
live API, then exercised through a real investigation.

| Provider | Env var | Live check | Result |
|----------|---------|-----------|--------|
| `virustotal` | `VIRUSTOTAL_API_KEY` | `GET /api/v3/domains/example.com` | **200 OK** |
| `alienvault_otx` | `OTX_API_KEY` | `GET /api/v1/indicators/domain/example.com/general` | **200 OK**, 50 pulses |
| `urlhaus` + `threatfox` | `ABUSECH_AUTH_KEY` | `POST urlhaus-api.abuse.ch/v1/host/` | **200 OK**, `query_status=ok` |
| `abuseipdb` | `ABUSEIPDB_API_KEY` | `GET /api/v2/check?ipAddress=8.8.8.8` | **200 OK** |
| `greynoise` | `GREYNOISE_API_KEY` | `GET /v3/community/8.8.8.8` | **key accepted** (404 = IP not observed) |
| `hybrid_analysis` | `HYBRID_ANALYSIS_API_KEY` | `GET /api/v2/search/hash` | **200 OK**, restricted tier |
| `shodan` | `SHODAN_API_KEY` | `GET /api/shodan.io/api-info` | **200 OK**, `plan=oss`, 0 query credits |
| `censys` | `CENSYS_API_TOKEN` | `GET /v3/global/asset/host/8.8.8.8` | **200 OK** (lookup only) |
| `whoisxml` | `WHOISXML_API_KEY` | `GET WhoisService?domainName=example.com` | **200 OK**, live WHOIS record |

Provider matrix after loading the keys: **41 total, 30 enabled, 11 skipped,
0 failed**. Enabled count went from 20 to 30.

### Vendor changes found and fixed

- **Censys** retired the legacy Search API v2 on 2026-09-30 (`410`/`decommissioned`).
  The Platform *search* endpoint returns 403 without a paid organization ID, but
  the per-asset **lookup** endpoint works on the free wallet with the
  `censys_...` Personal Access Token. The provider now calls
  `GET https://api.platform.censys.io/v3/global/asset/host/{ip}` with
  `Authorization: Bearer`. `CENSYS_API_ID` / `CENSYS_API_SECRET` are gone.
- **Hybrid Analysis** deprecated `POST /api/v2/search/hash` in API 2.35
  (returns 410 "deprecated in API version 2.35.0"). The current form is
  `GET /api/v2/search/hash?hash=...`, which the provider now uses; the
  domain/URL path (`POST /api/v2/search/terms`) is unchanged.
- **GreyNoise / Hybrid Analysis 404s** are now treated as "no record for this
  indicator" instead of a provider failure, so a clean negative is not reported
  as a broken key.

## Tier 1 — free, high value

| # | Platform | Env var(s) | Unlocks (provider) | Free tier | Signup |
|---|----------|------------|--------------------|-----------|--------|
| 1 | VirusTotal | `VIRUSTOTAL_API_KEY` | `virustotal` — file/URL/domain/IP verdicts, relations | 4 req/min, 500 req/day | https://www.virustotal.com/gui/my-apikey |
| 2 | AlienVault OTX | `OTX_API_KEY` | `alienvault_otx` — pulses, passive DNS, URL reputation | Yes | https://otx.alienvault.com/settings |
| 3 | abuse.ch | `ABUSECH_AUTH_KEY` | `urlhaus` + `threatfox` (one key covers both) | Yes | https://auth.abuse.ch/ |
| 4 | AbuseIPDB | `ABUSEIPDB_API_KEY` | `abuseipdb` — IP abuse reports, hosting/proxy flags | 1,000 checks/day | https://www.abuseipdb.com/account/api |
| 5 | GreyNoise | `GREYNOISE_API_KEY` | `greynoise` — scanner noise vs targeted activity | Community API, low daily quota | https://viz.greynoise.io/account/api-key |
| 6 | Hybrid Analysis | `HYBRID_ANALYSIS_API_KEY` | `hybrid_analysis` — sandbox reports, dropped IOCs | Yes (restricted tier) | https://www.hybrid-analysis.com/apikeys/info |

## Tier 2 — free account, small quota

| # | Platform | Env var(s) | Unlocks (provider) | Free tier | Signup |
|---|----------|------------|--------------------|-----------|--------|
| 7 | Shodan | `SHODAN_API_KEY` | `shodan` — open ports/banners, host history, favicon/HTML hashes | Free key is very limited (`plan=oss`, 0 credits); $49 one-time Membership = 100 credits/mo | https://account.shodan.io |
| 8 | Censys | `CENSYS_API_TOKEN` | `censys` — host service/cert lookups | 100 credits/mo, lookup endpoints only (search needs a paid org) | https://platform.censys.io (API tab) |
| 9 | Mastodon | `MASTODON_TOKEN` | `mastodon` — toot search across instances | Free | https://mastodon.social/settings/applications |

## Tier 3 — paid / commercial

| # | Platform | Env var(s) | Unlocks (provider) | Notes |
|---|----------|------------|--------------------|-------|
| 10 | SecurityTrails | `SECURITYTRAILS_API_KEY` | `securitytrails` — historical DNS, subdomains, WHOIS | Commercial; no dependable free API tier |
| 11 | WhoisXML | `WHOISXML_API_KEY` | `whoisxml` — historical WHOIS, reverse WHOIS | Free trial credits, then paid |

## Not obtainable

- **PhishTank** (`PHISHTANK_API_KEY`) — provider is implemented, but new
  registration has been closed since 2020, so a key is unobtainable unless you
  already hold an account. `openphish` / `phishing_database` / `phishstats`
  already cover feeds keylessly.

## Declared but not implemented

`config.key_presence()` lists more names than the code actually consumes. These
have no provider behind them yet, so adding a key changes nothing:
`VALIDIN_API_KEY`, `SILENTPUSH_API_KEY`, `DOMAINTOOLS_API_KEY`, `INTELX_API_KEY`,
`DEHASHED_API_KEY`, `MDTI_TOKEN`, `X_BEARER_TOKEN`, `YOUTUBE_API_KEY`,
`SERPAPI_KEY`, `BRAVE_API_KEY`, `GOOGLE_CSE_API_KEY`, `TELEGRAM_API_ID`/`HASH`,
`HUDSONROCK_API_KEY` (the free Cavalier OSINT endpoint needs no key and is
already used), `NETLAS_API_KEY`, `CRIMINALIP_API_KEY`, `SPIDERFOOT_API_KEY`,
`REDDIT_CLIENT_ID`, `BLUESKY_APP_PASSWORD`.

## Quota notes

- **Shodan** `plan=oss` with 0 query credits: `host` lookups consume credits, so
  expect `402/403` on busy days. The keyless `shodan_internetdb` provider still
  returns ports for most IPs.
- **Censys** free wallet is per-lookup; a full investigation with several IPs can
  burn the monthly allowance quickly.
- **VirusTotal** 4 req/min is enforced by the provider's `rate_limit`.
