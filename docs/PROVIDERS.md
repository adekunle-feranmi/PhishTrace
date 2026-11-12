# Provider catalogue

PhishTrace discovers plugins by importing every module in `phishtrace/providers/`
and collecting `BaseProvider` subclasses. A provider declares its own metadata
(`ProviderMeta`), so adding one is a matter of dropping a module into that
package — no registry list to edit.

```
phishtrace/providers/
├── base.py          ProviderMeta, BaseProvider.can_run(), availability rules
├── context.py       run context: emit(), event(), partial(), budgets
├── archives.py, certificates.py, domain_intel.py, feeds.py,
│   infrastructure.py, social.py, urlscan.py
│                    Phase A — public, unauthenticated sources
├── keyed.py         Phase B — API-key sources
└── tool_wrappers.py Phase C — installed CLI tools

MISP and OpenCTI are report export targets, not pivot providers; their code
lives in `phishtrace/reports/`.
```

`ProviderMeta.phase` drives the coverage table in reports:

| Phase | Meaning | Runs when |
| --- | --- | --- |
| `A` | Public endpoint, no credential | always (unless disabled) |
| `B` | Needs an API key | its key variable is present in `.env` |
| `C` | Needs an installed binary | the binary resolves on `PATH` or `options.path` |

Anything that cannot run is reported as **skipped with a reason**
(`VIRUSTOTAL_API_KEY not configured`, `required tool 'dnstwist' is not installed`,
`disabled in config.yaml`), so a report never silently implies a source was
consulted.

## Phase A — keyless (23 providers)

| Name | Selectors accepted | What it contributes |
| --- | --- | --- |
| `crt_sh` | domain | Certificate-transparency subdomains and issuers |
| `certspotter` | domain | Second CT log view, issuance history |
| `urlscan` | url, domain | Live scan metadata, page resources, contacting IPs |
| `urlhaus` | url, domain, ip | Malware distribution URLs and payload hashes |
| `threatfox` | url, domain, ip, file_hash | IOC records with malware family and confidence |
| `openphish` | url, domain | Community phishing feed membership |
| `phishing_database` | url, domain | Phishing Database feed membership |
| `phishtank` | url, domain | PhishTank verification status (free key raises limits) |
| `wayback` | url, domain | First/last capture timestamps, historical hosts |
| `memento` | url | Time-travel aggregation across archives |
| `hackertarget` | domain, ip | Passive DNS and reverse-DNS lookups |
| `threatminer` | domain, ip, file_hash | Passive DNS, WHOIS, related samples |
| `phishstats` | domain, ip, url | Phishing score and hosting metadata |
| `shodan_internetdb` | ip | Open ports and banners without an API key |
| `ipinfo` | ip | ASN, organisation, country, privacy flags |
| `hudsonrock` | email, domain, username | Infostealer infection exposure |
| `typosquat` | domain | Registered look-alike permutations (passive DNS only) |
| `dns_intel` | domain, ip | A/AAAA/MX/NS/TXT plus resolver consensus |
| `rdap` | domain, ip | Registry data: registrar, dates, status, name servers |
| `telegram_public` | telegram | Public channel metadata for `t.me` handles |
| `reddit` | username, url | Public account existence and karma |
| `bluesky` | username, domain | Handle resolution and DID document |
| `mastodon` | username, domain | Account discovery across instances |

All Phase A providers are safe to leave enabled. They respect the global
request budget (`limits.global_request_budget`) and per-provider budget, and
each records its HTTP exchange as evidence.

## Phase B — keyed APIs (10 providers)

Keys are read from the environment only (`Config.api_key`), never from YAML.
Every key below is documented in `.env.example`.

| Name | Environment variables | Emits | Notes |
| --- | --- | --- | --- |
| `virustotal` | `VIRUSTOTAL_API_KEY` | ip, domain, asn, file_hash | v3 API; URL/file identifiers are base64url; one request per indicator |
| `shodan` | `SHODAN_API_KEY` | ip, domain, asn | Resolves domains through `dns/resolve`, then one host lookup per IP (max 3) |
| `censys` | `CENSYS_API_ID`, `CENSYS_API_SECRET` | domain, asn | HTTP Basic auth; certificate SANs are the main pivot value |
| `securitytrails` | `SECURITYTRAILS_API_KEY` | ip, domain, nameserver | Current DNS plus subdomain list; one request per domain |
| `whoisxml` | `WHOISXML_API_KEY` | nameserver, email, domain | `apiKey` travels in the query string; the stored evidence URL is redacted |
| `alienvault_otx` | `OTX_API_KEY` | ip, domain, url | Pulses become `ti-pulse` events; passive DNS and URL list become selectors |
| `abuseipdb` | `ABUSEIPDB_API_KEY` | domain, ip | Abuse confidence and report count; the registrant domain is context-only, hostnames become pivots |
| `greynoise` | `GREYNOISE_API_KEY` | ip | RIOT/benign services are marked `context_only` so shared CDN IPs never become hosting abuse targets |
| `hybrid_analysis` | `HYBRID_ANALYSIS_API_KEY` | file_hash | `api-key` header; picks the highest-threat report of the returned samples |
| `malwarebazaar` | `MALWAREBAZAAR_API_KEY` (optional) | file_hash, domain | Works anonymously; the key only raises rate limits. Domains found in tags are context-only |

Behaviour shared by every Phase B provider:

* **Missing key ⇒ no request.** The provider calls `ctx.partial(...)` and returns;
  the investigation continues and the coverage table records the gap.
* **Malformed payload ⇒ partial, not fatal.** A vendor returning `{}`, `null`
  or an unexpected wrapper is recorded as a partial result with a reason.
  A single bad record inside a list is skipped.
* **HTTP failure ⇒ partial.** Status, error text and the attempt count are kept;
  the orchestrator decides whether to retry.
* **Secrets never reach evidence verbatim.** Keys are preferred in headers.
  For vendors that require a query-string key, `redact_url()` rewrites the
  stored URL and `redact_mapping()` scrubs request parameters.

## Phase C — wrapped CLI tools (8 providers)

Tools are executed by `phishtrace.tools.runner.ToolRunner`, never through a
shell. The runner:

1. validates the target (`validate_target`): rejects a leading `-` (argv
   injection), whitespace, control characters, non-ASCII and anything over
   512 characters;
2. builds an argv list and executes it with `create_subprocess_exec`;
3. runs in a fresh temporary working directory and a sanitised environment
   (`PATH`, `HOME`, `LANG`, `TZ`, `TMPDIR` only — inherited secrets and proxy
   variables are dropped);
4. enforces a wall-clock timeout and kills the whole process group on expiry;
5. caps stdout and stderr independently and marks the result truncated when
   the cap is hit;
6. collects declared report files (`collects`) and, where the tool's filename
   is unpredictable, any `*.json` it left in the scratch directory
   (`collect_json`);
7. stores the exact command, exit code, duration and captured output as
   evidence under `tool://<name>`.

| Name | Binary | Options | Default | Selector policy |
| --- | --- | --- | --- | --- |
| `dnstwist` | `dnstwist` | `path`, `max_output` | enabled | Registered permutations only; each look-alike is `context_only` with its A/MX/NS records |
| `theharvester` | `theHarvester` | `path`, `sources`, `limit` | enabled | Emails and hosts are filtered to the target domain; out-of-domain hits are dropped |
| `spiderfoot` | `spiderfoot` | `path` (alias `cli_path`), `mode`, `modules` | enabled | CSV output mapped to selector types; phone/BTC findings are context-only |
| `sherlock` | `sherlock` | `path` | enabled | Only `Claimed`/`Found` accounts become URLs; `Available` is ignored |
| `maigret` | `maigret` | `path` | enabled | NDJSON output; same claimed-only policy as sherlock |
| `phoneinfoga` | `phoneinfoga` | `path` | enabled | Carrier/region metadata only, context-only; never treated as attribution |
| `holehe` | `holehe` | `path`, `legal_acknowledged` | **disabled** | Registered-service list only, context-only. Requires `legal_acknowledged: true` |
| `ghunt` | `ghunt` | `path`, `cookies`, `cookie_flag`, `legal_acknowledged` | **disabled** | Existence + service names only. Names, photos and GAIA IDs are discarded before anything is stored |

`holehe` and `ghunt` actively probe account existence, so they carry a
`legal_note` and `BaseProvider.can_run()` refuses to start them unless
`options.legal_acknowledged: true`. `ghunt` additionally requires a Netscape
cookie file in `options.cookies`.

### Timeouts and caps

| Setting | Location | Effect |
| --- | --- | --- |
| `timeout` | provider block | Wall clock for one tool invocation |
| `options.max_output` | provider block | Byte cap for stdout and stderr (default 4 MB, spiderfoot 8 MB) |
| `limits.provider_timeout_seconds` | global | Default HTTP timeout for requests that do not pass their own |

## Not implemented (tracked, not wired)

These names appear in `.env.example` and are mentioned as future work; no plugin
exists, so configuring them has no effect:

* Search APIs: `youtube`, `x_search`, `serpapi`, `brave_search`, `google_cse`.
* Commercial feeds: `domaintools`, `validin`, `silentpush`, `netlas`,
  `criminalip`, `greynoise_ri`.
* Breach data: `dehashed`, `intelx` — require legal review before any code lands.
* `misp` / `opencti` / `telegram` as *providers*: MISP and OpenCTI are report
  export targets (`phishtrace/reports/`), and Telegram collection is limited to
  the public-channel provider above.

## Adding a provider

1. Create a module in `phishtrace/providers/` with a `BaseProvider` subclass.
2. Fill in `ProviderMeta`: `name`, `phase`, `accepts`, `emits`, `category`,
   `reliability`, `timeout`, and `api_keys` (Phase B) or `requires_tool`
   (Phase C).
3. Implement `async def run(self, ctx)`; use `ctx.http.get_json(...)` so the
   exchange is cached, budgeted and recorded as evidence.
4. Emit only normalised selectors with a relation, strength and evidence id.
   Anything that must not drive expansion gets `context_only=True`.
5. Add a test with `httpx.MockTransport` (keyed) or a stub executable in
   `tmp_path` (tools). No test may touch a live vendor.
