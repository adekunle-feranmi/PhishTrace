# PhishTrace

PhishTrace is a defensive OSINT console for phishing infrastructure and persona
investigations. Give it a URL, domain, IP, email, phone number, crypto address,
Telegram handle, analytics ID or certificate selector; it pivots across passive
sources, records every observation with evidence, and produces analyst-ready
reports and abuse packages.

It is built for brand-protection teams, incident responders and threat
intelligence analysts who need a repeatable, auditable workflow rather than a
pile of browser tabs.

## What it does

* **Passive-first pivoting** across certificate transparency, DNS, RDAP/WHOIS,
  URL scan archives, phishing feeds, threat intelligence and optional keyed
  APIs. Active fetching of attacker infrastructure is off by default.
* **Explainable graph**: every edge carries its provider, confidence, selector
  strength and evidence; weak selectors are context-only unless explicitly
  expanded.
* **Evidence you can defend**: raw responses are hashed and stored, sightings
  and page snapshots are archived, and every report links back to its source.
* **Live investigation UI** with progress streaming, graph, timeline, evidence
  browser, coverage panel and watchlists.
* **Reports** in HTML, PDF, JSON, STIX 2.1, MISP, Markdown, text and CSV, plus
  abuse-report email drafts and a manifest for registrars/hosts.
* **41 providers** in three phases: 23 keyless, 10 keyed and 8 wrapped CLI tools.
  Providers without credentials or binaries are skipped, not failed.

## Quick start

```bash
git clone https://github.com/<your-org>/phishtrace.git
cd phishtrace
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"

cp .env.example .env
# edit .env: set PHISHTRACE_SESSION_SECRET and any provider keys
phishtrace create-admin --username analyst
phishtrace serve
```

Open <http://127.0.0.1:8088>, sign in, and paste an indicator. The server binds
loopback by default. To expose it, use the TLS reverse-proxy and systemd or
Docker instructions in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

The first administrator can also be created non-interactively with
`PHISHTRACE_ADMIN_PASSWORD`:

```bash
PHISHTRACE_ADMIN_PASSWORD='a-long-passphrase' phishtrace create-admin --username analyst
```

## CLI

```bash
phishtrace run example.com                 # investigate and store the result
phishtrace run example.com --json          # machine-readable result
phishtrace providers                       # availability by phase
phishtrace doctor                          # config, keys, binaries
phishtrace report --latest                 # render configured formats
phishtrace report <id> --format pdf --format stix
phishtrace abuse --latest --zip            # draft emails, no message is sent
phishtrace export --latest --target stix --push   # OpenCTI, if configured
phishtrace purge --days 180                # retention
```

`phishtrace run --no-sightings` skips social sightings; `--no-reuse` forces a
new investigation instead of reusing the latest result for the same seed.

## Configuration

`config.yaml` holds non-secret settings: bind address, limits, fetcher policy,
provider timeouts/options, stoplists and report defaults. Secrets are read only
from the environment or `.env`:

```dotenv
PHISHTRACE_SESSION_SECRET=...       # required for non-loopback binds
VIRUSTOTAL_API_KEY=...
SHODAN_API_KEY=...
# see .env.example for the full list
```

Useful environment overrides: `PHISHTRACE_HOST`, `PHISHTRACE_PORT`,
`PHISHTRACE_DATA_DIR`, `PHISHTRACE_DATABASE_URL`,
`PHISHTRACE_TRUSTED_PROXIES`.

Provider credentials, accepted indicator types, wrapper binaries and options are
documented in [docs/PROVIDERS.md](docs/PROVIDERS.md).

## Reports and integrations

Reports render from a normalized snapshot, so the same findings produce
consistent HTML/PDF/JSON/STIX/MISP output. Abuse drafts are written to disk with
a recipient manifest; PhishTrace never sends email. OpenCTI and MISP pushes are
opt-in and disabled by default in `config.yaml`.

## Security

PhishTrace handles hostile content and sensitive evidence. Defaults are
deliberately conservative:

* authentication on, loopback bind, no active fetching;
* Argon2id passwords, signed HttpOnly cookies, CSRF protection, login throttling;
* SSRF-safe fetcher with DNS pinning, redirect revalidation and byte caps;
* argv-only tool execution with sanitized environment and process-group kill;
* redacted config snapshots and evidence URLs (API keys never reach reports);
* hardened systemd unit and a read-only, capability-free container recipe.

Read [docs/SECURITY.md](docs/SECURITY.md) for the threat model, implemented
controls and residual risks before exposing the console to a network.

## Deployment

* [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) — systemd, nginx/TLS, Docker Compose,
  backups, upgrades and troubleshooting.
* `deploy/phishtrace.service` and `deploy/phishtrace.env.example` — hardened
  service unit and environment template.
* `Dockerfile` and `docker-compose.yml` — non-root image with a read-only root
  filesystem and a loopback-published port.

## Performance

The local pipeline is measured in [docs/PERFORMANCE.md](docs/PERFORMANCE.md):
a 600-node/878-edge synthetic investigation ingests in ~1.1 s, reads back in
~22 ms, assembles report data in ~117 ms and renders all eight formats in about
one second (~13 MiB peak). Real investigations are usually dominated by provider
latency.

## Architecture

```
phishtrace/
  api/         FastAPI app, auth, SSE runs, investigation routes
  core/        normalizer, pivot engine, orchestrator, registry, fetcher
  providers/   keyless + keyed providers, CLI tool wrappers
  analyzers/   kit analyzer (static), persona/sighting helpers
  storage/     SQLAlchemy models, repository, evidence store, archiver
  reports/     renderers, STIX/MISP builders, abuse package generator
  tools/       bounded argv-only subprocess runner
  ui/          single-page console and static assets
config/        stoplists
deploy/        systemd unit and environment template
docs/          provider, deployment, security and performance notes
scripts/       load test and container healthcheck
```

## Development

```bash
pip install -e ".[dev]"
pytest -q
python scripts/loadtest.py --nodes 200
```

The suite uses mocked HTTP transports and stub CLI scripts, so it runs without
provider keys, network access or the wrapped binaries. Live provider schemas
and tool versions are not exercised by the tests; check the coverage panel after
enabling a new provider.

## Status and limits

Version 1.0.0 is a single-process, SQLite-backed application. It is not a
multi-tenant SaaS: there is no fine-grained RBAC, no automatic schema migration
framework and no encryption at rest (use disk encryption and filesystem
permissions). Archived evidence may contain victim PII; apply your retention and
handling policy.

## Authorized use

Use PhishTrace only against infrastructure you are authorized to investigate.
Respect provider terms, rate limits and applicable law. The abuse workflow
produces drafts for human review; it does not contact registrars or hosts on
your behalf.
