# PhishTrace

PhishTrace is a defensive, one-click phishing infrastructure and persona investigation
platform. Give it a seed indicator (URL, domain, email, phone, IP, certificate hash,
file hash, Telegram handle/bot ID or analytics ID) and it pivots across public and
commercial sources, builds an evidence-backed graph and timeline, finds the earliest
observed social/web mentions, and produces CERT/registrar/host-ready reports.

- Passive by default; direct contact with attacker infrastructure is opt-in and
  isolated behind an SSRF-protected fetcher.
- Provider plugin architecture with graceful degradation: missing API keys skip a
  provider, never fail an investigation.
- Full evidence preservation (raw response, SHA-256, UTC retrieval timestamp,
  provider, redacted request parameters).
- Reports as HTML, PDF, JSON, STIX 2.1, Markdown, text and CSV.

Full documentation is in `docs/`. Start with `docs/DEPLOYMENT.md` and
`docs/ADDING_PROVIDERS.md`.

> Use only against indicators and infrastructure you are authorized to investigate.
> PhishTrace reports observations and confidence, never accusations.
