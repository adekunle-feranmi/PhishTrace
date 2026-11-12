# Cross-investigation entity model

One investigation answers *what is attached to this link*. Attribution needs the
second question: **have we seen this contact, handle, publisher ID or certificate
before, on a different case?** The entity layer stores that answer so it is
auditable instead of being recomputed (and re-guessed) on every run.

## Objects

| Table | Purpose |
| --- | --- |
| `entities` | One normalized join key with a `kind`: `identity`, `infrastructure` or `case`. `key` is globally unique, so the same mailbox on a second case resolves to the same row. |
| `entity_members` | One row per (entity, indicator, investigation, role). Records the rule that fired, its strength, confidence, evidence ID and a human-readable reason. Nothing is attributed without a member row pointing back to an indicator. |
| `entity_links` | Typed edges between entities: `observed-in-case` (identity → case) and `co-occurs-with` (weak, capped at the 15 strongest pairs per case). |

An investigation's own seed becomes a `case` entity keyed
`case:<seed_normalized>`, so an entity can be walked back to every case it
appeared in.

## Join rules

`phishtrace/core/entities.py` is deliberately table-driven and side-effect free
(`joins_for()` can be unit-tested without a database).

| Indicator | Rule | Kind | Role | Strength |
| --- | --- | --- | --- | --- |
| email tagged `rdap`/`whois`/`registrant` | `email-indicator` | identity | `registrant-contact` | strong |
| other email | `email-indicator` | identity | `contact` | medium |
| email tagged `exfil` | `email-indicator` | identity | `exfil-channel` | strong |
| email at a privacy service | `privacy-proxy` | infrastructure | `provider-contact` | weak |
| email at a registrar/hoster or `abuse@`-style mailbox | `provider-desk` | infrastructure | `provider-contact` | weak |
| phone | `phone-indicator` | identity | `contact` | strong |
| Telegram handle | `telegram-indicator` | identity | `operator-handle` | strong |
| username | `username-indicator` | identity | `operator-handle` | medium |
| BTC address | `wallet-indicator` | identity | `wallet` | strong |
| analytics/publisher ID | `analytics-publisher` | identity | `publisher-id` | strong |
| certificate SHA-256 | `certificate-cluster` | infrastructure | `certificate` | strong |
| ASN | `asn-aggregate` | infrastructure | `network-aggregate` | weak |
| domain sharing ≥2 nameservers with another domain | `nameserver-pair` | infrastructure | `nameserver-pair` | medium |

Registrar and hosting desks (`abuse@`, `hostmaster@`, `noc@`, privacy-proxy
domains) are recorded as provider contacts and **never** ranked as suspects.
Mistaking a datacentre abuse mailbox for the operator is the classic
phishing-attribution false positive.

## Suspect scoring

Scores are additive and explainable: an analyst can recompute them by hand from
the members shown next to the candidate.

```
score = base(best strength: strong 40 / medium 22 / weak 10)
      + min(30, 15 × (investigations - 1))       # cross-case corroboration
      + max(role bonus)                          # publisher 20, registrant 15,
                                                 # exfil 12, operator 10, wallet 8,
                                                 # certificate 6, provider -25
      + min(15, 5 × distinct join rules)
      - 10 if every membership is context-only
```

Clamped to 1–99. Bands: `high ≥ 70`, `medium ≥ 45`, otherwise `low`.

Every suspect carries the caveat that linkage is circumstantial, plus specific
caveats for free webmail, reused handles and context-only observations.

## CLI

```
phishtrace entities [--kind identity|infrastructure|case] [--limit N]
                    [--min-investigations N] [--json]
phishtrace entity <entity id or join key>
phishtrace suspects <investigation id> [--limit N]
```

## HTTP API

All routes require an authenticated session. Analysts only see entities that
appear in a case they own; administrators see everything.

| Route | Returns |
| --- | --- |
| `GET /api/entities?kind=&q=&limit=&min_investigations=` | Entity index, most corroborated first. |
| `GET /api/entities/{id or join key}` | Entity, its members, links and cases. |
| `GET /api/investigations/{id}/entities` | Entities touched by one investigation, with roles. |
| `GET /api/investigations/{id}/suspects?limit=` | Ranked identity candidates with rules, evidence IDs and caveats. |

## Limitations

- The layer links **cases and selectors**, not people. It does not resolve a
  mailbox to a subscriber; that requires registry records or legal process.
- A shared certificate, nameserver pair or ASN is infrastructure proximity, not
  proof of common ownership: shared hosting produces these by accident.
- `co-occurs-with` is a weak hint for pivot suggestions only.
- Entity tables are created by `init_db`; re-running `phishtrace run` on an
  existing database adds them without touching existing investigations.
