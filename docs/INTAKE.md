# Intake: one link in, an ordered seed set out

A submitted URL is not itself an IOC. It is a container: a host, usually a
deeper subdomain, a registrable domain, and a path/query string that frequently
carries the operator's mailbox, Telegram handle, phone number, wallet or
analytics ID. Intake decomposes that container **before** any provider runs, so
the pivot engine expands the selectors that actually exist inside the link.

The planner lives in `phishtrace/core/intake.py`. It performs no network or
database I/O and can be inspected without starting an investigation:

```
phishtrace intake "https://paypal-secure.login-check.co.uk/verify?email=owner@evil-example.com"
```

```
Seed       : https://paypal-secure.login-check.co.uk/verify?email=owner@evil-example.com
Normalized : https://paypal-secure.login-check.co.uk/verify?email=owner%40evil-example.com (url)
Selectors  : 3
  0 domain        url-host             paypal-secure.login-check.co.uk
      why: hostname of the submitted link
  1 email         url-email            owner@evil-example.com
      why: mailbox found in query parameter 'email' of the submitted link
  4 domain        registrable-domain   login-check.co.uk
      why: registrable domain behind paypal-secure.login-check.co.uk
```

## What is derived

| Relation | Source | Priority | Strength |
| --- | --- | --- | --- |
| `url-host` | URL hostname (domain or IP) | 0 | strong |
| `url-email` | mailbox in the path or a query value | 1 | strong |
| `url-telegram` | `t.me/<handle>` or `telegram=`/`@handle` value | 1 | strong |
| `email-domain` | mail domain of an email seed | 1 | strong |
| `url-phone` | `phone=`, `tel=`, `whatsapp=`, `msisdn=` | 2 | strong |
| `url-analytics` | `UA-…`, `G-…`, `GTM-…`, `AW-…` tokens | 2 | strong |
| `url-wallet` | BTC address in the path or wallet/address parameters | 2 | strong |
| `registrable-domain` | eTLD+1 behind the host | 4 | strong |
| `parent-domain` | registrable domain of a subdomain seed | 6 | medium |

Lower priority numbers are expanded first. Duplicate selectors are removed and
the whole plan is capped at 12 derived seeds, so one link cannot turn into an
unbounded crawl.

Every derived indicator is stored with:

- `parent_id` = the seed (or parent) indicator,
- a typed edge (`url-email`, `url-host`, …) with provider `normalizer`,
- tags (`intake`, `url-email`, …),
- a human-readable `note` on the edge explaining why it was chased.

## Notes, not guesses

Some properties are recorded as notes instead of selectors because chasing them
would be unsafe or meaningless:

- non-HTTP(S) schemes (redirectors, `javascript:`, `mailto:`),
- credentials embedded in the URL userinfo section (never copied into the plan),
- non-standard ports,
- punycode hosts (the decoded form is noted),
- URL shorteners (`bit.ly`, `t.co`, …): the destination must be resolved before
  attribution,
- seed types with no deterministic decomposition (hashes, ASNs, …).

## Bounds and safety

- Pure functions; no sockets, no database writes.
- URL length is capped by the API/CLI layer; intake never fetches the link.
- The planner only reports selectors that the normalizer accepts, so malformed
  tokens are dropped rather than persisted.
- Intake does not decide whether a selector is malicious; the stop-list and the
  providers do.

## API

`GET /api/intake?seed=<url>&kind=` returns the same plan as JSON. It requires an
authenticated session and performs no writes.
