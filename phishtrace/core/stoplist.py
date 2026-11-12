"""Stop-lists and selector-role classification.

Pivoting from shared infrastructure is how investigations turn into noise: one
Cloudflare edge address maps to hundreds of thousands of hostnames, and one
Gmail address says nothing about an attacker's servers. This module decides,
per indicator, whether the pivot engine may expand it or must keep it as
context only.

Three independent lists are maintained:

* IP networks - CDN/edge ranges, public DNS resolvers and non-routable space.
* Domains - CDNs, shared hosting platforms, archives, URL shorteners, social
  platforms, free webmail, disposable mail and managed DNS providers.
* ASN aggregates - every ASN is treated as an aggregate selector, because a
  single ASN almost always contains unrelated tenants.

Deliberately **not** on the list: generic VPS/cloud compute ranges (AWS EC2,
GCP, Azure VMs, DigitalOcean, Hetzner, OVH, ...). Phishing kits are routinely
hosted there and those addresses are attributable to a single tenant, so they
remain useful pivots. Only *edge* networks where thousands of unrelated
origins share one address are suppressed.

Operators can extend both lists without code changes by pointing
``config.stoplists.domains`` / ``config.stoplists.ips`` at newline-delimited
files (``#`` comments and blank lines are ignored). The built-in lists are a
maintained snapshot and should be refreshed as provider ranges change.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit

from phishtrace.normalizer import registrable_domain

# --------------------------------------------------------------------------- roles
ROLE_SEED = "seed"
ROLE_INFRASTRUCTURE = "attacker-infrastructure"
ROLE_CDN = "cdn-edge"
ROLE_RESOLVER = "public-resolver"
ROLE_NON_ROUTABLE = "non-routable"
ROLE_ARCHIVE = "archive"
ROLE_SHORTENER = "url-shortener"
ROLE_SOCIAL = "social-platform"
ROLE_FREE_MAIL = "free-webmail"
ROLE_DISPOSABLE_MAIL = "disposable-email"
ROLE_HOSTING = "shared-hosting"
ROLE_DNS = "dns-provider"
ROLE_ASN = "asn-aggregate"
ROLE_HASH = "file-artifact"
ROLE_UNKNOWN = "unknown"


@dataclass(frozen=True)
class StopDecision:
    """Whether an indicator may be expanded, and why."""

    expand: bool
    role: str
    category: str | None = None
    reason: str | None = None
    matched: str | None = None

    def as_dict(self) -> dict:
        return {
            "expand": self.expand,
            "role": self.role,
            "category": self.category,
            "reason": self.reason,
            "matched": self.matched,
        }


# ------------------------------------------------------------------------ networks
# (network, category, label). Categories feed StopDecision.category; label is
# what an analyst sees as the matched entry.
_PUBLIC_NETWORKS: tuple[tuple[str, str, str], ...] = (
    # Cloudflare edge (https://www.cloudflare.com/ips/)
    ("173.245.48.0/20", ROLE_CDN, "cloudflare"),
    ("103.21.244.0/22", ROLE_CDN, "cloudflare"),
    ("103.22.200.0/22", ROLE_CDN, "cloudflare"),
    ("103.31.4.0/22", ROLE_CDN, "cloudflare"),
    ("141.101.64.0/18", ROLE_CDN, "cloudflare"),
    ("108.162.192.0/18", ROLE_CDN, "cloudflare"),
    ("190.93.240.0/20", ROLE_CDN, "cloudflare"),
    ("188.114.96.0/20", ROLE_CDN, "cloudflare"),
    ("197.234.240.0/22", ROLE_CDN, "cloudflare"),
    ("198.41.128.0/17", ROLE_CDN, "cloudflare"),
    ("162.158.0.0/15", ROLE_CDN, "cloudflare"),
    ("104.16.0.0/13", ROLE_CDN, "cloudflare"),
    ("104.24.0.0/14", ROLE_CDN, "cloudflare"),
    ("172.64.0.0/13", ROLE_CDN, "cloudflare"),
    ("131.0.72.0/22", ROLE_CDN, "cloudflare"),
    ("2400:cb00::/32", ROLE_CDN, "cloudflare"),
    ("2606:4700::/32", ROLE_CDN, "cloudflare"),
    ("2803:f800::/32", ROLE_CDN, "cloudflare"),
    ("2405:b500::/32", ROLE_CDN, "cloudflare"),
    ("2405:8100::/32", ROLE_CDN, "cloudflare"),
    ("2a06:98c0::/29", ROLE_CDN, "cloudflare"),
    ("2c0f:f248::/32", ROLE_CDN, "cloudflare"),
    # Fastly (https://api.fastly.com/public-ip-list)
    ("23.235.32.0/20", ROLE_CDN, "fastly"),
    ("43.249.72.0/22", ROLE_CDN, "fastly"),
    ("103.244.50.0/24", ROLE_CDN, "fastly"),
    ("103.245.222.0/23", ROLE_CDN, "fastly"),
    ("103.245.224.0/24", ROLE_CDN, "fastly"),
    ("104.156.80.0/20", ROLE_CDN, "fastly"),
    ("146.75.0.0/16", ROLE_CDN, "fastly"),
    ("151.101.0.0/16", ROLE_CDN, "fastly"),
    ("157.52.64.0/18", ROLE_CDN, "fastly"),
    ("167.82.0.0/17", ROLE_CDN, "fastly"),
    ("167.82.128.0/20", ROLE_CDN, "fastly"),
    ("167.82.160.0/20", ROLE_CDN, "fastly"),
    ("167.82.224.0/20", ROLE_CDN, "fastly"),
    ("172.111.64.0/18", ROLE_CDN, "fastly"),
    ("185.31.16.0/22", ROLE_CDN, "fastly"),
    ("199.27.72.0/21", ROLE_CDN, "fastly"),
    ("199.232.0.0/16", ROLE_CDN, "fastly"),
    ("2a04:4e40::/32", ROLE_CDN, "fastly"),
    ("2a04:4e42::/32", ROLE_CDN, "fastly"),
    # Akamai edge
    ("23.32.0.0/11", ROLE_CDN, "akamai"),
    ("104.64.0.0/10", ROLE_CDN, "akamai"),
    ("184.24.0.0/13", ROLE_CDN, "akamai"),
    ("2600:1400::/24", ROLE_CDN, "akamai"),
    # Amazon CloudFront / Global Accelerator edge
    ("13.32.0.0/15", ROLE_CDN, "cloudfront"),
    ("13.224.0.0/14", ROLE_CDN, "cloudfront"),
    ("13.249.0.0/16", ROLE_CDN, "cloudfront"),
    ("18.160.0.0/15", ROLE_CDN, "cloudfront"),
    ("18.238.0.0/15", ROLE_CDN, "cloudfront"),
    ("52.84.0.0/15", ROLE_CDN, "cloudfront"),
    ("54.182.0.0/16", ROLE_CDN, "cloudfront"),
    ("54.192.0.0/16", ROLE_CDN, "cloudfront"),
    ("54.230.0.0/16", ROLE_CDN, "cloudfront"),
    ("54.239.128.0/18", ROLE_CDN, "cloudfront"),
    ("54.240.128.0/18", ROLE_CDN, "cloudfront"),
    ("99.84.0.0/16", ROLE_CDN, "cloudfront"),
    ("204.246.164.0/22", ROLE_CDN, "cloudfront"),
    ("205.251.192.0/19", ROLE_CDN, "cloudfront"),
    ("2600:9000::/28", ROLE_CDN, "cloudfront"),
    # Google frontends (search/Gmail/YouTube edges; NOT GCP VM ranges)
    ("64.233.160.0/19", ROLE_CDN, "google-frontend"),
    ("66.102.0.0/20", ROLE_CDN, "google-frontend"),
    ("72.14.192.0/18", ROLE_CDN, "google-frontend"),
    ("74.125.0.0/16", ROLE_CDN, "google-frontend"),
    ("108.177.0.0/17", ROLE_CDN, "google-frontend"),
    ("142.250.0.0/15", ROLE_CDN, "google-frontend"),
    ("172.217.0.0/16", ROLE_CDN, "google-frontend"),
    ("173.194.0.0/16", ROLE_CDN, "google-frontend"),
    ("209.85.128.0/17", ROLE_CDN, "google-frontend"),
    ("216.58.192.0/19", ROLE_CDN, "google-frontend"),
    ("2a00:1450::/32", ROLE_CDN, "google-frontend"),
    ("2a03:2880::/32", ROLE_CDN, "meta-edge"),
    # Microsoft edge / Office 365 front doors
    ("13.107.0.0/16", ROLE_CDN, "microsoft-edge"),
    ("52.96.0.0/14", ROLE_CDN, "microsoft-edge"),
    ("150.171.0.0/16", ROLE_CDN, "microsoft-edge"),
    ("2603:1000::/24", ROLE_CDN, "microsoft-edge"),
    # Imperva / Incapsula
    ("45.64.64.0/22", ROLE_CDN, "imperva"),
    ("103.28.248.0/22", ROLE_CDN, "imperva"),
    ("149.126.72.0/21", ROLE_CDN, "imperva"),
    ("185.11.124.0/22", ROLE_CDN, "imperva"),
    ("192.230.64.0/18", ROLE_CDN, "imperva"),
    ("198.143.32.0/19", ROLE_CDN, "imperva"),
    ("199.83.128.0/21", ROLE_CDN, "imperva"),
    # Sucuri
    ("185.67.120.0/22", ROLE_CDN, "sucuri"),
    ("192.124.249.0/24", ROLE_CDN, "sucuri"),
    # StackPath / Highwinds
    ("151.139.0.0/16", ROLE_CDN, "stackpath"),
    # Bunny CDN
    ("185.151.204.0/22", ROLE_CDN, "bunnycdn"),
    # Edgio / Verizon Digital Media
    ("152.195.0.0/16", ROLE_CDN, "edgio"),
    ("152.199.0.0/16", ROLE_CDN, "edgio"),
    # Gcore / CDN77
    ("92.223.0.0/17", ROLE_CDN, "gcore"),
    ("185.104.208.0/22", ROLE_CDN, "cdn77"),
    # Public DNS resolvers
    ("8.8.8.8/32", ROLE_RESOLVER, "google-dns"),
    ("8.8.4.4/32", ROLE_RESOLVER, "google-dns"),
    ("2001:4860:4860::/48", ROLE_RESOLVER, "google-dns"),
    ("1.1.1.1/32", ROLE_RESOLVER, "cloudflare-dns"),
    ("1.0.0.1/32", ROLE_RESOLVER, "cloudflare-dns"),
    ("2606:4700:4700::/48", ROLE_RESOLVER, "cloudflare-dns"),
    ("9.9.9.9/32", ROLE_RESOLVER, "quad9"),
    ("149.112.112.0/24", ROLE_RESOLVER, "quad9"),
    ("2620:fe::fe/128", ROLE_RESOLVER, "quad9"),
    ("208.67.222.0/24", ROLE_RESOLVER, "opendns"),
    ("208.67.220.0/24", ROLE_RESOLVER, "opendns"),
    ("2620:119:35::/48", ROLE_RESOLVER, "opendns"),
    ("64.6.64.6/32", ROLE_RESOLVER, "verisign"),
    ("64.6.65.6/32", ROLE_RESOLVER, "verisign"),
    ("77.88.8.0/24", ROLE_RESOLVER, "yandex-dns"),
    ("94.140.14.0/24", ROLE_RESOLVER, "adguard-dns"),
    ("94.140.15.0/24", ROLE_RESOLVER, "adguard-dns"),
    ("76.76.2.0/24", ROLE_RESOLVER, "controld"),
)

_PRIVATE_NETWORKS: tuple[tuple[str, str, str], ...] = (
    ("0.0.0.0/8", ROLE_NON_ROUTABLE, "this-network"),
    ("10.0.0.0/8", ROLE_NON_ROUTABLE, "private"),
    ("100.64.0.0/10", ROLE_NON_ROUTABLE, "cgnat"),
    ("127.0.0.0/8", ROLE_NON_ROUTABLE, "loopback"),
    ("169.254.0.0/16", ROLE_NON_ROUTABLE, "link-local"),
    ("172.16.0.0/12", ROLE_NON_ROUTABLE, "private"),
    ("192.0.0.0/24", ROLE_NON_ROUTABLE, "ietf-protocol"),
    ("192.0.2.0/24", ROLE_NON_ROUTABLE, "documentation"),
    ("192.168.0.0/16", ROLE_NON_ROUTABLE, "private"),
    ("198.18.0.0/15", ROLE_NON_ROUTABLE, "benchmark"),
    ("198.51.100.0/24", ROLE_NON_ROUTABLE, "documentation"),
    ("203.0.113.0/24", ROLE_NON_ROUTABLE, "documentation"),
    ("224.0.0.0/4", ROLE_NON_ROUTABLE, "multicast"),
    ("240.0.0.0/4", ROLE_NON_ROUTABLE, "reserved"),
    ("::1/128", ROLE_NON_ROUTABLE, "loopback"),
    ("::/128", ROLE_NON_ROUTABLE, "unspecified"),
    ("fc00::/7", ROLE_NON_ROUTABLE, "unique-local"),
    ("fe80::/10", ROLE_NON_ROUTABLE, "link-local"),
    ("ff00::/8", ROLE_NON_ROUTABLE, "multicast"),
    ("2001:db8::/32", ROLE_NON_ROUTABLE, "documentation"),
)


# ------------------------------------------------------------------------- domains
def _domain_rules(pairs: Iterable[tuple[str, str]]) -> dict[str, str]:
    return {domain: category for domain, category in pairs}


_DOMAIN_RULES: dict[str, str] = _domain_rules(
    [
        # CDN / edge / asset hosting
        ("cloudflare.com", ROLE_CDN),
        ("cloudflare.net", ROLE_CDN),
        ("cloudflare-dns.com", ROLE_CDN),
        ("cdnjs.cloudflare.com", ROLE_CDN),
        ("akamai.net", ROLE_CDN),
        ("akamaized.net", ROLE_CDN),
        ("akamaihd.net", ROLE_CDN),
        ("akamaiedge.net", ROLE_CDN),
        ("edgekey.net", ROLE_CDN),
        ("edgesuite.net", ROLE_CDN),
        ("fastly.net", ROLE_CDN),
        ("fastlylb.net", ROLE_CDN),
        ("cloudfront.net", ROLE_CDN),
        ("azureedge.net", ROLE_CDN),
        ("msecnd.net", ROLE_CDN),
        ("jsdelivr.net", ROLE_CDN),
        ("unpkg.com", ROLE_CDN),
        ("bootstrapcdn.com", ROLE_CDN),
        ("stackpathdns.com", ROLE_CDN),
        ("stackpathcdn.com", ROLE_CDN),
        ("sucuri.net", ROLE_CDN),
        ("incapsula.com", ROLE_CDN),
        ("impervadns.net", ROLE_CDN),
        ("bunnycdn.com", ROLE_CDN),
        ("b-cdn.net", ROLE_CDN),
        ("gcdn.co", ROLE_CDN),
        ("cdn77.org", ROLE_CDN),
        ("gstatic.com", ROLE_CDN),
        ("googleapis.com", ROLE_CDN),
        ("googleusercontent.com", ROLE_CDN),
        ("ggpht.com", ROLE_CDN),
        ("ytimg.com", ROLE_CDN),
        ("fbcdn.net", ROLE_CDN),
        ("twimg.com", ROLE_CDN),
        ("licdn.com", ROLE_CDN),
        ("tiktokcdn.com", ROLE_CDN),
        # Shared hosting / free site builders (common for throwaway phishing)
        ("blogspot.com", ROLE_HOSTING),
        ("blogger.com", ROLE_HOSTING),
        ("wordpress.com", ROLE_HOSTING),
        ("wpcomstaging.com", ROLE_HOSTING),
        ("wixsite.com", ROLE_HOSTING),
        ("wix.com", ROLE_HOSTING),
        ("weebly.com", ROLE_HOSTING),
        ("webs.com", ROLE_HOSTING),
        ("site123.me", ROLE_HOSTING),
        ("webnode.com", ROLE_HOSTING),
        ("jimdosite.com", ROLE_HOSTING),
        ("strikingly.com", ROLE_HOSTING),
        ("carrd.co", ROLE_HOSTING),
        ("notion.site", ROLE_HOSTING),
        ("notion.so", ROLE_HOSTING),
        ("gitbook.io", ROLE_HOSTING),
        ("readthedocs.io", ROLE_HOSTING),
        ("netlify.app", ROLE_HOSTING),
        ("netlify.com", ROLE_HOSTING),
        ("vercel.app", ROLE_HOSTING),
        ("now.sh", ROLE_HOSTING),
        ("pages.dev", ROLE_HOSTING),
        ("workers.dev", ROLE_HOSTING),
        ("herokuapp.com", ROLE_HOSTING),
        ("firebaseapp.com", ROLE_HOSTING),
        ("web.app", ROLE_HOSTING),
        ("appspot.com", ROLE_HOSTING),
        ("github.io", ROLE_HOSTING),
        ("gitlab.io", ROLE_HOSTING),
        ("surge.sh", ROLE_HOSTING),
        ("fly.dev", ROLE_HOSTING),
        ("deno.dev", ROLE_HOSTING),
        ("glitch.me", ROLE_HOSTING),
        ("render.com", ROLE_HOSTING),
        ("onrender.com", ROLE_HOSTING),
        ("railway.app", ROLE_HOSTING),
        ("repl.co", ROLE_HOSTING),
        ("replit.app", ROLE_HOSTING),
        ("000webhostapp.com", ROLE_HOSTING),
        ("byethost.com", ROLE_HOSTING),
        ("infinityfreeapp.com", ROLE_HOSTING),
        ("epizy.com", ROLE_HOSTING),
        ("rf.gd", ROLE_HOSTING),
        ("42web.io", ROLE_HOSTING),
        ("s3.amazonaws.com", ROLE_HOSTING),
        ("storage.googleapis.com", ROLE_HOSTING),
        ("blob.core.windows.net", ROLE_HOSTING),
        ("forms.gle", ROLE_HOSTING),
        ("docs.google.com", ROLE_HOSTING),
        ("drive.google.com", ROLE_HOSTING),
        ("sites.google.com", ROLE_HOSTING),
        ("dropbox.com", ROLE_HOSTING),
        ("box.com", ROLE_HOSTING),
        ("mega.nz", ROLE_HOSTING),
        ("mediafire.com", ROLE_HOSTING),
        ("4shared.com", ROLE_HOSTING),
        ("sendspace.com", ROLE_HOSTING),
        # Social / communication platforms
        ("facebook.com", ROLE_SOCIAL),
        ("fb.com", ROLE_SOCIAL),
        ("fb.me", ROLE_SOCIAL),
        ("instagram.com", ROLE_SOCIAL),
        ("threads.net", ROLE_SOCIAL),
        ("twitter.com", ROLE_SOCIAL),
        ("x.com", ROLE_SOCIAL),
        ("t.co", ROLE_SOCIAL),
        ("linkedin.com", ROLE_SOCIAL),
        ("lnkd.in", ROLE_SOCIAL),
        ("youtube.com", ROLE_SOCIAL),
        ("youtu.be", ROLE_SOCIAL),
        ("tiktok.com", ROLE_SOCIAL),
        ("telegram.org", ROLE_SOCIAL),
        ("telegram.me", ROLE_SOCIAL),
        ("telegram.dog", ROLE_SOCIAL),
        ("t.me", ROLE_SOCIAL),
        ("whatsapp.com", ROLE_SOCIAL),
        ("whatsapp.net", ROLE_SOCIAL),
        ("discord.com", ROLE_SOCIAL),
        ("discord.gg", ROLE_SOCIAL),
        ("reddit.com", ROLE_SOCIAL),
        ("redd.it", ROLE_SOCIAL),
        ("medium.com", ROLE_SOCIAL),
        ("pinterest.com", ROLE_SOCIAL),
        ("snapchat.com", ROLE_SOCIAL),
        ("tumblr.com", ROLE_SOCIAL),
        ("bsky.app", ROLE_SOCIAL),
        ("mastodon.social", ROLE_SOCIAL),
        ("github.com", ROLE_SOCIAL),
        ("gitlab.com", ROLE_SOCIAL),
        ("bitbucket.org", ROLE_SOCIAL),
        ("substack.com", ROLE_SOCIAL),
        ("ghost.io", ROLE_SOCIAL),
        # Archives and caches
        ("archive.org", ROLE_ARCHIVE),
        ("archive.ph", ROLE_ARCHIVE),
        ("archive.today", ROLE_ARCHIVE),
        ("archive.is", ROLE_ARCHIVE),
        ("archive.li", ROLE_ARCHIVE),
        ("archive.vn", ROLE_ARCHIVE),
        ("archive.fo", ROLE_ARCHIVE),
        ("ghostarchive.org", ROLE_ARCHIVE),
        ("arquivo.pt", ROLE_ARCHIVE),
        ("perma.cc", ROLE_ARCHIVE),
        ("webcitation.org", ROLE_ARCHIVE),
        ("cachedview.com", ROLE_ARCHIVE),
        ("timetravel.mementoweb.org", ROLE_ARCHIVE),
        # URL shorteners
        ("bit.ly", ROLE_SHORTENER),
        ("bitly.com", ROLE_SHORTENER),
        ("tinyurl.com", ROLE_SHORTENER),
        ("goo.gl", ROLE_SHORTENER),
        ("ow.ly", ROLE_SHORTENER),
        ("is.gd", ROLE_SHORTENER),
        ("v.gd", ROLE_SHORTENER),
        ("buff.ly", ROLE_SHORTENER),
        ("rebrand.ly", ROLE_SHORTENER),
        ("cutt.ly", ROLE_SHORTENER),
        ("shorturl.at", ROLE_SHORTENER),
        ("tiny.cc", ROLE_SHORTENER),
        ("s.id", ROLE_SHORTENER),
        ("rb.gy", ROLE_SHORTENER),
        ("t.ly", ROLE_SHORTENER),
        ("short.io", ROLE_SHORTENER),
        ("bl.ink", ROLE_SHORTENER),
        ("urlz.fr", ROLE_SHORTENER),
        ("0rz.tw", ROLE_SHORTENER),
        ("qrco.de", ROLE_SHORTENER),
        ("rebrandly.com", ROLE_SHORTENER),
        # Free webmail
        ("gmail.com", ROLE_FREE_MAIL),
        ("googlemail.com", ROLE_FREE_MAIL),
        ("yahoo.com", ROLE_FREE_MAIL),
        ("yahoo.co.uk", ROLE_FREE_MAIL),
        ("yahoo.co.in", ROLE_FREE_MAIL),
        ("yahoo.fr", ROLE_FREE_MAIL),
        ("yahoo.de", ROLE_FREE_MAIL),
        ("ymail.com", ROLE_FREE_MAIL),
        ("rocketmail.com", ROLE_FREE_MAIL),
        ("outlook.com", ROLE_FREE_MAIL),
        ("hotmail.com", ROLE_FREE_MAIL),
        ("hotmail.co.uk", ROLE_FREE_MAIL),
        ("live.com", ROLE_FREE_MAIL),
        ("msn.com", ROLE_FREE_MAIL),
        ("aol.com", ROLE_FREE_MAIL),
        ("icloud.com", ROLE_FREE_MAIL),
        ("me.com", ROLE_FREE_MAIL),
        ("mac.com", ROLE_FREE_MAIL),
        ("proton.me", ROLE_FREE_MAIL),
        ("protonmail.com", ROLE_FREE_MAIL),
        ("pm.me", ROLE_FREE_MAIL),
        ("gmx.com", ROLE_FREE_MAIL),
        ("gmx.net", ROLE_FREE_MAIL),
        ("gmx.de", ROLE_FREE_MAIL),
        ("mail.com", ROLE_FREE_MAIL),
        ("zoho.com", ROLE_FREE_MAIL),
        ("yandex.com", ROLE_FREE_MAIL),
        ("yandex.ru", ROLE_FREE_MAIL),
        ("mail.ru", ROLE_FREE_MAIL),
        ("inbox.ru", ROLE_FREE_MAIL),
        ("list.ru", ROLE_FREE_MAIL),
        ("bk.ru", ROLE_FREE_MAIL),
        ("qq.com", ROLE_FREE_MAIL),
        ("163.com", ROLE_FREE_MAIL),
        ("126.com", ROLE_FREE_MAIL),
        ("sina.com", ROLE_FREE_MAIL),
        ("naver.com", ROLE_FREE_MAIL),
        ("daum.net", ROLE_FREE_MAIL),
        ("hanmail.net", ROLE_FREE_MAIL),
        ("web.de", ROLE_FREE_MAIL),
        ("t-online.de", ROLE_FREE_MAIL),
        ("free.fr", ROLE_FREE_MAIL),
        ("orange.fr", ROLE_FREE_MAIL),
        ("laposte.net", ROLE_FREE_MAIL),
        ("libero.it", ROLE_FREE_MAIL),
        ("virgilio.it", ROLE_FREE_MAIL),
        ("seznam.cz", ROLE_FREE_MAIL),
        ("wp.pl", ROLE_FREE_MAIL),
        ("o2.pl", ROLE_FREE_MAIL),
        ("interia.pl", ROLE_FREE_MAIL),
        ("rambler.ru", ROLE_FREE_MAIL),
        ("ukr.net", ROLE_FREE_MAIL),
        ("rediffmail.com", ROLE_FREE_MAIL),
        ("sify.com", ROLE_FREE_MAIL),
        ("hushmail.com", ROLE_FREE_MAIL),
        ("tutanota.com", ROLE_FREE_MAIL),
        ("tuta.com", ROLE_FREE_MAIL),
        ("mailfence.com", ROLE_FREE_MAIL),
        ("disroot.org", ROLE_FREE_MAIL),
        ("riseup.net", ROLE_FREE_MAIL),
        # Disposable / throwaway mail
        ("mailinator.com", ROLE_DISPOSABLE_MAIL),
        ("guerrillamail.com", ROLE_DISPOSABLE_MAIL),
        ("sharklasers.com", ROLE_DISPOSABLE_MAIL),
        ("10minutemail.com", ROLE_DISPOSABLE_MAIL),
        ("tempmail.com", ROLE_DISPOSABLE_MAIL),
        ("temp-mail.org", ROLE_DISPOSABLE_MAIL),
        ("yopmail.com", ROLE_DISPOSABLE_MAIL),
        ("trashmail.com", ROLE_DISPOSABLE_MAIL),
        ("throwawaymail.com", ROLE_DISPOSABLE_MAIL),
        ("getnada.com", ROLE_DISPOSABLE_MAIL),
        ("maildrop.cc", ROLE_DISPOSABLE_MAIL),
        ("luxusmail.org", ROLE_DISPOSABLE_MAIL),
        ("emailondeck.com", ROLE_DISPOSABLE_MAIL),
        ("moakt.com", ROLE_DISPOSABLE_MAIL),
        ("fakeinbox.com", ROLE_DISPOSABLE_MAIL),
        ("spamgourmet.com", ROLE_DISPOSABLE_MAIL),
        ("mailnesia.com", ROLE_DISPOSABLE_MAIL),
        ("mohmal.com", ROLE_DISPOSABLE_MAIL),
        ("cock.li", ROLE_DISPOSABLE_MAIL),
    ]
)

# Managed DNS providers. Only applied to nameserver selectors: a domain seed of
# `digitalocean.com` is a hosting company, not a DNS pivot.
_NAMESERVER_RULES: dict[str, str] = {
    "domaincontrol.com": "godaddy",
    "registrar-servers.com": "namecheap",
    "namecheap.com": "namecheap",
    "dnsimple.com": "dnsimple",
    "nsone.net": "ns1",
    "ultradns.net": "ultradns",
    "ultradns.com": "ultradns",
    "dynect.net": "oracle-dyn",
    "azure-dns.com": "azure",
    "azure-dns.net": "azure",
    "akam.net": "akamai",
    "googledomains.com": "google-cloud-dns",
    "hover.com": "hover",
    "digitalocean.com": "digitalocean",
    "linode.com": "linode",
    "vultr.com": "vultr",
    "route53.amazonaws.com": "aws-route53",
    "cloudflare.com": "cloudflare",
}


# Regex rules for provider name server families that are per-zone.
_DOMAIN_PATTERNS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"^awsdns-\d+\.(com|net|org|co\.uk)$"), ROLE_DNS, "aws-route53"),
    (re.compile(r"^ns\d+\.(cloudflare|digitalocean|linode|vultr)\.com$"), ROLE_DNS, "managed-dns"),
    (re.compile(r"^dns\d*\.(registrar-servers|namecheap)\.com$"), ROLE_DNS, "managed-dns"),
)


# ------------------------------------------------------------------------ classifier
class StopList:
    """Classifies indicators as expandable or context-only."""

    def __init__(
        self,
        extra_domains: Iterable[str] | None = None,
        extra_networks: Iterable[str] | None = None,
    ):
        self.domains: dict[str, str] = dict(_DOMAIN_RULES)
        self.networks: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str, str]] = []
        self.warnings: list[str] = []

        for cidr, category, label in _PRIVATE_NETWORKS + _PUBLIC_NETWORKS:
            try:
                self.networks.append((ipaddress.ip_network(cidr), category, label))
            except ValueError:  # pragma: no cover - static data is validated in tests
                self.warnings.append(f"invalid built-in network {cidr}")

        for domain in extra_domains or ():
            cleaned = domain.strip().lower().strip(".")
            if cleaned and not cleaned.startswith("#"):
                self.domains.setdefault(cleaned, ROLE_HOSTING)

        for cidr in extra_networks or ():
            cleaned = cidr.strip()
            if not cleaned or cleaned.startswith("#"):
                continue
            try:
                self.networks.append((ipaddress.ip_network(cleaned), ROLE_HOSTING, "operator-list"))
            except ValueError:
                self.warnings.append(f"invalid operator network {cleaned}")

    # ------------------------------------------------------------------ builders
    @classmethod
    def from_config(cls, config) -> "StopList":
        """Build a list, loading operator extensions from configured files."""
        domains: list[str] = []
        networks: list[str] = []
        stoplists = getattr(config, "stoplists", {}) or {}
        for key, target in (("domains", domains), ("ips", networks), ("networks", networks)):
            raw = stoplists.get(key)
            if not raw:
                continue
            path = Path(str(raw)).expanduser()
            if not path.is_file():
                continue
            try:
                target.extend(
                    line.split("#", 1)[0].strip()
                    for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
                )
            except OSError:
                continue
        instance = cls(extra_domains=domains, extra_networks=networks)
        return instance

    # ------------------------------------------------------------------- matching
    def match_network(self, value: str) -> tuple[str, str] | None:
        """Return (category, label) when the IP belongs to a listed network."""
        try:
            ip = ipaddress.ip_address(str(value).strip())
        except ValueError:
            return None
        for network, category, label in self.networks:
            if ip.version == network.version and ip in network:
                return category, label
        return None

    def is_stoplisted_ip(self, value: str) -> bool:
        return self.match_network(value) is not None

    def nameserver_category(self, host: str) -> tuple[str, str] | None:
        host = (host or "").strip().lower().strip(".")
        if not host:
            return None
        registered = registrable_domain(host) or host
        for candidate in (host, registered):
            if candidate in _NAMESERVER_RULES:
                return ROLE_DNS, candidate
        for pattern, category, label in _DOMAIN_PATTERNS:
            if pattern.match(host) or pattern.match(registered):
                return category, label
        return None

    def domain_category(self, host: str) -> tuple[str, str] | None:
        """Return (category, matched_domain) for a hostname."""
        host = (host or "").strip().lower().strip(".")
        if not host:
            return None
        if host in self.domains:
            return self.domains[host], host
        try:
            registered = registrable_domain(host)
        except Exception:  # noqa: BLE001 - publicsuffix data must never crash a run
            registered = None
        if registered and registered in self.domains:
            return self.domains[registered], registered
        for pattern, category, label in _DOMAIN_PATTERNS:
            if pattern.match(host):
                return category, label
            if registered and pattern.match(registered):
                return category, label
        # Suffix match for entries that are shared hosting zones rather than
        # registrable domains (e.g. a PSL entry such as `co.tv`).
        labels = host.split(".")
        for index in range(1, len(labels) - 1):
            suffix = ".".join(labels[index:])
            if suffix in self.domains and self.domains[suffix] == ROLE_HOSTING:
                return ROLE_HOSTING, suffix
        return None

    # ------------------------------------------------------------------ decisions
    def classify(self, indicator_type: str, normalized: str, *, is_seed: bool = False) -> StopDecision:
        kind = (indicator_type or "").lower()
        if kind == "ip":
            match = self.match_network(normalized)
            if match:
                category, label = match
                return StopDecision(
                    expand=False,
                    role=category,
                    category=category,
                    reason=f"{label} address space is shared infrastructure; pivoting would produce unrelated results",
                    matched=label,
                )
            return StopDecision(expand=True, role=ROLE_SEED if is_seed else ROLE_INFRASTRUCTURE)

        if kind in {"domain", "nameserver", "hostname", "url", "email"}:
            host = normalized
            if kind == "url":
                try:
                    host = (urlsplit(normalized if "//" in normalized else f"//{normalized}").hostname or "")
                except ValueError:
                    host = ""
            elif kind == "email":
                host = normalized.rsplit("@", 1)[-1]
            host = host.strip().lower().strip(".")
            if not host:
                return StopDecision(expand=False, role=ROLE_UNKNOWN, reason="empty hostname")
            if kind == "nameserver":
                ns_match = self.nameserver_category(host)
                if ns_match:
                    category, matched = ns_match
                    return StopDecision(
                        expand=False,
                        role=category,
                        category=category,
                        reason=f"nameserver belongs to managed DNS provider {matched}; nameserver pivots are not attributable",
                        matched=matched,
                    )
            try:
                ip = ipaddress.ip_address(host)
            except ValueError:
                ip = None
            if ip is not None:
                return self.classify("ip", str(ip), is_seed=is_seed)
            match = self.domain_category(host)
            if match:
                category, matched = match
                return StopDecision(
                    expand=False,
                    role=category,
                    category=category,
                    reason=f"{matched} is a shared {category.replace('-', ' ')}; expand=False to avoid unrelated pivots",
                    matched=matched,
                )
            return StopDecision(expand=True, role=ROLE_SEED if is_seed else ROLE_INFRASTRUCTURE)

        if kind == "asn":
            return StopDecision(
                expand=False,
                role=ROLE_ASN,
                category=ROLE_ASN,
                reason="an ASN aggregates unrelated tenants; kept as context only",
            )
        if kind in {"cert_sha256", "file_hash"}:
            return StopDecision(expand=True, role=ROLE_HASH)
        if kind == "unknown":
            return StopDecision(expand=False, role=ROLE_UNKNOWN, reason="untyped selector")
        # phone, telegram, analytics_id, btc_address, ja3, username
        return StopDecision(expand=True, role=ROLE_SEED if is_seed else ROLE_INFRASTRUCTURE)


def describe(decision: StopDecision) -> str:
    """One-line human description used in logs, reports and the UI."""
    state = "expand" if decision.expand else "context-only"
    parts = [state, decision.role]
    if decision.matched:
        parts.append(f"matched={decision.matched}")
    if decision.reason:
        parts.append(decision.reason)
    return " | ".join(parts)


DEFAULT_STOPLIST = StopList()


def classify_indicator(indicator_type: str, normalized: str, *, is_seed: bool = False) -> StopDecision:
    """Classify with the built-in lists (no operator extensions)."""
    return DEFAULT_STOPLIST.classify(indicator_type, normalized, is_seed=is_seed)


def is_stoplisted_ip(value: str) -> bool:
    return DEFAULT_STOPLIST.is_stoplisted_ip(value)
