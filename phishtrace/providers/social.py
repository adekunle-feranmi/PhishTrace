"""Social-platform sightings providers.

These implement ``sightings()`` rather than ``run()``: they look for posts that
*mention* the indicator, they do not pivot infrastructure.  Every provider
degrades to a documented skip/partial result instead of failing the run.

Platform reality check (documented in BUILD_LOG.md and docs/ADDING_PROVIDERS):
* Telegram  - public web preview (t.me/s/<channel>) only, no search API.
* Bluesky   - public AppView search, keyless.
* Mastodon  - search requires an access token on essentially every instance.
* Reddit    - public JSON search works without OAuth but is aggressively
              rate-limited/blocked from datacentre IPs; OAuth is preferred.
"""

from __future__ import annotations

import base64
import html
import re
from datetime import datetime, timezone
from urllib.parse import quote

from phishtrace.models import SelectorStrength
from phishtrace.providers._util import (
    as_int, as_list, first, parse_date, result_error, strip_tags, text,
)
from phishtrace.providers.base import BaseProvider, ProviderMeta

TAG_RE = re.compile(r"<[^>]+>")
TELEGRAM_POST_RE = re.compile(
    r'data-post="(?P<post>[^"]+)"(?P<body>.*?)(?=data-post="|\Z)', re.DOTALL
)
TELEGRAM_TEXT_RE = re.compile(
    r'class="tgme_widget_message_text[^"]*"[^>]*>(?P<text>.*?)</div>', re.DOTALL
)
TELEGRAM_TIME_RE = re.compile(r'<time[^>]+datetime="(?P<dt>[^"]+)"')


def _clean_html(value: str) -> str:
    return html.unescape(TAG_RE.sub(" ", value or "")).strip()


def query_terms(indicator, variants: list[dict], *, limit: int = 3) -> list[dict]:
    """Pick the most selective searchable forms, best first."""
    preferred = ("url", "email", "domain", "telegram_handle", "username", "phone_e164", "hash")
    by_kind: dict[str, list[str]] = {}
    for variant in variants or []:
        kind = variant.get("kind", "")
        value = text(variant.get("value"))
        if value:
            by_kind.setdefault(kind, []).append(value)
    terms: list[dict] = []
    for kind in preferred:
        for value in by_kind.get(kind, []):
            if len(value) < 4:
                continue
            terms.append({"kind": kind, "value": value})
            break
    if not terms and indicator is not None:
        terms.append({"kind": indicator.type, "value": indicator.normalized})
    return terms[:limit]


def match_terms(blob: str, terms: list[dict]) -> dict | None:
    """Return the first search term that literally appears in ``blob``."""
    lowered = (blob or "").lower()
    for term in terms:
        value = term["value"].lower()
        if value and value in lowered:
            return term
        # Compare without a scheme so "http://x" also matches "x".
        stripped = re.sub(r"^https?://", "", value).rstrip("/")
        if len(stripped) >= 6 and stripped in lowered:
            return term
    return None


class TelegramPublicProvider(BaseProvider):
    meta = ProviderMeta(
        name="telegram_public",
        accepts=("telegram",),
        emits=(),
        rate_limit=0.5,
        timeout=25.0,
        reliability=0.65,
        category="social",
        description="Public Telegram channel preview (t.me/s/) - posts, authors and timestamps",
        homepage="https://telegram.org/",
        supports_sightings=True,
        cache_ttl=300.0,
    )

    async def run(self, ctx):
        ctx.result.notes.append("telegram_public is a sightings provider")
        return ctx.result

    async def sightings(self, ctx, variants: list[dict]):
        handle = ""
        for variant in variants or []:
            if variant.get("kind") == "telegram_handle":
                handle = text(variant.get("value"))
                break
        if not handle and ctx.indicator is not None and ctx.indicator.type == "telegram":
            normalized = ctx.indicator.normalized
            if normalized.startswith("bot:"):
                ctx.partial("bot IDs are not searchable on the public web preview")
                return ctx.result
            if normalized.startswith("invite:"):
                ctx.partial("invite links require joining the channel")
                return ctx.result
            handle = normalized
        if not handle:
            ctx.partial("telegram_public requires a Telegram handle seed")
            return ctx.result
        res = await ctx.http.get_text(
            f"https://t.me/s/{quote(handle)}", timeout=25.0, max_bytes=4_000_000,
            cache_key=f"telegram:{handle.lower()}", cache_ttl=300.0,
        )
        if not res.ok:
            ctx.partial(f"telegram preview unavailable: {result_error(res)}")
            return ctx.result
        terms = [{"kind": "telegram_handle", "value": handle}] + query_terms(ctx.indicator, variants)
        found = 0
        for match in TELEGRAM_POST_RE.finditer(res.text[:2_000_000]):
            post_id = match.group("post").strip()
            body = match.group("body")
            text_match = TELEGRAM_TEXT_RE.search(body)
            if not text_match:
                continue
            post_text = _clean_html(text_match.group("text"))
            if not post_text:
                continue
            time_match = TELEGRAM_TIME_RE.search(body)
            posted = parse_date(time_match.group("dt")) if time_match else None
            matched = match_terms(post_text, terms) or {"value": handle}
            short_id = post_id.rsplit("/", 1)[-1]
            ctx.sighting(
                platform="telegram",
                post_url=f"https://t.me/{post_id}",
                post_id=short_id,
                author_handle=handle,
                posted_at=posted,
                text=post_text[:4000],
                indicator_form_matched=matched.get("value"),
                evidence_id=res.evidence_id,
                meta={"channel": post_id.rsplit("/", 1)[0]},
            )
            found += 1
            if found >= 40:
                break
        if not found:
            ctx.partial("telegram preview contained no public posts")
        return ctx.result


class BlueskyProvider(BaseProvider):
    meta = ProviderMeta(
        name="bluesky",
        accepts=("url", "domain", "email", "telegram", "phone", "file_hash"),
        emits=(),
        rate_limit=0.6,
        timeout=25.0,
        reliability=0.6,
        category="social",
        description="Bluesky public AppView post search (keyless)",
        homepage="https://bsky.app/",
        supports_sightings=True,
        cache_ttl=300.0,
    )

    async def run(self, ctx):
        ctx.result.notes.append("bluesky is a sightings provider")
        return ctx.result

    async def sightings(self, ctx, variants: list[dict]):
        terms = query_terms(ctx.indicator, variants)
        if not terms:
            ctx.partial("bluesky: no searchable indicator form")
            return ctx.result
        seen: set[str] = set()
        for term in terms:
            res = await ctx.http.get_json(
                "https://public.api.bsky.app/xrpc/app.bsky.feed.searchPosts",
                params={"q": term["value"], "limit": 50, "sort": "latest"},
                timeout=25.0, max_bytes=4_000_000,
                cache_key=f"bluesky:{term['value']}", cache_ttl=300.0,
            )
            if not res.ok:
                ctx.partial(f"bluesky search failed: {result_error(res)}")
                continue
            data = res.data if isinstance(res.data, dict) else {}
            for post in as_list(data.get("posts"))[:50]:
                if not isinstance(post, dict):
                    continue
                record = first(post, "record", default={})
                if not isinstance(record, dict):
                    record = {}
                post_text = text(first(record, "text"))
                if not post_text:
                    continue
                matched = match_terms(post_text, [term])
                if not matched:
                    continue
                uri = text(first(post, "uri"))
                if not uri or uri in seen:
                    continue
                seen.add(uri)
                handle = text(first(first(post, "author", default={}), "handle"))
                rkey = uri.rsplit("/", 1)[-1]
                author = first(post, "author", default={})
                ctx.sighting(
                    platform="bluesky",
                    post_url=f"https://bsky.app/profile/{handle}/post/{rkey}" if handle else uri,
                    post_id=rkey,
                    author_handle=handle,
                    author_id=text(first(author, "did")) if isinstance(author, dict) else None,
                    author_created_at=parse_date(first(author, "createdAt")) if isinstance(author, dict) else None,
                    posted_at=parse_date(first(record, "createdAt") or first(post, "indexedAt")),
                    text=post_text[:4000],
                    indicator_form_matched=matched.get("value"),
                    evidence_id=res.evidence_id,
                    meta={"langs": as_list(first(record, "langs", default=[]))[:5]},
                )
            if len(seen) >= 60:
                break
        if not seen:
            ctx.result.notes.append("bluesky: no matching posts")
        return ctx.result


class MastodonProvider(BaseProvider):
    meta = ProviderMeta(
        name="mastodon",
        accepts=("url", "domain", "email", "telegram", "phone"),
        emits=(),
        api_keys=("MASTODON_TOKEN",),
        rate_limit=0.5,
        timeout=25.0,
        reliability=0.6,
        category="social",
        description="Mastodon status search (requires MASTODON_TOKEN; instance configurable)",
        homepage="https://joinmastodon.org/",
        supports_sightings=True,
        cache_ttl=300.0,
    )

    async def run(self, ctx):
        ctx.result.notes.append("mastodon is a sightings provider")
        return ctx.result

    async def sightings(self, ctx, variants: list[dict]):
        terms = query_terms(ctx.indicator, variants)
        if not terms:
            ctx.partial("mastodon: no searchable indicator form")
            return ctx.result
        token = ctx.config.api_key("MASTODON_TOKEN")
        if not token:
            ctx.partial("MASTODON_TOKEN not configured")
            return ctx.result
        instance = str(self.options.get("instance") or "mastodon.social").strip().rstrip("/")
        if not re.match(r"^https?://", instance):
            instance = "https://" + instance
        headers = {"Authorization": f"Bearer {token}"}
        for term in terms:
            res = await ctx.http.get_json(
                f"{instance}/api/v2/search",
                params={"q": term["value"], "type": "statuses", "limit": 40, "resolve": "false"},
                headers=headers, timeout=25.0, max_bytes=4_000_000,
                cache_key=f"mastodon:{instance}:{term['value']}", cache_ttl=300.0,
            )
            if not res.ok:
                ctx.partial(f"mastodon search failed: {result_error(res)}")
                continue
            data = res.data if isinstance(res.data, dict) else {}
            for status in as_list(data.get("statuses"))[:40]:
                if not isinstance(status, dict):
                    continue
                status_text = _clean_html(text(first(status, "content")))
                account = first(status, "account", default={})
                ctx.sighting(
                    platform="mastodon",
                    post_url=text(first(status, "url", "uri")),
                    post_id=text(first(status, "id")),
                    author_handle=text(first(account, "acct")) if isinstance(account, dict) else None,
                    author_id=text(first(account, "id")) if isinstance(account, dict) else None,
                    author_created_at=parse_date(first(account, "created_at")) if isinstance(account, dict) else None,
                    posted_at=parse_date(first(status, "created_at")),
                    text=status_text[:4000],
                    indicator_form_matched=term["value"],
                    evidence_id=res.evidence_id,
                    meta={"instance": instance,
                          "reblogs": as_int(first(status, "reblogs_count"), 0),
                          "favourites": as_int(first(status, "favourites_count"), 0)},
                )
        return ctx.result


class RedditProvider(BaseProvider):
    meta = ProviderMeta(
        name="reddit",
        accepts=("url", "domain", "email", "telegram", "phone"),
        emits=(),
        rate_limit=0.4,
        timeout=30.0,
        reliability=0.55,
        category="social",
        description="Reddit post search (OAuth when REDDIT_CLIENT_ID/SECRET set, else public JSON)",
        homepage="https://www.reddit.com/",
        supports_sightings=True,
        cache_ttl=300.0,
    )

    async def run(self, ctx):
        ctx.result.notes.append("reddit is a sightings provider")
        return ctx.result

    async def _token(self, ctx) -> str | None:
        client_id = ctx.config.api_key("REDDIT_CLIENT_ID")
        secret = ctx.config.api_key("REDDIT_CLIENT_SECRET")
        if not client_id or not secret:
            return None
        basic = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
        res = await ctx.http.request(
            "POST", "https://www.reddit.com/api/v1/access_token",
            data={"grant_type": "client_credentials"},
            headers={"Authorization": f"Basic {basic}", "User-Agent": ctx.config.limits.user_agent},
            expect_json=True, timeout=20.0,
        )
        if not res.ok or not isinstance(res.data, dict):
            ctx.partial(f"reddit OAuth failed: {result_error(res)}")
            return None
        return text(res.data.get("access_token")) or None

    async def sightings(self, ctx, variants: list[dict]):
        terms = query_terms(ctx.indicator, variants)
        if not terms:
            ctx.partial("reddit: no searchable indicator form")
            return ctx.result
        token = await self._token(ctx)
        if token:
            base, headers = "https://oauth.reddit.com", {"Authorization": f"Bearer {token}"}
        else:
            base, headers = "https://www.reddit.com", {"User-Agent": ctx.config.limits.user_agent}
        for term in terms:
            res = await ctx.http.get_json(
                f"{base}/search.json",
                params={"q": f'"{term["value"]}"', "limit": 50, "sort": "new", "type": "link"},
                headers=headers, timeout=30.0, max_bytes=5_000_000,
                cache_key=f"reddit:{term['value']}", cache_ttl=300.0,
            )
            if not res.ok:
                ctx.partial(
                    "reddit search unavailable "
                    f"({result_error(res)}); set REDDIT_CLIENT_ID/REDDIT_CLIENT_SECRET for OAuth"
                )
                continue
            data = res.data if isinstance(res.data, dict) else {}
            children = as_list(first(first(data, "data", default={}), "children", default=[]))
            for child in children[:50]:
                post = first(child, "data", default={}) if isinstance(child, dict) else {}
                if not isinstance(post, dict):
                    continue
                blob = " ".join([
                    text(first(post, "title")), text(first(post, "selftext")),
                    text(first(post, "url")),
                ])
                matched = match_terms(blob, [term])
                if not matched:
                    continue
                permalink = text(first(post, "permalink"))
                ctx.sighting(
                    platform="reddit",
                    post_url=f"https://www.reddit.com{permalink}" if permalink.startswith("/") else permalink,
                    post_id=text(first(post, "id")),
                    author_handle=text(first(post, "author")),
                    author_id=text(first(post, "author_fullname")),
                    author_created_at=datetime.fromtimestamp(
                        as_int(first(post, "author_created_utc"), 0), tz=timezone.utc
                    ) if as_int(first(post, "author_created_utc"), 0) else None,
                    posted_at=datetime.fromtimestamp(
                        as_int(first(post, "created_utc"), 0), tz=timezone.utc
                    ) if as_int(first(post, "created_utc"), 0) else None,
                    text=blob[:4000],
                    indicator_form_matched=matched.get("value"),
                    evidence_id=res.evidence_id,
                    meta={"subreddit": text(first(post, "subreddit")),
                          "score": as_int(first(post, "score"), 0)},
                )
        return ctx.result
