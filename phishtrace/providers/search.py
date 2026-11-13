"""Web and social search-API providers (Phase B).

These close the "search APIs" gap tracked in docs/PROVIDERS.md: YouTube, X
(Twitter), SerpApi (Google results), Brave Search and Google Programmable
Search.  They are sightings providers: they look for public posts, videos and
web pages that mention the indicator, exactly like the keyless social
providers in ``social.py``, except each needs an API key.

Design rules shared with the social providers:

* a search hit is only recorded when the indicator appears verbatim in the
  title, snippet or URL (``match_terms``) - search-engine fuzzy matching alone
  is not evidence;
* every recorded sighting also yields a context-only URL observation so the
  graph shows the page without turning third-party pages into expansion seeds;
* a failed search degrades to ``ctx.partial`` and never fails the run.

Every request carries its key in a header or query parameter that the evidence
redactor already covers (``X-Subscription-Token``, ``Authorization``, ``key``,
``api_key``), so keys are never stored verbatim in evidence.
"""

from __future__ import annotations

from phishtrace.models import SelectorStrength
from phishtrace.providers._util import (
    as_int, as_list, first, parse_date, result_error, strip_tags, text, url_host,
)
from phishtrace.providers.base import BaseProvider, ProviderMeta
from phishtrace.providers.social import match_terms, query_terms

MAX_SIGHTINGS = 40
MAX_CONTEXT_URLS = 20


class _SearchSightingsProvider(BaseProvider):
    """Shared sightings loop for query/response search APIs."""

    platform = "web"

    async def run(self, ctx):
        ctx.result.notes.append(f"{self.meta.name} is a sightings provider")
        return ctx.result

    async def _search(self, ctx, query: str) -> tuple[list[dict], object | None]:
        raise NotImplementedError

    async def sightings(self, ctx, variants: list[dict]):
        terms = query_terms(ctx.indicator, variants, limit=2)
        # A bare word (e.g. a registrable-domain fallback like "example") is
        # not selective enough for a search engine: it matches random pages
        # and burns quota.  Require something host-, mailbox- or token-like.
        terms = [term for term in terms
                 if len(term.get("value", "")) >= 8 or "." in term.get("value", "") or "@" in term.get("value", "")]
        if not terms:
            ctx.partial(f"{self.meta.name}: no searchable indicator form")
            return ctx.result
        seen = 0
        context_urls = 0
        recorded: set[str] = set()
        for term in terms:
            results, res = await self._search(ctx, term["value"])
            if res is None:
                continue
            if not res.ok:
                ctx.partial(f"{self.meta.name} search failed: {result_error(res)}")
                continue
            for item in results:
                if seen >= MAX_SIGHTINGS:
                    break
                link = text(item.get("url"))
                title = strip_tags(item.get("title"))
                snippet = strip_tags(item.get("snippet"))
                matched = match_terms(f"{title} {snippet} {link}", [term])
                if not matched:
                    continue
                dedupe_key = link or f"search:{term['value']}:{title}"
                if dedupe_key in recorded:
                    continue
                recorded.add(dedupe_key)
                seen += 1
                ctx.sighting(
                    platform=self.platform,
                    post_url=link or f"search:{term['value']}",
                    post_id=text(item.get("post_id")) or None,
                    author_handle=text(item.get("author")) or None,
                    author_id=text(item.get("author_id")) or None,
                    author_created_at=parse_date(item.get("author_created")),
                    posted_at=parse_date(item.get("published")),
                    text=f"{title}\n{snippet}".strip()[:4000],
                    role=text(item.get("role")) or "unknown",
                    indicator_form_matched=matched.get("value"),
                    evidence_id=res.evidence_id,
                    meta=dict(item.get("meta") or {}),
                )
                if link and context_urls < MAX_CONTEXT_URLS:
                    context_urls += 1
                    ctx.emit(
                        "url", link, "web-result", SelectorStrength.WEAK,
                        evidence_id=res.evidence_id,
                        tags=[self.meta.name, "search-result"], context_only=True,
                        note=f"{self.meta.name}: search result mentioning the indicator",
                    )
            if seen >= MAX_SIGHTINGS:
                break
        if not seen:
            ctx.result.notes.append(f"{self.meta.name}: no verbatim indicator matches")
        return ctx.result


# --------------------------------------------------------------------------- #
# SerpApi (Google SERP)
# --------------------------------------------------------------------------- #
class SerpApiProvider(_SearchSightingsProvider):
    meta = ProviderMeta(
        name="serpapi",
        phase="B",
        accepts=("url", "domain", "email", "telegram", "phone", "file_hash"),
        emits=("url",),
        api_keys=("SERPAPI_KEY",),
        rate_limit=1.0,
        timeout=30.0,
        reliability=0.7,
        category="search",
        description="Google search results via SerpApi (organic results mentioning the indicator)",
        homepage="https://serpapi.com/",
        supports_sightings=True,
        cache_ttl=600.0,
    )
    platform = "google"

    async def _search(self, ctx, query: str):
        key = ctx.config.api_key("SERPAPI_KEY")
        if not key:
            ctx.partial("SERPAPI_KEY not configured")
            return [], None
        res = await ctx.http.get_json(
            "https://serpapi.com/search.json",
            params={"engine": "google", "q": query, "num": 20, "safe": "active", "api_key": key},
            timeout=30.0, max_bytes=2_000_000,
            cache_key=f"serpapi:{query}", cache_ttl=600.0,
        )
        if not res.ok:
            return [], res
        data = res.data if isinstance(res.data, dict) else {}
        if data.get("error"):
            ctx.partial(f"serpapi rejected the query: {text(data.get('error'))}")
            return [], res
        results = []
        for row in as_list(data.get("organic_results")):
            if not isinstance(row, dict):
                continue
            link = text(first(row, "link", "url"))
            if not link:
                continue
            results.append({
                "url": link,
                "title": text(first(row, "title")),
                "snippet": text(first(row, "snippet")),
                "published": first(row, "date"),
                "author": url_host(link),
                "meta": {"position": as_int(row.get("position"), 0)},
            })
        return results, res


# --------------------------------------------------------------------------- #
# Brave Search
# --------------------------------------------------------------------------- #
class BraveSearchProvider(_SearchSightingsProvider):
    meta = ProviderMeta(
        name="brave_search",
        phase="B",
        accepts=("url", "domain", "email", "telegram", "phone", "file_hash"),
        emits=("url",),
        api_keys=("BRAVE_API_KEY",),
        rate_limit=1.0,
        timeout=30.0,
        reliability=0.7,
        category="search",
        description="Brave Search web API (results mentioning the indicator)",
        homepage="https://brave.com/search/api/",
        supports_sightings=True,
        cache_ttl=600.0,
    )
    platform = "brave"

    async def _search(self, ctx, query: str):
        key = ctx.config.api_key("BRAVE_API_KEY")
        if not key:
            ctx.partial("BRAVE_API_KEY not configured")
            return [], None
        res = await ctx.http.get_json(
            "https://api.search.brave.com/res/v1/web/search",
            params={"q": query, "count": 20},
            headers={"Accept": "application/json", "X-Subscription-Token": key},
            timeout=30.0, max_bytes=2_000_000,
            cache_key=f"brave:{query}", cache_ttl=600.0,
        )
        if not res.ok:
            return [], res
        data = res.data if isinstance(res.data, dict) else {}
        web = first(data, "web", default={})
        results = []
        for row in as_list(first(web, "results", default=[])):
            if not isinstance(row, dict):
                continue
            link = text(first(row, "url"))
            if not link:
                continue
            results.append({
                "url": link,
                "title": text(first(row, "title")),
                "snippet": text(first(row, "description")),
                "published": first(row, "age"),
                "author": url_host(link),
                "meta": {"source": text(first(row, "source"))},
            })
        return results, res


# --------------------------------------------------------------------------- #
# Google Programmable Search (CSE)
# --------------------------------------------------------------------------- #
class GoogleCseProvider(_SearchSightingsProvider):
    meta = ProviderMeta(
        name="google_cse",
        phase="B",
        accepts=("url", "domain", "email", "telegram", "phone", "file_hash"),
        emits=("url",),
        api_keys=("GOOGLE_CSE_API_KEY", "GOOGLE_CSE_CX"),
        rate_limit=1.0,
        timeout=30.0,
        reliability=0.75,
        category="search",
        description="Google Programmable Search JSON API (results mentioning the indicator)",
        homepage="https://developers.google.com/custom-search/v1/overview",
        supports_sightings=True,
        cache_ttl=600.0,
    )
    platform = "google_cse"

    async def _search(self, ctx, query: str):
        key = ctx.config.api_key("GOOGLE_CSE_API_KEY")
        cx = ctx.config.api_key("GOOGLE_CSE_CX")
        if not key or not cx:
            ctx.partial("GOOGLE_CSE_API_KEY / GOOGLE_CSE_CX not configured")
            return [], None
        res = await ctx.http.get_json(
            "https://www.googleapis.com/customsearch/v1",
            params={"key": key, "cx": cx, "q": query, "num": 10, "safe": "active"},
            timeout=30.0, max_bytes=2_000_000,
            cache_key=f"gcse:{cx}:{query}", cache_ttl=600.0,
        )
        if not res.ok:
            return [], res
        data = res.data if isinstance(res.data, dict) else {}
        if data.get("error"):
            message = text(first(first(data, "error", default={}), "message"))
            ctx.partial(f"google_cse rejected the query: {message or 'unknown error'}")
            return [], res
        results = []
        for row in as_list(data.get("items")):
            if not isinstance(row, dict):
                continue
            link = text(first(row, "link"))
            if not link:
                continue
            results.append({
                "url": link,
                "title": text(first(row, "title")),
                "snippet": text(first(row, "snippet")),
                "author": text(first(row, "displayLink")) or url_host(link),
                "meta": {},
            })
        return results, res


# --------------------------------------------------------------------------- #
# YouTube Data API v3
# --------------------------------------------------------------------------- #
class YouTubeProvider(_SearchSightingsProvider):
    meta = ProviderMeta(
        name="youtube",
        phase="B",
        accepts=("url", "domain", "email", "telegram", "phone", "file_hash"),
        emits=("url", "username"),
        api_keys=("YOUTUBE_API_KEY",),
        rate_limit=0.5,
        timeout=30.0,
        reliability=0.7,
        category="search",
        description="YouTube Data API v3 search (videos and channels mentioning the indicator)",
        homepage="https://developers.google.com/youtube/v3",
        supports_sightings=True,
        cache_ttl=600.0,
    )
    platform = "youtube"

    async def _search(self, ctx, query: str):
        key = ctx.config.api_key("YOUTUBE_API_KEY")
        if not key:
            ctx.partial("YOUTUBE_API_KEY not configured")
            return [], None
        res = await ctx.http.get_json(
            "https://www.googleapis.com/youtube/v3/search",
            params={"part": "snippet", "q": query, "type": "video,channel", "maxResults": 25, "key": key},
            timeout=30.0, max_bytes=2_000_000,
            cache_key=f"youtube:{query}", cache_ttl=600.0,
        )
        if not res.ok:
            return [], res
        data = res.data if isinstance(res.data, dict) else {}
        if data.get("error"):
            message = text(first(first(data, "error", default={}), "message"))
            ctx.partial(f"youtube rejected the query: {message or 'unknown error'}")
            return [], res
        results = []
        for row in as_list(data.get("items")):
            if not isinstance(row, dict):
                continue
            snippet = first(row, "snippet", default={})
            if not isinstance(snippet, dict):
                snippet = {}
            item_id = first(row, "id", default={})
            if not isinstance(item_id, dict):
                item_id = {}
            video_id = text(item_id.get("videoId"))
            channel_id = text(item_id.get("channelId"))
            if video_id:
                link = f"https://www.youtube.com/watch?v={video_id}"
            elif channel_id:
                link = f"https://www.youtube.com/channel/{channel_id}"
            else:
                continue
            results.append({
                "url": link,
                "title": text(snippet.get("title")),
                "snippet": text(snippet.get("description")),
                "published": snippet.get("publishedAt"),
                "author": text(snippet.get("channelTitle")) or None,
                "author_id": channel_id or None,
                "post_id": video_id or channel_id,
                "meta": {"kind": "video" if video_id else "channel"},
            })
            if channel_id and not video_id:
                # A channel hit is an attribution pivot worth keeping.
                ctx.emit(
                    "username", f"youtube.com/channel/{channel_id}", "channel-reference",
                    SelectorStrength.WEAK, evidence_id=res.evidence_id,
                    tags=["youtube", "channel"], context_only=True,
                    note="YouTube channel returned for this indicator",
                )
        return results, res


# --------------------------------------------------------------------------- #
# X (Twitter) API v2 recent search
# --------------------------------------------------------------------------- #
class XSearchProvider(_SearchSightingsProvider):
    meta = ProviderMeta(
        name="x_search",
        phase="B",
        accepts=("url", "domain", "email", "telegram", "phone", "file_hash"),
        emits=("url", "username"),
        api_keys=("X_BEARER_TOKEN",),
        rate_limit=0.5,
        timeout=30.0,
        reliability=0.7,
        category="search",
        description="X (Twitter) API v2 recent tweet search (posts mentioning the indicator)",
        homepage="https://developer.x.com/en/docs/x-api",
        supports_sightings=True,
        cache_ttl=600.0,
    )
    platform = "x"

    async def _search(self, ctx, query: str):
        token = ctx.config.api_key("X_BEARER_TOKEN")
        if not token:
            ctx.partial("X_BEARER_TOKEN not configured")
            return [], None
        res = await ctx.http.get_json(
            "https://api.twitter.com/2/tweets/search/recent",
            params={
                "query": query, "max_results": 25,
                "tweet.fields": "created_at", "expansions": "author_id",
                "user.fields": "username,name,created_at",
            },
            headers={"Authorization": f"Bearer {token}"},
            timeout=30.0, max_bytes=2_000_000,
            cache_key=f"xsearch:{query}", cache_ttl=600.0,
        )
        if not res.ok:
            if res.status == 403:
                ctx.partial("x_search: rejected (403); the X tier in use does not include recent search")
            return [], res
        data = res.data if isinstance(res.data, dict) else {}
        users: dict[str, dict] = {}
        includes = first(data, "includes", default={})
        if isinstance(includes, dict):
            for user in as_list(includes.get("users")):
                if isinstance(user, dict) and user.get("id"):
                    users[str(user["id"])] = user
        results = []
        for row in as_list(data.get("data")):
            if not isinstance(row, dict):
                continue
            tweet_id = text(row.get("id"))
            author = users.get(text(row.get("author_id")), {}) or {}
            username = text(author.get("username"))
            if tweet_id and username:
                link = f"https://x.com/{username}/status/{tweet_id}"
            else:
                link = ""
            results.append({
                "url": link,
                "title": "",
                "snippet": text(row.get("text")),
                "published": row.get("created_at"),
                "author": username or None,
                "author_id": text(row.get("author_id")) or None,
                "author_created": author.get("created_at"),
                "post_id": tweet_id or None,
                "meta": {},
            })
        return results, res
