"""Heuristic classification of the people behind social posts about a campaign.

The classifier answers one question per account: *what role did this account
play in the campaign?* It never asserts identity. Every answer carries the
signals that produced it and a confidence value, and "unknown" is a first-class
result rather than a failure.

Roles
-----
``threat_actor``      appears to operate or promote the campaign itself
``distributor``       repeatedly posts campaign links (possibly many domains)
``amplifier``         reshares someone else's post (RT / repost / via)
``victim_reporting``  a person reporting that they were targeted
``researcher``        security researcher, CERT, vendor or journalist analysing it
``brand``             the impersonated brand warning its own customers
``unknown``           no distinguishing signal

Design notes
------------
* Signals are additive but saturating: ``score = 1 - Π(1 - w)`` so many weak
  cues never exceed 1.0 and a single cue stays weak.
* Text cues cover the languages most common in malspam reports (en, es, pt, fr,
  de, it, id, vi, ru, ar, zh, tr, pl) because campaigns are global even when the
  analyst is not.
* Posting several *distinct registrable domains* is the strongest single
  distributor signal; it is computed across the whole author cluster, not from
  one post.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable
from urllib.parse import urlsplit

from phishtrace.models import SightingDraft, parse_timestamp, utcnow

ROLES = (
    "threat_actor",
    "distributor",
    "amplifier",
    "victim_reporting",
    "researcher",
    "brand",
    "unknown",
)

ROLE_LABELS = {
    "threat_actor": "Likely campaign operator",
    "distributor": "Link distributor / spam account",
    "amplifier": "Amplifier (reshares others)",
    "victim_reporting": "Target reporting the attempt",
    "researcher": "Researcher / CERT / press",
    "brand": "Impersonated brand or its staff",
    "unknown": "Unclassified",
}


# --------------------------------------------------------------------------- text
# (pattern, weight, label). Weights are deliberately modest; a single phrase is
# never enough on its own to classify an account.
_VICTIM_CUES = [
    (r"\bi (?:just )?(?:received|got)\b", 0.55, "first-person receipt"),
    (r"\b(?:sent|texted|messaged|called) me\b", 0.5, "targeted directly"),
    (r"\balmost (?:clicked|fell|paid)\b", 0.55, "nearly victimised"),
    (r"\bis this (?:a )?(?:scam|phishing|legit|real)\b", 0.5, "asking if it is a scam"),
    (r"\b(?:received|got) (?:this|these) (?:text|sms|email|message|dm)\b", 0.5, "received the lure"),
    (r"\bthey tried to (?:scam|phish)\b", 0.5, "attempted scam"),
    (r"\bme (?:lleg[oó]|enviaron)\b", 0.5, "ES: received"),
    (r"\brecib[ií] (?:este|un) (?:mensaje|sms|correo)\b", 0.5, "ES: received"),
    (r"\b(?:es|ser[áa]) (?:una )?estafa\b", 0.45, "ES: scam"),
    (r"\brecebi (?:este|uma)\b", 0.5, "PT: received"),
    (r"\b[ée] (?:um )?golpe\b", 0.45, "PT: scam"),
    (r"\bj'ai re[çc]u\b", 0.5, "FR: received"),
    (r"\bc'est une arnaque\b|\best-ce une arnaque\b", 0.45, "FR: scam"),
    (r"\bich habe (?:diese|eine) (?:sms|nachricht|mail|e-mail) erhalten\b", 0.5, "DE: received"),
    (r"\bist das betrug\b|\bbetrugsversuch\b", 0.45, "DE: scam"),
    (r"\bho ricevuto\b", 0.5, "IT: received"),
    (r"\b[èe] una truffa\b", 0.45, "IT: scam"),
    (r"\bsaya menerima\b", 0.5, "ID: received"),
    (r"\bini penipuan\b", 0.45, "ID: scam"),
    (r"\bt[oô]i (?:nh[ậa]n|b[ịi] lừa)\b", 0.5, "VI: received/defrauded"),
    (r"\bя получил\b|\bмне пришло\b", 0.5, "RU: received"),
    (r"\bэто мошенничество\b", 0.45, "RU: fraud"),
    (r"تحقق من", 0.2, "AR: verify (ambiguous)"),
    (r"\b(?:almac|recib)\w*\b", 0.15, "ES: receipt token"),
]

_RESEARCHER_CUES = [
    (r"\bphishing (?:campaign|kit|infrastructure|wave)\b", 0.5, "campaign analysis"),
    (r"\b(?:iocs?|indicators of compromise)\b", 0.5, "shares IOCs"),
    (r"\b(?:threat intel|threat intelligence|malware analysis|teardown|reverse engineered)\b", 0.5, "technical analysis"),
    (r"\bwe (?:observed|tracked|analysed|analyzed|detected)\b", 0.45, "tracking statement"),
    (r"\b(?:cert|csirt|soc|dfir)\b", 0.35, "security team marker"),
    (r"\b(?:takedown|take-down|take down|reported to (?:the )?(?:registrar|host|cloudflare))\b", 0.4, "takedown action"),
    (r"\b(?:sample|payload|hash|sha256|md5)\b", 0.3, "sample reference"),
    (r"\b(?:advisory|bulletin|write-?up|blog post)\b", 0.35, "publication"),
    (r"\b(?:scam|fraud) (?:alert|warning)\b", 0.35, "alert"),
]

_BRAND_CUES = [
    (r"\bofficial (?:account|channel|page)\b", 0.5, "declares official channel"),
    (r"\bwe (?:never|do not|don't|will never) (?:ask|request|call|text)\b", 0.55, "brand never-ask policy"),
    (r"\bbeware of (?:fake|fraudulent|imitation)\b", 0.45, "warns about fakes"),
    (r"\b(?:our|your) (?:customers|users|clients)\b", 0.25, "speaks for a customer base"),
    (r"\breport (?:it|this|suspicious messages?) to us\b", 0.4, "asks for reports"),
    (r"\bverify (?:all )?(?:messages|communications) (?:through|via) our official\b", 0.45, "channel verification guidance"),
]

_ACTOR_CUES = [
    (r"\bverify (?:your )?account\b", 0.5, "credential lure"),
    (r"\b(?:account|profile) (?:will be|has been|is) (?:suspended|locked|limited|closed)\b", 0.55, "account-threat lure"),
    (r"\bconfirm your (?:identity|details|information)\b", 0.45, "identity lure"),
    (r"\bclaim your (?:prize|reward|refund|winnings)\b", 0.5, "reward lure"),
    (r"\byou (?:have )?won\b", 0.45, "prize lure"),
    (r"\b(?:delivery|shipping|redelivery) fee\b", 0.5, "parcel-fee lure"),
    (r"\b(?:small|processing) fee\b", 0.4, "fee lure"),
    (r"\burgent action (?:required|needed)\b", 0.4, "urgency"),
    (r"\bfinal (?:warning|notice)\b", 0.35, "urgency"),
    (r"\bunusual sign-?in\b", 0.4, "security-alert lure"),
    (r"\b(?:parcel|package) (?:is )?(?:waiting|held|on hold)\b", 0.4, "parcel lure"),
    (r"\btax refund\b", 0.45, "tax lure"),
    (r"\bjob offer\b.{0,80}\b(?:fee|deposit|payment)\b", 0.45, "job-fee lure"),
    (r"\bguaranteed (?:returns|profit)\b", 0.45, "investment lure"),
    (r"\bverifica (?:tu|su) cuenta\b", 0.45, "ES: account lure"),
    (r"\bverifique (?:sua|a sua) conta\b", 0.45, "PT: account lure"),
    (r"\bv[ée]rifiez votre compte\b", 0.45, "FR: account lure"),
    (r"\b(?:konto )?best[äa]tigen sie ihr konto\b|\bkonto best[äa]tigen\b", 0.45, "DE: account lure"),
    (r"\bverifica (?:il tuo|la tua) account\b", 0.4, "IT: account lure"),
    (r"\bverifikasi akun\b", 0.45, "ID: account lure"),
    (r"\bx[áa]c minh t[àa]i kho[ảa]n\b", 0.45, "VI: account lure"),
    (r"\bподтвердите (?:свой )?аккаунт\b", 0.45, "RU: account lure"),
    (r"تحقق من حسابك", 0.45, "AR: account lure"),
    (r"验证您的?账户|確認您的?帳戶", 0.45, "ZH: account lure"),
    (r"\bhesab[ıi]n[ıi]z[ıi] do[ğg]rulay[ıi]n\b", 0.45, "TR: account lure"),
    (r"\bpotwierd[źz] (?:swoje )?konto\b", 0.45, "PL: account lure"),
]

_AMPLIFIER_CUES = [
    (r"^\s*(?:rt|mt)\s*@\w+", 0.6, "retweet syntax"),
    (r"\breposted\b|\brepost\b", 0.45, "explicit repost"),
    (r"\bshared via\b|\bvia @\w+", 0.5, "shared-via attribution"),
    (r"\b(?:signal boost|boosting)\b", 0.4, "signal boost"),
]

_COMPILED: list[tuple[re.Pattern[str], float, str, str]] = []


def _rules() -> list[tuple[re.Pattern[str], float, str, str]]:
    if _COMPILED:
        return _COMPILED
    for role, cues in (
        ("victim_reporting", _VICTIM_CUES),
        ("researcher", _RESEARCHER_CUES),
        ("brand", _BRAND_CUES),
        ("threat_actor", _ACTOR_CUES),
        ("amplifier", _AMPLIFIER_CUES),
    ):
        for pattern, weight, label in cues:
            _COMPILED.append((re.compile(pattern, re.IGNORECASE | re.UNICODE), weight, label, role))
    return _COMPILED


def _combine(weights: Iterable[float]) -> float:
    """Saturating combination: 1 - Π(1 - w)."""
    remaining = 1.0
    for weight in weights:
        remaining *= max(0.0, 1.0 - min(0.95, float(weight)))
    return 1.0 - remaining


# --------------------------------------------------------------------------- handle
_RANDOM_HANDLE = re.compile(r"[A-Za-z]*\d{4,}[A-Za-z0-9_]*$")


def handle_randomness(handle: str | None) -> float:
    """0..1 estimate of how auto-generated a handle looks.

    Only structural properties are used (digit runs, entropy-ish character mix,
    length). It is a weak cue and never decisive alone.
    """
    if not handle:
        return 0.0
    name = handle.lstrip("@").split("@")[0]
    if not name:
        return 0.0
    digits = sum(ch.isdigit() for ch in name)
    ratio = digits / len(name)
    score = 0.0
    if _RANDOM_HANDLE.search(name):
        score += 0.35
    if ratio >= 0.4:
        score += 0.3
    elif ratio >= 0.25:
        score += 0.15
    if len(name) >= 16 and digits >= 3:
        score += 0.15
    # long unbroken lowercase+digit blobs look machine-generated
    if len(name) >= 14 and re.fullmatch(r"[a-z0-9_]+", name):
        score += 0.1
    return min(1.0, score)


_BRANDISH = re.compile(
    r"(?:official|support|help|service|security|verify|secure|account|billing|update|alert|notice|team)",
    re.IGNORECASE,
)


def _registrable(value: str) -> str:
    host = value
    if "://" in host:
        host = urlsplit(host).hostname or host
    else:
        host = host.split("/")[0]
    host = host.lower().strip(".")
    parts = [p for p in host.split(".") if p]
    if len(parts) <= 2:
        return host
    # common two-label public suffixes; good enough for a clustering heuristic
    if parts[-2] in {"co", "com", "org", "net", "gov", "ac", "edu"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _domains_in(text: str) -> set[str]:
    found = set()
    for match in re.finditer(r"(?:https?://)?([a-z0-9][a-z0-9.\-]+\.[a-z]{2,})(?:[/:?#\s]|$)", text or "", re.IGNORECASE):
        candidate = match.group(1)
        if "." in candidate and not candidate.endswith((".png", ".jpg", ".gif", ".css", ".js")):
            found.add(_registrable(candidate))
    return found


# --------------------------------------------------------------------------- result
@dataclass
class RoleAssessment:
    role: str
    confidence: float
    signals: list[str] = field(default_factory=list)
    scores: dict[str, float] = field(default_factory=dict)
    ambiguous: bool = False
    rationale: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "label": ROLE_LABELS.get(self.role, self.role),
            "confidence": round(self.confidence, 3),
            "signals": list(self.signals),
            "scores": {k: round(v, 3) for k, v in self.scores.items() if v > 0},
            "ambiguous": self.ambiguous,
            "rationale": self.rationale or self._default_rationale(),
        }

    def _default_rationale(self) -> str:
        if self.role == "unknown":
            return "No distinguishing signals in the post text, handle or posting pattern."
        top = ", ".join(self.signals[:4]) or "weak structural cues"
        return f"Classified from {top}."


def classify_role(
    *,
    text: str = "",
    author_handle: str | None = None,
    platform: str | None = None,
    posted_at: datetime | str | None = None,
    author_created_at: datetime | str | None = None,
    verified: bool = False,
    indicator_forms: Iterable[str] | None = None,
    link_count: int | None = None,
) -> RoleAssessment:
    """Classify one post/account. Never raises on odd input."""
    body = (text or "")[:8000]
    weights: dict[str, list[float]] = {role: [] for role in ROLES}
    signals: list[str] = []

    for pattern, weight, label, role in _rules():
        if pattern.search(body):
            weights[role].append(weight)
            signals.append(f"{role}: {label}")

    # Structural cues -------------------------------------------------------
    randomness = handle_randomness(author_handle)
    if randomness >= 0.4:
        weights["threat_actor"].append(0.2 * randomness)
        signals.append(f"threat_actor: auto-generated-looking handle ({randomness:.2f})")
    elif randomness >= 0.2:
        weights["threat_actor"].append(0.1 * randomness)

    posted = parse_timestamp(posted_at)
    created = parse_timestamp(author_created_at)
    if posted and created:
        age_days = (posted - created).total_seconds() / 86400.0
        if age_days < 0:
            age_days = 0.0
        if age_days <= 14:
            weights["threat_actor"].append(0.3)
            signals.append(f"threat_actor: account was {age_days:.0f} day(s) old when posting")
        elif age_days <= 60:
            weights["threat_actor"].append(0.18)
            signals.append(f"threat_actor: account was {age_days:.0f} days old when posting")
        elif age_days >= 730:
            weights["victim_reporting"].append(0.1)
            weights["researcher"].append(0.1)
            signals.append("established account (2+ years old)")

    if verified:
        weights["brand"].append(0.25)
        signals.append("brand: platform-verified account")

    forms = [str(f) for f in (indicator_forms or []) if f]
    body_lower = body.lower()
    matched_forms = sum(1 for form in forms if form.lower() in body_lower)
    urls = re.findall(r"https?://\S+", body, re.IGNORECASE)
    links = link_count if link_count is not None else len(urls)
    if links == 1 and len(body.strip()) <= 45 and matched_forms:
        weights["threat_actor"].append(0.12)
        signals.append("threat_actor: bare link post")

    # Saturate per role -----------------------------------------------------
    saturated = {role: _combine(weights[role]) for role in ROLES if weights[role]}

    ranked = sorted(saturated.items(), key=lambda kv: kv[1], reverse=True)
    if not ranked:
        return RoleAssessment(role="unknown", confidence=0.0, scores={}, signals=[], rationale="No distinguishing signals.")

    top_role, top_score = ranked[0]
    second = ranked[1][1] if len(ranked) > 1 else 0.0
    ambiguous = (top_score - second) < 0.08 and top_score > 0.25
    if top_score < 0.3:
        return RoleAssessment(
            role="unknown",
            confidence=round(top_score, 3),
            signals=signals[:12],
            scores=saturated,
            ambiguous=ambiguous,
            rationale="Signals were too weak or contradictory to assign a role.",
        )
    rationale = f"Classified as {top_role} from {len([s for s in signals if s.startswith(top_role)])} cue(s)"
    if ambiguous:
        rationale += f"; close call against {ranked[1][0]}"
    return RoleAssessment(
        role=top_role,
        confidence=round(min(0.95, top_score), 3),
        signals=signals[:12],
        scores=saturated,
        ambiguous=ambiguous,
        rationale=rationale + ".",
    )


def classify_author_cluster(
    sightings: list[SightingDraft],
    *,
    handle: str | None = None,
) -> RoleAssessment:
    """Classify an author across all of their collected posts.

    Cross-post behaviour is the best available signal for distributors: an
    account posting many distinct registrable domains is not a victim.
    """
    posts = [s for s in sightings if (handle is None or (s.author_handle or "") == handle)]
    if not posts:
        return RoleAssessment(role="unknown", confidence=0.0, rationale="No posts for this author.")

    combined_text = "\n".join((p.text or "") for p in posts)
    domains: set[str] = set()
    for post in posts:
        domains |= _domains_in(post.text or "")
        if post.post_url:
            domains |= _domains_in(post.post_url)
    first = posts[0]
    base = classify_role(
        text=combined_text,
        author_handle=handle or first.author_handle,
        platform=first.platform,
        posted_at=first.posted_at,
        author_created_at=first.author_created_at,
        indicator_forms=[p.indicator_form_matched for p in posts if p.indicator_form_matched],
    )
    scores = dict(base.scores)
    signals = list(base.signals)

    distinct_domains = len({d for d in domains if d})
    if distinct_domains >= 4:
        scores["distributor"] = _combine([scores.get("distributor", 0.0), 0.6])
        signals.append(f"distributor: posts {distinct_domains} distinct domains")
    elif distinct_domains >= 2:
        scores["distributor"] = _combine([scores.get("distributor", 0.0), 0.4])
        signals.append(f"distributor: posts {distinct_domains} distinct domains")

    if len(posts) >= 5:
        scores["distributor"] = _combine([scores.get("distributor", 0.0), 0.25])
        signals.append(f"distributor: {len(posts)} posts collected")

    ranked = sorted(((r, v) for r, v in scores.items() if v > 0), key=lambda kv: kv[1], reverse=True)
    if not ranked or ranked[0][1] < 0.3:
        return RoleAssessment("unknown", 0.0, signals[:12], scores, rationale="Author pattern is inconclusive.")
    role, score = ranked[0]
    second = ranked[1][1] if len(ranked) > 1 else 0.0
    return RoleAssessment(
        role=role,
        confidence=round(min(0.95, score), 3),
        signals=signals[:12],
        scores=scores,
        ambiguous=(score - second) < 0.08,
        rationale=f"Author cluster of {len(posts)} post(s): {role}.",
    )


def classify_sightings(drafts: list[SightingDraft]) -> dict[str, RoleAssessment]:
    """Assign ``draft.role`` in place per author cluster; return the assessments."""
    by_handle: dict[str, list[SightingDraft]] = {}
    for draft in drafts:
        key = (draft.author_handle or f"anon:{draft.post_id or draft.post_url}").lower()
        by_handle.setdefault(key, []).append(draft)

    assessments: dict[str, RoleAssessment] = {}
    for key, posts in by_handle.items():
        assessment = classify_author_cluster(posts, handle=posts[0].author_handle)
        for post in posts:
            post.role = assessment.role
        assessments[key] = assessment
    return assessments


def summarize_roles(assessments: Iterable[RoleAssessment]) -> dict[str, int]:
    counts = {role: 0 for role in ROLES}
    for assessment in assessments:
        counts[assessment.role] = counts.get(assessment.role, 0) + 1
    return counts
