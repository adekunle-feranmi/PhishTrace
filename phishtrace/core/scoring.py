"""Selector ranking and confidence scoring.

Every edge in the graph carries an explicit confidence. The score is derived
from three observable facts and nothing else:

* the selector strength the provider claimed (strong / medium / weak),
* the provider's reliability weight from its plugin metadata,
* how many independent providers reported the same relationship.

An optional provider confidence hint can soften or strengthen the result, but
it can never turn an unverified guess into a strong edge. Path confidence is
the product of the edges that led to a node, so a chain of weak links cannot
masquerade as a reliable finding.

All values are in ``[0, 1]`` and rounded to four decimals so that persisted
graphs and tests are deterministic.
"""

from __future__ import annotations

from datetime import datetime, timezone

from phishtrace.models import STRENGTH_RANK, Observation, SelectorStrength

STRENGTH_BASE: dict[str, float] = {
    SelectorStrength.STRONG.value: 0.9,
    SelectorStrength.MEDIUM.value: 0.65,
    SelectorStrength.WEAK.value: 0.3,
}

# A provider's reliability scales the base weight; even a perfect provider
# cannot make a weak selector strong.
RELIABILITY_FLOOR = 0.55
RELIABILITY_RANGE = 0.45
CORROBORATION_STEP = 0.06
CORROBORATION_CAP = 0.18
HINT_WEIGHT = 0.35

DEFAULT_PATH_FLOOR = 0.25


def clamp01(value: float, low: float = 0.0, high: float = 1.0) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return low
    return max(low, min(high, number))


def edge_confidence(
    strength: str,
    reliability: float = 1.0,
    *,
    corroborations: int = 0,
    hint: float | None = None,
) -> float:
    """Score one provider assertion about one relationship.

    ``corroborations`` counts independent providers that reported the same
    child; pass 0 or 1 for a single source.
    """
    base = STRENGTH_BASE.get(str(strength).lower(), STRENGTH_BASE[SelectorStrength.WEAK.value])
    weight = clamp01(reliability)
    value = base * (RELIABILITY_FLOOR + RELIABILITY_RANGE * weight)
    extra = max(0, int(corroborations) - 1)
    if extra:
        value += min(CORROBORATION_CAP, CORROBORATION_STEP * extra)
    if hint is not None:
        value = (1.0 - HINT_WEIGHT) * value + HINT_WEIGHT * clamp01(hint)
    # Never claim certainty from a single automated observation.
    return round(clamp01(value, 0.02, 0.99), 4)


def path_confidence(parent_confidence: float, edge: float) -> float:
    """Confidence of a node reached through ``edge`` from ``parent_confidence``."""
    return round(clamp01(clamp01(parent_confidence) * clamp01(edge), 0.0, 1.0), 4)


def should_expand(
    *,
    strength: str,
    path: float,
    depth: int,
    context_only: bool,
    stop_expand: bool,
    max_depth: int,
    expand_weak: bool = False,
    expand_medium: bool = True,
    path_floor: float = DEFAULT_PATH_FLOOR,
) -> tuple[bool, str | None]:
    """Decide whether a discovered node may itself be pivoted on."""
    if context_only:
        return False, "context-only"
    if not stop_expand:
        return False, "stop-listed"
    if depth >= max_depth:
        return False, f"max depth {max_depth} reached"
    if path < path_floor:
        return False, f"path confidence {path:.2f} below floor {path_floor:.2f}"
    rank = STRENGTH_RANK.get(str(strength).lower(), 1)
    if rank <= 1 and not expand_weak:
        return False, "weak selector (expand_weak disabled)"
    if rank == 2 and not expand_medium:
        return False, "medium selector (expand_medium disabled)"
    return True, None


def _observation_sort_key(observation: Observation) -> tuple:
    observed = observation.observed_at
    if isinstance(observed, datetime):
        when = observed.astimezone(timezone.utc) if observed.tzinfo else observed.replace(tzinfo=timezone.utc)
        stamp = when.timestamp()
    else:
        stamp = 0.0
    return (
        -STRENGTH_RANK.get(observation.strength, 0),
        -(observation.confidence_hint or 0.0),
        -stamp,
        observation.type,
        observation.value.lower(),
    )


def rank_observations(observations: list[Observation]) -> list[Observation]:
    """Deduplicate equivalent observations, strongest first.

    Two observations are equivalent when they have the same type and the same
    case-insensitive value. The survivor keeps the strongest selector, the
    earliest observed timestamp and the union of tags.
    """
    best: dict[tuple[str, str], Observation] = {}
    for observation in observations:
        key = observation.normalized_key()
        current = best.get(key)
        if current is None:
            best[key] = observation
            continue
        winner, loser = (
            (observation, current)
            if _observation_sort_key(observation)[:1] < _observation_sort_key(current)[:1]
            else (current, observation)
        )
        merged_tags = list(dict.fromkeys((winner.tags or []) + (loser.tags or [])))
        merged_meta = {**(loser.meta or {}), **(winner.meta or {})}
        if winner.observed_at is None:
            winner.observed_at = loser.observed_at
        elif loser.observed_at is not None:
            lhs = winner.observed_at if winner.observed_at.tzinfo else winner.observed_at.replace(tzinfo=timezone.utc)
            rhs = loser.observed_at if loser.observed_at.tzinfo else loser.observed_at.replace(tzinfo=timezone.utc)
            winner.observed_at = min(lhs, rhs)
        winner.tags = merged_tags
        winner.meta = merged_meta
        winner.context_only = winner.context_only and loser.context_only
        best[key] = winner
    return sorted(best.values(), key=_observation_sort_key)


def strength_rank(strength: str) -> int:
    return STRENGTH_RANK.get(str(strength).lower(), 0)
