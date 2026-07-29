"""Cluster-aware statistics for paired-diff evaluation.

The evaluation rows in this project are not independent. Each pair group
contributes two rows that are exact mirror renderings of the same patch, so a
row-level test over N rows has roughly N/2 independent units. Separately, the
"five split seeds" used previously are random re-partitions of one fixed
prediction set and overlap pairwise at Jaccard ~0.53; resampling them does not
estimate generalisation.

This module provides the replacement primitives:

* :func:`cluster_bootstrap` -- resample **pair groups**, not rows.
* :func:`paired_cluster_bootstrap_diff` -- clustered CI for a metric difference
  between two systems evaluated on the same groups.
* :func:`group_sign_test` / :func:`exact_binomial_two_sided` -- paired tests at
  the group level.
* :func:`clopper_pearson` -- exact binomial interval, for small-n rates such as
  gate precision.

Pure standard library: no numpy/scipy requirement, so the clean-run path stays
dependency-light and deterministic.
"""

from __future__ import annotations

import math
import random
from typing import Any, Callable, Iterable, Sequence

# ---------------------------------------------------------------------------
# Incomplete beta (for exact binomial intervals)
# ---------------------------------------------------------------------------


def _betacf(a: float, b: float, x: float, *, iterations: int = 200, epsilon: float = 3e-14) -> float:
    """Continued-fraction expansion for the incomplete beta function (Lentz)."""

    tiny = 1e-300
    qab = a + b
    qap = a + 1.0
    qam = a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < tiny:
        d = tiny
    d = 1.0 / d
    h = d
    for m in range(1, iterations + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < tiny:
            d = tiny
        c = 1.0 + aa / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < tiny:
            d = tiny
        c = 1.0 + aa / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < epsilon:
            break
    return h


def betainc(a: float, b: float, x: float) -> float:
    """Regularized incomplete beta function ``I_x(a, b)``."""

    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    log_prefix = (
        math.lgamma(a + b)
        - math.lgamma(a)
        - math.lgamma(b)
        + a * math.log(x)
        + b * math.log1p(-x)
    )
    prefix = math.exp(log_prefix)
    if x < (a + 1.0) / (a + b + 2.0):
        return prefix * _betacf(a, b, x) / a
    return 1.0 - prefix * _betacf(b, a, 1.0 - x) / b


def _invert_betainc(a: float, b: float, target: float) -> float:
    """Solve ``I_x(a, b) = target`` for x by bisection."""

    low, high = 0.0, 1.0
    for _ in range(200):
        mid = (low + high) / 2
        if betainc(a, b, mid) < target:
            low = mid
        else:
            high = mid
    return (low + high) / 2


def clopper_pearson(successes: int, total: int, *, alpha: float = 0.05) -> dict[str, Any]:
    """Exact (Clopper-Pearson) binomial confidence interval."""

    if total <= 0:
        return {"point": None, "low": None, "high": None, "n": 0, "method": "clopper_pearson"}
    if successes < 0 or successes > total:
        raise ValueError("successes must lie in [0, total]")
    low = 0.0 if successes == 0 else _invert_betainc(successes, total - successes + 1, alpha / 2)
    high = 1.0 if successes == total else _invert_betainc(successes + 1, total - successes, 1 - alpha / 2)
    return {
        "point": round(successes / total, 4),
        "low": round(low, 4),
        "high": round(high, 4),
        "n": total,
        "successes": successes,
        "alpha": alpha,
        "method": "clopper_pearson",
    }


def wilson_interval(successes: int, total: int, *, z: float = 1.959963985) -> dict[str, Any] | None:
    """Wilson score interval (better small-sample behaviour than normal approx)."""

    if total <= 0:
        return None
    phat = successes / total
    denominator = 1 + z * z / total
    centre = (phat + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(phat * (1 - phat) / total + z * z / (4 * total * total)) / denominator
    return {
        "point": round(phat, 4),
        "low": round(max(0.0, centre - margin), 4),
        "high": round(min(1.0, centre + margin), 4),
        "n": total,
        "successes": successes,
        "method": "wilson",
    }


# ---------------------------------------------------------------------------
# Exact paired tests at the group level
# ---------------------------------------------------------------------------


def exact_binomial_two_sided(successes: int, total: int, *, p: float = 0.5) -> float:
    """Two-sided exact binomial p-value (used for sign / McNemar tests)."""

    if total == 0:
        return 1.0

    def pmf(k: int) -> float:
        return math.comb(total, k) * (p**k) * ((1 - p) ** (total - k))

    observed = pmf(successes)
    tolerance = observed * (1 + 1e-9)
    return min(1.0, sum(pmf(k) for k in range(total + 1) if pmf(k) <= tolerance))


def group_sign_test(wins: int, losses: int) -> dict[str, Any]:
    """Exact sign test over discordant *groups* (ties excluded)."""

    discordant = wins + losses
    if not discordant:
        p_value = 1.0
    else:
        p_value = exact_binomial_two_sided(wins, discordant)
    return {
        "wins": wins,
        "losses": losses,
        "discordant_groups": discordant,
        # Never round a small p-value down to 0.0: report it in a form that
        # stays truthful about the magnitude.
        "two_sided_p_value": float(f"{p_value:.3g}"),
        "two_sided_p_value_display": f"{p_value:.3g}" if p_value >= 1e-300 else "<1e-300",
        "test": "exact_sign_test_over_pair_groups",
        "unit": "pair_key group",
    }


# ---------------------------------------------------------------------------
# Clustered bootstrap
# ---------------------------------------------------------------------------


def _percentile(values: Sequence[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = (len(ordered) - 1) * q
    low = math.floor(index)
    high = math.ceil(index)
    if low == high:
        return ordered[low]
    weight = index - low
    return ordered[low] * (1 - weight) + ordered[high] * weight


def cluster_bootstrap(
    groups: Sequence[Any],
    statistic: Callable[[Sequence[Any]], float],
    *,
    iterations: int = 10000,
    seed: int = 20260727,
    alpha: float = 0.05,
) -> dict[str, Any]:
    """Bootstrap a statistic by resampling whole groups with replacement.

    ``groups`` is the list of independent units (one entry per ``pair_key``).
    ``statistic`` receives a resampled list of groups and returns a scalar.
    """

    if not groups:
        raise ValueError("cluster_bootstrap requires at least one group")
    rng = random.Random(seed)
    point = statistic(groups)
    samples: list[float] = []
    count = len(groups)
    for _ in range(iterations):
        resampled = [groups[rng.randrange(count)] for _ in range(count)]
        samples.append(statistic(resampled))
    return {
        "point": round(point, 4),
        "ci95_low": round(_percentile(samples, alpha / 2), 4),
        "ci95_high": round(_percentile(samples, 1 - alpha / 2), 4),
        "iterations": iterations,
        "seed": seed,
        "independent_units": count,
        "unit": "pair_key group",
        "method": "cluster_bootstrap_over_pair_groups",
    }


def paired_cluster_bootstrap_diff(
    groups: Sequence[Any],
    statistic_a: Callable[[Sequence[Any]], float],
    statistic_b: Callable[[Sequence[Any]], float],
    *,
    iterations: int = 10000,
    seed: int = 20260727,
    alpha: float = 0.05,
) -> dict[str, Any]:
    """Clustered CI for ``statistic_b - statistic_a`` on the *same* groups."""

    def difference(sample: Sequence[Any]) -> float:
        return statistic_b(sample) - statistic_a(sample)

    result = cluster_bootstrap(groups, difference, iterations=iterations, seed=seed, alpha=alpha)
    result["baseline_point"] = round(statistic_a(groups), 4)
    result["system_point"] = round(statistic_b(groups), 4)
    result["method"] = "paired_cluster_bootstrap_over_pair_groups"
    return result


def group_rows_by_pair(rows: Iterable[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Group evaluation rows into independent units keyed by ``pair_key``."""

    buckets: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        key = str(row.get("pair_key") or row.get("id"))
        buckets.setdefault(key, []).append(row)
    return list(buckets.values())
