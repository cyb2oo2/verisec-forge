"""Cheap, semantics-free surface features of a rendered pair.

Everything here is a count or a set-overlap over the *shape* of the
unified diff: polarity glyphs, character / line / token mass, and the
suite's own buckets. Nothing reads identifier names or patch meaning.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

from vrf.pair_decision import mean
from vrf.polarity_control import diff_line_counts

_ROUND = 4


def _round(value: float | None, digits: int = _ROUND) -> float | None:
    return None if value is None else round(float(value), digits)


def _tokens(body: str) -> list[str]:
    return [part for part in body.split() if part]


def pair_surface_features(
    pair: Mapping[str, Any],
    glyph_canonical_text: str,
) -> dict[str, Any]:
    """Surface vector for one pair, always from the glyph canonical rendering."""

    counts = diff_line_counts(glyph_canonical_text)
    added_tokens: list[str] = []
    removed_tokens: list[str] = []
    plus_lines = 0
    minus_lines = 0
    for line in glyph_canonical_text.split("\n"):
        if line.startswith("+++") or line.startswith("---"):
            continue
        if line.startswith("+"):
            plus_lines += 1
            added_tokens.extend(_tokens(line[1:]))
        elif line.startswith("-"):
            minus_lines += 1
            removed_tokens.extend(_tokens(line[1:]))

    added_set = set(added_tokens)
    removed_set = set(removed_tokens)
    union = added_set | removed_set
    inter = added_set & removed_set
    jaccard = (len(inter) / len(union)) if union else None
    only_added = len(added_set - removed_set)
    only_removed = len(removed_set - added_set)

    return {
        "pair_key": pair.get("pair_key"),
        "dataset": pair.get("dataset"),
        "gold": pair.get("gold"),
        "net": int(pair.get("net") or counts["char_net"]),
        "net_sign": pair.get("net_sign"),
        "cell": pair.get("cell"),
        "balanced": bool(pair.get("balanced")),
        "char_net": int(counts["char_net"]),
        "abs_char_net": abs(int(counts["char_net"])),
        "char_total": int(counts["char_total"]),
        "added_chars": int(counts["added_chars"]),
        "removed_chars": int(counts["removed_chars"]),
        "line_net": int(counts["net"]),
        "abs_line_net": abs(int(counts["net"])),
        "line_total": int(counts["total"]),
        "added_lines": int(counts["added"]),
        "removed_lines": int(counts["removed"]),
        "indent_net": int(counts["indent_net"]),
        "plus_lines": plus_lines,
        "minus_lines": minus_lines,
        "glyph_imbalance": abs(plus_lines - minus_lines),
        "added_token_count": len(added_tokens),
        "removed_token_count": len(removed_tokens),
        "token_net": len(added_tokens) - len(removed_tokens),
        "abs_token_net": abs(len(added_tokens) - len(removed_tokens)),
        "token_jaccard": _round(jaccard),
        "tokens_only_added": only_added,
        "tokens_only_removed": only_removed,
        "control_label": pair.get("control_label"),
    }


def summarise_feature_group(
    features: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Means and polarity mix for a frozen / unfrozen partition."""

    if not features:
        return {"n_pairs": 0}

    def col(name: str) -> list[float]:
        return [float(row[name]) for row in features if row.get(name) is not None]

    n = len(features)
    plus = sum(1 for row in features if row.get("net_sign") == "+")
    minus = n - plus
    concordant = sum(1 for row in features if row.get("cell") == "concordant")
    datasets: dict[str, int] = {}
    for row in features:
        key = str(row.get("dataset") or "unknown")
        datasets[key] = datasets.get(key, 0) + 1

    return {
        "n_pairs": n,
        "n_net_plus": plus,
        "n_net_minus": minus,
        "net_plus_fraction": _round(plus / n),
        "n_concordant": concordant,
        "n_discordant": n - concordant,
        "concordant_fraction": _round(concordant / n),
        "mean_abs_char_net": _round(mean(col("abs_char_net"))),
        "mean_char_net": _round(mean(col("char_net"))),
        "mean_char_total": _round(mean(col("char_total"))),
        "mean_abs_line_net": _round(mean(col("abs_line_net"))),
        "mean_line_total": _round(mean(col("line_total"))),
        "mean_glyph_imbalance": _round(mean(col("glyph_imbalance"))),
        "mean_abs_token_net": _round(mean(col("abs_token_net"))),
        "mean_token_jaccard": _round(mean(col("token_jaccard"))),
        "mean_tokens_only_added": _round(mean(col("tokens_only_added"))),
        "mean_tokens_only_removed": _round(mean(col("tokens_only_removed"))),
        "datasets": datasets,
    }


def compare_groups(
    frozen: Sequence[Mapping[str, Any]],
    unfrozen: Sequence[Mapping[str, Any]],
    keys: Iterable[str],
) -> dict[str, Any]:
    """Frozen minus unfrozen means for the listed numeric columns."""

    def avg(rows: Sequence[Mapping[str, Any]], key: str) -> float | None:
        return mean(
            [float(row[key]) for row in rows if row.get(key) is not None]
        )

    out: dict[str, Any] = {}
    for key in keys:
        frozen_mean = avg(frozen, key)
        unfrozen_mean = avg(unfrozen, key)
        delta = (
            None
            if frozen_mean is None or unfrozen_mean is None
            else frozen_mean - unfrozen_mean
        )
        out[key] = {
            "frozen": _round(frozen_mean),
            "unfrozen": _round(unfrozen_mean),
            "frozen_minus_unfrozen": _round(delta),
        }
    return out
