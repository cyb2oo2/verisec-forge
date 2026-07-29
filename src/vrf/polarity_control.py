"""Semantics-free structural controls over rendered unified diffs.

These controls read only the *shape* of a diff -- how many lines were added,
removed, and changed -- and never the tokens inside those lines. They exist so
that any claim about a model "reading secure-patch semantics" can be measured
against a baseline that provably reads no semantics at all.

Every rule here is fit on training/calibration rows only and then applied
unchanged to evaluation rows. Nothing in this module reads an evaluation label.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable, Sequence

DIFF_MARKER = "Unified diff:"


def diff_body(text: str) -> str:
    """Return the diff portion of a rendered ``pair_text`` block."""

    if DIFF_MARKER in text:
        return text.split(DIFF_MARKER, 1)[1]
    return text


def diff_line_counts(text: str) -> dict[str, int]:
    """Count added/removed lines *and characters* in a rendered diff.

    Only line-leading ``+``/``-`` markers are inspected; file headers
    (``+++``/``---``) are excluded. The *content* of each line is never read --
    only how many lines and how many characters were added or removed -- which
    is what makes these controls semantics-free.

    Character counts matter: net character change is a materially stronger
    signal than net line change on this benchmark, because it ties on far fewer
    pairs. Reporting only the line-count rule understates how much of the task
    diff shape alone solves.
    """

    added = removed = 0
    added_chars = removed_chars = 0
    added_indent = removed_indent = 0
    for line in diff_body(text).split("\n"):
        if line.startswith("+") and not line.startswith("+++"):
            added += 1
            added_chars += len(line) - 1
            added_indent += len(line[1:]) - len(line[1:].lstrip())
        elif line.startswith("-") and not line.startswith("---"):
            removed += 1
            removed_chars += len(line) - 1
            removed_indent += len(line[1:]) - len(line[1:].lstrip())
    return {
        "added": added,
        "removed": removed,
        "net": added - removed,
        "total": added + removed,
        "added_chars": added_chars,
        "removed_chars": removed_chars,
        "char_net": added_chars - removed_chars,
        "char_total": added_chars + removed_chars,
        "indent_net": added_indent - removed_indent,
    }


def structural_features(text: str) -> dict[str, int]:
    """Full semantics-free feature vector for one rendered diff."""

    counts = diff_line_counts(text)
    return {
        **counts,
        # sign of the net change; the "diff direction" signal
        "direction": (counts["net"] > 0) - (counts["net"] < 0),
        "char_direction": (counts["char_net"] > 0) - (counts["char_net"] < 0),
    }


def row_text(row: dict[str, Any]) -> str:
    return str(row.get("pair_text") or row.get("prompt") or "")


def row_features(row: dict[str, Any]) -> dict[str, int]:
    return structural_features(row_text(row))


def row_gold(row: dict[str, Any]) -> int:
    if "gold" in row:
        return int(row["gold"])
    return int(bool(row.get("has_vulnerability")))


# --------------------------------------------------------------------------
# Candidate rules
# --------------------------------------------------------------------------


ScoreFn = Callable[[dict[str, int]], float]


@dataclass(frozen=True)
class PolarityRule:
    """A fitted, semantics-free decision rule.

    ``score`` maps structural features to a real number where larger means
    "more likely vulnerable". ``sign`` (+1/-1) and ``threshold`` are fit on
    training data only.
    """

    name: str
    description: str
    score_fn: ScoreFn
    sign: int = 1
    threshold: float = 0.0

    def score(self, features: dict[str, int]) -> float:
        return self.sign * self.score_fn(features)

    def predict(self, features: dict[str, int]) -> int | None:
        """Return 1/0, or ``None`` when the rule abstains (a tie)."""

        value = self.score(features)
        if value > self.threshold:
            return 1
        if value < self.threshold:
            return 0
        return None


CANDIDATE_SCORES: dict[str, tuple[str, ScoreFn]] = {
    "net_polarity": (
        "net added-minus-removed line count",
        lambda f: float(f["net"]),
    ),
    "diff_direction": (
        "sign of the net line change only (loses magnitude)",
        lambda f: float(f["direction"]),
    ),
    "added_lines": (
        "added-line count alone",
        lambda f: float(f["added"]),
    ),
    "removed_lines": (
        "removed-line count alone",
        lambda f: float(f["removed"]),
    ),
    "total_changed_lines": (
        "total changed-line count (size only, no direction)",
        lambda f: float(f["total"]),
    ),
    "char_polarity": (
        "net added-minus-removed CHARACTER count (strongest known semantics-free rule)",
        lambda f: float(f["char_net"]),
    ),
    "char_direction": (
        "sign of the net character change only",
        lambda f: float(f["char_direction"]),
    ),
    "char_net_over_total": (
        "net character change normalised by total character change",
        lambda f: float(f["char_net"]) / float(f["char_total"]) if f["char_total"] else 0.0,
    ),
    "removed_chars": (
        "removed-character count alone",
        lambda f: float(f["removed_chars"]),
    ),
    "total_changed_chars": (
        "total changed-character count (size only, no direction)",
        lambda f: float(f["char_total"]),
    ),
    "indent_polarity": (
        "net added-minus-removed leading-whitespace count (formatting signal only)",
        lambda f: float(f["indent_net"]),
    ),
    "net_over_total": (
        "net change normalised by total change (combination)",
        lambda f: float(f["net"]) / float(f["total"]) if f["total"] else 0.0,
    ),
    "added_minus_two_removed": (
        "asymmetric combination of added and removed counts",
        lambda f: float(f["added"]) - 2.0 * float(f["removed"]),
    ),
}


def _balanced_accuracy(pairs: Sequence[tuple[int, int]]) -> float:
    tp = sum(1 for gold, pred in pairs if gold == 1 and pred == 1)
    fn = sum(1 for gold, pred in pairs if gold == 1 and pred == 0)
    tn = sum(1 for gold, pred in pairs if gold == 0 and pred == 0)
    fp = sum(1 for gold, pred in pairs if gold == 0 and pred == 1)
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    specificity = tn / (tn + fp) if (tn + fp) else 0.0
    return (recall + specificity) / 2


def fit_rule(name: str, train_rows: Iterable[dict[str, Any]]) -> PolarityRule:
    """Fit sign and threshold for one candidate score on training rows only."""

    if name not in CANDIDATE_SCORES:
        raise KeyError(f"unknown polarity rule: {name}")
    description, score_fn = CANDIDATE_SCORES[name]
    observations = [(row_features(row), row_gold(row)) for row in train_rows]
    if not observations:
        raise ValueError(f"cannot fit polarity rule {name!r} on zero training rows")

    raw = sorted({score_fn(features) for features, _ in observations})
    # Candidate thresholds are midpoints between observed score values, so the
    # grid is data-driven rather than hand-picked. Zero is always included
    # because it is the principled predetermined split for a signed polarity
    # score. Continuous features (character counts) can have thousands of
    # distinct values, so the grid is subsampled to keep fitting tractable
    # without changing which threshold family is searched.
    all_midpoints = [(low + high) / 2 for low, high in zip(raw, raw[1:])]
    max_candidates = 256
    if len(all_midpoints) > max_candidates:
        step = len(all_midpoints) / max_candidates
        all_midpoints = [all_midpoints[int(index * step)] for index in range(max_candidates)]
    midpoints = [0.0] + all_midpoints

    best: tuple[float, int, float] | None = None
    for sign in (1, -1):
        for threshold in midpoints:
            scored = []
            for features, gold in observations:
                value = sign * score_fn(features)
                if value > threshold:
                    scored.append((gold, 1))
                elif value < threshold:
                    scored.append((gold, 0))
            if not scored:
                continue
            metric = _balanced_accuracy(scored)
            if best is None or metric > best[0]:
                best = (metric, sign, threshold)

    assert best is not None
    _, sign, threshold = best
    return PolarityRule(
        name=name,
        description=description,
        score_fn=score_fn,
        sign=sign,
        threshold=threshold,
    )


def fit_all_rules(train_rows: Sequence[dict[str, Any]]) -> dict[str, PolarityRule]:
    return {name: fit_rule(name, train_rows) for name in CANDIDATE_SCORES}
