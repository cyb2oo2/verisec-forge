from __future__ import annotations

import difflib
import hashlib
import math
import random
import re
from collections import Counter
from dataclasses import asdict, dataclass
from typing import Any, Iterable

from vrf.polarity_control import diff_line_counts


@dataclass(frozen=True)
class CanonicalSide:
    id: str
    code: str
    vulnerable: bool


@dataclass(frozen=True)
class CanonicalPair:
    dataset: str
    pair_key: str
    project: str
    language: str
    cwe: str
    cve: str
    year: int | None
    side_a: CanonicalSide
    side_b: CanonicalSide

    @property
    def gold_riskier_side(self) -> str:
        return "A" if self.side_a.vulnerable else "B"


@dataclass(frozen=True)
class InterventionResult:
    text: str
    family: str
    template: str
    expected_relation: str
    validation_tier: int
    validation: dict[str, Any]
    changed_regions: list[str]
    runtime_transform: dict[str, Any]
    structural_accounting: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def stable_int(value: str) -> int:
    return int(hashlib.sha256(value.encode("utf-8")).hexdigest()[:16], 16)


def normalize_language(row: dict[str, Any]) -> str:
    value = str(
        row.get("programming_language")
        or row.get("language")
        or row.get("file_extension")
        or "unknown"
    ).lower()
    aliases = {
        "c": "c",
        "cc": "cpp",
        "cpp": "cpp",
        "cxx": "cpp",
        "py": "python",
        "js": "javascript",
    }
    return aliases.get(value, value)


def extract_year(row: dict[str, Any]) -> int | None:
    for key in ("cve", "vulnerability_id", "published_date", "commit_datetime"):
        match = re.search(r"(?:19|20)\d{2}", str(row.get(key) or ""))
        if match:
            return int(match.group(0))
    return None


def build_canonical_pair(
    pair_key: str, rows: list[dict[str, Any]], *, dataset: str
) -> CanonicalPair:
    if len(rows) != 2:
        raise ValueError("canonical pair requires exactly two rows")
    if {bool(row.get("has_vulnerability")) for row in rows} != {False, True}:
        raise ValueError("canonical pair requires one vulnerable and one secure side")
    ordered = sorted(rows, key=lambda row: str(row["id"]))
    if stable_int(f"{dataset}::{pair_key}") % 2:
        ordered.reverse()
    first = ordered[0]
    return CanonicalPair(
        dataset=dataset,
        pair_key=pair_key,
        project=str(first.get("project") or "unknown"),
        language=normalize_language(first),
        cwe=str(
            first.get("cwe") or first.get("vulnerability_type") or "unknown"
        ).lower(),
        cve=str(first.get("cve") or first.get("vulnerability_id") or "unknown"),
        year=extract_year(first),
        side_a=CanonicalSide(
            id=str(ordered[0]["id"]),
            code=str(ordered[0].get("code") or ""),
            vulnerable=bool(ordered[0].get("has_vulnerability")),
        ),
        side_b=CanonicalSide(
            id=str(ordered[1]["id"]),
            code=str(ordered[1].get("code") or ""),
            vulnerable=bool(ordered[1].get("has_vulnerability")),
        ),
    )


def swap_pair(pair: CanonicalPair) -> CanonicalPair:
    return CanonicalPair(
        dataset=pair.dataset,
        pair_key=pair.pair_key,
        project=pair.project,
        language=pair.language,
        cwe=pair.cwe,
        cve=pair.cve,
        year=pair.year,
        side_a=pair.side_b,
        side_b=pair.side_a,
    )


DEFAULT_CONTEXT_LINES = 3
"""``difflib.unified_diff`` default. Every v2-v4 artifact was built with this."""


def unified_diff(pair: CanonicalPair, *, context_lines: int = DEFAULT_CONTEXT_LINES) -> str:
    return "".join(
        difflib.unified_diff(
            pair.side_a.code.splitlines(keepends=True),
            pair.side_b.code.splitlines(keepends=True),
            fromfile="Side A",
            tofile="Side B",
            lineterm="\n",
            n=context_lines,
        )
    ).rstrip()


def render_pair(
    pair: CanonicalPair,
    *,
    include_metadata: bool = True,
    prefix: str = "",
    context_lines: int = DEFAULT_CONTEXT_LINES,
) -> str:
    metadata = ""
    if include_metadata:
        metadata = (
            f"Dataset: {pair.dataset}\n"
            f"Project: {pair.project}\n"
            f"CVE: {pair.cve}\n"
            f"CWE: {pair.cwe}\n"
            f"Language: {pair.language}\n\n"
        )
    return (
        "Task: compare two related code states and choose the riskier side.\n"
        "Output one label: A_RISKIER, B_RISKIER, or INSUFFICIENT_CONTEXT.\n\n"
        f"{metadata}"
        f"{prefix}"
        "Unified diff from Side A to Side B:\n"
        f"{unified_diff(pair, context_lines=context_lines)}\n"
    )


def is_line_structured(code: str, *, min_chars: int = 120) -> bool:
    """Does this record carry real line boundaries?

    Sources that flatten a whole function onto one line produce unified diffs in
    which the added body is concatenated onto the removed line, destroying all
    line-level polarity structure. ``swap_mirror_is_exact`` rejects the result,
    but this predicate names the *cause* so ingestion can be fixed rather than
    the pair silently dropped. Short records are exempt: a genuinely one-line
    function is fine.
    """

    text = str(code or "")
    return len(text) < min_chars or len(text.splitlines()) > 1


def swap_mirror_is_exact(pair: CanonicalPair) -> bool:
    """Does the side swap produce an exact structural mirror of the rendering?

    A side-swap evaluation is only meaningful when swapping the two sides
    genuinely reverses the rendered diff: what was removed must become added and
    vice versa. Sources that store a whole function on one line with no trailing
    newline break this -- ``difflib.unified_diff`` then emits the added body on
    the same physical line as the removed body, so the row carries no line-level
    polarity structure and *nothing flips under the swap*. Such a pair cannot
    support side-swap equivariance, both-directions-correct, or robust accuracy,
    and admitting it silently contaminates all three.

    See ``reports/VERIPATCH_RR_STRUCTURAL_CONTROL.md``.
    """

    forward = diff_line_counts(render_pair(pair))
    reverse = diff_line_counts(render_pair(swap_pair(pair)))
    return (
        forward["added"] == reverse["removed"]
        and forward["removed"] == reverse["added"]
        and forward["added_chars"] == reverse["removed_chars"]
        and forward["removed_chars"] == reverse["added_chars"]
    )


def changed_line_occurrences(text: str) -> list[dict[str, Any]]:
    occurrences = []
    cursor = 0
    for line_index, line_with_end in enumerate(text.splitlines(keepends=True)):
        line = line_with_end.rstrip("\r\n")
        if (
            line.startswith(("+", "-"))
            and not line.startswith(("+++", "---"))
            and line[1:].strip()
        ):
            occurrences.append(
                {
                    "occurrence": len(occurrences),
                    "line_index": line_index,
                    "text": line,
                    "char_start": cursor,
                    "char_end": cursor + len(line),
                }
            )
        cursor += len(line_with_end)
    return occurrences


def changed_line_contents(text: str) -> list[str]:
    return [row["text"][1:].strip() for row in changed_line_occurrences(text)]


def structural_accounting(text: str) -> dict[str, Any]:
    occurrences = changed_line_occurrences(text)
    return {
        "character_count": len(text),
        "line_count": len(text.splitlines()),
        "critical_changed_lines": len(occurrences),
        "critical_line_occurrences": occurrences,
    }


def neutral_padding(lines: int, *, template: str) -> str:
    if template == "numbered_comments":
        return (
            "\n".join(
                f"// non-security context line {index + 1}" for index in range(lines)
            )
            + "\n\n"
        )
    if template == "blank_comment_block":
        return (
            "/*\n"
            + "\n".join(
                f" * neutral context line {index + 1}" for index in range(lines)
            )
            + "\n */\n\n"
        )
    raise ValueError(f"unsupported padding template: {template}")


def insert_before_diff(base_text: str, content: str) -> str:
    marker = "Unified diff from Side A to Side B:\n"
    if marker not in base_text:
        raise ValueError("canonical diff marker missing")
    return base_text.replace(marker, f"{content}{marker}", 1)


def build_interventions(pair: CanonicalPair) -> list[InterventionResult]:
    base_text = render_pair(pair)
    padding = neutral_padding(12, template="numbered_comments")
    before_diff = insert_before_diff(
        base_text, f"Non-security context:\n{padding}"
    )
    end_padding = f"{base_text.rstrip()}\n\nNon-security context:\n{padding}"
    results = [
        InterventionResult(
            text=render_pair(pair, include_metadata=False),
            family="metadata",
            template="metadata_removed_v2",
            expected_relation="invariant",
            validation_tier=1,
            validation={
                "structural_valid": True,
                "semantic_basis": "metadata-only removal; code and diff unchanged",
            },
            changed_regions=["metadata"],
            runtime_transform={},
            structural_accounting={},
        ),
        InterventionResult(
            text=end_padding,
            family="padding",
            template="length_only_end_numbered_comments_v2",
            expected_relation="invariant",
            validation_tier=1,
            validation={
                "structural_valid": True,
                "semantic_basis": "neutral text appended after the complete diff",
            },
            changed_regions=["prompt_suffix"],
            runtime_transform={},
            structural_accounting={},
        ),
        InterventionResult(
            text=before_diff,
            family="padding",
            template="position_before_diff_numbered_comments_v2",
            expected_relation="invariant",
            validation_tier=1,
            validation={
                "structural_valid": True,
                "semantic_basis": "neutral text inserted before the unchanged diff",
            },
            changed_regions=["pre_diff_context"],
            runtime_transform={},
            structural_accounting={},
        ),
        InterventionResult(
            text=render_pair(swap_pair(pair)),
            family="side_order",
            template="canonical_renderer_swap_v2",
            expected_relation="equivariant_swap",
            validation_tier=1,
            validation={
                "structural_valid": True,
                "semantic_basis": "same canonical pair rendered with A/B order reversed",
            },
            changed_regions=["side_order", "diff_direction"],
            runtime_transform={},
            structural_accounting={},
        ),
    ]
    for ratio in (0.25, 0.50, 0.75):
        results.append(
            InterventionResult(
                text=base_text,
                family="context_pressure",
                template=f"budget_{int(ratio * 100)}pct_before_diff_v2",
                expected_relation="context_pressure",
                validation_tier=1,
                validation={
                    "structural_valid": True,
                    "semantic_basis": (
                        "runtime tokenizer generates controlled token-budget "
                        "pressure before the unchanged diff"
                    ),
                    "target_budget_ratio": ratio,
                },
                changed_regions=["pre_diff_context"],
                runtime_transform={
                    "operation": "insert_token_budget_padding_before_diff",
                    "target_budget_ratio": ratio,
                    "padding_template": "blank_comment_block",
                },
                structural_accounting={},
            )
        )
    return [
        InterventionResult(
            **{
                **asdict(result),
                "structural_accounting": structural_accounting(result.text),
            }
        )
        for result in results
    ]


def char_bucket(character_count: int) -> str:
    if character_count <= 1000:
        return "<=1k"
    if character_count <= 4000:
        return "1k-4k"
    if character_count <= 16000:
        return "4k-16k"
    return "16k+"


def diff_bucket(changed_lines: int) -> str:
    if changed_lines <= 2:
        return "00-02"
    if changed_lines <= 5:
        return "03-05"
    if changed_lines <= 10:
        return "06-10"
    if changed_lines <= 25:
        return "11-25"
    return "26+"


def pair_metadata(pair: CanonicalPair) -> dict[str, Any]:
    diff = unified_diff(pair)
    changed_lines = len(changed_line_contents(diff))
    character_count = len(render_pair(pair))
    return {
        "dataset": pair.dataset,
        "pair_key": pair.pair_key,
        "cluster_id": f"{pair.dataset}::{pair.pair_key}",
        "project": pair.project,
        "language": pair.language,
        "cwe": pair.cwe,
        "cve": pair.cve,
        "year": pair.year,
        "changed_lines": changed_lines,
        "diff_bucket": diff_bucket(changed_lines),
        "character_count": character_count,
        "character_bucket": char_bucket(character_count),
        "gold_riskier_side": pair.gold_riskier_side,
    }


def _effective_categories(values: Iterable[str]) -> float:
    counts = Counter(values)
    total = sum(counts.values())
    if not total:
        return 0.0
    return 1.0 / sum((count / total) ** 2 for count in counts.values())


def sampling_diagnostics(
    selected: list[CanonicalPair],
    *,
    suite: str,
    target_diff_buckets: list[str] | None = None,
    target_character_buckets: list[str] | None = None,
) -> dict[str, Any]:
    metadata = [pair_metadata(pair) for pair in selected]
    projects = Counter(row["project"] for row in metadata)
    cwes = Counter(row["cwe"] for row in metadata)
    achieved_diff = Counter(row["diff_bucket"] for row in metadata)
    achieved_char = Counter(row["character_bucket"] for row in metadata)
    total = max(1, len(metadata))
    return {
        "suite": suite,
        "pairs": len(metadata),
        "target_marginals": {
            "diff_bucket": target_diff_buckets or "source_distribution",
            "character_bucket": target_character_buckets or "source_distribution",
        },
        "achieved_marginals": {
            "diff_bucket": dict(achieved_diff),
            "character_bucket": dict(achieved_char),
            "language": dict(Counter(row["language"] for row in metadata)),
        },
        "unavailable_target_buckets": {
            "diff_bucket": [
                bucket
                for bucket in target_diff_buckets or []
                if achieved_diff[bucket] == 0
            ],
            "character_bucket": [
                bucket
                for bucket in target_character_buckets or []
                if achieved_char[bucket] == 0
            ],
        },
        "maximum_project_concentration": max(projects.values(), default=0) / total,
        "maximum_cwe_concentration": max(cwes.values(), default=0) / total,
        "effective_projects": _effective_categories(projects.elements()),
        "effective_cwes": _effective_categories(cwes.elements()),
    }


def sample_representative(
    pairs: list[CanonicalPair], *, limit: int, seed: int
) -> list[CanonicalPair]:
    values = sorted(pairs, key=lambda pair: pair.pair_key)
    random.Random(seed).shuffle(values)
    return values[:limit]


def sample_balanced_stress(
    pairs: list[CanonicalPair],
    *,
    limit: int,
    seed: int,
    project_cap: int | None = None,
    cwe_cap: int | None = None,
) -> list[CanonicalPair]:
    if limit >= len(pairs):
        return sorted(pairs, key=lambda pair: pair.pair_key)
    metadata = {pair.pair_key: pair_metadata(pair) for pair in pairs}
    diff_values = ["00-02", "03-05", "06-10", "11-25", "26+"]
    char_values = ["<=1k", "1k-4k", "4k-16k", "16k+"]
    target_diff = math.ceil(limit / len(diff_values))
    target_char = math.ceil(limit / len(char_values))
    project_cap = project_cap or max(2, math.ceil(limit * 0.05))
    cwe_cap = cwe_cap or max(2, math.ceil(limit * 0.10))
    rng = random.Random(seed)
    candidates = sorted(pairs, key=lambda pair: pair.pair_key)
    rng.shuffle(candidates)
    selected = []
    diff_counts: Counter[str] = Counter()
    char_counts: Counter[str] = Counter()
    project_counts: Counter[str] = Counter()
    cwe_counts: Counter[str] = Counter()

    while candidates and len(selected) < limit:
        best_index = None
        best_score = None
        for index, pair in enumerate(candidates):
            row = metadata[pair.pair_key]
            if project_counts[row["project"]] >= project_cap:
                continue
            if cwe_counts[row["cwe"]] >= cwe_cap:
                continue
            diff_deficit = max(0, target_diff - diff_counts[row["diff_bucket"]])
            char_deficit = max(
                0, target_char - char_counts[row["character_bucket"]]
            )
            score = (
                diff_deficit + char_deficit,
                -project_counts[row["project"]],
                -cwe_counts[row["cwe"]],
                stable_int(f"{seed}::{pair.dataset}::{pair.pair_key}"),
            )
            if best_score is None or score > best_score:
                best_index = index
                best_score = score
        if best_index is None:
            project_cap += 1
            cwe_cap += 1
            continue
        pair = candidates.pop(best_index)
        row = metadata[pair.pair_key]
        selected.append(pair)
        diff_counts[row["diff_bucket"]] += 1
        char_counts[row["character_bucket"]] += 1
        project_counts[row["project"]] += 1
        cwe_counts[row["cwe"]] += 1
    return selected


def sample_pairs(
    pairs: list[CanonicalPair],
    *,
    limit: int,
    seed: int,
    mode: str,
    encode: Any = None,
    stratify_by: Iterable[str] = (),
) -> list[CanonicalPair]:
    del encode, stratify_by
    if mode == "representative":
        return sample_representative(pairs, limit=limit, seed=seed)
    if mode in {"balanced", "balanced_stress", "stress"}:
        return sample_balanced_stress(pairs, limit=limit, seed=seed)
    raise ValueError(f"unsupported sampling mode: {mode}")
