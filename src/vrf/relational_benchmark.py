from __future__ import annotations

import difflib
import hashlib
import random
import re
from dataclasses import asdict, dataclass
from typing import Any, Callable, Iterable


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
    token_accounting: dict[str, Any]

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


def build_canonical_pair(pair_key: str, rows: list[dict[str, Any]], *, dataset: str) -> CanonicalPair:
    if len(rows) != 2:
        raise ValueError("canonical pair requires exactly two rows")
    if {bool(row.get("has_vulnerability")) for row in rows} != {False, True}:
        raise ValueError("canonical pair requires one vulnerable and one secure side")
    ordered = sorted(rows, key=lambda row: str(row["id"]))
    if stable_int(pair_key) % 2:
        ordered.reverse()
    first = ordered[0]
    return CanonicalPair(
        dataset=dataset,
        pair_key=pair_key,
        project=str(first.get("project") or "unknown"),
        language=normalize_language(first),
        cwe=str(first.get("cwe") or first.get("vulnerability_type") or "unknown").lower(),
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


def unified_diff(pair: CanonicalPair) -> str:
    return "".join(
        difflib.unified_diff(
            pair.side_a.code.splitlines(keepends=True),
            pair.side_b.code.splitlines(keepends=True),
            fromfile="Side A",
            tofile="Side B",
            lineterm="\n",
        )
    ).rstrip()


def render_pair(pair: CanonicalPair, *, include_metadata: bool = True, prefix: str = "") -> str:
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
        f"{unified_diff(pair)}\n"
    )


def changed_line_contents(text: str) -> list[str]:
    return [
        line[1:].strip()
        for line in text.splitlines()
        if line.startswith(("+", "-"))
        and not line.startswith(("+++", "---"))
        and line[1:].strip()
    ]


def changed_lines_raw(text: str) -> list[str]:
    return [
        line
        for line in text.splitlines()
        if line.startswith(("+", "-"))
        and not line.startswith(("+++", "---"))
        and line[1:].strip()
    ]


def contains_subsequence(values: list[int], target: list[int]) -> bool:
    if not target:
        return True
    return any(values[index : index + len(target)] == target for index in range(len(values) - len(target) + 1))


def token_accounting(
    original_text: str,
    transformed_text: str,
    *,
    encode: Callable[[str], list[int]],
    max_length: int,
) -> dict[str, Any]:
    original_ids = encode(original_text)
    transformed_ids = encode(transformed_text)
    retained = transformed_ids[:max_length]
    truncate_text = getattr(encode, "truncate_text", None)
    original_critical_lines = changed_lines_raw(original_text)
    original_retained = original_ids[:max_length]
    if truncate_text:
        original_visible = normalize_for_retention_check(truncate_text(original_text, max_length))
        original_retained_count = sum(
            normalize_for_retention_check(line) in original_visible
            for line in original_critical_lines
        )
    else:
        original_retained_count = sum(
            contains_subsequence(original_retained, encode(line))
            for line in original_critical_lines
        )
    critical_lines = changed_lines_raw(transformed_text)
    if truncate_text:
        transformed_visible = normalize_for_retention_check(truncate_text(transformed_text, max_length))
        retained_count = sum(
            normalize_for_retention_check(line) in transformed_visible
            for line in critical_lines
        )
    else:
        retained_count = sum(contains_subsequence(retained, encode(line)) for line in critical_lines)
    original_truncated = original_retained_count < len(original_critical_lines)
    transformed_truncated = retained_count < len(critical_lines)
    return {
        "original_token_count": len(original_ids),
        "transformed_token_count": len(transformed_ids),
        "token_delta": len(transformed_ids) - len(original_ids),
        "max_length": max_length,
        "truncated_tokens": max(0, len(transformed_ids) - max_length),
        "critical_changed_lines": len(critical_lines),
        "critical_changed_lines_retained": retained_count,
        "base_critical_hunk_truncated": original_truncated,
        "critical_hunk_truncated": transformed_truncated,
        "transformation_introduced_critical_truncation": transformed_truncated and not original_truncated,
    }


def normalize_for_retention_check(text: str) -> str:
    return " ".join(text.split())


def neutral_padding(lines: int, *, template: str) -> str:
    if template == "numbered_comments":
        return "\n".join(f"// non-security context line {index + 1}" for index in range(lines)) + "\n\n"
    if template == "blank_comment_block":
        return "/*\n" + "\n".join(" * neutral context" for _ in range(lines)) + "\n */\n\n"
    raise ValueError(f"unsupported padding template: {template}")


def build_interventions(
    pair: CanonicalPair,
    *,
    encode: Callable[[str], list[int]],
    max_length: int,
) -> list[InterventionResult]:
    base_text = render_pair(pair)
    padding = neutral_padding(12, template="numbered_comments")
    before_diff = render_pair(pair, prefix=f"Non-security context:\n{padding}")
    end_padding = f"{base_text.rstrip()}\n\nNon-security context:\n{padding}"
    results = [
        InterventionResult(
            text=render_pair(pair, include_metadata=False),
            family="metadata",
            template="metadata_removed_v1",
            expected_relation="invariant",
            validation_tier=1,
            validation={
                "structural_valid": True,
                "semantic_basis": "metadata-only removal; code and diff unchanged",
            },
            changed_regions=["metadata"],
            token_accounting={},
        ),
        InterventionResult(
            text=end_padding,
            family="padding",
            template="length_only_end_numbered_comments_v1",
            expected_relation="invariant",
            validation_tier=1,
            validation={
                "structural_valid": True,
                "semantic_basis": "neutral text appended after the complete diff",
            },
            changed_regions=["prompt_suffix"],
            token_accounting={},
        ),
        InterventionResult(
            text=before_diff,
            family="padding",
            template="position_before_diff_numbered_comments_v1",
            expected_relation="invariant",
            validation_tier=1,
            validation={
                "structural_valid": True,
                "semantic_basis": "neutral text inserted before the unchanged diff",
            },
            changed_regions=["pre_diff_context"],
            token_accounting={},
        ),
        InterventionResult(
            text=render_pair(swap_pair(pair)),
            family="side_order",
            template="canonical_renderer_swap_v1",
            expected_relation="equivariant_swap",
            validation_tier=1,
            validation={
                "structural_valid": True,
                "semantic_basis": "same canonical pair rendered with A/B order reversed",
            },
            changed_regions=["side_order", "diff_direction"],
            token_accounting={},
        ),
    ]
    base_tokens = max(1, len(encode(base_text)))
    for ratio in (0.25, 0.50, 0.75):
        target_lines = max(1, round(base_tokens * ratio / 6))
        pressure = neutral_padding(target_lines, template="blank_comment_block")
        results.append(
            InterventionResult(
                text=render_pair(pair, prefix=f"Additional context-pressure block:\n{pressure}"),
                family="context_pressure",
                template=f"budget_{int(ratio * 100)}pct_before_diff_v1",
                expected_relation="context_pressure",
                validation_tier=1,
                validation={
                    "structural_valid": True,
                    "semantic_basis": "controlled token-budget pressure before unchanged diff",
                    "target_budget_ratio": ratio,
                },
                changed_regions=["pre_diff_context"],
                token_accounting={},
            )
        )
    return [
        InterventionResult(
            **{
                **asdict(result),
                "token_accounting": token_accounting(
                    base_text,
                    result.text,
                    encode=encode,
                    max_length=max_length,
                ),
            }
        )
        for result in results
    ]


def pair_metadata(pair: CanonicalPair, *, encode: Callable[[str], list[int]]) -> dict[str, Any]:
    diff = unified_diff(pair)
    changed_lines = len(changed_line_contents(diff))
    token_count = len(encode(render_pair(pair)))
    return {
        "dataset": pair.dataset,
        "pair_key": pair.pair_key,
        "project": pair.project,
        "language": pair.language,
        "cwe": pair.cwe,
        "cve": pair.cve,
        "year": pair.year,
        "changed_lines": changed_lines,
        "diff_bucket": diff_bucket(changed_lines),
        "token_count": token_count,
        "token_bucket": token_bucket(token_count),
        "gold_riskier_side": pair.gold_riskier_side,
    }


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


def token_bucket(token_count: int) -> str:
    if token_count <= 256:
        return "<=256"
    if token_count <= 512:
        return "257-512"
    if token_count <= 1024:
        return "513-1024"
    return "1025+"


def sample_pairs(
    pairs: list[CanonicalPair],
    *,
    limit: int,
    seed: int,
    mode: str,
    encode: Callable[[str], list[int]],
    stratify_by: Iterable[str],
) -> list[CanonicalPair]:
    if limit >= len(pairs):
        return sorted(pairs, key=lambda pair: pair.pair_key)
    metadata = {pair.pair_key: pair_metadata(pair, encode=encode) for pair in pairs}
    rng = random.Random(seed)
    if mode == "representative":
        selected = list(pairs)
        rng.shuffle(selected)
        return selected[:limit]
    if mode == "stress":
        ordered = sorted(
            pairs,
            key=lambda pair: (
                metadata[pair.pair_key]["token_count"],
                metadata[pair.pair_key]["changed_lines"],
                pair.pair_key,
            ),
        )
        selected = []
        left, right = 0, len(ordered) - 1
        while len(selected) < limit:
            selected.append(ordered[right])
            right -= 1
            if len(selected) < limit:
                selected.append(ordered[left])
                left += 1
        return selected
    if mode != "balanced":
        raise ValueError(f"unsupported sampling mode: {mode}")

    fields = list(stratify_by)
    strata: dict[tuple[str, ...], list[CanonicalPair]] = {}
    for pair in pairs:
        row = metadata[pair.pair_key]
        key = tuple(str(row.get(field, "unknown")) for field in fields)
        strata.setdefault(key, []).append(pair)
    for key in sorted(strata):
        values = strata[key]
        values.sort(key=lambda pair: pair.pair_key)
        rng.shuffle(values)
    keys = sorted(strata)
    rng.shuffle(keys)
    selected = []
    while len(selected) < limit and keys:
        next_keys = []
        for key in keys:
            if strata[key]:
                selected.append(strata[key].pop())
                if len(selected) >= limit:
                    break
            if strata[key]:
                next_keys.append(key)
        keys = next_keys
    return selected
