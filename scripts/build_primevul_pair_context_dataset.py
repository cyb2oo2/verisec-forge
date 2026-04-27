from __future__ import annotations

import argparse
import difflib
import json
import random
import re
from collections import defaultdict
from typing import Any

from vrf.io_utils import read_jsonl, write_json, write_jsonl

SECURITY_KEYWORDS = {
    "alloc",
    "bound",
    "check",
    "copy",
    "free",
    "len",
    "length",
    "mem",
    "overflow",
    "sanitize",
    "size",
    "strcat",
    "strcpy",
    "strlen",
    "sprintf",
    "valid",
}


def pair_key(row: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(row.get("project") or "unknown"),
        str(row.get("commit_id") or "unknown"),
        str(row.get("cve") or "unknown"),
    )


def build_pair_diff(candidate: dict[str, Any], counterpart: dict[str, Any]) -> str:
    candidate_code = str(candidate.get("code") or "").splitlines(keepends=True)
    counterpart_code = str(counterpart.get("code") or "").splitlines(keepends=True)
    return "".join(
        difflib.unified_diff(
            counterpart_code,
            candidate_code,
            fromfile="paired_counterpart",
            tofile="candidate",
            lineterm="",
        )
    )


def _split_diff_hunks(pair_diff: str) -> tuple[list[str], list[list[str]]]:
    pair_diff = re.sub(r"(--- paired_counterpart)(\+\+\+ candidate)", r"\1\n\2\n", pair_diff)
    pair_diff = re.sub(r"(\+\+\+ candidate)(@@ )", r"\1\n\2", pair_diff)
    pair_diff = re.sub(r"(?<!\n)(@@ -)", r"\n\1", pair_diff)
    headers: list[str] = []
    hunks: list[list[str]] = []
    current: list[str] = []
    for line in pair_diff.splitlines():
        if line.startswith("@@"):
            if current:
                hunks.append(current)
            current = [line]
        elif current:
            current.append(line)
        else:
            headers.append(line)
    if current:
        hunks.append(current)
    return headers, hunks


def _hunk_score(hunk: list[str]) -> tuple[int, int, int]:
    changed = [line for line in hunk if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))]
    text = "\n".join(changed).lower()
    keyword_hits = sum(1 for keyword in SECURITY_KEYWORDS if keyword in text)
    return (keyword_hits, len(changed), len("\n".join(hunk)))


def localize_pair_diff(pair_diff: str, *, max_chars: int = 3600, max_hunks: int = 6) -> str:
    headers, hunks = _split_diff_hunks(pair_diff)
    if not hunks or len(pair_diff) <= max_chars:
        return pair_diff

    ranked = sorted(enumerate(hunks), key=lambda item: _hunk_score(item[1]), reverse=True)
    selected_indexes = [index for index, _hunk in ranked[:max_hunks]]
    selected_hunks: list[list[str]] = []
    current_chars = len("\n".join(headers))
    for index in selected_indexes:
        hunk = hunks[index]
        hunk_text = "\n".join(hunk)
        if selected_hunks and current_chars + len(hunk_text) > max_chars:
            continue
        selected_hunks.append(hunk)
        current_chars += len(hunk_text)

    omitted = len(hunks) - len(selected_hunks)
    localized = headers + [f"[localized diff: kept {len(selected_hunks)} of {len(hunks)} hunks; omitted {omitted}]"]
    for hunk in selected_hunks:
        localized.extend(hunk)
    localized_text = "\n".join(localized) + "\n"
    if len(localized_text) <= max_chars:
        return localized_text

    clipped_lines: list[str] = []
    used_chars = 0
    marker = "[localized diff truncated to fit character budget]"
    budget = max(0, max_chars - len(marker) - 2)
    for line in localized_text.splitlines():
        line_chars = len(line) + 1
        if used_chars + line_chars > budget:
            remaining = budget - used_chars
            if remaining > 12:
                clipped_lines.append(line[:remaining])
            break
        clipped_lines.append(line)
        used_chars += line_chars
    clipped_lines.append(marker)
    return "\n".join(clipped_lines) + "\n"


def build_pair_text(candidate: dict[str, Any], counterpart: dict[str, Any], *, text_mode: str = "pair_context") -> str:
    metadata = (
        f"Project: {candidate.get('project') or 'unknown'}\n"
        f"CVE: {candidate.get('cve') or 'unknown'}\n"
        f"CWE: {candidate.get('vulnerability_type') or 'unknown'}\n"
    )
    candidate_code = str(candidate.get("code") or "")
    counterpart_code = str(counterpart.get("code") or "")
    pair_diff = build_pair_diff(candidate, counterpart)

    if text_mode == "candidate_only":
        return (
            "Task: decide whether the candidate function is vulnerable.\n\n"
            f"{metadata}\n"
            "Candidate function:\n"
            f"{candidate_code}\n"
        )
    if text_mode == "counterpart_only":
        return (
            "Task: decide whether the hidden candidate function is vulnerable using only the paired counterpart.\n\n"
            f"{metadata}\n"
            "Paired counterpart function:\n"
            f"{counterpart_code}\n"
        )
    if text_mode == "metadata_only":
        return (
            "Task: decide whether the candidate function is vulnerable using only metadata.\n\n"
            f"{metadata}"
        )
    if text_mode == "diff_only":
        return (
            "Task: decide whether the candidate side of this diff is the vulnerable version.\n"
            "The diff is from paired_counterpart to candidate.\n\n"
            f"{metadata}\n"
            "Unified diff:\n"
            f"{pair_diff}\n"
        )
    if text_mode == "diff_no_metadata":
        return (
            "Task: decide whether the candidate side of this diff is the vulnerable version.\n"
            "The diff is from paired_counterpart to candidate.\n\n"
            "Unified diff:\n"
            f"{pair_diff}\n"
        )
    if text_mode == "diff_localized":
        return (
            "Task: decide whether the candidate side of this localized diff is the vulnerable version.\n"
            "The diff is from paired_counterpart to candidate. Long diffs are reduced to repair-relevant hunks.\n\n"
            f"{metadata}\n"
            "Localized unified diff:\n"
            f"{localize_pair_diff(pair_diff)}\n"
        )
    if text_mode == "candidate_plus_diff":
        return (
            "Task: decide whether the candidate function is the vulnerable version in this paired example.\n\n"
            f"{metadata}\n"
            "Candidate function:\n"
            f"{candidate_code}\n\n"
            "Unified diff from paired_counterpart to candidate:\n"
            f"{pair_diff}\n"
        )
    if text_mode != "pair_context":
        raise ValueError(f"Unknown text_mode: {text_mode}")
    return (
        "Task: decide whether the candidate function is the vulnerable version in this paired example.\n"
        "The candidate and counterpart come from the same project/CVE context.\n\n"
        f"{metadata}\n"
        "Candidate function:\n"
        f"{candidate_code}\n\n"
        "Paired counterpart function:\n"
        f"{counterpart_code}\n"
    )


def build_pair_context_rows(
    rows: list[dict[str, Any]],
    *,
    per_label_count: int,
    seed: int,
    text_mode: str = "pair_context",
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    grouped: defaultdict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[pair_key(row)].append(row)

    pair_context_rows: list[dict[str, Any]] = []
    usable_groups = 0
    for key, group_rows in grouped.items():
        positives = [row for row in group_rows if bool(row.get("has_vulnerability"))]
        negatives = [row for row in group_rows if not bool(row.get("has_vulnerability"))]
        if not positives or not negatives:
            continue
        usable_groups += 1
        for index, positive in enumerate(positives):
            negative = negatives[index % len(negatives)]
            enriched = dict(positive)
            enriched["id"] = f"{positive['id']}::pairctx"
            enriched["pair_key"] = "|".join(key)
            enriched["pair_counterpart_id"] = negative["id"]
            enriched["pair_text"] = build_pair_text(positive, negative, text_mode=text_mode)
            enriched["pair_text_mode"] = text_mode
            pair_context_rows.append(enriched)
        for index, negative in enumerate(negatives):
            positive = positives[index % len(positives)]
            enriched = dict(negative)
            enriched["id"] = f"{negative['id']}::pairctx"
            enriched["pair_key"] = "|".join(key)
            enriched["pair_counterpart_id"] = positive["id"]
            enriched["pair_text"] = build_pair_text(negative, positive, text_mode=text_mode)
            enriched["pair_text_mode"] = text_mode
            pair_context_rows.append(enriched)

    rng = random.Random(seed)
    positives = [row for row in pair_context_rows if bool(row.get("has_vulnerability"))]
    negatives = [row for row in pair_context_rows if not bool(row.get("has_vulnerability"))]
    rng.shuffle(positives)
    rng.shuffle(negatives)
    limit = min(len(positives), len(negatives))
    if per_label_count:
        limit = min(limit, per_label_count)
    selected = positives[:limit] + negatives[:limit]
    rng.shuffle(selected)

    summary = {
        "input_rows": len(rows),
        "group_count": len(grouped),
        "usable_pair_group_count": usable_groups,
        "candidate_pair_context_rows": len(pair_context_rows),
        "selected": {
            "vulnerable": sum(1 for row in selected if bool(row.get("has_vulnerability"))),
            "safe": sum(1 for row in selected if not bool(row.get("has_vulnerability"))),
            "total": len(selected),
        },
        "per_label_count_requested": per_label_count,
        "seed": seed,
        "text_mode": text_mode,
    }
    return selected, summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Build pair-context PrimeVul rows for paired comparison training.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--summary-output", default="")
    parser.add_argument("--split", default="train", help="Input split to use, or 'any'")
    parser.add_argument(
        "--text-mode",
        choices=[
            "pair_context",
            "candidate_only",
            "counterpart_only",
            "metadata_only",
            "diff_only",
            "diff_no_metadata",
            "diff_localized",
            "candidate_plus_diff",
        ],
        default="pair_context",
    )
    parser.add_argument("--per-label-count", type=int, default=0)
    parser.add_argument("--seed", type=int, default=13)
    args = parser.parse_args()

    rows = read_jsonl(args.input)
    if args.split != "any":
        rows = [row for row in rows if str(row.get("split") or "") == args.split]

    selected, summary = build_pair_context_rows(
        rows,
        per_label_count=args.per_label_count,
        seed=args.seed,
        text_mode=args.text_mode,
    )
    write_jsonl(args.output, selected)
    summary = {"output": args.output, "split": args.split, **summary}
    if args.summary_output:
        write_json(args.summary_output, summary)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
