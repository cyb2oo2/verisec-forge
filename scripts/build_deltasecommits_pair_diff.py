from __future__ import annotations

import argparse
import json
import random
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from datasets import load_dataset

from vrf.io_utils import ensure_parent, write_json, write_jsonl


DEFAULT_EXTENSIONS = ("c", "cc", "cpp")


def _safe_text(value: Any) -> str:
    return str(value or "").strip()


def normalize_cwe(row: dict[str, Any]) -> str:
    cwe = _safe_text(row.get("cwe"))
    if cwe:
        return cwe
    cwe_id = _safe_text(row.get("cwe_id"))
    if cwe_id:
        return cwe_id.strip("{}'\" ")
    return "unknown"


def changed_line_bucket(pair_text: str) -> str:
    changed = sum(
        1
        for line in pair_text.splitlines()
        if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))
    )
    if changed <= 2:
        return "00-02"
    if changed <= 5:
        return "03-05"
    if changed <= 10:
        return "06-10"
    if changed <= 25:
        return "11-25"
    return "26+"


def normalize_code_for_diff(code: str) -> str:
    """DeltaSecommits snapshots are often single-line; expand C-like separators for readable diffs.

    This MUST be applied to the emitted ``code`` field, not only to ``pair_text``.
    ``src/vrf/relational_benchmark.py::build_canonical_pair`` reads ``code`` and
    re-diffs it. On a single-line snapshot with no trailing newline,
    ``difflib.unified_diff`` emits the added body on the same physical line as
    the removed body, leaving the row with no line-level ``+``/``-`` structure --
    which silently destroys every side-swap measurement built over it. See
    ``reports/VERIPATCH_RR_STRUCTURAL_CONTROL.md``.
    """

    code = _safe_text(code)
    if code.count("\n") > 2:
        return code
    expanded = re.sub(r"([{};])", r"\1\n", code)
    lines = [line.strip() for line in expanded.splitlines() if line.strip()]
    return "\n".join(lines) + ("\n" if lines else "")


def unified_pair_diff(candidate_code: str, counterpart_code: str) -> str:
    import difflib

    candidate_lines = normalize_code_for_diff(candidate_code).splitlines()
    counterpart_lines = normalize_code_for_diff(counterpart_code).splitlines()
    diff_lines = difflib.unified_diff(
        counterpart_lines,
        candidate_lines,
        fromfile="paired_counterpart",
        tofile="candidate",
        lineterm="",
    )
    return "\n".join(diff_lines) + "\n"


def build_delta_pair_text(candidate: dict[str, Any], counterpart: dict[str, Any], *, text_mode: str) -> str:
    metadata = (
        f"Project: {candidate.get('project') or 'unknown'}\n"
        f"CVE: {candidate.get('cve') or 'unknown'}\n"
        f"CWE: {candidate.get('vulnerability_type') or 'unknown'}\n"
    )
    pair_diff = unified_pair_diff(str(candidate.get("code") or ""), str(counterpart.get("code") or ""))
    if text_mode == "diff_no_metadata":
        return (
            "Task: decide whether the candidate side of this diff is the vulnerable version.\n"
            "The diff is from paired_counterpart to candidate.\n\n"
            "Unified diff:\n"
            f"{pair_diff}\n"
        )
    if text_mode == "diff_localized":
        # DeltaSecommits snapshots are short enough that the normalized full diff is the localized view.
        return (
            "Task: decide whether the candidate side of this localized diff is the vulnerable version.\n"
            "The diff is from paired_counterpart to candidate. Long diffs are reduced to repair-relevant hunks.\n\n"
            f"{metadata}\n"
            "Localized unified diff:\n"
            f"{pair_diff}\n"
        )
    return (
        "Task: decide whether the candidate side of this diff is the vulnerable version.\n"
        "The diff is from paired_counterpart to candidate.\n\n"
        f"{metadata}\n"
        "Unified diff:\n"
        f"{pair_diff}\n"
    )


def pair_rows_from_example(example: dict[str, Any], *, index: int, text_mode: str) -> list[dict[str, Any]]:
    vulnerable_code = _safe_text(example.get("prior_version"))
    secure_code = _safe_text(example.get("after_version"))
    if not vulnerable_code or not secure_code:
        return []

    # Emit line-structured code. Downstream consumers (the relational benchmark)
    # re-diff this field directly, so it must carry real line boundaries.
    # ``unified_pair_diff`` normalizes again and is idempotent here, so
    # ``pair_text`` is unchanged by this.
    vulnerable_code = normalize_code_for_diff(vulnerable_code)
    secure_code = normalize_code_for_diff(secure_code)

    pair_key = f"deltasecommits-{index}"
    cwe = normalize_cwe(example)
    base = {
        "source_dataset": "DeltaSecommits",
        "pair_key": pair_key,
        "vulnerability_id": _safe_text(example.get("vuln_id")),
        "cve": _safe_text(example.get("vuln_id")),
        "cwe": cwe,
        "vulnerability_type": cwe,
        "project": _safe_text(example.get("project")),
        "commit_id": _safe_text(example.get("commit_sha")),
        "commit_href": _safe_text(example.get("commit_href")),
        "file_extension": _safe_text(example.get("file_extension")).lower(),
        "file_paths": example.get("file_paths") or [],
        "file_paths_str": _safe_text(example.get("file_paths_str")),
        "severity_score": example.get("score"),
        "published_date": _safe_text(example.get("published_date")),
        "commit_datetime": _safe_text(example.get("commit_datetime")),
        "summary": _safe_text(example.get("summary")),
        "message": _safe_text(example.get("message")),
    }
    vulnerable = {
        **base,
        "id": f"{pair_key}:vulnerable",
        "code": vulnerable_code,
        "has_vulnerability": True,
        "candidate_side": "vulnerable",
    }
    secure = {
        **base,
        "id": f"{pair_key}:secure",
        "code": secure_code,
        "has_vulnerability": False,
        "candidate_side": "secure",
    }

    rows: list[dict[str, Any]] = []
    for candidate, counterpart in ((vulnerable, secure), (secure, vulnerable)):
        pair_text = build_delta_pair_text(candidate, counterpart, text_mode=text_mode)
        rows.append(
            {
                **candidate,
                "counterpart_id": counterpart["id"],
                "counterpart_side": counterpart["candidate_side"],
                "pair_text": pair_text,
                "pair_text_mode": text_mode,
                "changed_line_bucket": changed_line_bucket(pair_text),
            }
        )
    return rows


def build_rows(
    dataset_rows: list[dict[str, Any]],
    *,
    extensions: set[str],
    text_mode: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    selected_examples: list[dict[str, Any]] = []
    pair_rows: list[dict[str, Any]] = []
    for index, example in enumerate(dataset_rows):
        extension = _safe_text(example.get("file_extension")).lower().lstrip(".")
        if extension not in extensions:
            continue
        rows = pair_rows_from_example(example, index=index, text_mode=text_mode)
        if not rows:
            continue
        selected_examples.append(example)
        pair_rows.extend(rows)

    label_counts = Counter(bool(row["has_vulnerability"]) for row in pair_rows)
    bucket_counts = Counter(str(row["changed_line_bucket"]) for row in pair_rows)
    extension_counts = Counter(_safe_text(row.get("file_extension")).lower() for row in pair_rows)
    cwe_counts = Counter(str(row.get("cwe") or "unknown") for row in pair_rows)
    prompt_lengths = sorted(len(str(row.get("pair_text") or "")) for row in pair_rows)
    summary = {
        "status": "ok",
        "scope": "deltasecommits_pair_diff_dataset",
        "source": {
            "hf_dataset": "rufimelo/DeltaSecommits",
            "license": "mit",
            "input_rows": len(dataset_rows),
            "selected_pairs": len(selected_examples),
            "selected_pair_rows": len(pair_rows),
            "extensions": sorted(extensions),
        },
        "labels": {"safe": label_counts.get(False, 0), "vulnerable": label_counts.get(True, 0)},
        "unique_pair_count": len({str(row["pair_key"]) for row in pair_rows}),
        "unique_projects": len({str(row.get("project")) for row in pair_rows if row.get("project")}),
        "unique_vulnerabilities": len({str(row.get("vulnerability_id")) for row in pair_rows if row.get("vulnerability_id")}),
        "extension_counts": dict(sorted(extension_counts.items())),
        "cwe_top20": cwe_counts.most_common(20),
        "changed_line_buckets": dict(sorted(bucket_counts.items())),
        "pair_text_length": {
            "p50": prompt_lengths[len(prompt_lengths) // 2] if prompt_lengths else 0,
            "p90": prompt_lengths[int(len(prompt_lengths) * 0.9)] if prompt_lengths else 0,
            "max": prompt_lengths[-1] if prompt_lengths else 0,
        },
    }
    return pair_rows, summary


def split_by_pair_key(rows: list[dict[str, Any]], *, eval_fraction: float, seed: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    pair_keys = sorted({str(row["pair_key"]) for row in rows})
    rng = random.Random(seed)
    rng.shuffle(pair_keys)
    eval_count = max(1, round(len(pair_keys) * eval_fraction)) if pair_keys else 0
    eval_keys = set(pair_keys[:eval_count])
    train_rows = [row for row in rows if str(row["pair_key"]) not in eval_keys]
    eval_rows = [row for row in rows if str(row["pair_key"]) in eval_keys]
    return train_rows, eval_rows


def render_report(summary: dict[str, Any]) -> str:
    split = summary["split"]
    return "\n".join(
        [
            "# DeltaSecommits Pair-Diff Dataset",
            "",
            "This report materializes a second paired vulnerable/fixed patch source for cross-dataset validation.",
            "Rows are converted into the same candidate-vs-counterpart diff contract used by the PrimeVul paired-diff line.",
            "",
            "## Source",
            "",
            "- Hugging Face dataset: `rufimelo/DeltaSecommits`",
            "- License: `MIT`",
            "- Selected extensions: `" + ", ".join(summary["source"]["extensions"]) + "`",
            f"- Selected pairs: `{summary['source']['selected_pairs']}`",
            f"- Pair rows: `{summary['source']['selected_pair_rows']}`",
            f"- Unique projects: `{summary['unique_projects']}`",
            f"- Unique vulnerabilities: `{summary['unique_vulnerabilities']}`",
            "",
            "## Split",
            "",
            "| Split | Rows | Safe | Vulnerable | Pair Keys |",
            "| --- | ---: | ---: | ---: | ---: |",
            f"| train | `{split['train']['rows']}` | `{split['train']['safe']}` | `{split['train']['vulnerable']}` | `{split['train']['pair_keys']}` |",
            f"| eval | `{split['eval']['rows']}` | `{split['eval']['safe']}` | `{split['eval']['vulnerable']}` | `{split['eval']['pair_keys']}` |",
            "",
            "## Prompt Length",
            "",
            f"- p50: `{summary['pair_text_length']['p50']}` characters",
            f"- p90: `{summary['pair_text_length']['p90']}` characters",
            f"- max: `{summary['pair_text_length']['max']}` characters",
            "",
            "## Changed-Line Buckets",
            "",
            "```json",
            json.dumps(summary["changed_line_buckets"], indent=2),
            "```",
            "",
            "## Interpretation",
            "",
            "DeltaSecommits is a good second-source stress target because it is much shorter than PrimeVul, uses paired pre/post-fix snapshots, and comes from a different curation pipeline. The first use should be zero-shot transfer from the PrimeVul paired-diff detector before training a Delta-specific model.",
            "",
        ]
    )


def summarize_split(rows: list[dict[str, Any]]) -> dict[str, Any]:
    labels = Counter(bool(row["has_vulnerability"]) for row in rows)
    return {
        "rows": len(rows),
        "safe": labels.get(False, 0),
        "vulnerable": labels.get(True, 0),
        "pair_keys": len({str(row["pair_key"]) for row in rows}),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build DeltaSecommits paired diff datasets for cross-source validation.")
    parser.add_argument("--dataset", default="rufimelo/DeltaSecommits")
    parser.add_argument("--extensions", default=",".join(DEFAULT_EXTENSIONS))
    parser.add_argument("--text-mode", default="diff_only", choices=["diff_only", "diff_no_metadata", "diff_localized"])
    parser.add_argument("--eval-fraction", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=20260519)
    parser.add_argument("--all-output", default="data/processed/secure_code_deltasecommits_pair_diff_cpp_all_metadata.jsonl")
    parser.add_argument("--train-output", default="data/processed/secure_code_deltasecommits_pair_diff_cpp_train_metadata.jsonl")
    parser.add_argument("--eval-output", default="data/processed/secure_code_deltasecommits_pair_diff_cpp_eval_metadata.jsonl")
    parser.add_argument("--json-output", default="reports/secure_code_deltasecommits_pair_diff_dataset_v1.json")
    parser.add_argument("--md-output", default="reports/DELTASECCOMMITS_PAIR_DIFF_DATASET.md")
    args = parser.parse_args()

    dataset_rows = [dict(row) for row in load_dataset(args.dataset, split="train")]
    extensions = {item.strip().lower().lstrip(".") for item in args.extensions.split(",") if item.strip()}
    rows, summary = build_rows(dataset_rows, extensions=extensions, text_mode=args.text_mode)
    train_rows, eval_rows = split_by_pair_key(rows, eval_fraction=args.eval_fraction, seed=args.seed)
    summary["protocol"] = {
        "text_mode": args.text_mode,
        "eval_fraction": args.eval_fraction,
        "seed": args.seed,
        "split_policy": "pair-key disjoint random split",
    }
    summary["split"] = {
        "train": summarize_split(train_rows),
        "eval": summarize_split(eval_rows),
    }
    summary["outputs"] = {
        "all": args.all_output,
        "train": args.train_output,
        "eval": args.eval_output,
        "json": args.json_output,
        "markdown": args.md_output,
    }

    write_jsonl(ROOT / args.all_output, rows)
    write_jsonl(ROOT / args.train_output, train_rows)
    write_jsonl(ROOT / args.eval_output, eval_rows)
    write_json(ROOT / args.json_output, summary)
    ensure_parent(ROOT / args.md_output).write_text(render_report(summary), encoding="utf-8")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
