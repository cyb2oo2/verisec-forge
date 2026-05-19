from __future__ import annotations

import argparse
import difflib
import json
import random
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from datasets import load_dataset

from vrf.io_utils import ensure_parent, write_json, write_jsonl


def _text(value: Any) -> str:
    return str(value or "").strip()


def _first_cwe(cwe_info: Any) -> str:
    if isinstance(cwe_info, dict) and cwe_info:
        return sorted(str(key) for key in cwe_info.keys())[0]
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


def unified_pair_diff(candidate_code: str, counterpart_code: str) -> str:
    diff_lines = difflib.unified_diff(
        _text(counterpart_code).splitlines(),
        _text(candidate_code).splitlines(),
        fromfile="paired_counterpart",
        tofile="candidate",
        lineterm="",
    )
    return "\n".join(diff_lines) + "\n"


def build_pair_text(candidate: dict[str, Any], counterpart: dict[str, Any]) -> str:
    metadata = (
        f"Project: {candidate.get('project') or 'unknown'}\n"
        f"CVE: {candidate.get('cve') or 'unknown'}\n"
        f"CWE: {candidate.get('vulnerability_type') or 'unknown'}\n"
        f"Language: {candidate.get('programming_language') or 'unknown'}\n"
    )
    return (
        "Task: decide whether the candidate side of this diff is the vulnerable version.\n"
        "The diff is from paired_counterpart to candidate.\n\n"
        f"{metadata}\n"
        "Unified diff:\n"
        f"{unified_pair_diff(str(candidate.get('code') or ''), str(counterpart.get('code') or ''))}\n"
    )


def pair_rows_from_example(example: dict[str, Any], *, example_index: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    vul_funcs = list(example.get("vul_func") or [])
    fix_funcs = list(example.get("fix_func") or [])
    for func_index, (vul_func, fix_func) in enumerate(zip(vul_funcs, fix_funcs)):
        vul_code = _text(vul_func.get("snippet"))
        fix_code = _text(fix_func.get("snippet"))
        if not vul_code or not fix_code:
            continue
        pair_key = f"patcheval-{example_index}-{func_index}"
        cwe = _first_cwe(example.get("cwe_info"))
        base = {
            "source_dataset": "ByteDance/PatchEval",
            "pair_key": pair_key,
            "vulnerability_id": _text(example.get("cve_id")),
            "cve": _text(example.get("cve_id")),
            "cwe": cwe,
            "vulnerability_type": cwe,
            "project": _text(example.get("repo")),
            "programming_language": _text(example.get("programming_language")),
            "patch_url": example.get("patch_url") or [],
            "cve_description": _text(example.get("cve_description")),
            "vul_patch": _text(example.get("vul_patch")),
            "file_path": _text(vul_func.get("file_path") or fix_func.get("file_path")),
        }
        vulnerable = {
            **base,
            "id": f"{pair_key}:vulnerable",
            "code": vul_code,
            "commit_id": _text(vul_func.get("commit")),
            "has_vulnerability": True,
            "candidate_side": "vulnerable",
        }
        secure = {
            **base,
            "id": f"{pair_key}:secure",
            "code": fix_code,
            "commit_id": _text(fix_func.get("commit")),
            "has_vulnerability": False,
            "candidate_side": "secure",
        }
        for candidate, counterpart in ((vulnerable, secure), (secure, vulnerable)):
            pair_text = build_pair_text(candidate, counterpart)
            rows.append(
                {
                    **candidate,
                    "counterpart_id": counterpart["id"],
                    "counterpart_side": counterpart["candidate_side"],
                    "pair_text": pair_text,
                    "pair_text_mode": "diff_only",
                    "changed_line_bucket": changed_line_bucket(pair_text),
                }
            )
    return rows


def split_by_pair_key(rows: list[dict[str, Any]], *, eval_fraction: float, seed: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    pair_keys = sorted({str(row["pair_key"]) for row in rows})
    rng = random.Random(seed)
    rng.shuffle(pair_keys)
    eval_keys = set(pair_keys[: max(1, round(len(pair_keys) * eval_fraction))])
    return [row for row in rows if row["pair_key"] not in eval_keys], [row for row in rows if row["pair_key"] in eval_keys]


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    labels = Counter(bool(row["has_vulnerability"]) for row in rows)
    return {
        "rows": len(rows),
        "safe": labels.get(False, 0),
        "vulnerable": labels.get(True, 0),
        "pair_keys": len({str(row["pair_key"]) for row in rows}),
    }


def build_summary(rows: list[dict[str, Any]], train_rows: list[dict[str, Any]], eval_rows: list[dict[str, Any]], args: argparse.Namespace) -> dict[str, Any]:
    prompt_lengths = sorted(len(str(row.get("pair_text") or "")) for row in rows)
    return {
        "status": "ok",
        "scope": "patcheval_pair_diff_dataset",
        "source": {
            "hf_dataset": args.dataset,
            "license": "apache-2.0",
            "input_examples": args.input_examples,
            "selected_pairs": len({str(row["pair_key"]) for row in rows}),
            "selected_pair_rows": len(rows),
        },
        "labels": summarize(rows),
        "split": {"train": summarize(train_rows), "eval": summarize(eval_rows)},
        "language_counts": dict(sorted(Counter(str(row.get("programming_language") or "unknown") for row in rows).items())),
        "changed_line_buckets": dict(sorted(Counter(str(row["changed_line_bucket"]) for row in rows).items())),
        "pair_text_length": {
            "p50": prompt_lengths[len(prompt_lengths) // 2] if prompt_lengths else 0,
            "p90": prompt_lengths[int(len(prompt_lengths) * 0.9)] if prompt_lengths else 0,
            "max": prompt_lengths[-1] if prompt_lengths else 0,
        },
        "protocol": {
            "eval_fraction": args.eval_fraction,
            "seed": args.seed,
            "split_policy": "pair-key disjoint random split",
        },
    }


def render_report(summary: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# PatchEval Pair-Diff Dataset",
            "",
            "This report materializes a third paired vulnerable/fixed patch source for cross-dataset validation.",
            "",
            "## Source",
            "",
            "- Hugging Face dataset: `ByteDance/PatchEval`",
            "- License: `Apache-2.0`",
            f"- Selected pairs: `{summary['source']['selected_pairs']}`",
            f"- Pair rows: `{summary['source']['selected_pair_rows']}`",
            "",
            "## Split",
            "",
            "| Split | Rows | Safe | Vulnerable | Pair Keys |",
            "| --- | ---: | ---: | ---: | ---: |",
            f"| train | `{summary['split']['train']['rows']}` | `{summary['split']['train']['safe']}` | `{summary['split']['train']['vulnerable']}` | `{summary['split']['train']['pair_keys']}` |",
            f"| eval | `{summary['split']['eval']['rows']}` | `{summary['split']['eval']['safe']}` | `{summary['split']['eval']['vulnerable']}` | `{summary['split']['eval']['pair_keys']}` |",
            "",
            "## Languages",
            "",
            "```json",
            json.dumps(summary["language_counts"], indent=2),
            "```",
            "",
            "## Interpretation",
            "",
            "PatchEval is a stronger third-source stress target because it covers Python, JavaScript, and Go repair examples rather than the C/C++-heavy setting used by DeltaSecommits.",
            "",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Build PatchEval paired diff datasets for third-source validation.")
    parser.add_argument("--dataset", default="ByteDance/PatchEval")
    parser.add_argument("--eval-fraction", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=20260519)
    parser.add_argument("--all-output", default="data/processed/secure_code_patcheval_pair_diff_all_metadata.jsonl")
    parser.add_argument("--train-output", default="data/processed/secure_code_patcheval_pair_diff_train_metadata.jsonl")
    parser.add_argument("--eval-output", default="data/processed/secure_code_patcheval_pair_diff_eval_metadata.jsonl")
    parser.add_argument("--json-output", default="reports/secure_code_patcheval_pair_diff_dataset_v1.json")
    parser.add_argument("--md-output", default="reports/PATCHEVAL_PAIR_DIFF_DATASET.md")
    args = parser.parse_args()

    examples = [dict(row) for row in load_dataset(args.dataset, split="train")]
    args.input_examples = len(examples)
    rows: list[dict[str, Any]] = []
    for index, example in enumerate(examples):
        rows.extend(pair_rows_from_example(example, example_index=index))
    train_rows, eval_rows = split_by_pair_key(rows, eval_fraction=args.eval_fraction, seed=args.seed)
    summary = build_summary(rows, train_rows, eval_rows, args)

    write_jsonl(ROOT / args.all_output, rows)
    write_jsonl(ROOT / args.train_output, train_rows)
    write_jsonl(ROOT / args.eval_output, eval_rows)
    write_json(ROOT / args.json_output, summary)
    ensure_parent(ROOT / args.md_output).write_text(render_report(summary), encoding="utf-8")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
