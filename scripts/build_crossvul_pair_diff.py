from __future__ import annotations

import argparse
import difflib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterator

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.io_utils import ensure_parent, write_json, write_jsonl

C_LANGUAGES = {"c", "cpp"}


def _text(value: Any) -> str:
    return str(value or "").strip()


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


def iter_raw_pairs(path: Path, *, languages: set[str]) -> Iterator[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if str(row.get("language") or "").lower() not in languages:
                continue
            yield row


def pair_rows_from_example(example: dict[str, Any]) -> list[dict[str, Any]]:
    vul_code = _text(example.get("vulnerable_code"))
    fix_code = _text(example.get("fixed_code"))
    if not vul_code or not fix_code or vul_code == fix_code:
        return []
    pair_key = f"crossvul-{example.get('file_pair_id')}"
    base = {
        "source_dataset": "crossvul",
        "pair_key": pair_key,
        "vulnerability_id": _text(example.get("cwe_id")),
        "cve": "unknown",
        "cwe": _text(example.get("cwe_id")) or "unknown",
        "vulnerability_type": _text(example.get("cwe_id")) or "unknown",
        "project": "unknown",
        "programming_language": _text(example.get("language")),
        "file_path": "",
    }
    vulnerable = {**base, "id": f"{pair_key}:vulnerable", "code": vul_code, "has_vulnerability": True, "candidate_side": "vulnerable"}
    secure = {**base, "id": f"{pair_key}:secure", "code": fix_code, "has_vulnerability": False, "candidate_side": "secure"}
    rows: list[dict[str, Any]] = []
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


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    labels = Counter(bool(row["has_vulnerability"]) for row in rows)
    return {
        "rows": len(rows),
        "safe": labels.get(False, 0),
        "vulnerable": labels.get(True, 0),
        "pair_keys": len({str(row["pair_key"]) for row in rows}),
    }


def build_summary(rows: list[dict[str, Any]], args: argparse.Namespace, input_examples: int) -> dict[str, Any]:
    prompt_lengths = sorted(len(str(row.get("pair_text") or "")) for row in rows)
    return {
        "status": "ok",
        "scope": "crossvul_pair_diff_dataset",
        "source": {
            "raw_path": args.input,
            "license": "see data/raw/README.md upstream source notes",
            "languages": sorted(args.languages),
            "input_examples": input_examples,
            "selected_pairs": len({str(row["pair_key"]) for row in rows}),
            "selected_pair_rows": len(rows),
        },
        "labels": summarize(rows),
        "language_counts": dict(sorted(Counter(str(row.get("programming_language") or "unknown") for row in rows).items())),
        "changed_line_buckets": dict(sorted(Counter(str(row["changed_line_bucket"]) for row in rows).items())),
        "pair_text_length": {
            "p50": prompt_lengths[len(prompt_lengths) // 2] if prompt_lengths else 0,
            "p90": prompt_lengths[int(len(prompt_lengths) * 0.9)] if prompt_lengths else 0,
            "max": prompt_lengths[-1] if prompt_lengths else 0,
        },
    }


def render_report(summary: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# CrossVul Pair-Diff Dataset",
            "",
            "This report materializes a fourth paired vulnerable/fixed patch source, never previously",
            "used in this repository, for a genuine open-set source-shift stress test. CrossVul rows already",
            "ship as direct vulnerable/fixed code pairs, so no func-list stitching is needed.",
            "",
            "This dataset is eval-only. It is not used for training; the existing PrimeVul-trained",
            "paired-diff detector is evaluated zero-shot against it.",
            "",
            "## Source",
            "",
            f"- Raw file: `{summary['source']['raw_path']}`",
            f"- Languages: `{', '.join(summary['source']['languages'])}`",
            f"- Input examples scanned: `{summary['source']['input_examples']}`",
            f"- Selected pairs: `{summary['source']['selected_pairs']}`",
            f"- Pair rows: `{summary['source']['selected_pair_rows']}`",
            "",
            "## Labels",
            "",
            f"- Safe: `{summary['labels']['safe']}`",
            f"- Vulnerable: `{summary['labels']['vulnerable']}`",
            f"- Pair keys: `{summary['labels']['pair_keys']}`",
            "",
            "## Languages",
            "",
            "```json",
            json.dumps(summary["language_counts"], indent=2),
            "```",
            "",
            "## Changed-Line Buckets",
            "",
            "```json",
            json.dumps(summary["changed_line_buckets"], indent=2),
            "```",
            "",
            "## Interpretation",
            "",
            "CrossVul is a source the existing PrimeVul/DeltaSecommits/PatchEval-trained detector has",
            "never seen in training or development. It is restricted to C/C++ here to isolate a genuine",
            "open-set *source* shift from a confounded language shift; CrossVul also covers many other",
            "languages (PHP, JavaScript, Python, Java, ...) not used here, which remains a separate,",
            "not-yet-run language-shift stress test for future work.",
            "",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a CrossVul paired-diff eval set for open-set source-shift stress testing.")
    parser.add_argument("--input", default="data/raw/crossvul_train_raw.jsonl")
    parser.add_argument("--languages", nargs="+", default=sorted(C_LANGUAGES))
    parser.add_argument("--output", default="data/processed/secure_code_crossvul_pair_diff_eval_metadata.jsonl")
    parser.add_argument("--json-output", default="reports/secure_code_crossvul_pair_diff_dataset_v1.json")
    parser.add_argument("--md-output", default="reports/CROSSVUL_PAIR_DIFF_DATASET.md")
    args = parser.parse_args()
    args.languages = {lang.lower() for lang in args.languages}

    input_examples = 0
    rows: list[dict[str, Any]] = []
    for example in iter_raw_pairs(ROOT / args.input, languages=args.languages):
        input_examples += 1
        rows.extend(pair_rows_from_example(example))

    summary = build_summary(rows, args, input_examples)
    write_jsonl(ROOT / args.output, rows)
    write_json(ROOT / args.json_output, summary)
    ensure_parent(ROOT / args.md_output).write_text(render_report(summary), encoding="utf-8")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
