from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.build_primevul_pair_context_dataset import build_pair_context_rows
from vrf.io_utils import read_jsonl, write_json, write_jsonl


def cve_year(value: Any) -> int | None:
    match = re.match(r"CVE-(\d{4})-", str(value or ""))
    return int(match.group(1)) if match else None


def with_cve_year(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    enriched: list[dict[str, Any]] = []
    for row in rows:
        year = cve_year(row.get("cve"))
        if year is None:
            continue
        item = dict(row)
        item["cve_year"] = year
        enriched.append(item)
    return enriched


def summarize_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    labels = Counter(bool(row.get("has_vulnerability")) for row in rows)
    years = Counter(int(row["cve_year"]) for row in rows if row.get("cve_year") is not None)
    return {
        "rows": len(rows),
        "safe": labels.get(False, 0),
        "vulnerable": labels.get(True, 0),
        "unique_pair_keys": len({str(row.get("pair_key") or "") for row in rows if row.get("pair_key")}),
        "unique_projects": len({str(row.get("project")) for row in rows if row.get("project")}),
        "unique_cves": len({str(row.get("cve")) for row in rows if row.get("cve")}),
        "year_counts": dict(sorted(years.items())),
    }


def build_time_disjoint(
    rows: list[dict[str, Any]],
    *,
    train_max_year: int,
    eval_min_year: int,
    train_per_label: int,
    eval_per_label: int,
    seed: int,
    text_mode: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    rows = with_cve_year(rows)
    train_source = [row for row in rows if int(row["cve_year"]) <= train_max_year]
    eval_source = [row for row in rows if int(row["cve_year"]) >= eval_min_year]
    train_rows, train_summary = build_pair_context_rows(
        train_source,
        per_label_count=train_per_label,
        seed=seed,
        text_mode=text_mode,
    )
    eval_rows, eval_summary = build_pair_context_rows(
        eval_source,
        per_label_count=eval_per_label,
        seed=seed + 1,
        text_mode=text_mode,
    )
    for row in train_rows:
        row["time_disjoint_split"] = "train"
    for row in eval_rows:
        row["time_disjoint_split"] = "eval"

    train_years = {int(row["cve_year"]) for row in train_rows if row.get("cve_year") is not None}
    eval_years = {int(row["cve_year"]) for row in eval_rows if row.get("cve_year") is not None}
    train_projects = {str(row.get("project")) for row in train_rows if row.get("project")}
    eval_projects = {str(row.get("project")) for row in eval_rows if row.get("project")}
    train_cves = {str(row.get("cve")) for row in train_rows if row.get("cve")}
    eval_cves = {str(row.get("cve")) for row in eval_rows if row.get("cve")}
    train_pair_keys = {str(row.get("pair_key")) for row in train_rows if row.get("pair_key")}
    eval_pair_keys = {str(row.get("pair_key")) for row in eval_rows if row.get("pair_key")}

    summary = {
        "status": "ok",
        "scope": "primevul_time_disjoint_pair_diff_split",
        "protocol": {
            "train_condition": f"cve_year <= {train_max_year}",
            "eval_condition": f"cve_year >= {eval_min_year}",
            "text_mode": text_mode,
            "seed": seed,
            "train_per_label_requested": train_per_label,
            "eval_per_label_requested": eval_per_label,
        },
        "source": {
            "rows_with_cve_year": len(rows),
            "train_source": summarize_rows(train_source),
            "eval_source": summarize_rows(eval_source),
        },
        "selected": {
            "train": {**summarize_rows(train_rows), "builder_summary": train_summary},
            "eval": {**summarize_rows(eval_rows), "builder_summary": eval_summary},
        },
        "overlap": {
            "year_overlap": sorted(train_years & eval_years),
            "cve_overlap": len(train_cves & eval_cves),
            "pair_key_overlap": len(train_pair_keys & eval_pair_keys),
            "project_overlap": len(train_projects & eval_projects),
        },
    }
    return train_rows, eval_rows, summary


def render_report(summary: dict[str, Any]) -> str:
    train = summary["selected"]["train"]
    eval_ = summary["selected"]["eval"]
    overlap = summary["overlap"]
    return "\n".join(
        [
            "# PrimeVul Time-Disjoint Pair-Diff Split",
            "",
            "This report constructs a true time-disjoint paired-diff dataset from the full PrimeVul paired metadata.",
            "It is a dataset-construction artifact: no model is trained or evaluated here yet.",
            "",
            "## Protocol",
            "",
            f"- Train: `{summary['protocol']['train_condition']}`",
            f"- Eval: `{summary['protocol']['eval_condition']}`",
            f"- Text mode: `{summary['protocol']['text_mode']}`",
            f"- Seed: `{summary['protocol']['seed']}`",
            "",
            "## Selected Split",
            "",
            "| Split | Rows | Safe | Vulnerable | Pair Keys | Projects | CVEs |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
            f"| train | `{train['rows']}` | `{train['safe']}` | `{train['vulnerable']}` | `{train['unique_pair_keys']}` | `{train['unique_projects']}` | `{train['unique_cves']}` |",
            f"| eval | `{eval_['rows']}` | `{eval_['safe']}` | `{eval_['vulnerable']}` | `{eval_['unique_pair_keys']}` | `{eval_['unique_projects']}` | `{eval_['unique_cves']}` |",
            "",
            "## Overlap Checks",
            "",
            f"- CVE year overlap: `{overlap['year_overlap']}`",
            f"- CVE overlap: `{overlap['cve_overlap']}`",
            f"- Pair-key overlap: `{overlap['pair_key_overlap']}`",
            f"- Project overlap: `{overlap['project_overlap']}`",
            "",
            "## Interpretation",
            "",
            "This split is stricter than filtering the old eval slice because it rebuilds train/eval by CVE year from the full paired metadata. It still allows project overlap, so it is a time-disjoint stress target rather than a fully project-disjoint external dataset.",
            "",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a true CVE-year time-disjoint PrimeVul paired-diff split.")
    parser.add_argument("--input", default="data/processed/secure_code_primevul_paired_metadata.jsonl")
    parser.add_argument("--train-max-year", type=int, default=2020)
    parser.add_argument("--eval-min-year", type=int, default=2021)
    parser.add_argument("--train-per-label", type=int, default=3000)
    parser.add_argument("--eval-per-label", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=20260519)
    parser.add_argument("--text-mode", default="diff_only", choices=["diff_only", "diff_no_metadata", "diff_localized"])
    parser.add_argument("--train-output", default="data/processed/secure_code_primevul_pair_diff_time_train_le2020_balanced_6000_metadata.jsonl")
    parser.add_argument("--eval-output", default="data/processed/secure_code_primevul_pair_diff_time_eval_ge2021_balanced_2000_metadata.jsonl")
    parser.add_argument("--json-output", default="reports/secure_code_primevul_time_disjoint_pair_diff_split_v1.json")
    parser.add_argument("--md-output", default="reports/PRIMEVUL_TIME_DISJOINT_PAIR_DIFF_SPLIT.md")
    args = parser.parse_args()

    train_rows, eval_rows, summary = build_time_disjoint(
        read_jsonl(ROOT / args.input),
        train_max_year=args.train_max_year,
        eval_min_year=args.eval_min_year,
        train_per_label=args.train_per_label,
        eval_per_label=args.eval_per_label,
        seed=args.seed,
        text_mode=args.text_mode,
    )
    write_jsonl(ROOT / args.train_output, train_rows)
    write_jsonl(ROOT / args.eval_output, eval_rows)
    summary["outputs"] = {
        "train": args.train_output,
        "eval": args.eval_output,
        "json": args.json_output,
        "markdown": args.md_output,
    }
    write_json(ROOT / args.json_output, summary)
    (ROOT / args.md_output).write_text(render_report(summary), encoding="utf-8")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
