from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.analyze_primevul_large_diff_windows import top_hunks
from scripts.analyze_primevul_pair_evidence_localization import support_label_for_decision, support_scores
from vrf.io_utils import read_jsonl, write_json, write_jsonl


def pseudo_label_for_hunk(*, gold: int, hunk: dict[str, Any]) -> int:
    scores = support_scores(hunk)
    return int(
        support_label_for_decision(
            decision=gold,
            risk_support=scores["risk_support"],
            safety_support=scores["safety_support"],
        )
        == "supported"
    )


def hunk_to_row(source_row: dict[str, Any], hunk: dict[str, Any], *, hunk_rank: int) -> dict[str, Any]:
    gold = int(bool(source_row.get("has_vulnerability")))
    scores = support_scores(hunk)
    pseudo_label = pseudo_label_for_hunk(gold=gold, hunk=hunk)
    return {
        "id": f"{source_row['id']}::hunk{hunk_rank}",
        "source_id": source_row["id"],
        "pair_key": source_row.get("pair_key") or source_row["id"],
        "project": source_row.get("project", "unknown"),
        "cve": source_row.get("cve", "unknown"),
        "vulnerability_type": source_row.get("vulnerability_type", "unknown"),
        "gold": gold,
        "hunk_rank": hunk_rank,
        "pseudo_label": pseudo_label,
        "header": hunk["header"],
        "changed_lines": hunk["changed_lines"],
        "added_lines": hunk["added_lines"],
        "removed_lines": hunk["removed_lines"],
        "keywords": hunk["keywords"],
        "direction_labels": hunk["direction_labels"],
        "risk_support": scores["risk_support"],
        "safety_support": scores["safety_support"],
        "net_risk_support": scores["net_risk_support"],
        "protection_delta": hunk["protection_delta"],
        "risk_delta": hunk["risk_delta"],
        "safer_delta": hunk["safer_delta"],
        "removed_preview": hunk["removed_preview"],
        "added_preview": hunk["added_preview"],
    }


def build_hunk_rows(rows: list[dict[str, Any]], *, max_hunks: int) -> list[dict[str, Any]]:
    hunk_rows: list[dict[str, Any]] = []
    for row in rows:
        pair_text = str(row.get("pair_text") or row.get("prompt") or "")
        for rank, hunk in enumerate(top_hunks(pair_text, limit=max_hunks), start=1):
            hunk_rows.append(hunk_to_row(row, hunk, hunk_rank=rank))
    return hunk_rows


def rate(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def coverage_at_k(hunk_rows: list[dict[str, Any]], *, k: int) -> dict[str, Any]:
    grouped: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in hunk_rows:
        grouped[str(row["source_id"])].append(row)
    covered = 0
    vuln_total = 0
    vuln_covered = 0
    safe_total = 0
    safe_covered = 0
    for group in grouped.values():
        ordered = sorted(group, key=lambda row: int(row["hunk_rank"]))
        top = ordered[:k]
        is_covered = any(int(row["pseudo_label"]) == 1 for row in top)
        gold = int(ordered[0]["gold"])
        covered += int(is_covered)
        if gold == 1:
            vuln_total += 1
            vuln_covered += int(is_covered)
        else:
            safe_total += 1
            safe_covered += int(is_covered)
    return {
        "k": k,
        "coverage": rate(covered, len(grouped)),
        "covered_rows": covered,
        "rows": len(grouped),
        "vulnerable_coverage": rate(vuln_covered, vuln_total),
        "safe_coverage": rate(safe_covered, safe_total),
    }


def summarize(hunk_rows: list[dict[str, Any]], *, coverage_k: list[int]) -> dict[str, Any]:
    label_counts = Counter(int(row["pseudo_label"]) for row in hunk_rows)
    gold_counts = Counter(int(row["gold"]) for row in hunk_rows)
    direction_counts: Counter[str] = Counter()
    cwe_counts: Counter[str] = Counter()
    for row in hunk_rows:
        direction_counts.update(row["direction_labels"])
        cwe_counts[str(row["vulnerability_type"])] += 1
    return {
        "hunk_rows": len(hunk_rows),
        "source_rows": len({str(row["source_id"]) for row in hunk_rows}),
        "pair_groups": len({str(row["pair_key"]) for row in hunk_rows}),
        "positive_hunks": label_counts[1],
        "negative_hunks": label_counts[0],
        "positive_rate": rate(label_counts[1], len(hunk_rows)),
        "vulnerable_hunks": gold_counts[1],
        "safe_hunks": gold_counts[0],
        "coverage_at_k": [coverage_at_k(hunk_rows, k=k) for k in coverage_k],
        "top_direction_labels": direction_counts.most_common(10),
        "top_cwes": cwe_counts.most_common(10),
    }


def render_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# PrimeVul Hunk Pseudo-Label Dataset",
        "",
        "This report builds hunk-level pseudo labels from direction-aware support heuristics. It is a bootstrapping artifact for training or evaluating a learned hunk scorer, not human evidence-span ground truth.",
        "",
        "## Summary",
        "",
        f"- Hunk rows: `{summary['hunk_rows']}`",
        f"- Source rows: `{summary['source_rows']}`",
        f"- Pair groups: `{summary['pair_groups']}`",
        f"- Positive hunk rate: `{summary['positive_rate']}`",
        "",
        "## Top-K Coverage",
        "",
        "| k | coverage | vulnerable_coverage | safe_coverage | covered_rows | rows |",
        "| ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in summary["coverage_at_k"]:
        lines.append(
            f"| {row['k']} | {row['coverage']} | {row['vulnerable_coverage']} | {row['safe_coverage']} | {row['covered_rows']} | {row['rows']} |"
        )
    lines.extend(
        [
            "",
            "## Aggregate Signals",
            "",
            f"- Top direction labels: `{summary['top_direction_labels']}`",
            f"- Top CWEs: `{summary['top_cwes']}`",
            "",
        ]
    )
    return "\n".join(lines)


def parse_ints(value: str) -> list[int]:
    return [int(part.strip()) for part in value.split(",") if part.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(description="Build hunk-level pseudo labels for PrimeVul paired diffs.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--max-hunks", type=int, default=8)
    parser.add_argument("--coverage-k", default="1,2,3,5,8")
    parser.add_argument("--output", required=True)
    parser.add_argument("--summary-json", required=True)
    parser.add_argument("--summary-md", required=True)
    args = parser.parse_args()

    hunk_rows = build_hunk_rows(read_jsonl(args.input), max_hunks=args.max_hunks)
    summary = summarize(hunk_rows, coverage_k=parse_ints(args.coverage_k))
    write_jsonl(args.output, hunk_rows)
    write_json(args.summary_json, summary)
    md_path = Path(args.summary_md)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(render_markdown(summary), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
