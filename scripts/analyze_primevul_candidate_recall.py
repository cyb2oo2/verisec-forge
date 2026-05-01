from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.analyze_primevul_large_diff_windows import changed_lines, summarize_hunk
from scripts.build_primevul_hunk_pseudo_label_dataset import hunk_to_row, summarize
from scripts.build_primevul_localized_diff_dataset import extract_diff
from scripts.build_primevul_pair_context_dataset import _hunk_score, _split_diff_hunks
from vrf.io_utils import read_jsonl, write_json, write_jsonl


def hunk_candidates(pair_text: str, *, max_candidates: int) -> list[dict[str, Any]]:
    _headers, hunks = _split_diff_hunks(extract_diff(pair_text))
    ranked = sorted(hunks, key=_hunk_score, reverse=True)
    return [summarize_hunk(hunk) for hunk in ranked[:max_candidates]]


def line_window_candidates(
    pair_text: str,
    *,
    window_size: int,
    max_candidates: int,
) -> list[dict[str, Any]]:
    _headers, hunks = _split_diff_hunks(extract_diff(pair_text))
    windows: list[list[str]] = []
    for hunk in hunks:
        header = hunk[0] if hunk else "@@"
        changed = changed_lines(hunk)
        if not changed:
            continue
        if len(changed) <= window_size:
            windows.append([f"{header} [changed-window all]"] + changed)
            continue
        for start in range(0, len(changed) - window_size + 1):
            window = changed[start : start + window_size]
            windows.append([f"{header} [changed-window {start + 1}]"] + window)
    ranked = sorted(windows, key=_hunk_score, reverse=True)
    return [summarize_hunk(window) for window in ranked[:max_candidates]]


def merged_candidates(
    pair_text: str,
    *,
    window_size: int,
    max_candidates: int,
) -> list[dict[str, Any]]:
    candidates = [
        *hunk_candidates(pair_text, max_candidates=max_candidates),
        *line_window_candidates(pair_text, window_size=window_size, max_candidates=max_candidates),
    ]
    deduped: dict[tuple[str, tuple[str, ...], tuple[str, ...]], dict[str, Any]] = {}
    for candidate in candidates:
        key = (
            str(candidate["header"]),
            tuple(candidate["removed_preview"]),
            tuple(candidate["added_preview"]),
        )
        deduped[key] = candidate
    ranked = sorted(
        deduped.values(),
        key=lambda candidate: (
            len(candidate["keywords"]),
            int(candidate["changed_lines"]),
            abs(int(candidate["net_risk_support"])) if "net_risk_support" in candidate else 0,
        ),
        reverse=True,
    )
    return ranked[:max_candidates]


def build_candidate_rows(
    rows: list[dict[str, Any]],
    *,
    strategy: str,
    max_candidates: int,
    window_size: int,
) -> list[dict[str, Any]]:
    candidate_rows: list[dict[str, Any]] = []
    for source_row in rows:
        pair_text = str(source_row.get("pair_text") or source_row.get("prompt") or "")
        if strategy == "hunk":
            candidates = hunk_candidates(pair_text, max_candidates=max_candidates)
        elif strategy == "line_window":
            candidates = line_window_candidates(pair_text, window_size=window_size, max_candidates=max_candidates)
        elif strategy == "hunk_plus_window":
            candidates = merged_candidates(pair_text, window_size=window_size, max_candidates=max_candidates)
        else:
            raise ValueError(f"Unsupported candidate strategy: {strategy}")
        for rank, candidate in enumerate(candidates, start=1):
            row = hunk_to_row(source_row, candidate, hunk_rank=rank)
            row["candidate_strategy"] = strategy
            row["window_size"] = window_size if "window" in strategy else None
            candidate_rows.append(row)
    return candidate_rows


def compare_strategies(
    rows: list[dict[str, Any]],
    *,
    strategies: list[str],
    max_candidates: int,
    window_size: int,
    coverage_k: list[int],
) -> dict[str, Any]:
    reports: dict[str, Any] = {}
    for strategy in strategies:
        candidate_rows = build_candidate_rows(
            rows,
            strategy=strategy,
            max_candidates=max_candidates,
            window_size=window_size,
        )
        reports[strategy] = summarize(candidate_rows, coverage_k=coverage_k)
    return {
        "config": {
            "strategies": strategies,
            "max_candidates": max_candidates,
            "window_size": window_size,
            "coverage_k": coverage_k,
        },
        "strategies": reports,
    }


def build_rows_by_strategy(
    rows: list[dict[str, Any]],
    *,
    strategies: list[str],
    max_candidates: int,
    window_size: int,
) -> dict[str, list[dict[str, Any]]]:
    return {
        strategy: build_candidate_rows(
            rows,
            strategy=strategy,
            max_candidates=max_candidates,
            window_size=window_size,
        )
        for strategy in strategies
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# PrimeVul Candidate Recall Analysis",
        "",
        "This report compares hunk candidate-generation strategies using the same heuristic pseudo labels. It estimates whether the evidence-localization bottleneck is candidate recall or only candidate scoring.",
        "",
        "## Strategy Summary",
        "",
        "| strategy | candidate_rows | source_rows | positive_rate | top1 | top3 | top8 |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for strategy, report in payload["strategies"].items():
        coverage = {row["k"]: row["coverage"] for row in report["coverage_at_k"]}
        lines.append(
            f"| {strategy} | {report['hunk_rows']} | {report['source_rows']} | {report['positive_rate']} | {coverage.get(1, 0.0)} | {coverage.get(3, 0.0)} | {coverage.get(8, 0.0)} |"
        )
    lines.extend(["", "## Top-K Details", ""])
    for strategy, report in payload["strategies"].items():
        lines.extend(
            [
                f"### {strategy}",
                "",
                "| k | coverage | vulnerable_coverage | safe_coverage | covered_rows | rows |",
                "| ---: | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for row in report["coverage_at_k"]:
            lines.append(
                f"| {row['k']} | {row['coverage']} | {row['vulnerable_coverage']} | {row['safe_coverage']} | {row['covered_rows']} | {row['rows']} |"
            )
        lines.append("")
    return "\n".join(lines)


def parse_csv(value: str) -> list[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def parse_ints(value: str) -> list[int]:
    return [int(part.strip()) for part in value.split(",") if part.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare PrimeVul hunk candidate-generation recall.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--strategies", default="hunk,line_window,hunk_plus_window")
    parser.add_argument("--max-candidates", type=int, default=8)
    parser.add_argument("--window-size", type=int, default=2)
    parser.add_argument("--coverage-k", default="1,2,3,5,8")
    parser.add_argument("--json-output", required=True)
    parser.add_argument("--md-output", required=True)
    parser.add_argument("--rows-output-dir")
    args = parser.parse_args()
    input_rows = read_jsonl(args.input)
    strategies = parse_csv(args.strategies)

    payload = compare_strategies(
        input_rows,
        strategies=strategies,
        max_candidates=args.max_candidates,
        window_size=args.window_size,
        coverage_k=parse_ints(args.coverage_k),
    )
    write_json(args.json_output, payload)
    md_path = Path(args.md_output)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(render_markdown(payload), encoding="utf-8")
    if args.rows_output_dir:
        output_dir = Path(args.rows_output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        for strategy, rows in build_rows_by_strategy(
            input_rows,
            strategies=strategies,
            max_candidates=args.max_candidates,
            window_size=args.window_size,
        ).items():
            write_jsonl(output_dir / f"{strategy}_candidates.jsonl", rows)
    print(json.dumps(payload["strategies"], indent=2))


if __name__ == "__main__":
    main()
