from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from vrf.io_utils import read_json, write_json

DEFAULT_GATE_SPECS = [
    {
        "pool": "top5",
        "gate_variant": "strict_or",
        "path": "reports/secure_code_primevul_side_inversion_safe_flip_gate_top5_strict_v1.json",
    },
    {
        "pool": "rank6_10",
        "gate_variant": "strict_or",
        "path": "reports/secure_code_primevul_side_inversion_safe_flip_gate_rank6_10_strict_v1.json",
    },
    {
        "pool": "fresh_seed_top5",
        "gate_variant": "strict_or",
        "path": "reports/secure_code_primevul_side_inversion_safe_flip_gate_fresh_seeds_top5_strict_v1.json",
    },
    {
        "pool": "project_holdout_top5",
        "gate_variant": "strict_or",
        "path": "reports/secure_code_primevul_side_inversion_safe_flip_gate_project_holdout_top5_strict_v1.json",
    },
    {
        "pool": "project_holdout_top5",
        "gate_variant": "evidence_conditioned",
        "path": "reports/secure_code_primevul_side_inversion_safe_flip_gate_project_holdout_top5_evidence_conditioned_v1.json",
    },
    {
        "pool": "project_holdout_top5",
        "gate_variant": "conservative",
        "path": "reports/secure_code_primevul_side_inversion_safe_flip_gate_project_holdout_top5_conservative_v1.json",
    },
]

SELECTION_PROTOCOL = {
    "discovery_pool": "top5",
    "rank_holdout_pool": "rank6_10",
    "fresh_seed_pool": "fresh_seed_top5",
    "stress_pool": "project_holdout_top5",
    "selection_policy": (
        "Prefer zero-introduced-error gates; break ties by accepted repairs. "
        "A gate that introduces side errors on the project-holdout stress pool is not cross-project safe."
    ),
    "current_preferred_gate": "project_holdout_top5:evidence_conditioned",
}


def load_gate_row(spec: dict[str, str], *, repo_root: Path = REPO_ROOT) -> dict[str, Any]:
    payload = read_json(repo_root / spec["path"])
    config = payload["config"]
    summary = payload["summary"]
    return {
        "pool": spec["pool"],
        "gate_variant": spec["gate_variant"],
        "gate": config["gate"],
        "rows": summary["rows"],
        "unique_pair_count": summary["unique_pair_count"],
        "candidate_true_flip_rows": summary["candidate_true_flip_rows"],
        "accepted_rows": summary["accepted_rows"],
        "accepted_unique_pairs": summary["accepted_unique_pairs"],
        "repaired_side_error_rows": summary["repaired_side_error_rows"],
        "introduced_side_error_rows": summary["introduced_side_error_rows"],
        "missed_true_flip_rows": summary["missed_true_flip_rows"],
        "accept_precision": summary["accept_precision"],
        "accept_recall": summary["accept_recall"],
        "net_row_gain_if_applied": summary["net_row_gain_if_applied"],
        "source_path": spec["path"],
    }


def annotate_protocol_status(row: dict[str, Any]) -> str:
    pool = row["pool"]
    variant = row["gate_variant"]
    introduced = int(row["introduced_side_error_rows"])
    if f"{pool}:{variant}" == SELECTION_PROTOCOL["current_preferred_gate"]:
        return "preferred_stress_safe"
    if pool == SELECTION_PROTOCOL["stress_pool"] and introduced > 0:
        return "stress_invalidated"
    if pool == SELECTION_PROTOCOL["stress_pool"] and introduced == 0:
        return "stress_safe_but_lower_recall"
    if introduced == 0:
        return "development_safe"
    return "development_risky"


def best_zero_introduced(rows: list[dict[str, Any]]) -> dict[str, Any]:
    candidates = [row for row in rows if row["introduced_side_error_rows"] == 0]
    if not candidates:
        return {}
    return max(candidates, key=lambda row: (row["accepted_rows"], row["accept_recall"], row["accept_precision"]))


def build_summary(specs: list[dict[str, str]], *, repo_root: Path = REPO_ROOT) -> dict[str, Any]:
    rows = [load_gate_row(spec, repo_root=repo_root) for spec in specs]
    for row in rows:
        row["protocol_status"] = annotate_protocol_status(row)
    by_pool: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_pool.setdefault(row["pool"], []).append(row)
    pool_summaries = {
        pool: {
            "variants": len(pool_rows),
            "best_zero_introduced": best_zero_introduced(pool_rows),
            "max_accepted_rows": max(row["accepted_rows"] for row in pool_rows),
            "min_introduced_rows": min(row["introduced_side_error_rows"] for row in pool_rows),
        }
        for pool, pool_rows in sorted(by_pool.items())
    }
    return {
        "summary": {
            "gate_reports": len(rows),
            "pools": len(pool_summaries),
            "zero_introduced_reports": sum(1 for row in rows if row["introduced_side_error_rows"] == 0),
            "stress_invalidated_reports": sum(1 for row in rows if row["protocol_status"] == "stress_invalidated"),
        },
        "selection_protocol": SELECTION_PROTOCOL,
        "pool_summaries": pool_summaries,
        "rows": rows,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# PrimeVul Side-Inversion Gate Summary",
        "",
        "This generated table compares safe-flip gates across side-inversion candidate pools. It separates in-pool, rank-holdout, fresh-seed, and project-holdout behavior so the evidence-coupled system is not judged from a single pool.",
        "",
        "## Summary",
        "",
        f"- Gate reports: `{summary['gate_reports']}`",
        f"- Pools: `{summary['pools']}`",
        f"- Zero-introduced-error reports: `{summary['zero_introduced_reports']}`",
        f"- Stress-invalidated reports: `{summary['stress_invalidated_reports']}`",
        "",
        "## Gate Selection Protocol",
        "",
        f"- Discovery pool: `{payload['selection_protocol']['discovery_pool']}`",
        f"- Rank holdout pool: `{payload['selection_protocol']['rank_holdout_pool']}`",
        f"- Fresh-seed pool: `{payload['selection_protocol']['fresh_seed_pool']}`",
        f"- Cross-project stress pool: `{payload['selection_protocol']['stress_pool']}`",
        f"- Selection policy: {payload['selection_protocol']['selection_policy']}",
        f"- Current preferred gate: `{payload['selection_protocol']['current_preferred_gate']}`",
        "",
        "## Cross-Pool Gates",
        "",
        "| pool | variant | status | accepted | repaired | introduced | precision | recall | missed | net row gain | gate |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for row in payload["rows"]:
        lines.append(
            f"| {row['pool']} | {row['gate_variant']} | {row['protocol_status']} | {row['accepted_rows']} | "
            f"{row['repaired_side_error_rows']} | {row['introduced_side_error_rows']} | "
            f"{row['accept_precision']} | {row['accept_recall']} | {row['missed_true_flip_rows']} | "
            f"{row['net_row_gain_if_applied']} | `{row['gate']}` |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "The project-holdout pool is the stress test for cross-project safety. The evidence-conditioned gate is the current preferred safety point there because it preserves zero introduced side errors while accepting more repairs than the conservative repeat-only fallback.",
            "",
        ]
    )
    return "\n".join(lines)


def parse_specs(value: str | None) -> list[dict[str, str]]:
    if not value:
        return DEFAULT_GATE_SPECS
    loaded = json.loads(value)
    if not isinstance(loaded, list):
        raise ValueError("Gate specs must be a JSON list")
    return loaded


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a cross-pool PrimeVul side-inversion gate summary.")
    parser.add_argument("--gate-specs-json", help="Optional JSON list of {pool, gate_variant, path} entries.")
    parser.add_argument("--json-output", required=True)
    parser.add_argument("--md-output")
    args = parser.parse_args()

    payload = build_summary(parse_specs(args.gate_specs_json))
    write_json(args.json_output, payload)
    if args.md_output:
        output = Path(args.md_output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(render_markdown(payload), encoding="utf-8")
    print(json.dumps(payload["summary"], indent=2))


if __name__ == "__main__":
    main()
