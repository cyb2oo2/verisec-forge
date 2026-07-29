"""Report safe-flip gate precision with sample size, uncertainty, and selection provenance.

The gate summary previously headlined ``precision 1.0000`` for the preferred
gate without a sample size or interval, on the same pool where that gate variant
was introduced. Two corrections are applied here:

* every precision is reported with ``n`` and an exact (Clopper-Pearson) interval;
* each pool is labelled by the role it actually played -- whether it was used to
  *select* the reported gate or only to describe it.

A gate variant that exists for exactly one pool, and is preferred on that pool,
is selected-on-holdout. That is recorded explicitly rather than presented as
independent validation.

Usage::

    python scripts/build_primevul_side_inversion_gate_uncertainty.py \
        --json-output reports/secure_code_primevul_side_inversion_gate_uncertainty_v1.json \
        --md-output reports/PRIMEVUL_SIDE_INVERSION_GATE_UNCERTAINTY.md
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from scripts.build_primevul_side_inversion_gate_summary import (  # noqa: E402
    DEFAULT_GATE_SPECS,
    SELECTION_PROTOCOL,
)
from vrf.io_utils import read_json, write_json  # noqa: E402
from vrf.stats_cluster import clopper_pearson  # noqa: E402


def _counts(payload: dict[str, Any]) -> dict[str, int] | None:
    """Extract accepted/repaired/introduced counts at row and pair level.

    Pair counts matter: a gate accepting 9 *rows* across 4 *pairs* has 4
    independent units, because the two rows of a pair are mirror renderings of
    one patch. Reporting n=9 overstates the evidence.
    """

    summary = payload.get("summary")
    if not isinstance(summary, dict):
        return None
    if "accepted_rows" not in summary:
        return None
    return {
        "accepted_rows": int(summary.get("accepted_rows", 0)),
        "repaired_rows": int(summary.get("repaired_side_error_rows", 0)),
        "introduced_rows": int(summary.get("introduced_side_error_rows", 0)),
        "accepted_pairs": int(summary.get("accepted_unique_pairs", 0)),
        "repaired_pairs": int(summary.get("repaired_side_error_pairs", 0)),
        "introduced_pairs": int(summary.get("introduced_side_error_pairs", 0)),
    }


def build_report() -> dict[str, Any]:
    preferred = SELECTION_PROTOCOL.get("current_preferred_gate", "")
    preferred_pool, _, preferred_variant = preferred.partition(":")

    variants_by_pool: dict[str, set[str]] = collections.defaultdict(set)
    for spec in DEFAULT_GATE_SPECS:
        variants_by_pool[spec["pool"]].add(spec["gate_variant"])

    multi_variant_pools = sorted(pool for pool, values in variants_by_pool.items() if len(values) > 1)
    variant_pools = collections.defaultdict(set)
    for spec in DEFAULT_GATE_SPECS:
        variant_pools[spec["gate_variant"]].add(spec["pool"])
    preferred_variant_is_pool_specific = variant_pools.get(preferred_variant, set()) == {preferred_pool}

    rows: list[dict[str, Any]] = []
    missing: list[str] = []
    for spec in DEFAULT_GATE_SPECS:
        path = REPO_ROOT / spec["path"]
        if not path.exists():
            missing.append(spec["path"])
            rows.append(
                {
                    "pool": spec["pool"],
                    "gate_variant": spec["gate_variant"],
                    "protocol_role": spec["protocol_role"],
                    "status": "artifact_missing",
                    "path": spec["path"],
                }
            )
            continue
        payload = read_json(str(path))
        counts = _counts(payload)
        if counts is None:
            rows.append(
                {
                    "pool": spec["pool"],
                    "gate_variant": spec["gate_variant"],
                    "protocol_role": spec["protocol_role"],
                    "status": "unrecognised_schema",
                    "path": spec["path"],
                }
            )
            continue
        is_preferred = f"{spec['pool']}:{spec['gate_variant']}" == preferred
        rows.append(
            {
                "pool": spec["pool"],
                "gate_variant": spec["gate_variant"],
                "protocol_role": spec["protocol_role"],
                "status": "ok",
                **counts,
                "precision_rows_point": round(counts["repaired_rows"] / counts["accepted_rows"], 4)
                if counts["accepted_rows"]
                else None,
                "precision_rows_exact_95_ci": clopper_pearson(counts["repaired_rows"], counts["accepted_rows"])
                if counts["accepted_rows"]
                else None,
                "precision_pairs_point": round(counts["repaired_pairs"] / counts["accepted_pairs"], 4)
                if counts["accepted_pairs"]
                else None,
                "precision_pairs_exact_95_ci": clopper_pearson(counts["repaired_pairs"], counts["accepted_pairs"])
                if counts["accepted_pairs"]
                else None,
                "preferred_unit": "pair",
                "unit_note": "pair-level n is the honest sample size; the two rows of a pair are mirror renderings of one patch",
                "is_preferred_gate": is_preferred,
                "pool_role_for_this_gate": (
                    "SELECTION (the reported gate variant was introduced and preferred on this pool)"
                    if is_preferred and preferred_variant_is_pool_specific
                    else "descriptive only"
                ),
            }
        )

    return {
        "scope": "primevul_side_inversion_gate_uncertainty",
        "supersedes_headline": "reports/PRIMEVUL_SIDE_INVERSION_GATE_SUMMARY.md precision 1.0000 headline",
        "selection_provenance": {
            "preferred_gate": preferred,
            "preferred_pool": preferred_pool,
            "preferred_variant": preferred_variant,
            "pools_with_more_than_one_variant": multi_variant_pools,
            "preferred_variant_defined_only_for_preferred_pool": preferred_variant_is_pool_specific,
            "verdict": (
                "SELECTED-ON-HOLDOUT: the preferred gate variant is defined only for the pool it is "
                "reported on, which is the pool where the original variant failed. It is not "
                "independently validated."
                if preferred_variant_is_pool_specific
                else "The preferred variant is defined across multiple pools."
            ),
            "selection_pool": preferred_pool,
            "descriptive_pools": sorted(pool for pool in variants_by_pool if pool != preferred_pool),
        },
        "gates": rows,
        "missing_artifacts": missing,
        "reporting_rule": (
            "Precision must always be reported as point estimate, n, and exact binomial interval, "
            "with pair groups as the unit. The preferred gate accepts 9 rows spanning only 4 pairs; "
            "at n=4 pairs the 95% lower bound on a precision of 1.0 is about 0.40, and even at n=9 "
            "rows it is about 0.66. Neither supports a zero-error claim."
        ),
    }


def render_markdown(report: dict[str, Any]) -> str:
    provenance = report["selection_provenance"]
    lines = [
        "# PrimeVul Side-Inversion Gate: Precision Uncertainty and Selection Provenance",
        "",
        "Generated by `scripts/build_primevul_side_inversion_gate_uncertainty.py`.",
        "",
        "## Selection provenance",
        "",
        f"- Preferred gate: `{provenance['preferred_gate']}`",
        f"- Pool used for **selection**: `{provenance['selection_pool']}`",
        f"- Pools used for **description only**: {', '.join(f'`{p}`' for p in provenance['descriptive_pools']) or 'none'}",
        f"- Preferred variant defined only for its own pool: `{provenance['preferred_variant_defined_only_for_preferred_pool']}`",
        "",
        f"**{provenance['verdict']}**",
        "",
        "## Gate results with uncertainty",
        "",
        "| pool | variant | role | accepted pairs (n) | repaired pairs | introduced pairs | precision (pairs) | exact 95% CI (pairs) | precision (rows) | exact 95% CI (rows) |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in report["gates"]:
        if row["status"] != "ok":
            label = "_artifact missing_" if row["status"] == "artifact_missing" else "_unrecognised schema_"
            lines.append(
                f"| {row['pool']} | {row['gate_variant']} | {row['protocol_role']} | {label} | | | | | | |"
            )
            continue
        pair_ci = row["precision_pairs_exact_95_ci"]
        row_ci = row["precision_rows_exact_95_ci"]
        marker = " **(preferred)**" if row["is_preferred_gate"] else ""
        lines.append(
            f"| {row['pool']} | {row['gate_variant']}{marker} | {row['protocol_role']} | "
            f"`{row['accepted_pairs']}` | `{row['repaired_pairs']}` | `{row['introduced_pairs']}` | "
            f"`{row['precision_pairs_point']}` | "
            + (f"`[{pair_ci['low']}, {pair_ci['high']}]`" if pair_ci else "n/a")
            + f" | `{row['precision_rows_point']}` | "
            + (f"`[{row_ci['low']}, {row_ci['high']}]`" if row_ci else "n/a")
            + " |"
        )

    lines.extend(
        [
            "",
            "## Reporting rule",
            "",
            report["reporting_rule"],
            "",
        ]
    )
    if report["missing_artifacts"]:
        lines.extend(
            [
                "## Missing artifacts",
                "",
                "These gate reports are absent from the tree, so their rows cannot be recomputed:",
                "",
            ]
            + [f"- `{path}`" for path in report["missing_artifacts"]]
            + [""]
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Gate precision with uncertainty and selection provenance.")
    parser.add_argument("--json-output", default="reports/secure_code_primevul_side_inversion_gate_uncertainty_v1.json")
    parser.add_argument("--md-output", default="reports/PRIMEVUL_SIDE_INVERSION_GATE_UNCERTAINTY.md")
    args = parser.parse_args()

    report = build_report()
    write_json(str(REPO_ROOT / args.json_output), report)
    (REPO_ROOT / args.md_output).write_text(render_markdown(report), encoding="utf-8")
    print(json.dumps(report["selection_provenance"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
