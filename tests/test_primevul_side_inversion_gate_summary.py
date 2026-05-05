from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

from scripts.build_primevul_side_inversion_gate_summary import build_summary, render_markdown


def write_gate(path: Path, *, gate: str, accepted: int, introduced: int, recall: float) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "config": {"gate": gate},
                "summary": {
                    "rows": 4,
                    "unique_pair_count": 2,
                    "candidate_true_flip_rows": 3,
                    "accepted_rows": accepted,
                    "accepted_unique_pairs": 1,
                    "repaired_side_error_rows": accepted - introduced,
                    "introduced_side_error_rows": introduced,
                    "missed_true_flip_rows": 3 - (accepted - introduced),
                    "accept_precision": 1.0 if introduced == 0 else 0.5,
                    "accept_recall": recall,
                    "net_row_gain_if_applied": accepted - (2 * introduced),
                },
            }
        ),
        encoding="utf-8",
    )


def test_build_summary_selects_best_zero_introduced_gate() -> None:
    tmp_path = Path(".tmp_test_runs") / f"gate-summary-{uuid4().hex}"
    good_path = tmp_path / "reports" / "good.json"
    conservative_path = tmp_path / "reports" / "conservative.json"
    risky_path = tmp_path / "reports" / "risky.json"
    write_gate(good_path, gate="evidence OR repeat", accepted=2, introduced=0, recall=0.67)
    write_gate(conservative_path, gate="repeat>=4", accepted=1, introduced=0, recall=0.33)
    write_gate(risky_path, gate="repeat>=3", accepted=3, introduced=1, recall=0.67)

    payload = build_summary(
        [
            {
                "pool": "project",
                "gate_variant": "evidence_conditioned",
                "path": "reports/good.json",
                "protocol_role": "project_stress_candidate",
                "selection_allowed": False,
            },
            {
                "pool": "project",
                "gate_variant": "conservative",
                "path": "reports/conservative.json",
                "protocol_role": "project_stress_baseline",
                "selection_allowed": False,
            },
            {
                "pool": "project",
                "gate_variant": "strict_or",
                "path": "reports/risky.json",
                "protocol_role": "project_stress_test",
                "selection_allowed": False,
            },
        ],
        repo_root=tmp_path,
    )

    best = payload["pool_summaries"]["project"]["best_zero_introduced"]
    assert best["gate_variant"] == "evidence_conditioned"
    assert payload["summary"]["zero_introduced_reports"] == 2
    assert payload["summary"]["audit_only_reports"] == 3
    assert payload["selection_protocol"]["stress_pool"] == "project_holdout_top5"


def test_render_markdown_includes_cross_pool_table() -> None:
    payload = {
        "summary": {
            "gate_reports": 1,
            "pools": 1,
            "zero_introduced_reports": 1,
            "stress_invalidated_reports": 0,
            "selection_allowed_reports": 1,
            "audit_only_reports": 0,
        },
        "selection_protocol": {
            "discovery_pool": "top5",
            "rank_holdout_pool": "rank6_10",
            "fresh_seed_pool": "fresh_seed_top5",
            "stress_pool": "project_holdout_top5",
            "selection_policy": "Prefer zero-introduced-error gates.",
            "current_preferred_gate": "project_holdout_top5:evidence_conditioned",
        },
        "pool_summaries": {},
        "rows": [
            {
                "pool": "top5",
                "gate_variant": "strict",
                "protocol_role": "discovery",
                "selection_allowed": True,
                "protocol_status": "development_safe",
                "accepted_rows": 2,
                "repaired_side_error_rows": 2,
                "introduced_side_error_rows": 0,
                "accept_precision": 1.0,
                "accept_recall": 0.5,
                "missed_true_flip_rows": 2,
                "net_row_gain_if_applied": 2,
                "gate": "repeat>=3",
            }
        ],
    }

    rendered = render_markdown(payload)

    assert "# PrimeVul Side-Inversion Gate Summary" in rendered
    assert "## Gate Selection Protocol" in rendered
    assert "| top5 | strict | discovery | yes | development_safe | 2 | 2 | 0 | 1.0 | 0.5 | 2 | 2 | `repeat>=3` |" in rendered
