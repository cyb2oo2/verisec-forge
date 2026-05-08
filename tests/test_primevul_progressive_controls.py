from __future__ import annotations

from scripts.build_primevul_progressive_controls import build_rows, first_coverage, render_markdown


def main_results() -> dict:
    def row(system: str, bal: float, source: str = "report.json") -> dict:
        return {
            "system": system,
            "source": source,
            "threshold": 0.5,
            "recall": 0.6,
            "specificity": 0.7,
            "balanced_accuracy": bal,
        }

    return {
        "summary": {
            "diff_seed_balanced_accuracy_mean": 0.83,
            "diff_seed_balanced_accuracy_min": 0.81,
            "diff_seed_balanced_accuracy_max": 0.84,
        },
        "rows": [
            row("same-source detector", 0.95),
            row("same-source detector on paired eval", 0.5),
            row("metadata-only control", 0.5),
            row("candidate-only control", 0.51),
            row("counterpart-only control", 0.52),
            row("diff-only detector, no metadata", 0.82),
        ],
    }


def pair_coupled() -> dict:
    return {
        "summary": {
            "pair_balanced_accuracy": {"mean": 0.86},
            "pair_minus_bucket_balanced_accuracy": {"mean": 0.03},
            "pair_minus_bucket_group_all_correct": {"mean": 0.11},
        }
    }


def predicted_side() -> dict:
    return {
        "coverage": {
            "pair_coupled_predicted_side": [{"k": 1, "coverage": 0.65}],
            "pair_coupled_predicted_side_correct_only": [{"k": 1, "coverage": 0.76}],
            "pair_coupled_predicted_side_wrong_only": [{"k": 1, "coverage": 0.06}],
        }
    }


def gate_summary() -> dict:
    return {
        "summary": {"stress_invalidated_reports": 1},
        "pool_summaries": {
            "project_holdout_top5": {
                "best_zero_introduced": {
                    "accept_precision": 1.0,
                    "accepted_rows": 9,
                    "introduced_side_error_rows": 0,
                }
            }
        },
    }


def test_first_coverage_finds_requested_k() -> None:
    report = {"coverage": {"model": [{"k": 1, "coverage": 0.1}, {"k": 3, "coverage": 0.3}]}}

    assert first_coverage(report, "coverage", "model", k=3) == 0.3


def test_build_rows_creates_progressive_story() -> None:
    rows = build_rows(main_results(), pair_coupled(), predicted_side(), gate_summary())

    assert [row["stage"] for row in rows] == [
        "Same-source baseline",
        "Paired stress test",
        "Shortcut controls",
        "Paired diff detector",
        "No-metadata check",
        "Pair-coupled decoding",
        "Evidence propagation",
        "Safe flip gate",
    ]
    assert rows[2]["value"] == 0.52
    assert rows[5]["value"] == 0.86
    assert "side_wrong_top1=0.06" in rows[6]["supporting_metric"]


def test_render_markdown_includes_application_table() -> None:
    payload = {
        "summary": {"rows": 1, "headline": "headline", "main_limitation": "limit"},
        "rows": [
            {
                "stage": "Diff",
                "question": "Q?",
                "key_metric": "balanced_accuracy",
                "value": 0.82,
                "supporting_metric": "support",
                "interpretation": "meaning",
            }
        ],
    }

    markdown = render_markdown(payload)

    assert "# PrimeVul Progressive Controls" in markdown
    assert "| Diff | Q? | balanced_accuracy | 0.8200 | support | meaning |" in markdown
