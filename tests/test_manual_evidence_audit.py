from __future__ import annotations

import shutil
from pathlib import Path

from vrf.evidence_audit import (
    analyze_manual_evidence_annotations,
    annotation_progress_summary,
    annotation_template_rows,
    apply_annotation_rows,
    build_manual_evidence_audit_set,
    parse_window_ids,
    normalize_review_queue_row,
    render_manual_evidence_review_packet,
    select_audit_rows,
    split_annotation_batches,
)
from vrf.io_utils import read_jsonl, write_jsonl


TMP_ROOT = Path(".tmp_test_runs/manual_evidence_audit")


def setup_function() -> None:
    if TMP_ROOT.exists():
        shutil.rmtree(TMP_ROOT)
    TMP_ROOT.mkdir(parents=True)


def teardown_function() -> None:
    if TMP_ROOT.exists():
        shutil.rmtree(TMP_ROOT)


def _queue_row(pair_key: str, *, rank: int, label: str = "A") -> dict[str, object]:
    return {
        "seed": 7,
        "rank": rank,
        "pair_key": pair_key,
        "side_model_score": 1.0,
        "label": label,
        "is_true_inversion_candidate": label == "B",
        "side_a_id": f"{pair_key}::A",
        "side_b_id": f"{pair_key}::B",
        "side_a_probability": 0.8,
        "side_b_probability": 0.2,
        "probability_gap": 0.6,
        "project": "demo",
        "cve": "CVE-0000-0000",
        "changed_line_bucket": "01-02",
        "side_a_windows": [
            {
                "header": "@@ demo A @@",
                "direction_labels": ["candidate_removes_protection"],
                "risk_support": 2,
                "safety_support": 0,
                "removed_preview": ["guard();"],
                "added_preview": ["unguarded();"],
            }
        ],
        "side_b_windows": [
            {
                "header": "@@ demo B @@",
                "direction_labels": ["candidate_adds_protection"],
                "risk_support": 0,
                "safety_support": 2,
                "removed_preview": ["unguarded();"],
                "added_preview": ["guard();"],
            }
        ],
    }


def test_normalize_review_queue_row_adds_annotation_contract() -> None:
    row = normalize_review_queue_row(_queue_row("p1", rank=1), source_pool="top5", index=0)

    assert row["audit_id"].startswith("manual_evidence_audit::")
    assert row["model_vulnerable_side"] == "A"
    assert row["gold_vulnerable_side"] == "A"
    assert row["side_a"]["windows"][0]["window_id"] == "A1"
    assert row["annotation"]["selected_window_ids"] == []
    assert row["annotation"]["label_issue"] == "none"


def test_select_audit_rows_balances_pools_and_deduplicates_pairs() -> None:
    rows = [
        normalize_review_queue_row(_queue_row("p1", rank=1), source_pool="top5", index=0),
        normalize_review_queue_row(_queue_row("p1", rank=2), source_pool="fresh", index=0),
        normalize_review_queue_row(_queue_row("p2", rank=1), source_pool="fresh", index=1),
        normalize_review_queue_row(_queue_row("p3", rank=1), source_pool="project", index=0),
    ]

    selected = select_audit_rows(rows, sample_size=3, seed=1)

    assert len(selected) == 3
    assert len({row["pair_key"] for row in selected}) == 3
    assert {row["source_pool"] for row in selected} >= {"fresh", "project"}


def test_build_manual_evidence_audit_set_writes_jsonl_and_summary() -> None:
    first = TMP_ROOT / "secure_code_primevul_side_inversion_review_queue_top5_v1.jsonl"
    second = TMP_ROOT / "secure_code_primevul_side_inversion_review_queue_project_holdout_top5_v1.jsonl"
    write_jsonl(first, [_queue_row("p1", rank=1), _queue_row("p2", rank=2, label="B")])
    write_jsonl(second, [_queue_row("p3", rank=1), _queue_row("p4", rank=2)])
    output = TMP_ROOT / "audit.jsonl"

    summary = build_manual_evidence_audit_set(
        input_paths=[first, second],
        output_path=output,
        sample_size=3,
        seed=42,
    )

    rows = read_jsonl(output)
    assert summary["rows"] == 3
    assert summary["unique_pair_keys"] == 3
    assert len(rows) == 3
    assert "annotation_schema" in summary


def test_analyze_manual_evidence_annotations_counts_completed_rows() -> None:
    row = normalize_review_queue_row(_queue_row("p1", rank=1), source_pool="top5", index=0)
    row["annotation"] = {
        "human_vulnerable_side": "A",
        "evidence_side": "A",
        "evidence_quality": 3,
        "selected_window_ids": ["A1"],
        "label_issue": "none",
        "notes": "direct guard removal",
        "annotator": "test",
        "reviewed_at": "2026-05-11T00:00:00Z",
    }

    payload = analyze_manual_evidence_annotations([row])

    assert payload["completed_annotations"] == 1
    assert payload["completion_rate"] == 1.0
    assert payload["human_vs_gold"] == {"match": 1}
    assert payload["evidence_quality_counts"] == {"3": 1}


def test_analyze_manual_evidence_annotations_reports_invalid_rows() -> None:
    row = normalize_review_queue_row(_queue_row("p1", rank=1), source_pool="top5", index=0)
    row["annotation"] = {
        "human_vulnerable_side": "candidate",
        "evidence_side": "A",
        "evidence_quality": 5,
        "selected_window_ids": "A1",
        "label_issue": "none",
    }

    payload = analyze_manual_evidence_annotations([row])

    assert payload["completed_annotations"] == 0
    assert payload["invalid_annotations"] == 1
    assert payload["invalid_rows"][0]["errors"] == [
        "human_vulnerable_side",
        "evidence_quality",
        "selected_window_ids",
    ]


def test_render_manual_evidence_review_packet_contains_annotation_block() -> None:
    row = normalize_review_queue_row(_queue_row("p1", rank=1), source_pool="top5", index=0)

    packet = render_manual_evidence_review_packet([row])

    assert "# PrimeVul Manual Evidence Review Packet" in packet
    assert "human_vulnerable_side:" in packet
    assert "Window `A1`" in packet
    assert "Window `B1`" in packet
    assert "```diff" in packet


def test_annotation_template_rows_include_reference_metadata() -> None:
    row = normalize_review_queue_row(_queue_row("p1", rank=1), source_pool="top5", index=0)

    template = annotation_template_rows([row], batch_id="batch_01")

    assert template[0]["audit_id"] == row["audit_id"]
    assert template[0]["human_vulnerable_side"] == ""
    assert template[0]["batch_id"] == "batch_01"
    assert template[0]["batch_index"] == 1
    assert template[0]["project"] == "demo"
    assert template[0]["gold_vulnerable_side"] == "A"


def test_split_annotation_batches_uses_fixed_batch_size() -> None:
    rows = [
        normalize_review_queue_row(_queue_row(f"p{index}", rank=index), source_pool="top5", index=index)
        for index in range(5)
    ]

    batches = split_annotation_batches(rows, batch_size=2)

    assert [len(batch) for batch in batches] == [2, 2, 1]


def test_parse_window_ids_accepts_semicolon_or_comma_lists() -> None:
    assert parse_window_ids("A1, B2;A3") == ["A1", "B2", "A3"]


def test_apply_annotation_rows_updates_matching_audit_rows() -> None:
    row = normalize_review_queue_row(_queue_row("p1", rank=1), source_pool="top5", index=0)
    payload = apply_annotation_rows(
        [row],
        [
            {
                "audit_id": row["audit_id"],
                "human_vulnerable_side": "A",
                "evidence_side": "A",
                "evidence_quality": "3",
                "selected_window_ids": "A1",
                "label_issue": "none",
                "notes": "guard removed",
                "annotator": "test",
                "reviewed_at": "2026-05-12T00:00:00Z",
            }
        ],
    )

    assert payload["status"] == "ok"
    assert payload["updated"] == 1
    assert payload["audit_rows"][0]["annotation"]["selected_window_ids"] == ["A1"]
    assert payload["audit_rows"][0]["annotation"]["evidence_quality"] == 3


def test_apply_annotation_rows_rejects_unknown_window_ids() -> None:
    row = normalize_review_queue_row(_queue_row("p1", rank=1), source_pool="top5", index=0)
    payload = apply_annotation_rows(
        [row],
        [
            {
                "audit_id": row["audit_id"],
                "human_vulnerable_side": "A",
                "evidence_side": "A",
                "evidence_quality": "3",
                "selected_window_ids": "Z9",
                "label_issue": "none",
            }
        ],
    )

    assert payload["status"] == "failed"
    assert payload["errors"][0]["errors"] == ["selected_window_ids"]


def test_annotation_progress_summary_counts_blank_and_completed_rows() -> None:
    completed = normalize_review_queue_row(_queue_row("p1", rank=1), source_pool="top5", index=0)
    blank = normalize_review_queue_row(_queue_row("p2", rank=2), source_pool="fresh", index=1)
    completed["annotation"] = {
        "human_vulnerable_side": "A",
        "evidence_side": "A",
        "evidence_quality": 2,
        "selected_window_ids": ["A1"],
        "label_issue": "none",
        "notes": "",
        "annotator": "test",
        "reviewed_at": "2026-05-12T00:00:00Z",
    }

    payload = annotation_progress_summary([completed, blank])

    assert payload["completed_annotations"] == 1
    assert payload["blank_annotations"] == 1
    assert payload["by_source_pool"]["top5"]["completed"] == 1
    assert payload["by_source_pool"]["fresh"]["blank"] == 1
