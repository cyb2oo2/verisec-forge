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
from scripts.build_manual_evidence_pilot_findings import build_findings
from scripts.build_manual_evidence_draft_adjudications import (
    build_draft_adjudications,
    summarize_drafts,
)
from scripts.export_high_quality_manual_evidence_adjudication_template import (
    build_payload as build_high_quality_adjudication_payload,
    render_report as render_high_quality_adjudication_report,
)
from scripts.build_high_quality_adjudication_brief import (
    build_case_briefs as build_high_quality_case_briefs,
    render_report as render_high_quality_case_brief_report,
)
from scripts.build_insufficient_context_review_brief import (
    build_context_brief as build_insufficient_context_brief,
    render_report as render_insufficient_context_brief_report,
)
from scripts.build_manual_adjudication_status_dashboard import (
    build_dashboard as build_manual_adjudication_dashboard,
    render_report as render_manual_adjudication_dashboard_report,
)
from scripts.build_ai_insufficient_context_adjudications import (
    build_rows as build_ai_insufficient_context_rows,
    summarize as summarize_ai_insufficient_context_rows,
)
from vrf.evidence_adjudication import (
    adjudication_template_rows,
    analyze_adjudications,
    apply_adjudication_rows,
)


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
    assert payload["annotator_counts"] == {"test": 1}


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
    assert "Gold vulnerable side" not in packet
    assert "Detector probability" not in packet


def test_render_manual_evidence_review_packet_can_include_labels() -> None:
    row = normalize_review_queue_row(_queue_row("p1", rank=1), source_pool="top5", index=0)

    packet = render_manual_evidence_review_packet([row], include_labels=True)

    assert "Gold vulnerable side" in packet
    assert "Detector probability" in packet


def test_annotation_template_rows_are_blinded_by_default() -> None:
    row = normalize_review_queue_row(_queue_row("p1", rank=1), source_pool="top5", index=0)

    template = annotation_template_rows([row], batch_id="batch_01")

    assert template[0]["audit_id"] == row["audit_id"]
    assert template[0]["human_vulnerable_side"] == ""
    assert template[0]["batch_id"] == "batch_01"
    assert template[0]["batch_index"] == 1
    assert "project" not in template[0]
    assert "gold_vulnerable_side" not in template[0]


def test_annotation_template_rows_preserve_existing_annotations() -> None:
    row = normalize_review_queue_row(_queue_row("p1", rank=1), source_pool="top5", index=0)
    row["annotation"] = {
        "human_vulnerable_side": "A",
        "evidence_side": "A",
        "evidence_quality": 3,
        "selected_window_ids": ["A1", "B1"],
        "label_issue": "none",
        "notes": "guard removed",
        "annotator": "test",
        "reviewed_at": "2026-05-12T00:00:00Z",
    }

    template = annotation_template_rows([row], batch_id="batch_01")

    assert template[0]["human_vulnerable_side"] == "A"
    assert template[0]["evidence_quality"] == "3"
    assert template[0]["selected_window_ids"] == "A1;B1"
    assert template[0]["annotator"] == "test"


def test_annotation_template_rows_can_include_reference_metadata() -> None:
    row = normalize_review_queue_row(_queue_row("p1", rank=1), source_pool="top5", index=0)

    template = annotation_template_rows([row], batch_id="batch_01", include_labels=True)

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


def test_build_manual_evidence_pilot_findings_queues_review_targets() -> None:
    high_quality = normalize_review_queue_row(_queue_row("p1", rank=1, label="A"), source_pool="top5", index=0)
    high_quality["annotation"] = {
        "human_vulnerable_side": "B",
        "evidence_side": "B",
        "evidence_quality": 3,
        "selected_window_ids": ["B1"],
        "label_issue": "none",
        "notes": "visible evidence points to B",
        "annotator": "test",
        "reviewed_at": "2026-05-12T00:00:00Z",
    }
    insufficient = normalize_review_queue_row(_queue_row("p2", rank=2, label="A"), source_pool="fresh", index=1)
    insufficient["annotation"] = {
        "human_vulnerable_side": "unclear",
        "evidence_side": "unclear",
        "evidence_quality": 1,
        "selected_window_ids": ["A1"],
        "label_issue": "insufficient_context",
        "notes": "needs context",
        "annotator": "test",
        "reviewed_at": "2026-05-12T00:00:00Z",
    }

    payload = build_findings([high_quality, insufficient])

    assert payload["high_quality_disagreement_count"] == 1
    assert payload["high_quality_disagreements"][0]["review_action"] == "adjudicate_gold_vs_pilot_direction"
    assert payload["high_quality_disagreements"][0]["priority"] == 1
    assert payload["insufficient_context_count"] == 1
    assert payload["insufficient_context_cases"][0]["review_action"] == "inspect_wider_context_before_direction_label"


def _adjudication_queue_row() -> dict[str, object]:
    return {
        "audit_id": "manual_evidence_audit::demo",
        "queue_type": "high_quality_disagreement",
        "priority": 1,
        "review_action": "adjudicate_gold_vs_pilot_direction",
        "gold_vulnerable_side": "A",
        "pilot_vulnerable_side": "B",
        "evidence_quality": 3,
        "selected_window_ids": ["A1", "B1"],
        "notes": "visible evidence points to B",
    }


def test_adjudication_template_rows_preserve_review_context() -> None:
    template = adjudication_template_rows([_adjudication_queue_row()])

    assert template[0]["audit_id"] == "manual_evidence_audit::demo"
    assert template[0]["queue_type"] == "high_quality_disagreement"
    assert template[0]["selected_window_ids"] == "A1;B1"
    assert template[0]["final_vulnerable_side"] == ""


def test_apply_adjudication_rows_updates_queue_rows() -> None:
    payload = apply_adjudication_rows(
        [_adjudication_queue_row()],
        [
            {
                "audit_id": "manual_evidence_audit::demo",
                "final_vulnerable_side": "B",
                "label_status": "corrected_side",
                "evidence_span_sufficient": "yes",
                "final_evidence_window_ids": "B1",
                "reviewer": "reviewer_a",
                "reviewed_at": "2026-05-13T00:00:00+08:00",
                "rationale": "B contains the unsafe change",
            }
        ],
    )

    assert payload["status"] == "ok"
    assert payload["updated"] == 1
    assert payload["completion_rate"] == 1.0
    assert payload["has_blank_adjudications"] is False
    adjudication = payload["queue_rows"][0]["adjudication"]
    assert adjudication["final_vulnerable_side"] == "B"
    assert adjudication["final_evidence_window_ids"] == ["B1"]


def test_apply_adjudication_rows_reports_blank_template_progress() -> None:
    payload = apply_adjudication_rows(
        [_adjudication_queue_row()],
        [
            {
                "audit_id": "manual_evidence_audit::demo",
                "final_vulnerable_side": "",
                "label_status": "",
                "evidence_span_sufficient": "",
                "final_evidence_window_ids": "",
                "reviewer": "",
                "reviewed_at": "",
                "rationale": "",
            }
        ],
    )

    assert payload["status"] == "ok"
    assert payload["updated"] == 0
    assert payload["skipped_blank"] == 1
    assert payload["completion_rate"] == 0.0
    assert payload["has_blank_adjudications"] is True
    assert "adjudication" not in payload["queue_rows"][0]


def test_apply_adjudication_rows_accepts_unclear_without_final_windows() -> None:
    payload = apply_adjudication_rows(
        [_adjudication_queue_row()],
        [
            {
                "audit_id": "manual_evidence_audit::demo",
                "final_vulnerable_side": "unclear",
                "label_status": "ambiguous",
                "evidence_span_sufficient": "not_applicable",
                "final_evidence_window_ids": "",
                "reviewer": "reviewer_a",
                "reviewed_at": "2026-05-13T00:00:00+08:00",
                "rationale": "Visible context is insufficient for a final side.",
            }
        ],
    )

    assert payload["status"] == "ok"
    adjudication = payload["queue_rows"][0]["adjudication"]
    assert adjudication["final_vulnerable_side"] == "unclear"
    assert adjudication["final_evidence_window_ids"] == []


def test_apply_adjudication_rows_rejects_unknown_audit_id() -> None:
    payload = apply_adjudication_rows(
        [_adjudication_queue_row()],
        [
            {
                "audit_id": "manual_evidence_audit::missing",
                "final_vulnerable_side": "B",
                "label_status": "corrected_side",
                "evidence_span_sufficient": "yes",
                "final_evidence_window_ids": "B1",
            }
        ],
    )

    assert payload["status"] == "failed"
    assert payload["errors"][0]["errors"] == ["unknown_audit_id"]


def test_apply_adjudication_rows_rejects_unknown_final_window_ids() -> None:
    payload = apply_adjudication_rows(
        [_adjudication_queue_row()],
        [
            {
                "audit_id": "manual_evidence_audit::demo",
                "final_vulnerable_side": "B",
                "label_status": "corrected_side",
                "evidence_span_sufficient": "yes",
                "final_evidence_window_ids": "Z9",
            }
        ],
    )

    assert payload["status"] == "failed"
    assert payload["errors"][0]["errors"] == ["final_evidence_window_ids"]


def test_analyze_adjudications_counts_completed_rows() -> None:
    row = _adjudication_queue_row()
    row["adjudication"] = {
        "final_vulnerable_side": "B",
        "label_status": "corrected_side",
        "evidence_span_sufficient": "yes",
        "final_evidence_window_ids": ["B1"],
        "reviewer": "reviewer_a",
        "reviewed_at": "2026-05-13T00:00:00+08:00",
        "rationale": "B contains the unsafe change",
    }

    payload = analyze_adjudications([row])

    assert payload["completed_adjudications"] == 1
    assert payload["label_status_counts"] == {"corrected_side": 1}
    assert payload["evidence_span_sufficiency_counts"] == {"yes": 1}
    assert payload["reviewer_counts"] == {"reviewer_a": 1}


def test_build_draft_adjudications_marks_outputs_non_final() -> None:
    draft_rows = build_draft_adjudications([_adjudication_queue_row()])
    summary = summarize_drafts(draft_rows)

    assert draft_rows[0]["draft_reviewer"] == "codex_draft"
    assert draft_rows[0]["draft_final_vulnerable_side"] == "B"
    assert "final_vulnerable_side" not in draft_rows[0]
    assert summary["is_final_adjudication"] is False


def test_high_quality_adjudication_payload_is_non_final_review_contract() -> None:
    payload = build_high_quality_adjudication_payload([_adjudication_queue_row()])

    assert payload["scope"] == "high_quality_disagreement"
    assert payload["rows"] == 1
    assert payload["is_final_adjudication"] is False
    assert payload["requires_independent_review"] is True
    assert payload["queue_type_counts"] == {"high_quality_disagreement": 1}


def test_high_quality_adjudication_report_points_to_focused_commands() -> None:
    payload = build_high_quality_adjudication_payload([_adjudication_queue_row()])
    report = render_high_quality_adjudication_report(payload)

    assert "High-Quality Evidence Adjudication Workflow" in report
    assert "--dry-run" in report
    assert "secure_code_primevul_manual_evidence_high_quality_adjudication_template_v1.csv" in report
    assert "not independent gold" in report


def test_high_quality_case_brief_summarizes_selected_windows() -> None:
    audit_row = normalize_review_queue_row(_queue_row("p1", rank=1), source_pool="top5", index=0)
    queue_row = _adjudication_queue_row()
    queue_row["audit_id"] = audit_row["audit_id"]
    queue_row["selected_window_ids"] = ["A1"]

    payload = build_high_quality_case_briefs([audit_row], [queue_row])

    assert payload["status"] == "ok"
    assert payload["rows"] == 1
    assert payload["is_final_adjudication"] is False
    assert payload["gold_pilot_conflicts"] == 1
    assert payload["cases"][0]["selected_windows"][0]["window_id"] == "A1"
    assert payload["cases"][0]["decision_questions"]


def test_high_quality_case_brief_report_is_review_guide_not_gold() -> None:
    audit_row = normalize_review_queue_row(_queue_row("p1", rank=1), source_pool="top5", index=0)
    queue_row = _adjudication_queue_row()
    queue_row["audit_id"] = audit_row["audit_id"]
    queue_row["selected_window_ids"] = ["A1"]
    payload = build_high_quality_case_briefs([audit_row], [queue_row])

    report = render_high_quality_case_brief_report(payload)

    assert "High-Quality Adjudication Brief" in report
    assert "not a final label artifact" in report
    assert "Reviewer questions" in report
    assert "Window `A1`" in report


def test_insufficient_context_brief_tracks_mixed_evidence_requests() -> None:
    audit_row = normalize_review_queue_row(_queue_row("p1", rank=1), source_pool="top5", index=0)
    queue_row = _adjudication_queue_row()
    queue_row["audit_id"] = audit_row["audit_id"]
    queue_row["queue_type"] = "insufficient_context"
    queue_row["evidence_side"] = "both"
    queue_row["selected_window_ids"] = ["A1", "B1"]
    queue_row["changed_line_bucket"] = "26+"

    payload = build_insufficient_context_brief([audit_row], [queue_row])

    assert payload["status"] == "ok"
    assert payload["rows"] == 1
    assert payload["is_final_adjudication"] is False
    assert payload["bucket_counts"] == {"26+": 1}
    assert payload["evidence_side_counts"] == {"both": 1}
    assert any(
        "Review surrounding control flow" in request
        for request in payload["cases"][0]["context_requests"]
    )


def test_insufficient_context_brief_report_discourages_guessing() -> None:
    audit_row = normalize_review_queue_row(_queue_row("p1", rank=1), source_pool="top5", index=0)
    queue_row = _adjudication_queue_row()
    queue_row["audit_id"] = audit_row["audit_id"]
    queue_row["queue_type"] = "insufficient_context"
    queue_row["evidence_side"] = "unclear"
    queue_row["selected_window_ids"] = ["A1"]
    payload = build_insufficient_context_brief([audit_row], [queue_row])

    report = render_insufficient_context_brief_report(payload)

    assert "Insufficient-Context Review Brief" in report
    assert "not a final label artifact" in report
    assert "Wider-context requests" in report
    assert "rather than forcing a vulnerable-side decision" in report


def test_manual_adjudication_dashboard_keeps_dry_run_non_final() -> None:
    payload = build_manual_adjudication_dashboard(
        {"rows": 6},
        {"updated": 0, "skipped_blank": 6, "dry_run": True, "errors": []},
        {},
        {"rows": 6, "gold_pilot_conflicts": 6, "model_pilot_conflicts": 4},
        {"rows": 14, "bucket_counts": {"26+": 4}, "evidence_side_counts": {"both": 8}},
    )

    assert payload["is_final_adjudication"] is False
    assert payload["total_rows"] == 20
    assert payload["total_completed"] == 0
    assert payload["human_confirmed_completed"] == 0
    assert payload["overall_completion_rate"] == 0.0
    assert payload["tracks"][0]["status"] == "not_started_dry_run"
    assert payload["tracks"][0]["diagnostics"]["skipped_blank"] == 6


def test_manual_adjudication_dashboard_report_links_both_tracks() -> None:
    payload = build_manual_adjudication_dashboard(
        {"rows": 6},
        {"updated": 0, "skipped_blank": 6, "dry_run": True, "errors": []},
        {},
        {"rows": 6, "gold_pilot_conflicts": 6, "model_pilot_conflicts": 4},
        {"rows": 14, "bucket_counts": {"26+": 4}, "evidence_side_counts": {"both": 8}},
    )

    report = render_manual_adjudication_dashboard_report(payload)

    assert "Manual Adjudication Status Dashboard" in report
    assert "`high_quality_disagreement`" in report
    assert "`insufficient_context`" in report
    assert "not a final adjudication artifact" in report


def test_manual_adjudication_dashboard_separates_ai_from_human_confirmation() -> None:
    payload = build_manual_adjudication_dashboard(
        {"rows": 6},
        {"updated": 6, "skipped_blank": 0, "dry_run": False, "errors": []},
        {
            "label_status_counts": {"corrected_side": 5, "insufficient_context": 1},
            "evidence_span_sufficiency_counts": {"yes": 3, "partial": 2, "no": 1},
            "reviewer_counts": {"codex_ai_adjudication_v1": 6},
        },
        {"rows": 6, "gold_pilot_conflicts": 6, "model_pilot_conflicts": 4},
        {"rows": 14, "bucket_counts": {"26+": 4}, "evidence_side_counts": {"both": 8}},
        {"updated": 14, "skipped_blank": 0, "dry_run": False, "errors": []},
        {"reviewer_counts": {"codex_ai_adjudication_v1": 14}},
    )

    assert payload["total_completed"] == 20
    assert payload["human_confirmed_completed"] == 0
    assert payload["tracks"][0]["status"] == "ai_adjudicated_needs_human_confirmation"
    assert payload["tracks"][1]["status"] == "ai_adjudicated_needs_human_confirmation"
    assert payload["tracks"][0]["diagnostics"]["ai_completed"] == 6
    assert payload["tracks"][1]["diagnostics"]["ai_completed"] == 14
    assert payload["tracks"][0]["diagnostics"]["human_confirmed_completed"] == 0


def test_ai_insufficient_context_adjudication_rows_are_non_final() -> None:
    queue_row = {
        "audit_id": "manual_evidence_audit::7::4::mruby__3cf291f72224715942beaf8553e42ba8891ab3c6__CVE-2022-1212",
        "queue_type": "insufficient_context",
        "priority": 3,
        "review_action": "inspect_wider_context_before_direction_label",
        "gold_vulnerable_side": "B",
        "pilot_vulnerable_side": "unclear",
        "evidence_quality": 0,
        "selected_window_ids": ["A1", "B1"],
    }

    rows = build_ai_insufficient_context_rows([queue_row])
    summary = summarize_ai_insufficient_context_rows(rows)

    assert rows[0]["reviewer"] == "codex_ai_adjudication_v1"
    assert rows[0]["final_vulnerable_side"] == "unclear"
    assert rows[0]["label_status"] == "insufficient_context"
    assert summary["is_final_adjudication"] is False
    assert summary["label_status_counts"] == {"insufficient_context": 1}
