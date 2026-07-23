from vrf.pair_annotation import (
    DEFAULT_SINGLE_AUTHOR_SAMPLE_SIZE,
    DEFAULT_SINGLE_AUTHOR_SEED,
    STUDY_ID_SINGLE_AUTHOR_50,
    analyze_independent_annotations,
    apply_adjudications,
    build_blinded_packet,
    empty_adjudication_template_rows,
    exact_dual_agreement_rows,
    is_answer_complete,
    normalize_side_label,
    not_applicable_agreement_report,
    packet_contains_identity_leak,
    paper_claim_boundary_statement,
    scrub_packet_diff_text,
    select_high_value_pairs,
    single_author_claim_boundary,
    single_author_study_id,
    single_author_study_status,
    study_status,
    validate_answer_row,
    validate_answer_rows,
)


def test_select_high_value_pairs_preserves_unique_pairs():
    rows = [
        {"pair_key": f"pair-{index}", "model_pair_correct": index % 5 != 0, "probability_gap": index / 20, "changed_lines": index}
        for index in range(20)
    ]
    selected = select_high_value_pairs(rows, sample_size=10, seed=7)
    assert len(selected) == 10
    assert len({row["pair_key"] for row in selected}) == 10
    assert {row["selection_stratum"] for row in selected}


def test_scrub_packet_diff_text_removes_project_cve_cwe():
    raw = (
        "Task: decide whether the candidate side of this diff is the vulnerable version.\n"
        "Project: libmobi\n"
        "CVE: CVE-2022-1533\n"
        "CWE: cwe-787\n"
        "\n"
        "Unified diff:\n"
        "--- a\n"
        "+++ b\n"
        "-bad\n"
        "+good\n"
    )
    scrubbed = scrub_packet_diff_text(raw)
    assert "Project:" not in scrubbed
    assert "CVE:" not in scrubbed
    assert "CWE:" not in scrubbed
    assert "CVE-2022-1533" not in scrubbed
    assert "Unified diff:" in scrubbed
    assert "+good" in scrubbed


def test_blinded_packets_exclude_gold_fields_and_identity_metadata():
    pair = {
        "pair_key": "project|commit|CVE",
        "gold_vulnerable_id": "vuln",
        "selection_stratum": "model_error",
        "rows": [
            {
                "id": "safe",
                # Identity can appear in code comments too — must be scrubbed for Code view.
                "code": "/* CVE-2022-1533 CWE-787 Project: libmobi */\nint safe(void) { return 0; }\n",
                "pair_text": "Project: x\nCVE: CVE-1\nCWE: cwe-1\nUnified diff:\n+safe\n",
            },
            {
                "id": "vuln",
                "code": "/* CVE-2022-1533 */\nint vuln(void) { return 1; }\n",
                "pair_text": "Project: x\nCVE: CVE-1\nCWE: cwe-1\nUnified diff:\n+vuln\n",
            },
        ],
    }
    packet, answers, mappings = build_blinded_packet([pair], annotator_id="reviewer_1", seed=42)
    assert "gold_vulnerable_id" not in packet[0]
    assert "project" not in packet[0]
    assert answers[0]["vulnerable_side"] == ""
    assert mappings[0]["gold_vulnerable_id"] == "vuln"
    assert packet_contains_identity_leak(packet[0]) == []
    for side_key in ("side_a", "side_b"):
        code = str((packet[0].get(side_key) or {}).get("code") or "")
        assert "CVE-2022-1533" not in code
        assert "CWE-787" not in code
        assert "Project:" not in code
        assert "libmobi" not in code


def test_agreement_maps_randomized_sides_to_canonical_ids():
    mappings = [
        {"case_id": "a-case", "annotator_id": "a", "pair_key": "pair", "side_a_id": "vuln", "side_b_id": "safe"},
        {"case_id": "b-case", "annotator_id": "b", "pair_key": "pair", "side_a_id": "safe", "side_b_id": "vuln"},
    ]
    rows_a = [
        {
            "case_id": "a-case",
            "annotator_id": "a",
            "vulnerable_side": "A",
            "root_cause": "bounds",
            "minimal_evidence_lines": "A:1-2",
            "context_sufficient": "yes",
            "confidence": "4",
        }
    ]
    rows_b = [
        {
            "case_id": "b-case",
            "annotator_id": "b",
            "vulnerable_side": "B",
            "root_cause": "bounds",
            "minimal_evidence_lines": "B:1-2",
            "context_sufficient": "yes",
            "confidence": "4",
        }
    ]
    report = analyze_independent_annotations(rows_a, rows_b, mappings)
    assert report["dual_complete_n"] == 1
    assert report["side_exact_agreement"] == 1.0
    assert report["context_exact_agreement"] == 1.0
    assert report["disagreement_count"] == 0
    assert report["side_cohen_kappa"] == 1.0


def test_empty_answers_do_not_yield_spurious_kappa():
    mappings = [
        {"case_id": "a-case", "annotator_id": "annotator_1", "pair_key": "pair", "side_a_id": "v", "side_b_id": "s", "selection_stratum": "control"},
        {"case_id": "b-case", "annotator_id": "annotator_2", "pair_key": "pair", "side_a_id": "v", "side_b_id": "s", "selection_stratum": "control"},
    ]
    empty_a = [{"case_id": "a-case", "annotator_id": "annotator_1", "vulnerable_side": "", "context_sufficient": ""}]
    empty_b = [{"case_id": "b-case", "annotator_id": "annotator_2", "vulnerable_side": "", "context_sufficient": ""}]
    report = analyze_independent_annotations(empty_a, empty_b, mappings)
    assert report["status"] == "annotation_pending"
    assert report["dual_complete_n"] == 0
    assert report["side_cohen_kappa"] is None
    assert report["context_cohen_kappa"] is None
    assert report["publishable_gate_met"] is False


def test_disagreement_taxonomy_and_status_partial():
    mappings = [
        {
            "case_id": "a1",
            "annotator_id": "annotator_1",
            "pair_key": "p1",
            "side_a_id": "v",
            "side_b_id": "s",
            "selection_stratum": "model_error",
        },
        {
            "case_id": "b1",
            "annotator_id": "annotator_2",
            "pair_key": "p1",
            "side_a_id": "v",
            "side_b_id": "s",
            "selection_stratum": "model_error",
        },
    ]
    complete = {
        "root_cause": "overflow",
        "minimal_evidence_lines": "A:1",
        "confidence": "3",
    }
    rows_a = [
        {
            "case_id": "a1",
            "annotator_id": "annotator_1",
            "vulnerable_side": "A",
            "context_sufficient": "yes",
            **complete,
        }
    ]
    rows_b = [
        {
            "case_id": "b1",
            "annotator_id": "annotator_2",
            "vulnerable_side": "B",
            "context_sufficient": "yes",
            **complete,
        }
    ]
    report = analyze_independent_annotations(rows_a, rows_b, mappings, minimum_publishable_dual_complete=100)
    assert report["dual_complete_n"] == 1
    assert report["status"] == "partial"
    assert report["disagreement_count"] == 1
    assert report["disagreements"][0]["taxonomy"] == "side_only"


def test_validate_and_complete_helpers():
    assert not is_answer_complete({"vulnerable_side": "A"})
    assert is_answer_complete(
        {
            "vulnerable_side": "A",
            "root_cause": "x",
            "minimal_evidence_lines": "A:1",
            "context_sufficient": "yes",
            "confidence": "5",
        }
    )
    # Case-insensitive sides: complete + validate + normalize agree.
    assert is_answer_complete(
        {
            "vulnerable_side": "a",
            "root_cause": "x",
            "minimal_evidence_lines": "A:1",
            "context_sufficient": "Yes",
            "confidence": "5",
        }
    )
    assert normalize_side_label("a") == "A"
    assert normalize_side_label("Neither") == "neither"
    assert validate_answer_row({"case_id": "c0", "vulnerable_side": "b"}) == []
    result = validate_answer_rows(
        [{"case_id": "c1", "vulnerable_side": "Z", "context_sufficient": "maybe", "confidence": "9"}]
    )
    assert result["status"] == "error"
    assert result["error_count"] >= 1


def test_lowercase_side_labels_map_to_canonical_agreement():
    mappings = [
        {"case_id": "a-case", "annotator_id": "a", "pair_key": "pair", "side_a_id": "vuln", "side_b_id": "safe"},
        {"case_id": "b-case", "annotator_id": "b", "pair_key": "pair", "side_a_id": "safe", "side_b_id": "vuln"},
    ]
    complete = {
        "root_cause": "bounds",
        "minimal_evidence_lines": "A:1",
        "context_sufficient": "yes",
        "confidence": "4",
    }
    # Lowercase "a"/"b" must not break dual-complete canonical mapping.
    rows_a = [{"case_id": "a-case", "annotator_id": "a", "vulnerable_side": "a", **complete}]
    rows_b = [{"case_id": "b-case", "annotator_id": "b", "vulnerable_side": "b", **complete}]
    report = analyze_independent_annotations(rows_a, rows_b, mappings)
    assert report["dual_complete_n"] == 1
    assert report["side_exact_agreement"] == 1.0


def test_study_status_empty():
    mappings = [
        {
            "case_id": "a",
            "annotator_id": "annotator_1",
            "pair_key": "p",
            "side_a_id": "1",
            "side_b_id": "2",
            "selection_stratum": "control",
        },
        {
            "case_id": "b",
            "annotator_id": "annotator_2",
            "pair_key": "p",
            "side_a_id": "1",
            "side_b_id": "2",
            "selection_stratum": "control",
        },
    ]
    status = study_status(
        [{"case_id": "a", "annotator_id": "annotator_1"}],
        [{"case_id": "b", "annotator_id": "annotator_2"}],
        mappings,
        target_pairs=1,
    )
    assert status["dual_complete_n"] == 0
    assert status["engineering_scaffold_ready"] is True
    assert status["human_annotation_complete"] is False


def test_select_high_value_pairs_exact_50_stratified():
    rows = []
    for index in range(100):
        rows.append(
            {
                "pair_key": f"pair-{index}",
                "model_pair_correct": index % 5 != 0,
                "probability_gap": (index % 20) / 20,
                "changed_lines": 5 + (index % 40),
            }
        )
    selected = select_high_value_pairs(rows, sample_size=50, seed=20260720)
    assert len(selected) == 50
    assert len({row["pair_key"] for row in selected}) == 50
    strata = {row["selection_stratum"] for row in selected}
    assert strata  # all assigned
    # All five strata should appear when pool is rich enough.
    assert len(strata) == 5


def test_single_author_study_id_tracks_sample_size_and_seed():
    assert (
        single_author_study_id(DEFAULT_SINGLE_AUTHOR_SAMPLE_SIZE, DEFAULT_SINGLE_AUTHOR_SEED)
        == STUDY_ID_SINGLE_AUTHOR_50
    )
    assert single_author_study_id(30, DEFAULT_SINGLE_AUTHOR_SEED) == "primevul_pair_study_author30_s20260720_v1"
    assert single_author_study_id(50, 1) == "primevul_pair_study_author50_s1_v1"
    boundary = single_author_claim_boundary(30)
    assert boundary["sample_size"] == 30
    assert "30-pair" in paper_claim_boundary_statement(30)


def test_not_applicable_agreement_report_blocks_stale_dual_iaa():
    report = not_applicable_agreement_report()
    assert report["status"] == "not_applicable_single_author"
    assert report["dual_complete_n"] == 0
    assert report["side_cohen_kappa"] is None
    assert report["paired_annotations"] == 0
    assert report["claim_boundary"]["no_inter_annotator_agreement"] is True
    md = __import__("vrf.pair_annotation", fromlist=["render_agreement_markdown"]).render_agreement_markdown(
        report
    )
    assert "not_applicable_single_author" in md
    assert "Not applicable" in md


def test_single_author_study_status_pending_and_complete():
    mappings = [
        {
            "case_id": "pair-001",
            "annotator_id": "author",
            "pair_key": "p1",
            "side_a_id": "v",
            "side_b_id": "s",
            "selection_stratum": "control",
        }
    ]
    empty = single_author_study_status(
        [{"case_id": "pair-001", "annotator_id": "author", "vulnerable_side": ""}],
        mappings,
        target_pairs=1,
        seed=99,
    )
    assert empty["status"] == "annotation_pending"
    assert empty["author_complete_n"] == 0
    assert empty["inter_annotator_agreement"] is None
    assert empty["claim_boundary"]["single_author_annotator"] is True
    assert empty["claim_boundary"]["sample_size"] == 1
    assert empty["study_id"] == single_author_study_id(1, 99)
    assert "1-pair" in empty["paper_claim_boundary_statement"]
    assert "dual-rater" in empty["paper_claim_boundary_statement"].lower() or "dual" in empty["paper_claim_boundary_statement"].lower()

    filled = single_author_study_status(
        [
            {
                "case_id": "pair-001",
                "annotator_id": "author",
                "vulnerable_side": "A",
                "root_cause": "bounds",
                "minimal_evidence_lines": "A:1",
                "context_sufficient": "yes",
                "confidence": "4",
            }
        ],
        mappings,
        target_pairs=1,
        seed=99,
    )
    assert filled["status"] == "ok"
    assert filled["author_complete_n"] == 1
    assert filled["publishable_gate_met"] is True


def test_apply_adjudications_requires_human_fields():
    disagreements = [
        {
            "pair_key": "p1",
            "taxonomy": "side_only",
            "annotator_a_side": "canonical_0",
            "annotator_b_side": "canonical_1",
        }
    ]
    mappings = [{"pair_key": "p1", "gold_vulnerable_id": "v1", "side_a_id": "v1", "side_b_id": "s1"}]
    empty = apply_adjudications(disagreements, empty_adjudication_template_rows(disagreements), mappings)
    assert empty["status"] == "incomplete"
    assert empty["missing_disagreement_pair_keys"] == ["p1"]

    filled = apply_adjudications(
        disagreements,
        [
            {
                "pair_key": "p1",
                "consensus_vulnerable_side_id": "v1",
                "consensus_context_sufficient": "yes",
                "adjudicator_id": "adj_3",
                "adjudication_basis": "diff shows missing bounds check on side v1",
                "taxonomy": "side_only",
            }
        ],
        mappings,
    )
    assert filled["status"] == "ok"
    assert filled["all_disagreements_adjudicated"] is True
    assert filled["consensus"][0]["source"] == "human_adjudication"


def test_full_consensus_includes_exact_agreements_and_adjudications():
    """human_gold_consensus must include dual agreements, not only adjudicated disputes."""
    mappings = [
        {
            "case_id": "a1",
            "annotator_id": "annotator_1",
            "pair_key": "agree",
            "side_a_id": "v_agree",
            "side_b_id": "s_agree",
            "gold_vulnerable_id": "v_agree",
            "selection_stratum": "control",
        },
        {
            "case_id": "b1",
            "annotator_id": "annotator_2",
            "pair_key": "agree",
            "side_a_id": "v_agree",
            "side_b_id": "s_agree",
            "gold_vulnerable_id": "v_agree",
            "selection_stratum": "control",
        },
        {
            "case_id": "a2",
            "annotator_id": "annotator_1",
            "pair_key": "disagree",
            "side_a_id": "v_d",
            "side_b_id": "s_d",
            "gold_vulnerable_id": "v_d",
            "selection_stratum": "model_error",
        },
        {
            "case_id": "b2",
            "annotator_id": "annotator_2",
            "pair_key": "disagree",
            "side_a_id": "v_d",
            "side_b_id": "s_d",
            "gold_vulnerable_id": "v_d",
            "selection_stratum": "model_error",
        },
    ]
    complete = {
        "root_cause": "overflow",
        "minimal_evidence_lines": "A:1",
        "context_sufficient": "yes",
        "confidence": "4",
    }
    annotations_a = [
        {"case_id": "a1", "annotator_id": "annotator_1", "vulnerable_side": "A", **complete},
        {"case_id": "a2", "annotator_id": "annotator_1", "vulnerable_side": "A", **complete},
    ]
    annotations_b = [
        {"case_id": "b1", "annotator_id": "annotator_2", "vulnerable_side": "A", **complete},
        {"case_id": "b2", "annotator_id": "annotator_2", "vulnerable_side": "B", **complete},
    ]
    agreements = exact_dual_agreement_rows(annotations_a, annotations_b, mappings)
    assert len(agreements) == 1
    assert agreements[0]["pair_key"] == "agree"
    assert agreements[0]["consensus_vulnerable_side_id"] == "v_agree"
    assert agreements[0]["source"] == "exact_dual_agreement"

    report = analyze_independent_annotations(annotations_a, annotations_b, mappings)
    result = apply_adjudications(
        report["disagreements"],
        [
            {
                "pair_key": "disagree",
                "consensus_vulnerable_side_id": "v_d",
                "consensus_context_sufficient": "yes",
                "adjudicator_id": "adj",
                "adjudication_basis": "manual",
            }
        ],
        mappings,
        exact_agreements=agreements,
    )
    assert result["status"] == "ok"
    assert result["exact_agreement_count"] == 1
    assert result["adjudicated_disagreement_count"] == 1
    assert result["consensus_count"] == 2
    sources = {row["pair_key"]: row["source"] for row in result["consensus"]}
    assert sources["agree"] == "exact_dual_agreement"
    assert sources["disagree"] == "human_adjudication"
