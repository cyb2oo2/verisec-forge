from vrf.joint_reasoning import build_joint_pair_record, summarize_joint_records


def _pair(pair_key):
    return build_joint_pair_record(
        pair_key,
        [
            {"id": f"{pair_key}-safe", "has_vulnerability": False, "code": "safe", "pair_text": "safe diff"},
            {"id": f"{pair_key}-vuln", "has_vulnerability": True, "code": "vuln", "pair_text": "vuln diff"},
        ],
        {
            f"{pair_key}-safe": {"support_label": "supported", "top_hunks": [{"header": "safe"}]},
            f"{pair_key}-vuln": {"support_label": "supported", "top_hunks": [{"header": "vuln"}]},
        },
    )


def test_joint_record_exposes_all_four_targets_and_masks():
    record = _pair("pair-1")
    assert record["side_choice_target"] in {"A", "B"}
    assert record["side_a"]["evidence_candidates"]
    assert record["loss_mask"] == {
        "side_choice": True,
        "evidence_ranking": True,
        "confidence": True,
        "insufficient_context": True,
    }
    assert record["insufficient_context_target"] is False


def test_joint_side_assignment_is_deterministic_but_not_constant():
    summary = summarize_joint_records([_pair(f"pair-{index}") for index in range(30)])
    assert set(summary["side_choice_counts"]) == {"A", "B"}
    assert sum(summary["side_choice_counts"].values()) == 30
