from scripts import build_patch_review_walkthrough as walkthrough


def _demo_payload():
    return {
        "pair_key": "demo|commit|CVE-0000-0001",
        "pair_decision": {
            "riskier_side_id": "risk",
            "safer_side_id": "safe",
            "probability_gap": 0.8,
            "pair_coupled": True,
        },
        "rows": [
            {
                "id": "risk",
                "decision": "vulnerable",
                "gold_label": "vulnerable",
                "correct_on_benchmark": True,
                "vulnerability_probability": 0.9,
                "support_label": "supported",
                "risk_support": 2,
                "safety_support": 0,
                "evidence_windows": [
                    {
                        "header": "@@ demo @@",
                        "direction_labels": ["candidate_removes_protection"],
                        "risk_support": 2,
                        "safety_support": 0,
                        "removed": "if (ok) return;",
                        "added": "DCHECK(ok);",
                    }
                ],
            },
            {
                "id": "safe",
                "decision": "safe",
                "gold_label": "safe",
                "correct_on_benchmark": True,
                "vulnerability_probability": 0.1,
                "support_label": "supported",
                "risk_support": 0,
                "safety_support": 2,
                "evidence_windows": [
                    {
                        "header": "@@ demo @@",
                        "direction_labels": ["candidate_adds_protection"],
                        "risk_support": 0,
                        "safety_support": 2,
                        "removed": "DCHECK(ok);",
                        "added": "if (ok) return;",
                    }
                ],
            },
        ],
    }


def test_patch_review_walkthrough_builds_default_example(monkeypatch):
    monkeypatch.setattr(walkthrough, "list_demo_examples", lambda limit=1: [{"pair_key": "demo|commit|CVE-0000-0001"}])
    monkeypatch.setattr(walkthrough, "build_patch_review_demo", lambda **_kwargs: _demo_payload())

    payload = walkthrough.build_walkthrough()

    assert payload["status"] == "ok"
    assert payload["selected_pair_key"] == "demo|commit|CVE-0000-0001"
    assert payload["row_summaries"][0]["top_evidence_direction"] == ["candidate_removes_protection"]


def test_patch_review_walkthrough_markdown_explains_boundary():
    payload = {
        "status": "ok",
        "walkthrough_type": "artifact_backed_external_validation_walkthrough",
        "selected_pair_key": "demo|commit|CVE-0000-0001",
        "pair_decision": _demo_payload()["pair_decision"],
        "row_summaries": [],
        "full_payload": _demo_payload(),
    }

    markdown = walkthrough.render_markdown(payload)

    assert markdown.startswith("# Patch Review External-Validation Walkthrough")
    assert "Pair-coupled decoding applied: `true`" in markdown
    assert "candidate_removes_protection" in markdown
    assert "not arbitrary online vulnerability scanning" in markdown
