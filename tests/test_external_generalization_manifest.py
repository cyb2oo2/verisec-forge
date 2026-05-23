from scripts import build_external_generalization_manifest as manifest_script


def test_external_generalization_manifest_declares_inputs_and_expected_metrics(monkeypatch):
    def fake_artifact_entry(role, path, note):
        return {
            "role": role,
            "path": path,
            "sha256": "0" * 64,
            "bytes": 1,
            "note": note,
        }

    monkeypatch.setattr(manifest_script, "artifact_entry", fake_artifact_entry)
    payload = manifest_script.build_manifest()

    assert payload["name"] == "external_generalization_and_source_routing_v1"
    assert payload["artifacts"]
    assert payload["generated_artifacts"]
    assert payload["expected"]["three_source_source_routed_ba"] == 0.8664
    assert any(item["role"] == "learned_content_source_router_report" for item in payload["generated_artifacts"])
    assert any(item["role"] == "learned_content_router_leave_one_source_report" for item in payload["generated_artifacts"])
    assert any(item["role"] == "learned_content_router_feature_ablation_report" for item in payload["generated_artifacts"])
    assert any(item["role"] == "learned_content_router_stability_char_report" for item in payload["generated_artifacts"])
    assert any(item["role"] == "learned_content_router_stability_token_report" for item in payload["generated_artifacts"])
    assert any(item["role"] == "learned_content_router_stability_report" for item in payload["generated_artifacts"])
    assert any(item["role"] == "learned_content_router_stability_summary" for item in payload["generated_artifacts"])
    assert any(item["role"] == "learned_content_router_stability_figure" for item in payload["generated_artifacts"])
    assert any(item["role"] == "learned_router_claim_boundary_report" for item in payload["generated_artifacts"])
    assert any(item["role"] == "learned_router_claim_boundary_figure" for item in payload["generated_artifacts"])
    assert payload["expected"]["leave_one_source_primevul_routed_minus_oracle_ba"] == -0.025
    assert payload["expected"]["feature_ablation_diff_line_routed_ba"] == 0.8649
    assert payload["expected"]["stability_char_half_train_ba_mean"] == 0.8649
    assert payload["expected"]["stability_token_half_train_ba_mean"] == 0.863
    assert payload["expected"]["stability_diff_line_half_train_ba_mean"] == 0.8634
    assert payload["expected"]["claim_boundary_closed_world_ba_delta"] == 0.0073
