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
