from __future__ import annotations

import importlib.util
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_current_navigation_and_retained_evidence_integrity():
    spec = importlib.util.spec_from_file_location("hygiene", ROOT / "scripts/check_repository_hygiene.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.check_hygiene() == []


def test_generated_manifests_do_not_require_retired_narratives():
    ledger = json.loads((ROOT / "reports/scientific_review_2026_09_07/cleanup_manifest.json").read_text(encoding="utf-8-sig"))
    removed = {item["path"] for item in ledger["removed_files"]}
    for path in (ROOT / "reproducibility").glob("*.json"):
        manifest = json.loads(path.read_text(encoding="utf-8"))
        for item in manifest.get("artifacts", []) + manifest.get("generated_artifacts", []):
            assert item["path"] not in removed, (path.name, item["path"])


def test_known_scientific_failures_remain_visible():
    snapshot = json.loads((ROOT / "reports/scientific_review_2026_09_07/audit_results.json").read_text(encoding="utf-8"))
    assert snapshot["raw_repair_gate"]["all_applicable_passed"] is False
    assert snapshot["manifest_check"]["status"] == "failed"
    assert snapshot["nuisance_visibility"]["canonical__split_view"]["zero_critical_lines"] == 600


def test_evidence_accepts_only_recorded_byte_representations(tmp_path):
    spec = importlib.util.spec_from_file_location("hygiene", ROOT / "scripts/check_repository_hygiene.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for relative in ["README.md", "REPRODUCIBILITY.md", "data/README.md", "paper/README.md",
                     "reproducibility/README.md", module.REVIEW]:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")
    (tmp_path / "configs").mkdir()
    (tmp_path / "configs/report_index.json").write_text('{"sections":[]}', encoding="utf-8")
    (tmp_path / "reports/scientific_review_2026_09_07/cleanup_manifest.json").write_text(
        '{"removed_files":[]}', encoding="utf-8")
    windows, git = b'{"value": 1}\r\n', b'{"value": 1}\n'
    item = {"path": "reports/evidence.json", "sha256": hashlib.sha256(windows).hexdigest(),
            "git_blob_sha256": hashlib.sha256(git).hexdigest()}
    (tmp_path / "reports/evidence_inventory.json").write_text(
        json.dumps({"artifacts": [item]}), encoding="utf-8")
    target = tmp_path / item["path"]
    for data in [windows, git]:
        target.write_bytes(data)
        assert module.check_hygiene(tmp_path) == []
    target.write_bytes(b'{"value": 2}\n')
    assert module.check_hygiene(tmp_path) == ["Historical evidence bytes changed: reports/evidence.json"]
