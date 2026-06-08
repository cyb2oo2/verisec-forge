import importlib.util
from pathlib import Path


def _load_script():
    path = Path(__file__).parents[1] / "scripts" / "build_primevul_real_joint_side_choice_train.py"
    spec = importlib.util.spec_from_file_location("build_primevul_real_joint_side_choice_train", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_real_bidirectional_rows_use_adjacent_pairs_and_exclusion():
    module = _load_script()
    vuln = {"id": "v", "project": "p", "commit_id": "c", "cve": "CVE-1", "code": "bad();", "has_vulnerability": True}
    safe = {"id": "s", "project": "p", "commit_id": "c", "cve": "CVE-1", "code": "good();", "has_vulnerability": False}
    rows, summary = module.build_real_bidirectional_rows([vuln, safe], excluded_source_keys=set())
    assert len(rows) == 2
    assert {row["label"] for row in rows} == {0, 1}
    assert rows[0]["pair_key"] == rows[1]["pair_key"]
    assert summary["real_pair_instances"] == 1

    excluded, excluded_summary = module.build_real_bidirectional_rows([vuln, safe], excluded_source_keys={"p|c|CVE-1"})
    assert excluded == []
    assert excluded_summary["skipped_excluded"] == 1
