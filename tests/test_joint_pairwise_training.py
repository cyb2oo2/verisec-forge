import importlib.util
from pathlib import Path


def _load_script():
    path = Path(__file__).parents[1] / "scripts" / "train_joint_pairwise_classifier.py"
    spec = importlib.util.spec_from_file_location("train_joint_pairwise_classifier", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_pair_records_requires_both_orientations():
    module = _load_script()
    rows = [
        {"pair_key": "complete", "label": 0, "text": "safe"},
        {"pair_key": "complete", "label": 1, "text": "vulnerable"},
        {"pair_key": "incomplete", "label": 1, "text": "only one"},
    ]
    assert module.pair_records(rows) == [
        {
            "pair_key": "complete",
            "safe_candidate_text": "safe",
            "vulnerable_candidate_text": "vulnerable",
        }
    ]
