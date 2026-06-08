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


def test_reverse_view_is_available_for_consistency_training():
    module = _load_script()
    text = (
        "Task: compare two versions of the same code change.\n"
        "The unified diff transforms Side A into Side B.\n"
        "Predict which side contains the security vulnerability.\n\n"
        "--- Side A\n+++ Side B\n@@ -1 +1 @@\n-bad\n+good"
    )
    reversed_text = module.reverse_side_choice_text(text)
    assert "@@ -1 +1 @@" in reversed_text
    assert "+bad\n-good" in reversed_text
