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
            "pair_length": 10,
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


def test_nuisance_selection_is_stable_and_supported():
    module = _load_script()
    interventions = ["identifier_normalized", "nonsecurity_padding"]

    selected = module.select_nuisance_intervention("pair-a", interventions)

    assert selected == module.select_nuisance_intervention("pair-a", interventions)
    transformed = module.nuisance_transform(
        "Task: keep this\n--- Side A\n+++ Side B\n-old_name\n+new_name",
        "identifier_normalized",
    )
    assert "Task: keep this" in transformed
    assert "old_name" not in transformed


def test_deterministic_pair_subset_is_order_independent():
    module = _load_script()
    rows = [{"pair_key": key} for key in ["c", "a", "d", "b"]]

    selected = module.deterministic_pair_subset(rows, 2)
    selected_reversed = module.deterministic_pair_subset(list(reversed(rows)), 2)

    assert selected == selected_reversed
    assert len(selected) == 2


def test_length_bucket_order_keeps_nearby_lengths_together():
    module = _load_script()
    rows = [{"pair_key": str(index), "pair_length": index} for index in range(16)]

    ordered = module.length_bucket_order(rows, seed=42, bucket_size=4)

    assert sorted(row["pair_key"] for row in ordered) == sorted(row["pair_key"] for row in rows)
    for start in range(0, len(ordered), 4):
        lengths = [row["pair_length"] for row in ordered[start : start + 4]]
        assert max(lengths) - min(lengths) <= 3
