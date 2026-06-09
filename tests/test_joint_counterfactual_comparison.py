import importlib.util
from pathlib import Path


def _load_script():
    path = Path(__file__).parents[1] / "scripts" / "compare_joint_counterfactual_variants.py"
    spec = importlib.util.spec_from_file_location("compare_joint_counterfactual_variants", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_summarize_averages_invariant_rates():
    module = _load_script()
    interventions = {
        name: {"unexpected_change_rate": value, "base_expected_label_accuracy": 0.8}
        for name, value in [
            ("format_normalized", 0.1),
            ("identifier_normalized", 0.2),
            ("metadata_removed", 0.3),
            ("nonsecurity_padding", 0.4),
            ("side_order_swapped", 0.5),
            ("context_truncated", 0.6),
        ]
    }
    summary = module.summarize({"by_intervention": interventions})
    assert summary["mean_invariant_unexpected_change_rate"] == 0.25
    assert summary["side_order_violation_rate"] == 0.5
