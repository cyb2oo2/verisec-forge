import importlib.util
from pathlib import Path


def _load_script():
    path = Path(__file__).parents[1] / "scripts" / "compare_joint_pairwise_variants.py"
    spec = importlib.util.spec_from_file_location("compare_joint_pairwise_variants", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_compare_counts_repaired_and_introduced():
    module = _load_script()
    result = module.compare(
        {"a": False, "b": True, "c": True},
        {"a": True, "b": False, "c": True},
    )
    assert result["repaired"] == 1
    assert result["introduced"] == 1
    assert result["delta"] == 0.0
    assert result["mcnemar_exact_pvalue"] == 1.0
