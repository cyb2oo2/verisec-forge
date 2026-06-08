import importlib.util
from pathlib import Path


def _load_script():
    path = Path(__file__).parents[1] / "scripts" / "analyze_synthetic_reverse_fidelity.py"
    spec = importlib.util.spec_from_file_location("analyze_synthetic_reverse_fidelity", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_percentile_handles_boundaries():
    module = _load_script()
    values = [0.1, 0.2, 0.3, 0.4]
    assert module.percentile(values, 0.0) == 0.1
    assert module.percentile(values, 0.5) == 0.3
    assert module.percentile(values, 1.0) == 0.4
