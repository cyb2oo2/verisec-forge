import importlib.util
from pathlib import Path


def load_script():
    path = Path("scripts/build_cross_model_relational_audit.py")
    spec = importlib.util.spec_from_file_location("cross_model_audit", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


def test_cross_model_protocol_has_eight_high_information_variants():
    module = load_script()

    assert len(module.PRIMARY_VARIANTS) == 8
    assert "padding_mid_diff_malformed_stress" not in module.PRIMARY_VARIANTS
    assert "padding_post_diff_terminal_phrase" in module.PRIMARY_VARIANTS
    assert "training_prompt_side_swap" in module.PRIMARY_VARIANTS
