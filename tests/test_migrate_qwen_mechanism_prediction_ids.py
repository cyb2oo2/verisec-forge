import importlib.util
from pathlib import Path


def load_script():
    path = Path("scripts/migrate_qwen_mechanism_prediction_ids.py")
    spec = importlib.util.spec_from_file_location("migrate_predictions", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


def test_migrate_only_changes_renamed_variant_suffixes():
    module = load_script()
    rows = module.migrate(
        [
            {"id": "audit::x::padding_mid_diff"},
            {"id": "audit::x::padding_post_diff_restored_ending"},
            {"id": "audit::x::canonical"},
        ]
    )

    assert rows[0]["id"].endswith("padding_mid_diff_malformed_stress")
    assert rows[1]["id"].endswith("padding_post_diff_terminal_phrase")
    assert rows[2]["id"].endswith("canonical")
