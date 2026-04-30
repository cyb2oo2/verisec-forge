from __future__ import annotations

import importlib.util
from pathlib import Path


def test_pair_coupled_statistics_module_loads() -> None:
    script_path = Path("scripts") / "analyze_primevul_pair_coupled_statistics.py"
    spec = importlib.util.spec_from_file_location("analyze_primevul_pair_coupled_statistics", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    payload = {
        "bootstrap": {
            "bucket_router": {
                "group_all_correct": {"observed": 0.7, "ci95_low": 0.6, "ci95_high": 0.8, "units": 10}
            },
            "pair_coupled": {
                "group_all_correct": {"observed": 0.8, "ci95_low": 0.7, "ci95_high": 0.9, "units": 10}
            },
        },
        "delta": {
            "group_all_correct": {"observed_delta": 0.1, "ci95_low": 0.0, "ci95_high": 0.2}
        },
        "sign_tests": {
            "group_all_correct": {"wins": 3, "losses": 1, "two_sided_p_value": 0.5}
        },
    }

    markdown = module.render_markdown(payload)

    assert "Pair-Coupled Minus Bucket Router" in markdown
    assert "group_all_correct" in markdown
