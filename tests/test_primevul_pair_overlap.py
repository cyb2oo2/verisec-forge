from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_module():
    script_path = Path("scripts") / "check_primevul_pair_overlap.py"
    spec = importlib.util.spec_from_file_location("check_primevul_pair_overlap", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_overlap_report_detects_exact_pair_text_overlap() -> None:
    module = _load_module()
    train_rows = [
        {
            "id": "train-1",
            "pair_key": "proj|commit|cve",
            "pair_text": "Unified diff:\n@@\n-old\n+new\n",
        }
    ]
    eval_rows = [
        {
            "id": "eval-1",
            "pair_key": "proj|commit|cve",
            "pair_text": "Unified diff:\n@@\n-old\n+new\n",
        }
    ]

    report = module.build_report(train_rows, eval_rows, threshold=0.95)

    assert report["field_overlaps"][1]["field"] == "pair_key"
    assert report["field_overlaps"][1]["overlap_count"] == 1
    assert report["exact_pair_text_overlap"]["overlap_count"] == 1
    assert report["exact_normalized_diff_overlap"]["overlap_count"] == 1
    assert report["near_duplicate_diff_scan"]["match_count_at_or_above_threshold_limited"] == 1


def test_overlap_report_ignores_different_pair_keys_for_near_duplicate_scan() -> None:
    module = _load_module()
    train_rows = [
        {
            "id": "train-1",
            "pair_key": "proj|commit-a|cve",
            "pair_text": "Unified diff:\n@@\n-old\n+new\n",
        }
    ]
    eval_rows = [
        {
            "id": "eval-1",
            "pair_key": "proj|commit-b|cve",
            "pair_text": "Unified diff:\n@@\n-old\n+new\n",
        }
    ]

    report = module.build_report(train_rows, eval_rows, threshold=0.95)

    assert report["exact_pair_text_overlap"]["overlap_count"] == 1
    assert report["near_duplicate_diff_scan"]["match_count_at_or_above_threshold_limited"] == 0
