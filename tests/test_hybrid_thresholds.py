from __future__ import annotations

import importlib.util
from pathlib import Path
from uuid import uuid4

from vrf.io_utils import write_jsonl


def _load_module():
    script_path = Path("scripts") / "evaluate_codexglue_hybrid_thresholds.py"
    spec = importlib.util.spec_from_file_location("evaluate_codexglue_hybrid_thresholds", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_build_hybrid_rows_normalizes_dict_evidence() -> None:
    module = _load_module()

    tmp_path = Path(".tmp_test_runs") / f"hybrid-thresholds-{uuid4().hex}"
    tmp_path.mkdir(parents=True, exist_ok=True)

    dataset_path = tmp_path / "dataset.jsonl"
    probs_path = tmp_path / "probs.jsonl"
    auditor_path = tmp_path / "auditor.jsonl"

    write_jsonl(
        dataset_path,
        [
            {
                "id": "sample-1",
                "task_type": "weakness_identification",
                "prompt": "Analyze code",
                "code": "memcpy(dst, src, len);",
                "language": "c",
                "split": "eval",
                "difficulty": "unknown",
                "source": "test",
                "has_vulnerability": True,
                "vulnerability_type": "unknown",
            }
        ],
    )
    write_jsonl(
        probs_path,
        [
            {
                "id": "sample-1",
                "vuln_probability": 0.9,
                "pred": 1,
                "gold": 1,
            }
        ],
    )
    write_jsonl(
        auditor_path,
        [
            {
                "id": "sample-1",
                "task_type": "weakness_identification",
                "prompt": "Analyze code",
                "code": "memcpy(dst, src, len);",
                "diff": None,
                "language": "c",
                "has_vulnerability": True,
                "predicted_vulnerability_type": "unknown",
                "predicted_severity": "unknown",
                "evidence": [
                    {
                        "file_path": "snippet",
                        "line_start": 1,
                        "line_end": 1,
                        "snippet": "memcpy(dst, src, len);",
                    }
                ],
                "explanation": "Potential unsafe copy.",
                "fix_principle": "Validate bounds.",
                "confidence": 0.9,
                "label_correct": True,
                "evidence_supported": True,
                "explanation_supported": True,
                "format_ok": True,
                "token_count": 12,
                "latency_ms": 10.0,
                "model_version": "auditor",
                "backend_type": "huggingface",
                "parse_method": "structured_json",
                "parse_confidence": 0.9,
                "parse_trigger": "none",
                "raw_text": "{}",
            }
        ],
    )

    rows = module.build_hybrid_rows(
        dataset_path=str(dataset_path),
        probability_path=str(probs_path),
        auditor_generations_path=str(auditor_path),
        threshold=0.5,
        model_version="hybrid_test",
    )

    assert len(rows) == 1
    row = rows[0]
    assert row["has_vulnerability"] is True
    assert row["evidence_supported"] is True
    assert row["evidence"][0]["snippet"] == "memcpy(dst, src, len);"
