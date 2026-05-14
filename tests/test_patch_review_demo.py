from __future__ import annotations

import json
import sys
from pathlib import Path

from fastapi.testclient import TestClient

from vrf import cli
from vrf.io_utils import write_jsonl
from vrf.patch_review_demo import build_patch_review_demo, list_demo_examples
from vrf.serving import create_app


def _write_demo_artifacts(tmp_path: Path) -> tuple[Path, Path, Path]:
    dataset = tmp_path / "dataset.jsonl"
    predictions = tmp_path / "predictions.jsonl"
    evidence = tmp_path / "evidence.jsonl"
    pair_key = "demo-project|demo-commit|CVE-0000-0001"

    write_jsonl(
        dataset,
        [
            {
                "id": "safe-side",
                "pair_key": pair_key,
                "has_vulnerability": False,
                "project": "demo-project",
                "cve": "CVE-0000-0001",
                "file_name": "demo.c",
                "vulnerability_type": "cwe-787",
            },
            {
                "id": "risk-side",
                "pair_key": pair_key,
                "has_vulnerability": True,
                "project": "demo-project",
                "cve": "CVE-0000-0001",
                "file_name": "demo.c",
                "vulnerability_type": "cwe-787",
            },
        ],
    )
    write_jsonl(
        predictions,
        [
            {
                "id": "safe-side",
                "gold": 0,
                "pred": 0,
                "pre_coupled_pred": 0,
                "pair_coupled": True,
                "vuln_probability": 0.12,
            },
            {
                "id": "risk-side",
                "gold": 1,
                "pred": 1,
                "pre_coupled_pred": 1,
                "pair_coupled": True,
                "vuln_probability": 0.91,
            },
        ],
    )
    write_jsonl(
        evidence,
        [
            {
                "id": "safe-side",
                "support_label": "supported",
                "risk_support": 0,
                "safety_support": 2,
                "net_risk_support": -2,
                "top_hunks": [],
            },
            {
                "id": "risk-side",
                "support_label": "supported",
                "risk_support": 3,
                "safety_support": 0,
                "net_risk_support": 3,
                "top_hunks": [
                    {
                        "header": "@@ demo @@",
                        "direction_labels": ["candidate_introduces_risk"],
                        "risk_support": 3,
                        "safety_support": 0,
                        "net_risk_support": 3,
                        "removed_preview": ["if (len < size) return;"],
                        "added_preview": ["memcpy(dst, src, size);"],
                    }
                ],
            },
        ],
    )
    return dataset, predictions, evidence


def test_build_patch_review_demo_combines_pair_decision_and_evidence(tmp_path: Path) -> None:
    dataset, predictions, evidence = _write_demo_artifacts(tmp_path)

    payload = build_patch_review_demo(
        dataset_path=dataset,
        predictions_path=predictions,
        evidence_path=evidence,
        sample_id="risk-side",
    )

    assert payload["mode"] == "artifact_backed_patch_review_demo"
    assert payload["pair_decision"]["riskier_side_id"] == "risk-side"
    assert payload["pair_decision"]["probability_gap"] == 0.79
    risk_row = next(row for row in payload["rows"] if row["id"] == "risk-side")
    assert risk_row["decision"] == "vulnerable"
    assert risk_row["support_label"] == "supported"
    assert risk_row["evidence_windows"][0]["direction_labels"] == ["candidate_introduces_risk"]
    assert risk_row["evidence_windows"][0]["added"] == "memcpy(dst, src, size);"


def test_list_demo_examples_returns_pair_metadata(tmp_path: Path) -> None:
    dataset, _predictions, _evidence = _write_demo_artifacts(tmp_path)

    examples = list_demo_examples(dataset, limit=1)

    assert examples == [
        {
            "pair_key": "demo-project|demo-commit|CVE-0000-0001",
            "ids": ["safe-side", "risk-side"],
            "project": "demo-project",
            "cve": "CVE-0000-0001",
            "vulnerability_type": "cwe-787",
        }
    ]


def test_cli_patch_demo_lists_examples(monkeypatch, capsys, tmp_path: Path) -> None:
    dataset, _predictions, _evidence = _write_demo_artifacts(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        ["vrf", "patch-demo", "--dataset", str(dataset), "--list-examples", "1"],
    )

    cli.main()

    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["pair_key"] == "demo-project|demo-commit|CVE-0000-0001"


def test_serving_review_pair_endpoint_reads_artifact_demo(monkeypatch, tmp_path: Path) -> None:
    dataset, predictions, evidence = _write_demo_artifacts(tmp_path)

    class StubBackend:
        model_version = "stub-model"

    monkeypatch.setattr("vrf.serving.build_backend", lambda _cfg: StubBackend())
    app = create_app(
        {
            "backend": {"type": "mock", "model_name": "stub"},
            "patch_review_demo": {
                "dataset": str(dataset),
                "predictions": str(predictions),
                "evidence": str(evidence),
            },
        }
    )
    client = TestClient(app)

    examples = client.get("/review-pair/examples", params={"limit": 1})
    assert examples.status_code == 200
    assert examples.json()[0]["ids"] == ["safe-side", "risk-side"]

    response = client.post("/review-pair", json={"sample_id": "risk-side", "evidence_limit": 1})
    assert response.status_code == 200
    payload = response.json()
    assert payload["pair_decision"]["riskier_side_id"] == "risk-side"
    risk_row = next(row for row in payload["rows"] if row["id"] == "risk-side")
    assert risk_row["evidence_windows"][0]["added"] == "memcpy(dst, src, size);"
