from __future__ import annotations

import json
import sys

from fastapi.testclient import TestClient

from vrf import cli, serving


def test_cli_baseline_dispatches_and_prints_summary(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "run_baseline", lambda config_path: {"num_examples": 2, "label_accuracy": 0.5})
    monkeypatch.setattr(sys, "argv", ["vrf", "baseline", "--config", "configs/example.json"])
    cli.main()
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["num_examples"] == 2
    assert payload["label_accuracy"] == 0.5


def test_cli_serve_once_builds_sample_and_serializes(monkeypatch, capsys) -> None:
    class StubRecord:
        def to_dict(self) -> dict[str, object]:
            return {"id": "adhoc-cli", "format_ok": True, "predicted_vulnerability_type": "cwe-78"}

    monkeypatch.setattr(cli, "read_json", lambda _path: {"backend": {"type": "mock", "model_name": "stub"}})
    monkeypatch.setattr(cli, "build_backend", lambda _cfg: object())
    monkeypatch.setattr(cli, "run_generation", lambda _backend, sample: StubRecord() if sample.id == "adhoc-cli" else None)
    monkeypatch.setattr(
        sys,
        "argv",
        ["vrf", "serve-once", "--config", "configs/mock.json", "--prompt", "Analyze this code", "--language", "python"],
    )
    cli.main()
    payload = json.loads(capsys.readouterr().out)
    assert payload["id"] == "adhoc-cli"
    assert payload["format_ok"] is True


def test_serving_app_health_and_infer(monkeypatch) -> None:
    class StubBackend:
        model_version = "stub-model"

    class StubRecord:
        def to_dict(self) -> dict[str, object]:
            return {"id": "sample-1", "format_ok": True, "predicted_vulnerability_type": "cwe-79"}

    monkeypatch.setattr(serving, "build_backend", lambda _cfg: StubBackend())
    monkeypatch.setattr(serving, "run_generation", lambda _backend, _sample: StubRecord())
    app = serving.create_app({"backend": {"type": "mock", "model_name": "stub"}})
    client = TestClient(app)

    health = client.get("/health")
    assert health.status_code == 200
    assert health.json() == {"status": "ok", "model_version": "stub-model"}

    response = client.post(
        "/infer",
        json={
            "sample_id": "sample-1",
            "task_type": "weakness_identification",
            "language": "python",
            "prompt": "Analyze this code",
            "code": "print('x')",
        },
    )
    assert response.status_code == 200
    assert response.json()["format_ok"] is True
    assert response.json()["predicted_vulnerability_type"] == "cwe-79"
