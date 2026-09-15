"""Exercise the public prediction adapter without model calls or downloads."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from vrf.external_adapter import evaluate_external_predictions
from vrf.io_utils import read_jsonl, write_jsonl


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("outputs/offline-demo"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    rows = read_jsonl(root / "examples/veripatch_rr_smoke_30.jsonl")
    predictions = [
        {"id": row["id"], "predicted_riskier_side": "A", "supports_abstention": False}
        for row in rows
    ]
    report = evaluate_external_predictions(rows, predictions, bootstrap_iterations=10)
    report["demo"] = {"mode": "MOCK_ONLY", "predictor": "constant_A", "model_calls": 0}
    args.output.mkdir(parents=True, exist_ok=True)
    write_jsonl(args.output / "predictions.jsonl", predictions)
    (args.output / "evaluation.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "mode": "MOCK_ONLY", "rows": len(rows),
                      "predictions": str(args.output / "predictions.jsonl"),
                      "evaluation": str(args.output / "evaluation.json")}))
    raise SystemExit(0 if report["status"] == "ok" else 1)


if __name__ == "__main__":
    main()
