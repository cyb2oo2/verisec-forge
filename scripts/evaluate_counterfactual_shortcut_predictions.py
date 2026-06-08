from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.counterfactuals import evaluate_intervention_predictions
from vrf.io_utils import read_jsonl


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate prediction stability under controlled shortcut interventions.")
    parser.add_argument("--predictions", required=True)
    parser.add_argument("--output", default="reports/secure_code_counterfactual_shortcut_evaluation_v1.json")
    args = parser.parse_args()
    report = evaluate_intervention_predictions(read_jsonl(ROOT / args.predictions))
    (ROOT / args.output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
