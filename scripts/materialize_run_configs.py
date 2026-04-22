from __future__ import annotations

import argparse
import json
from pathlib import Path

from vrf.io_utils import ensure_parent, write_json
from vrf.run_specs import build_run_artifact_spec


def main() -> None:
    parser = argparse.ArgumentParser(description="Materialize eval/analysis configs from a single run spec.")
    parser.add_argument("--dataset-path", required=True)
    parser.add_argument("--generations-path", required=True)
    parser.add_argument("--report-json-path", required=True)
    parser.add_argument("--report-csv-path", default=None)
    parser.add_argument("--analysis-output-path", default=None)
    parser.add_argument("--tracker-path", default=None)
    parser.add_argument("--metrics-json", default=None)
    parser.add_argument("--eval-config-path", required=True)
    parser.add_argument("--analysis-config-path", required=True)
    args = parser.parse_args()

    metrics = json.loads(args.metrics_json) if args.metrics_json else None
    spec = build_run_artifact_spec(
        dataset_path=args.dataset_path,
        generations_path=args.generations_path,
        report_json_path=args.report_json_path,
        report_csv_path=args.report_csv_path,
        analysis_output_path=args.analysis_output_path,
        tracker_path=args.tracker_path,
        metrics=metrics,
    )

    write_json(args.eval_config_path, spec.evaluate_config())
    write_json(args.analysis_config_path, spec.analysis_config())
    print(
        json.dumps(
            {
                "eval_config_path": str(Path(args.eval_config_path)),
                "analysis_config_path": str(Path(args.analysis_config_path)),
                "spec": spec.to_dict(),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
