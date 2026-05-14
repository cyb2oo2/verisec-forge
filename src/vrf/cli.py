from __future__ import annotations

import argparse
import json

from vrf.analysis import build_failure_analysis
from vrf.evaluation import evaluate_run
from vrf.inference import build_backend, run_generation
from vrf.io_utils import read_json
from vrf.pipelines import run_baseline
from vrf.patch_review_demo import (
    DEFAULT_DATASET_PATH,
    DEFAULT_EVIDENCE_PATH,
    DEFAULT_PREDICTIONS_PATH,
    build_patch_review_demo,
    list_demo_examples,
)
from vrf.schemas import SecureCodeSample
from vrf.training_dpo import run_dpo
from vrf.training_grpo import run_grpo
from vrf.training_reward import run_reward_model
from vrf.training_sft import run_sft


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="VeriSec Forge CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    for command in ["baseline", "evaluate", "analyze", "train-sft", "train-dpo", "train-reward", "train-grpo", "serve"]:
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--config", required=True)

    serve_once = subparsers.add_parser("serve-once")
    serve_once.add_argument("--config", required=True)
    serve_once.add_argument("--prompt", required=True)
    serve_once.add_argument("--task-type", default="weakness_identification")
    serve_once.add_argument("--language", default="python")

    patch_demo = subparsers.add_parser("patch-demo")
    patch_demo.add_argument("--id", dest="sample_id")
    patch_demo.add_argument("--pair-key")
    patch_demo.add_argument("--dataset", default=DEFAULT_DATASET_PATH)
    patch_demo.add_argument("--predictions", default=DEFAULT_PREDICTIONS_PATH)
    patch_demo.add_argument("--evidence", default=DEFAULT_EVIDENCE_PATH)
    patch_demo.add_argument("--evidence-limit", type=int, default=2)
    patch_demo.add_argument("--text-limit", type=int, default=700)
    patch_demo.add_argument("--list-examples", type=int, default=0)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "baseline":
        print(json.dumps(run_baseline(args.config), indent=2))
        return
    if args.command == "evaluate":
        config = read_json(args.config)
        print(json.dumps(evaluate_run(config, args.config)["summary"], indent=2))
        return
    if args.command == "analyze":
        print(json.dumps(build_failure_analysis(read_json(args.config)), indent=2))
        return
    if args.command == "train-sft":
        print(json.dumps(run_sft(args.config), indent=2))
        return
    if args.command == "train-dpo":
        print(json.dumps(run_dpo(args.config), indent=2))
        return
    if args.command == "train-reward":
        print(json.dumps(run_reward_model(args.config), indent=2))
        return
    if args.command == "train-grpo":
        print(json.dumps(run_grpo(args.config), indent=2))
        return
    if args.command == "serve":
        try:
            import uvicorn
        except ImportError as exc:
            raise RuntimeError("uvicorn is required for the serve command. Install project dependencies first.") from exc
        from vrf.serving import create_app
        config = read_json(args.config)
        app = create_app(config)
        uvicorn.run(app, host=config.get("host", "127.0.0.1"), port=config.get("port", 8000))
        return
    if args.command == "serve-once":
        config = read_json(args.config)
        backend = build_backend(config["backend"])
        sample = SecureCodeSample(
            id="adhoc-cli",
            task_type=args.task_type,
            language=args.language,
            prompt=args.prompt,
            split="adhoc",
            difficulty="unknown",
            source="cli",
        )
        print(json.dumps(run_generation(backend, sample).to_dict(), indent=2))
        return
    if args.command == "patch-demo":
        if args.list_examples:
            payload = list_demo_examples(args.dataset, limit=args.list_examples)
        else:
            payload = build_patch_review_demo(
                dataset_path=args.dataset,
                predictions_path=args.predictions,
                evidence_path=args.evidence,
                sample_id=args.sample_id,
                pair_key=args.pair_key,
                evidence_limit=args.evidence_limit,
                text_limit=args.text_limit,
            )
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return
    raise ValueError(f"Unknown command: {args.command}")


if __name__ == "__main__":
    main()
