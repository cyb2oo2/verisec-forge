from __future__ import annotations

import argparse
import json

from vrf.analysis import build_failure_analysis
from vrf.evaluation import evaluate_run
from vrf.inference import build_backend, run_generation
from vrf.io_utils import read_json
from vrf.pipelines import run_baseline
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
    raise ValueError(f"Unknown command: {args.command}")


if __name__ == "__main__":
    main()
