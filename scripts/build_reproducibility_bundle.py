from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.reproducibility import build_artifact_bundle, validate_manifests


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate or package manifest-listed reproducibility artifacts.",
    )
    parser.add_argument(
        "--manifest",
        action="append",
        required=True,
        help="Reproducibility manifest path. Repeat this flag to combine manifests.",
    )
    parser.add_argument(
        "--output",
        default="artifacts/verisec_forge_reproducibility_bundle.zip",
        help="Output zip path for bundle mode. Defaults to artifacts/.",
    )
    parser.add_argument(
        "--include-generated",
        action="store_true",
        help="Also include generated_artifacts entries from each manifest.",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Only validate local artifact paths, sizes, rows, and SHA256 hashes.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.check_only:
        payload = validate_manifests(
            args.manifest,
            repo_root=ROOT,
            include_generated=args.include_generated,
        )
    else:
        payload = build_artifact_bundle(
            args.manifest,
            output_path=ROOT / args.output,
            repo_root=ROOT,
            include_generated=args.include_generated,
        )

    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0 if payload["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
