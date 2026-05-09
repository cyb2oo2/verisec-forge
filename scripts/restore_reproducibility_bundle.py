from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.reproducibility import restore_artifact_bundle


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Restore and validate a VeriSec Forge reproducibility bundle.",
    )
    parser.add_argument(
        "--bundle",
        required=True,
        help="Path to a bundle created by scripts/build_reproducibility_bundle.py.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing artifact files. Without this flag, mismatching existing files block restoration.",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Validate bundle shape and report what would be extracted without writing files.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    payload = restore_artifact_bundle(
        args.bundle,
        repo_root=ROOT,
        overwrite=args.overwrite,
        check_only=args.check_only,
    )
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0 if payload["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
