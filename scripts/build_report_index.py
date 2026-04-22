from __future__ import annotations

import argparse
import json
from pathlib import Path

from vrf.report_index import build_report_index, load_report_index_manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a curated results index from a manifest.")
    parser.add_argument("--manifest", default="configs/report_index.json")
    parser.add_argument("--output-path", default="reports/RESULTS_INDEX.md")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    sections = load_report_index_manifest(args.manifest, root)
    output = build_report_index(sections, root)
    output_path = root / args.output_path
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(output, encoding="utf-8")
    print(json.dumps({"output_path": str(output_path), "manifest_path": args.manifest}, indent=2))


if __name__ == "__main__":
    main()
