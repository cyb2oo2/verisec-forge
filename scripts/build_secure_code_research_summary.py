from __future__ import annotations

import argparse
import json
from pathlib import Path

from vrf.research_summary import build_secure_code_research_summary, load_run_manifest

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"

DEFAULT_MANIFEST = ROOT / "configs" / "research_runs" / "primevul_summary.json"


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the secure-code research summary from a run manifest.")
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--output-path", default=str(REPORTS / "SECURE_CODE_RESEARCH_SUMMARY.md"))
    args = parser.parse_args()

    run_specs = load_run_manifest(args.manifest, ROOT)
    summary_text = build_secure_code_research_summary(run_specs)
    output_path = Path(args.output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(summary_text, encoding="utf-8")
    print(json.dumps({"output_path": str(output_path), "manifest_path": args.manifest}, indent=2))


if __name__ == "__main__":
    main()
