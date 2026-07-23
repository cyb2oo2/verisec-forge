from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.io_utils import read_jsonl


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Optional diagnostic: evidence-coupled metrics on human-consensus pair_keys only. "
            "Does not invent labels; exits not_run if consensus is missing."
        )
    )
    parser.add_argument("--study-dir", default="data/annotation/primevul_pair_study_v1")
    parser.add_argument("--consensus", default="")
    parser.add_argument(
        "--localization",
        default="outputs/secure_code_primevul_pair_evidence_localization_v1.jsonl",
    )
    parser.add_argument("--output", default="reports/secure_code_primevul_pair_annotation_subset_evidence_v1.json")
    parser.add_argument("--markdown-output", default="reports/PRIMEVUL_PAIR_ANNOTATION_SUBSET_EVIDENCE_V1.md")
    args = parser.parse_args()

    consensus_path = ROOT / (args.consensus or str(Path(args.study_dir) / "human_gold_consensus_v1.jsonl"))
    out = {
        "status": "not_run",
        "claim_boundary": {
            "diagnostic_subset_only": True,
            "not_headline_balanced_accuracy": True,
            "requires_human_consensus": True,
            "human_gold_not_ai_pilot": True,
        },
        "message": "Human consensus file missing or empty; subset evidence metrics not computed.",
        "consensus_path": consensus_path.relative_to(ROOT).as_posix() if consensus_path.is_relative_to(ROOT) else str(consensus_path),
    }
    if not consensus_path.exists():
        _write(ROOT / args.output, ROOT / args.markdown_output, out)
        print(json.dumps(out, indent=2))
        return 0

    consensus = read_jsonl(consensus_path)
    if not consensus:
        _write(ROOT / args.output, ROOT / args.markdown_output, out)
        print(json.dumps(out, indent=2))
        return 0

    pair_keys = {str(row.get("pair_key") or "") for row in consensus if row.get("pair_key")}
    localization_path = ROOT / args.localization
    overlap = 0
    if localization_path.exists():
        for row in read_jsonl(localization_path):
            key = str(row.get("pair_key") or row.get("id") or "")
            # Heuristic overlap on pair_key or id prefix.
            if key in pair_keys or any(key.startswith(pk.split("|")[0]) for pk in pair_keys if pk):
                if key in pair_keys:
                    overlap += 1
        # Count rows whose pair_key matches exactly.
        loc_rows = read_jsonl(localization_path)
        exact = [row for row in loc_rows if str(row.get("pair_key") or "") in pair_keys]
        overlap = len(exact)
        out = {
            "status": "ok" if exact else "no_overlap",
            "claim_boundary": out["claim_boundary"],
            "consensus_pairs": len(pair_keys),
            "localization_rows_for_subset": overlap,
            "message": (
                "Subset join prepared. Detailed top-1 localization stratified by human side correctness "
                "requires aligned localization schema fields; report only overlap until full join is configured."
                if exact
                else "Consensus exists but no localization rows share pair_key; not a model-quality claim."
            ),
            "note": "Diagnostic only — not a new headline BA.",
        }
    else:
        out = {
            "status": "localization_missing",
            "claim_boundary": out["claim_boundary"],
            "consensus_pairs": len(pair_keys),
            "message": f"Localization artifact missing: {args.localization}",
        }

    _write(ROOT / args.output, ROOT / args.markdown_output, out)
    print(json.dumps(out, indent=2))
    return 0


def _write(json_path: Path, md_path: Path, payload: dict) -> None:
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# Pair Annotation Subset Evidence v1",
        "",
        f"**Status:** `{payload.get('status')}`",
        "",
        "## Claim boundary",
        "",
        "- Optional diagnostic on **human-consensus** pair keys only.",
        "- **Not** a headline balanced-accuracy result.",
        "- **Human gold ≠ AI pilot.**",
        "",
        f"Message: {payload.get('message')}",
        "",
    ]
    md_path.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
