"""Validate response structure and evidence bounds, not factual correctness."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from vrf.ai_annotation import validate_annotation


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--responses", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=ROOT / "reports/scientific_review_2026_09_07/p1/ai_annotation_preparation.json")
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    path = ROOT / manifest["bundle"] / "cases.json"
    if hashlib.sha256(path.read_bytes()).hexdigest() != manifest["hashes"]["cases.json"]:
        raise ValueError("case bundle modified")
    cases = {r["case_id"]: r for r in json.loads(path.read_text(encoding="utf-8"))}
    seen, validated = set(), []
    for line in args.responses.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        identifier = r["case_id"]
        if identifier in seen or identifier not in cases:
            raise ValueError("duplicate or unknown case")
        seen.add(identifier)
        validated.append(validate_annotation(r, cases[identifier]))
    print(json.dumps({"status": "STRUCTURE_VALID" if seen == set(cases) else "INCOMPLETE",
                      "received": len(seen), "expected": len(cases), "missing": sorted(set(cases)-seen),
                      "eligible_provisional_ab": sum(r["eligible_for_provisional_ab"] for r in validated),
                      "human_gold": False, "factual_correctness_validated": False}, indent=2))
    return 0 if seen == set(cases) else 1


if __name__ == "__main__":
    raise SystemExit(main())
