from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.text_utils import family_root_label


def load_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def _normalized_verifier_type(verifier_row: dict) -> str:
    raw_type = str(verifier_row.get("predicted_vulnerability_type", "")).strip().lower()
    normalized = family_root_label(raw_type)
    if normalized in {"", "none", "unknown", "vulnerable"}:
        return ""
    if not normalized.startswith("cwe-"):
        return ""
    return normalized


def should_flip(
    main_row: dict,
    verifier_row: dict,
    verifier_conf_threshold: float,
    verifier_parse_threshold: float,
    require_format_ok: bool,
) -> tuple[bool, str]:
    if main_row.get("has_vulnerability") is not False:
        return False, "main_not_safe"
    if verifier_row.get("has_vulnerability") is not True:
        return False, "verifier_not_vulnerable"
    if require_format_ok and verifier_row.get("format_ok") is not True:
        return False, "verifier_format_not_ok"
    verifier_type = _normalized_verifier_type(verifier_row)
    if not verifier_type:
        return False, "non_canonical_vulnerability_type"
    verifier_conf = verifier_row.get("confidence")
    if not isinstance(verifier_conf, (int, float)):
        return False, "missing_confidence"
    if float(verifier_conf) < verifier_conf_threshold:
        return False, "low_verifier_confidence"
    parse_conf = verifier_row.get("parse_confidence")
    if not isinstance(parse_conf, (int, float)):
        return False, "missing_parse_confidence"
    if float(parse_conf) < verifier_parse_threshold:
        return False, "low_parse_confidence"
    return True, "accepted"


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a secure-code verifier ensemble from main and verifier generation files.")
    parser.add_argument("--main-generations", required=True)
    parser.add_argument("--verifier-generations", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--verifier-confidence-threshold", type=float, default=0.9)
    parser.add_argument("--verifier-parse-threshold", type=float, default=0.9)
    parser.add_argument("--allow-non-format-ok", action="store_true")
    args = parser.parse_args()

    main_rows = load_jsonl(Path(args.main_generations))
    verifier_rows = {row["id"]: row for row in load_jsonl(Path(args.verifier_generations))}

    merged: list[dict] = []
    override_count = 0
    reason_counts: dict[str, int] = {}
    for row in main_rows:
        merged_row = dict(row)
        verifier_row = verifier_rows.get(row["id"])
        merged_row["ensemble_used"] = False
        merged_row["ensemble_overrode"] = False
        if verifier_row:
            should_override, reason = should_flip(
                row,
                verifier_row,
                args.verifier_confidence_threshold,
                args.verifier_parse_threshold,
                require_format_ok=not args.allow_non_format_ok,
            )
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
        else:
            should_override, reason = False, "missing_verifier_row"
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
        if verifier_row and should_override:
            merged_row["ensemble_used"] = True
            merged_row["ensemble_overrode"] = True
            merged_row["has_vulnerability"] = verifier_row.get("has_vulnerability")
            merged_row["predicted_vulnerability_type"] = _normalized_verifier_type(verifier_row)
            merged_row["predicted_severity"] = verifier_row.get("predicted_severity", merged_row.get("predicted_severity"))
            merged_row["evidence"] = verifier_row.get("evidence", merged_row.get("evidence", []))
            merged_row["explanation"] = verifier_row.get("explanation", merged_row.get("explanation", ""))
            merged_row["fix_principle"] = verifier_row.get("fix_principle", merged_row.get("fix_principle", ""))
            merged_row["confidence"] = verifier_row.get("confidence", merged_row.get("confidence"))
            merged_row["label_correct"] = False
            merged_row["evidence_supported"] = verifier_row.get("evidence_supported", merged_row.get("evidence_supported", False))
            merged_row["explanation_supported"] = verifier_row.get("explanation_supported", merged_row.get("explanation_supported", False))
            merged_row["format_ok"] = verifier_row.get("format_ok", merged_row.get("format_ok", False))
            merged_row["parse_method"] = "ensemble_verifier"
            merged_row["parse_trigger"] = "external_verifier_override"
            merged_row["parse_confidence"] = verifier_row.get("parse_confidence", merged_row.get("parse_confidence", 1.0))
            merged_row["verifier_raw_text"] = verifier_row.get("raw_text", "")
            override_count += 1
        merged.append(merged_row)

    write_jsonl(Path(args.output), merged)
    print(
        json.dumps(
            {
                "rows": len(merged),
                "override_count": override_count,
                "output": args.output,
                "reason_counts": reason_counts,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
