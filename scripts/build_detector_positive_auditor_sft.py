from __future__ import annotations

import argparse
import json
from pathlib import Path

from vrf.io_utils import read_jsonl, write_jsonl


KEYWORDS = (
    "memcpy",
    "memmove",
    "strcpy",
    "strncpy",
    "strcat",
    "malloc",
    "calloc",
    "realloc",
    "free",
    "system",
    "exec",
    "input",
    "index",
    "offset",
    "size",
    "count",
    "buffer",
    "pointer",
)


def heuristic_evidence(code: str) -> list[dict[str, object]]:
    evidence: list[dict[str, object]] = []
    for line_no, line in enumerate(code.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        lowered = stripped.lower()
        score = sum(1 for keyword in KEYWORDS if keyword in lowered)
        if score <= 0:
            continue
        evidence.append(
            {
                "file_path": "snippet",
                "line_start": line_no,
                "line_end": line_no,
                "snippet": stripped[:240],
                "_score": score,
            }
        )
    evidence.sort(key=lambda item: (-int(item["_score"]), int(item["line_start"])))
    trimmed: list[dict[str, object]] = []
    for item in evidence[:2]:
        copied = dict(item)
        copied.pop("_score", None)
        trimmed.append(copied)
    return trimmed


def build_prompt(code: str, language: str, probability: float) -> str:
    return (
        "A first-pass vulnerability detector has flagged this function for defensive security review.\n"
        f"Detector vulnerability probability: {probability:.4f}\n"
        "Return valid JSON only with fields has_vulnerability, vulnerability_type, severity, evidence, explanation, "
        "fix_principle, confidence, and fix_choice.\n"
        "Only keep has_vulnerability=true when the snippet itself supports a defensible vulnerability claim and you can "
        "point to concrete evidence. Otherwise return has_vulnerability=false and vulnerability_type=none.\n\n"
        f"language: {language}\n"
        f"code:\n{code}"
    )


def build_response(row: dict[str, object], probability: float) -> str:
    has_vulnerability = bool(row.get("has_vulnerability"))
    code = str(row.get("code") or "")
    evidence = heuristic_evidence(code) if has_vulnerability else []
    if has_vulnerability:
        payload = {
            "has_vulnerability": True,
            "vulnerability_type": "unknown",
            "severity": "unknown",
            "evidence": evidence,
            "explanation": "The detector alert is defensible from the snippet and the code should be reviewed as vulnerable.",
            "fix_principle": "Inspect the flagged operations, validate inputs and bounds, and replace unsafe behavior with a safer implementation.",
            "confidence": max(0.8, min(0.98, probability)),
            "fix_choice": "",
        }
    else:
        payload = {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "severity": "none",
            "evidence": [],
            "explanation": "The detector alert is not sufficiently supported by concrete evidence in the snippet.",
            "fix_principle": "Do not escalate the alert without stronger code-level evidence.",
            "confidence": 0.7,
            "fix_choice": "",
        }
    return json.dumps(payload, ensure_ascii=False)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build detector-positive auditor SFT data from classifier scores.")
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--probabilities", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--max-rows", type=int, default=0)
    args = parser.parse_args()

    dataset_rows = {row["id"]: row for row in read_jsonl(args.dataset)}
    probability_rows = read_jsonl(args.probabilities)

    rows_out: list[dict[str, object]] = []
    for prob_row in probability_rows:
        probability = float(prob_row["vuln_probability"])
        if probability < args.threshold:
            continue
        row = dict(dataset_rows[prob_row["id"]])
        row["prompt"] = build_prompt(str(row.get("code") or ""), str(row.get("language") or "c"), probability)
        row["response"] = build_response(row, probability)
        row["detector_probability"] = probability
        rows_out.append(row)
        if args.max_rows and len(rows_out) >= args.max_rows:
            break

    write_jsonl(args.output, rows_out)
    print(json.dumps({"rows": len(rows_out), "output": args.output, "threshold": args.threshold}, indent=2))


if __name__ == "__main__":
    main()
