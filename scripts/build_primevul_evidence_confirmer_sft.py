from __future__ import annotations

import argparse
import json
from pathlib import Path

from vrf.io_utils import read_jsonl, write_jsonl
from vrf.text_utils import family_root_label


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
    "length",
    "copy",
    "array",
    "bounds",
)


def heuristic_evidence(code: str, limit: int = 2) -> list[dict[str, object]]:
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
    for item in evidence[:limit]:
        copied = dict(item)
        copied.pop("_score", None)
        trimmed.append(copied)
    return trimmed


def build_prompt(code: str, language: str, probability: float) -> str:
    return (
        "A first-pass vulnerability detector has flagged this function for evidence confirmation.\n"
        f"Detector vulnerability probability: {probability:.4f}\n"
        "Return valid JSON only with fields has_vulnerability, vulnerability_type, severity, evidence, explanation, "
        "fix_principle, confidence, and fix_choice.\n"
        "Your job is not to rediscover every possible issue. Only confirm has_vulnerability=true if the snippet itself "
        "contains concrete code-level evidence. If the alert is not concretely supported, return has_vulnerability=false, "
        "vulnerability_type=none, and evidence=[]. Keep explanation brief and evidence-focused.\n\n"
        f"language: {language}\n"
        f"code:\n{code}"
    )


def family_templates(family: str) -> tuple[str, str]:
    family = family_root_label(family)
    if family in {"cwe-119", "cwe-120", "cwe-121", "cwe-122", "cwe-125", "cwe-126", "cwe-787", "cwe-788"}:
        return (
            "The snippet contains memory or bounds-sensitive operations that provide concrete evidence for a memory-safety alert.",
            "Add explicit bounds checks and replace unsafe memory operations with safer, size-aware handling.",
        )
    if family in {"cwe-20", "cwe-129", "cwe-190", "cwe-191"}:
        return (
            "The snippet shows insufficient validation of sizes, indices, or numeric values, which supports the alert.",
            "Validate sizes, ranges, and arithmetic results before using them in allocation, indexing, or copy logic.",
        )
    if family in {"cwe-78", "cwe-88"}:
        return (
            "The snippet passes attacker-influenced data into command execution logic, which concretely supports the alert.",
            "Avoid direct command construction and enforce strict sanitization or safe APIs for process execution.",
        )
    if family in {"cwe-79", "cwe-89"}:
        return (
            "The snippet contains unsafe output or query construction patterns that provide concrete support for the alert.",
            "Use context-appropriate escaping or parameterization instead of composing unsafe output or queries directly.",
        )
    return (
        "The alert is supported by concrete code-level evidence in the snippet.",
        "Review the flagged operations and replace the unsafe pattern with a safer implementation.",
    )


def unsupported_explanation(row: dict[str, object]) -> tuple[str, str]:
    family = family_root_label(str(row.get("vulnerability_type") or "unknown"))
    if bool(row.get("has_vulnerability")) and family != "unknown":
        return (
            f"The detector suggests possible {family}, but this snippet does not expose concrete code-level evidence strong enough to confirm the alert.",
            "Do not escalate this alert without a directly evidenced unsafe operation or missing validation in the visible snippet.",
        )
    return (
        "The alert is not concretely supported by code-level evidence in the snippet.",
        "Do not escalate this alert without stronger code-level evidence.",
    )


def build_response(row: dict[str, object], probability: float, *, evidence_limit: int = 2, family_aware: bool = False) -> str:
    has_vulnerability = bool(row.get("has_vulnerability"))
    code = str(row.get("code") or "")
    evidence = heuristic_evidence(code, limit=evidence_limit) if has_vulnerability else []
    if has_vulnerability and evidence:
        vuln_family = family_root_label(str(row.get("vulnerability_type") or "unknown"))
        if family_aware:
            explanation, fix_principle = family_templates(vuln_family)
        else:
            explanation, fix_principle = (
                "The alert is supported by concrete code-level evidence in the snippet.",
                "Review the flagged operations and replace the unsafe pattern with a safer implementation.",
            )
        payload = {
            "has_vulnerability": True,
            "vulnerability_type": vuln_family,
            "severity": str(row.get("severity") or "unknown"),
            "evidence": evidence,
            "explanation": explanation,
            "fix_principle": fix_principle,
            "confidence": max(0.8, min(0.98, probability)),
            "fix_choice": "",
        }
    else:
        explanation, fix_principle = unsupported_explanation(row) if family_aware else (
            "The alert is not concretely supported by code-level evidence in the snippet.",
            "Do not escalate this alert without stronger code-level evidence.",
        )
        payload = {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "severity": "none",
            "evidence": [],
            "explanation": explanation,
            "fix_principle": fix_principle,
            "confidence": 0.7,
            "fix_choice": "",
        }
    return json.dumps(payload, ensure_ascii=False)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build PrimeVul detector-positive evidence confirmer SFT data.")
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--probabilities", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--max-rows", type=int, default=0)
    parser.add_argument("--include-response", action="store_true", help="Include gold response field for SFT data")
    parser.add_argument(
        "--safe-negative-repeat",
        type=int,
        default=1,
        help="Repeat count for detector-positive safe rows that should remain unsupported negatives.",
    )
    parser.add_argument(
        "--unsupported-vulnerable-repeat",
        type=int,
        default=1,
        help="Repeat count for vulnerable rows whose alert is not concretely supported by heuristic evidence.",
    )
    parser.add_argument(
        "--supported-positive-repeat",
        type=int,
        default=1,
        help="Repeat count for vulnerable rows with concrete heuristic evidence.",
    )
    parser.add_argument(
        "--evidence-limit",
        type=int,
        default=2,
        help="Maximum number of heuristic evidence items to include for supported positives.",
    )
    parser.add_argument(
        "--family-aware",
        action="store_true",
        help="Use family-aware explanations and unsupported-negative rationales.",
    )
    args = parser.parse_args()

    dataset_rows = {row["id"]: row for row in read_jsonl(args.dataset)}
    probability_rows = read_jsonl(args.probabilities)

    rows_out: list[dict[str, object]] = []
    for prob_row in probability_rows:
        probability = float(prob_row["vuln_probability"])
        if probability < args.threshold:
            continue
        row = dict(dataset_rows[prob_row["id"]])
        prompt = build_prompt(str(row.get("code") or ""), str(row.get("language") or "c"), probability)
        response = (
            build_response(
                row,
                probability,
                evidence_limit=max(1, args.evidence_limit),
                family_aware=bool(args.family_aware),
            )
            if args.include_response
            else None
        )

        row_has_vulnerability = bool(row.get("has_vulnerability"))
        row_evidence = heuristic_evidence(str(row.get("code") or ""), limit=max(1, args.evidence_limit)) if row_has_vulnerability else []
        if row_has_vulnerability and row_evidence:
            repeat_count = max(1, args.supported_positive_repeat)
        elif row_has_vulnerability and not row_evidence:
            repeat_count = max(1, args.unsupported_vulnerable_repeat)
        elif not row_has_vulnerability:
            repeat_count = max(1, args.safe_negative_repeat)
        else:
            repeat_count = 1

        for repeat_idx in range(repeat_count):
            emitted = dict(row)
            emitted["prompt"] = prompt
            if response is not None:
                emitted["response"] = response
            emitted["detector_probability"] = probability
            emitted["repeat_index"] = repeat_idx
            rows_out.append(emitted)
            if args.max_rows and len(rows_out) >= args.max_rows:
                break
        if args.max_rows and len(rows_out) >= args.max_rows:
            break

    write_jsonl(args.output, rows_out)
    print(
        json.dumps(
            {
                "rows": len(rows_out),
                "output": args.output,
                "threshold": args.threshold,
                "safe_negative_repeat": args.safe_negative_repeat,
                "unsupported_vulnerable_repeat": args.unsupported_vulnerable_repeat,
                "supported_positive_repeat": args.supported_positive_repeat,
                "evidence_limit": args.evidence_limit,
                "family_aware": args.family_aware,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
