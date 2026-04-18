from __future__ import annotations

import argparse
import json
from pathlib import Path

WRONG_CWE_BY_GOLD = {
    "cwe-787": "cwe-190",
    "cwe-125": "cwe-787",
    "cwe-190": "cwe-787",
    "cwe-369": "cwe-20",
    "cwe-476": "cwe-70",
    "cwe-295": "cwe-78",
    "cwe-354": "cwe-189",
    "cwe-200": "cwe-703",
    "cwe-20": "cwe-78",
    "cwe-401": "cwe-476",
    "cwe-94": "cwe-78",
    "cwe-416": "cwe-125",
    "cwe-120": "cwe-125",
    "cwe-122": "cwe-787",
    "cwe-119": "cwe-787",
    "cwe-310": "cwe-295",
}


def _short_explanation(has_vulnerability: bool, vulnerability_type: str) -> str:
    if has_vulnerability:
        return f"The snippet is consistent with {vulnerability_type}."
    return "The snippet does not show a confirmed security weakness."


def _short_fix_principle(has_vulnerability: bool) -> str:
    if has_vulnerability:
        return "Preserve behavior while removing the unsafe pattern with safer APIs and validation."
    return "Keep the implementation stable and avoid introducing unsupported security claims."


def _clean_severity(row: dict, *, safe_default: str = "none") -> str:
    severity = (row.get("severity") or safe_default).strip().lower()
    if severity in {"critical", "high", "medium", "low", "unknown", "none"}:
        return severity
    return safe_default


def _safe_chosen_payload(row: dict) -> dict:
    return {
        "has_vulnerability": False,
        "vulnerability_type": "none",
        "severity": _clean_severity(row),
        "evidence": row.get("gold_evidence") if isinstance(row.get("gold_evidence"), list) else [],
        "explanation": row.get("gold_explanation")
        or "No clear security weakness is evident from the provided snippet alone.",
        "fix_principle": row.get("gold_fix_principle") or "Preserve input validation and least-privilege design.",
        "confidence": 0.75,
        "fix_choice": row.get("gold_fix_choice") or "",
    }


def _safe_chosen_label_focused_payload(row: dict) -> dict:
    return {
        "has_vulnerability": False,
        "vulnerability_type": "none",
        "severity": _clean_severity(row),
        "evidence": row.get("gold_evidence") if isinstance(row.get("gold_evidence"), list) else [],
        "explanation": _short_explanation(False, "none"),
        "fix_principle": _short_fix_principle(False),
        "confidence": 0.78,
        "fix_choice": row.get("gold_fix_choice") or "",
    }


def _safe_rejected_payload() -> dict:
    return {
        "has_vulnerability": True,
        "vulnerability_type": "cwe-78",
        "severity": "high",
        "evidence": [],
        "explanation": "The snippet appears vulnerable because it may use untrusted input in an unsafe way.",
        "fix_principle": "Replace the risky code path with a safer API and sanitize all external input.",
        "confidence": 0.95,
        "fix_choice": "",
    }


def _safe_rejected_overflow_payload() -> dict:
    return {
        "has_vulnerability": True,
        "vulnerability_type": "cwe-787",
        "severity": "high",
        "evidence": [],
        "explanation": "The code likely has a memory-safety issue because buffer boundaries may not be enforced.",
        "fix_principle": "Add explicit bounds checks and reject unsafe accesses.",
        "confidence": 0.95,
        "fix_choice": "",
    }


def _vuln_chosen_payload(row: dict) -> dict:
    vulnerability_type = row.get("vulnerability_type") or "unknown"
    severity = _clean_severity(row, safe_default="unknown")
    return {
        "has_vulnerability": True,
        "vulnerability_type": vulnerability_type,
        "severity": severity,
        "evidence": row.get("gold_evidence") if isinstance(row.get("gold_evidence"), list) else [],
        "explanation": row.get("gold_explanation")
        or f"The code shows behavior consistent with {vulnerability_type} based on the provided snippet and context.",
        "fix_principle": row.get("gold_fix_principle")
        or "Remove the insecure behavior, validate untrusted input, and prefer safer APIs.",
        "confidence": 0.9,
        "fix_choice": row.get("gold_fix_choice") or "",
    }


def _vuln_rejected_payload(row: dict) -> dict:
    return {
        "has_vulnerability": False,
        "vulnerability_type": "none",
        "severity": "none",
        "evidence": [],
        "explanation": "No clear security weakness is evident from the provided snippet alone.",
        "fix_principle": "Preserve safe coding practices and input validation.",
        "confidence": 0.95,
        "fix_choice": "",
    }


def _vuln_rejected_wrong_cwe_payload(row: dict) -> dict:
    gold_cwe = row.get("vulnerability_type") or "unknown"
    wrong_cwe = WRONG_CWE_BY_GOLD.get(gold_cwe, "cwe-787")
    return {
        "has_vulnerability": True,
        "vulnerability_type": wrong_cwe,
        "severity": "high",
        "evidence": [],
        "explanation": (
            f"The snippet looks dangerous and is best explained as {wrong_cwe}. "
            "The control flow and memory handling suggest a serious vulnerability."
        ),
        "fix_principle": "Perform a broad security hardening pass and replace risky operations with safer alternatives.",
        "confidence": 0.98,
        "fix_choice": "",
    }


def _safe_rejected_calibrated_payload() -> dict:
    return {
        "has_vulnerability": True,
        "vulnerability_type": "cwe-78",
        "severity": "medium",
        "evidence": [],
        "explanation": "The snippet may be unsafe because external input could reach a sensitive operation.",
        "fix_principle": "Validate untrusted input and gate sensitive operations behind safer helpers.",
        "confidence": 0.9,
        "fix_choice": "",
    }


def _safe_rejected_wrong_cwe_payload() -> dict:
    return {
        "has_vulnerability": False,
        "vulnerability_type": "cwe-20",
        "severity": "none",
        "evidence": [],
        "explanation": "The code appears safe, but the weakness type is mislabeled.",
        "fix_principle": "Keep the existing implementation and avoid inventing unsupported CWE tags.",
        "confidence": 0.9,
        "fix_choice": "",
    }


def _safe_rejected_label_focused_payload() -> dict:
    return {
        "has_vulnerability": True,
        "vulnerability_type": "cwe-78",
        "severity": "medium",
        "evidence": [],
        "explanation": _short_explanation(True, "cwe-78"),
        "fix_principle": _short_fix_principle(True),
        "confidence": 0.82,
        "fix_choice": "",
    }


def _safe_rejected_label_focused_wrong_cwe_payload() -> dict:
    return {
        "has_vulnerability": False,
        "vulnerability_type": "cwe-20",
        "severity": "none",
        "evidence": [],
        "explanation": _short_explanation(False, "cwe-20"),
        "fix_principle": _short_fix_principle(False),
        "confidence": 0.82,
        "fix_choice": "",
    }


def _vuln_rejected_calibrated_payload(row: dict) -> dict:
    gold_cwe = row.get("vulnerability_type") or "unknown"
    return {
        "has_vulnerability": False,
        "vulnerability_type": gold_cwe,
        "severity": "none",
        "evidence": [],
        "explanation": "The snippet does not provide enough evidence to confirm a security weakness.",
        "fix_principle": "Keep current behavior unless stronger evidence is available.",
        "confidence": 0.9,
        "fix_choice": "",
    }


def _vuln_rejected_wrong_cwe_calibrated_payload(row: dict) -> dict:
    gold_cwe = row.get("vulnerability_type") or "unknown"
    wrong_cwe = WRONG_CWE_BY_GOLD.get(gold_cwe, "cwe-787")
    return {
        "has_vulnerability": True,
        "vulnerability_type": wrong_cwe,
        "severity": _clean_severity(row, safe_default="high"),
        "evidence": [],
        "explanation": f"The snippet is vulnerable, but it is better explained as {wrong_cwe}.",
        "fix_principle": "Use safer APIs and targeted validation to remove the risky behavior.",
        "confidence": 0.9,
        "fix_choice": "",
    }


def _vuln_chosen_label_focused_payload(row: dict) -> dict:
    vulnerability_type = row.get("vulnerability_type") or "unknown"
    severity = _clean_severity(row, safe_default="unknown")
    return {
        "has_vulnerability": True,
        "vulnerability_type": vulnerability_type,
        "severity": severity,
        "evidence": row.get("gold_evidence") if isinstance(row.get("gold_evidence"), list) else [],
        "explanation": _short_explanation(True, vulnerability_type),
        "fix_principle": _short_fix_principle(True),
        "confidence": 0.82,
        "fix_choice": row.get("gold_fix_choice") or "",
    }


def _vuln_rejected_label_focused_payload(row: dict) -> dict:
    return {
        "has_vulnerability": False,
        "vulnerability_type": "none",
        "severity": "none",
        "evidence": [],
        "explanation": _short_explanation(False, "none"),
        "fix_principle": _short_fix_principle(False),
        "confidence": 0.82,
        "fix_choice": "",
    }


def _vuln_rejected_label_focused_wrong_cwe_payload(row: dict) -> dict:
    gold_cwe = row.get("vulnerability_type") or "unknown"
    wrong_cwe = WRONG_CWE_BY_GOLD.get(gold_cwe, "cwe-787")
    return {
        "has_vulnerability": True,
        "vulnerability_type": wrong_cwe,
        "severity": _clean_severity(row, safe_default="unknown"),
        "evidence": [],
        "explanation": _short_explanation(True, wrong_cwe),
        "fix_principle": _short_fix_principle(True),
        "confidence": 0.82,
        "fix_choice": "",
    }


def build_preference_rows(row: dict, *, mode: str = "hard") -> list[dict]:
    has_vulnerability = bool(row.get("has_vulnerability", False))
    rows_out: list[dict] = []
    if mode == "calibrated":
        if has_vulnerability:
            chosen = _vuln_chosen_payload(row)
            rejected_payloads = [
                _vuln_rejected_calibrated_payload(row),
                _vuln_rejected_wrong_cwe_calibrated_payload(row),
            ]
        else:
            chosen = _safe_chosen_payload(row)
            rejected_payloads = [
                _safe_rejected_calibrated_payload(),
                _safe_rejected_wrong_cwe_payload(),
            ]
    elif mode == "label_focused":
        if has_vulnerability:
            chosen = _vuln_chosen_label_focused_payload(row)
            rejected_payloads = [
                _vuln_rejected_label_focused_payload(row),
                _vuln_rejected_label_focused_wrong_cwe_payload(row),
            ]
        else:
            chosen = _safe_chosen_label_focused_payload(row)
            rejected_payloads = [
                _safe_rejected_label_focused_payload(),
                _safe_rejected_label_focused_wrong_cwe_payload(),
            ]
    else:
        if has_vulnerability:
            chosen = _vuln_chosen_payload(row)
            rejected_payloads = [
                _vuln_rejected_payload(row),
                _vuln_rejected_wrong_cwe_payload(row),
            ]
        else:
            chosen = _safe_chosen_payload(row)
            rejected_payloads = [
                _safe_rejected_payload(),
                _safe_rejected_overflow_payload(),
            ]

    for idx, rejected in enumerate(rejected_payloads, start=1):
        rows_out.append(
            {
                "id": f"{row['id']}-{mode}-pref{idx}",
                "task_type": row.get("task_type", "weakness_identification"),
                "prompt": row["prompt"],
                "chosen": json.dumps(chosen, ensure_ascii=False),
                "rejected": json.dumps(rejected, ensure_ascii=False),
                "split": row.get("split", "train"),
                "source": row.get("source", "unknown"),
                "has_vulnerability": has_vulnerability,
                "vulnerability_type": row.get("vulnerability_type") or "none",
            }
        )
    return rows_out


def main() -> None:
    parser = argparse.ArgumentParser(description="Build secure-code DPO preference rows from normalized secure-code data.")
    parser.add_argument("--input", required=True, help="Normalized input JSONL")
    parser.add_argument("--output", required=True, help="Output preference JSONL")
    parser.add_argument("--split", default="train", help="Only keep rows from this split")
    parser.add_argument("--limit", type=int, default=None, help="Optional maximum number of rows")
    parser.add_argument(
        "--mode",
        choices=["hard", "calibrated", "label_focused"],
        default="hard",
        help="Preference construction style",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    rows_out: list[dict] = []
    with input_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if args.limit is not None and len(rows_out) >= args.limit:
                break
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if row.get("split", "train") != args.split:
                continue
            rows_out.extend(build_preference_rows(row, mode=args.mode))

    with output_path.open("w", encoding="utf-8") as handle:
        for row in rows_out:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(json.dumps({"rows": len(rows_out), "output_path": str(output_path)}, indent=2))


if __name__ == "__main__":
    main()
