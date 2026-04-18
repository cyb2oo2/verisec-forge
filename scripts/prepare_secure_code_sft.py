from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


FAMILY_KEYWORDS: dict[str, tuple[str, ...]] = {
    "memory_safety": (
        "memcpy", "memmove", "strcpy", "strncpy", "strcat", "malloc", "calloc", "realloc",
        "free", "delete", "buffer", "offset", "index", "length", "size", "count", "pointer",
    ),
    "input_validation": (
        "input", "request", "uri", "url", "path", "file", "parse", "exec", "system", "query",
        "validate", "check", "argv", "env", "deserialize",
    ),
    "information_exposure": ("print", "log", "debug", "dump", "trace", "response", "error"),
    "numeric_safety": ("size", "count", "offset", "index", "shift", "divide", "multiply", "add"),
    "resource_lifetime": ("alloc", "malloc", "free", "release", "close", "destroy", "open", "return"),
    "concurrency_state": ("lock", "unlock", "mutex", "thread", "atomic", "shared", "state", "race"),
    "auth_crypto": ("auth", "token", "credential", "permission", "access", "ssl", "tls", "crypto", "hash"),
    "null_exception": ("null", "nullptr", "none", "exception", "error", "assert", "check"),
    "availability_loop": ("while", "for", "loop", "recursive", "retry", "wait", "sleep"),
}

FAMILY_FIX_PRINCIPLES: dict[str, str] = {
    "memory_safety": "Bound memory operations, validate sizes and indices, and use safer buffer-handling APIs.",
    "input_validation": "Validate untrusted input early, constrain dangerous operations, and enforce allowlists or sanitization.",
    "information_exposure": "Avoid exposing sensitive internal state, and restrict logging or outputs to the minimum necessary.",
    "numeric_safety": "Validate arithmetic bounds and sizes before using them in memory access or allocation decisions.",
    "resource_lifetime": "Pair allocation with safe release paths and guard resource-handling code against leaks and misuse.",
    "concurrency_state": "Protect shared state with explicit synchronization and make state transitions atomic where required.",
    "auth_crypto": "Enforce authentication and access checks consistently and use approved cryptographic primitives safely.",
    "null_exception": "Check error and null states before dereference or propagation, and fail safely on exceptional paths.",
    "availability_loop": "Add clear termination and resource bounds so the code cannot spin or block indefinitely.",
    "other": "Remove the insecure behavior, validate untrusted input, and prefer safer APIs.",
}

FAMILY_EXPLANATIONS: dict[str, str] = {
    "memory_safety": "The code contains a memory-safety weakness consistent with {vulnerability_type}.",
    "input_validation": "The code exposes an input-validation weakness consistent with {vulnerability_type}.",
    "information_exposure": "The code risks exposing sensitive information in a way consistent with {vulnerability_type}.",
    "numeric_safety": "The code shows an arithmetic or bounds-handling weakness consistent with {vulnerability_type}.",
    "resource_lifetime": "The code shows a resource-management weakness consistent with {vulnerability_type}.",
    "concurrency_state": "The code shows a concurrency or state-management weakness consistent with {vulnerability_type}.",
    "auth_crypto": "The code shows an authentication, authorization, or cryptographic weakness consistent with {vulnerability_type}.",
    "null_exception": "The code shows an error-handling weakness consistent with {vulnerability_type}.",
    "availability_loop": "The code shows an availability or termination weakness consistent with {vulnerability_type}.",
    "other": "The code shows behavior consistent with {vulnerability_type} based on the provided snippet and context.",
}

TARGET_RECALL_CWES: set[str] = {
    "cwe-119",
    "cwe-20",
    "cwe-125",
    "cwe-264",
}

FAMILY_ROOT_LABELS: dict[str, str] = {
    "memory_safety": "cwe-119",
    "input_validation": "cwe-20",
    "information_exposure": "cwe-200",
    "numeric_safety": "cwe-189",
    "resource_lifetime": "cwe-399",
    "concurrency_state": "cwe-703",
    "auth_crypto": "cwe-264",
    "null_exception": "cwe-119",
    "availability_loop": "cwe-835",
    "other": "cwe-other",
}


def cwe_family(vulnerability_type: str) -> str:
    normalized = (vulnerability_type or "none").lower()
    memory = {"cwe-119", "cwe-120", "cwe-122", "cwe-125", "cwe-415", "cwe-416", "cwe-476", "cwe-787"}
    input_validation = {"cwe-20", "cwe-22", "cwe-59", "cwe-78", "cwe-79", "cwe-94", "cwe-502"}
    info_exposure = {"cwe-200"}
    numeric = {"cwe-189", "cwe-190", "cwe-191", "cwe-369"}
    resource = {"cwe-399", "cwe-400", "cwe-401", "cwe-772"}
    concurrency = {"cwe-362", "cwe-703", "cwe-754"}
    auth_crypto = {"cwe-264", "cwe-284", "cwe-287", "cwe-310", "cwe-320"}
    availability = {"cwe-617", "cwe-834", "cwe-835"}
    if normalized in memory:
        return "memory_safety"
    if normalized in input_validation:
        return "input_validation"
    if normalized in info_exposure:
        return "information_exposure"
    if normalized in numeric:
        return "numeric_safety"
    if normalized in resource:
        return "resource_lifetime"
    if normalized in concurrency:
        return "concurrency_state"
    if normalized in auth_crypto:
        return "auth_crypto"
    if normalized in availability:
        return "availability_loop"
    if normalized in {"cwe-476"}:
        return "null_exception"
    return "other"


def heuristic_evidence(row: dict, family: str) -> list[dict]:
    code = row.get("code") or ""
    if not code.strip():
        return []
    keywords = FAMILY_KEYWORDS.get(family, ())
    evidence: list[dict] = []
    for line_no, line in enumerate(code.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        lowered = stripped.lower()
        score = sum(1 for keyword in keywords if keyword in lowered)
        if score == 0:
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
    evidence.sort(key=lambda item: (-item["_score"], item["line_start"]))
    trimmed: list[dict] = []
    for item in evidence[:2]:
        copied = dict(item)
        copied.pop("_score", None)
        trimmed.append(copied)
    return trimmed


def is_targeted_recall_cwe(vulnerability_type: str) -> bool:
    return (vulnerability_type or "none").lower() in TARGET_RECALL_CWES


def build_response(row: dict, mode: str = "standard") -> str:
    has_vulnerability = bool(row.get("has_vulnerability", False))
    vulnerability_type = row.get("vulnerability_type", "none") or "none"
    severity = row.get("severity", "unknown") or "unknown"
    fix_choice = row.get("gold_fix_choice") or ""
    family = cwe_family(vulnerability_type) if has_vulnerability else "other"

    if mode in {
        "safe_none_only",
        "evidence_only",
        "family_evidence_clean",
        "recall_focused",
        "targeted_recall_boost",
        "family_label_vulnerable",
        "vulnerable_oversample_clean",
        "presence_only_vulnerable",
        "verifier_canonical",
    } and not has_vulnerability:
        vulnerability_type = "none"
        severity = "none"
    elif mode == "family_label_vulnerable" and has_vulnerability:
        vulnerability_type = FAMILY_ROOT_LABELS.get(family, "cwe-other")
    elif mode == "presence_only_vulnerable" and has_vulnerability:
        vulnerability_type = "vulnerable"
        severity = "unknown"

    explanation = row.get("gold_explanation")
    if not explanation:
        if has_vulnerability:
            if mode == "recall_focused":
                explanation = (
                    f"A security weakness is present and is most consistent with {vulnerability_type}. "
                    "Treat the code as vulnerable unless the unsafe behavior is explicitly removed."
                )
            elif mode == "targeted_recall_boost" and is_targeted_recall_cwe(vulnerability_type):
                explanation = (
                    f"Treat this code as vulnerable. The snippet contains a security weakness consistent with "
                    f"{vulnerability_type} and should not be considered safe."
                )
            elif mode in {"family_evidence_clean", "family_label_vulnerable"}:
                explanation = FAMILY_EXPLANATIONS.get(family, FAMILY_EXPLANATIONS["other"]).format(
                    vulnerability_type=vulnerability_type
                )
            elif mode == "presence_only_vulnerable":
                explanation = "A defensive security weakness is present in the provided code snippet."
            elif mode == "verifier_canonical":
                explanation = (
                    f"A defensible vulnerability claim is supported by the snippet and is most consistent with "
                    f"{vulnerability_type}."
                )
            else:
                explanation = (
                    f"The code shows behavior consistent with {vulnerability_type} "
                    "based on the provided snippet and context."
                )
        else:
            if mode == "recall_focused":
                explanation = "No clear security weakness is evident from the provided snippet alone."
            elif mode == "verifier_canonical":
                explanation = "The snippet does not support a defensible vulnerability claim."
            else:
                explanation = "No clear security weakness is evident from the provided snippet alone."

    fix_principle = row.get("gold_fix_principle")
    if not fix_principle:
        if has_vulnerability:
            if mode == "recall_focused":
                fix_principle = "Remove the unsafe behavior, enforce validation, and prefer safer APIs before shipping."
            elif mode == "targeted_recall_boost" and is_targeted_recall_cwe(vulnerability_type):
                fix_principle = FAMILY_FIX_PRINCIPLES.get(family, FAMILY_FIX_PRINCIPLES["other"])
            elif mode in {"family_evidence_clean", "family_label_vulnerable"}:
                fix_principle = FAMILY_FIX_PRINCIPLES.get(family, FAMILY_FIX_PRINCIPLES["other"])
            elif mode == "presence_only_vulnerable":
                fix_principle = "Remove the unsafe behavior, validate untrusted input, and replace it with a safer implementation."
            elif mode == "verifier_canonical":
                fix_principle = FAMILY_FIX_PRINCIPLES.get(family, FAMILY_FIX_PRINCIPLES["other"])
            else:
                fix_principle = "Remove the insecure behavior, validate untrusted input, and prefer safer APIs."
        else:
            if mode == "verifier_canonical":
                fix_principle = "No concrete remediation is justified from this snippet alone."
            else:
                fix_principle = "Preserve input validation and least-privilege design."

    evidence = row.get("gold_evidence")
    if not isinstance(evidence, list):
        evidence = []
    if mode in {"evidence_only", "family_evidence_clean", "family_label_vulnerable", "verifier_canonical"} and has_vulnerability and not evidence:
        evidence = heuristic_evidence(row, family)
    if mode == "targeted_recall_boost" and has_vulnerability and is_targeted_recall_cwe(vulnerability_type) and not evidence:
        evidence = heuristic_evidence(row, family)

    if mode == "recall_focused":
        confidence = 0.95 if has_vulnerability else 0.55
    elif mode == "targeted_recall_boost":
        confidence = 0.95 if has_vulnerability and is_targeted_recall_cwe(vulnerability_type) else (0.9 if has_vulnerability else 0.75)
    elif mode == "verifier_canonical":
        confidence = 0.85 if has_vulnerability else 0.65
    else:
        confidence = 0.9 if has_vulnerability else 0.75

    payload = {
        "has_vulnerability": has_vulnerability,
        "vulnerability_type": vulnerability_type,
        "severity": severity,
        "evidence": evidence,
        "explanation": explanation,
        "fix_principle": fix_principle,
        "confidence": confidence,
        "fix_choice": fix_choice,
    }
    return json.dumps(payload, ensure_ascii=False)


def build_prompt(row: dict, mode: str = "standard") -> str:
    language = row.get("language") or "unknown"
    code = row.get("code") or row.get("prompt") or ""
    if mode == "verifier_canonical":
        return (
            "You are performing a second-pass defensive security review.\n"
            "The first-pass model may have marked this code as safe.\n"
            "Only report a vulnerability when the snippet supports a defensible, canonical CWE claim.\n"
            "If the evidence is insufficient, return has_vulnerability=false and vulnerability_type=none.\n\n"
            f"language: {language}\n"
            "code:\n"
            f"{code}"
        )
    return row.get("prompt") or ""


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert normalized secure-code benchmark rows into structured SFT rows.")
    parser.add_argument("--input", required=True, help="Normalized input JSONL")
    parser.add_argument("--output", required=True, help="Output JSONL with response field for SFT")
    parser.add_argument("--split", default="train", help="Only keep rows from this split")
    parser.add_argument(
        "--mode",
        default="standard",
        choices=[
            "standard",
            "safe_none_only",
            "evidence_only",
            "family_evidence_clean",
            "recall_focused",
            "targeted_recall_boost",
            "family_label_vulnerable",
            "vulnerable_oversample_clean",
            "presence_only_vulnerable",
            "verifier_canonical",
        ],
        help="Target-shaping mode for SFT response generation",
    )
    parser.add_argument(
        "--duplicate-targeted-vulnerable",
        type=int,
        default=0,
        help="Duplicate vulnerable rows from the targeted recall CWE set this many extra times.",
    )
    parser.add_argument(
        "--duplicate-all-vulnerable",
        type=int,
        default=0,
        help="Duplicate all vulnerable rows this many extra times.",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    rows_out = []
    with input_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if row.get("split", "train") != args.split:
                continue
            row["prompt"] = build_prompt(row, mode=args.mode)
            row["response"] = build_response(row, mode=args.mode)
            rows_out.append(row)
            if (
                args.mode == "targeted_recall_boost"
                and args.duplicate_targeted_vulnerable > 0
                and row.get("has_vulnerability")
                and is_targeted_recall_cwe(row.get("vulnerability_type", "none"))
            ):
                for duplicate_idx in range(args.duplicate_targeted_vulnerable):
                    cloned = dict(row)
                    cloned["id"] = f"{row['id']}::targeteddup{duplicate_idx + 1}"
                    rows_out.append(cloned)
            if args.duplicate_all_vulnerable > 0 and row.get("has_vulnerability"):
                for duplicate_idx in range(args.duplicate_all_vulnerable):
                    cloned = dict(row)
                    cloned["id"] = f"{row['id']}::vulndup{duplicate_idx + 1}"
                    rows_out.append(cloned)

    with output_path.open("w", encoding="utf-8") as handle:
        for row in rows_out:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(json.dumps({"rows": len(rows_out), "output_path": str(output_path)}, indent=2))


if __name__ == "__main__":
    main()
