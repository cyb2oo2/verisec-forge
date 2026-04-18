from __future__ import annotations

import argparse
import json
import random
from collections import defaultdict
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.text_utils import family_root_label


FAMILY_KEYWORDS: dict[str, tuple[str, ...]] = {
    "cwe-119": (
        "memcpy", "memmove", "strcpy", "strncpy", "strcat", "malloc", "calloc", "realloc",
        "free", "delete", "buffer", "offset", "index", "length", "size", "count", "pointer",
    ),
    "cwe-20": (
        "input", "request", "uri", "url", "path", "file", "parse", "exec", "system", "query",
        "validate", "check", "argv", "env", "deserialize",
    ),
    "cwe-200": ("print", "log", "debug", "dump", "trace", "response", "error", "token", "secret"),
    "cwe-189": ("size", "count", "offset", "index", "shift", "divide", "multiply", "add"),
    "cwe-399": ("alloc", "malloc", "free", "release", "close", "destroy", "open", "return"),
    "cwe-703": ("lock", "unlock", "mutex", "thread", "atomic", "shared", "state", "race"),
    "cwe-264": ("auth", "token", "credential", "permission", "access", "ssl", "tls", "crypto", "hash"),
    "cwe-835": ("while", "for", "loop", "recursive", "retry", "wait", "sleep"),
}

FIX_PRINCIPLES: dict[str, str] = {
    "cwe-119": "Validate bounds before memory access and use safer buffer-handling patterns.",
    "cwe-20": "Validate untrusted input before using it in dangerous operations or parsing logic.",
    "cwe-200": "Avoid exposing secrets or internal state and limit data disclosure to the minimum necessary.",
    "cwe-189": "Check arithmetic bounds before using results in memory access, allocation, or indexing.",
    "cwe-399": "Ensure resources are allocated, released, and cleaned up along all relevant paths.",
    "cwe-703": "Guard shared state and exceptional paths with explicit safety checks and synchronization.",
    "cwe-264": "Enforce authentication, authorization, and secret-handling rules consistently.",
    "cwe-835": "Add clear termination or resource bounds so control flow cannot spin indefinitely.",
    "default": "Remove the unsafe behavior and replace it with a defensible secure implementation.",
}


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


def heuristic_evidence(code: str, vulnerability_type: str) -> list[dict]:
    root = family_root_label(vulnerability_type)
    keywords = FAMILY_KEYWORDS.get(root, ())
    evidence: list[dict] = []
    for line_no, line in enumerate(code.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        lowered = stripped.lower()
        score = sum(1 for keyword in keywords if keyword in lowered)
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
    evidence.sort(key=lambda item: (-item["_score"], item["line_start"]))
    trimmed: list[dict] = []
    for item in evidence[:2]:
        copied = dict(item)
        copied.pop("_score", None)
        trimmed.append(copied)
    return trimmed


def build_response(sample: dict) -> str:
    return build_response_with_style(sample, response_style="default")


def build_response_with_style(sample: dict, response_style: str = "default") -> str:
    has_vulnerability = bool(sample.get("has_vulnerability"))
    vulnerability_type = family_root_label(sample.get("vulnerability_type"))
    if not has_vulnerability:
        explanation = "No defensible vulnerability claim."
        fix_principle = "No remediation justified."
        confidence = 0.7
        if response_style == "compact":
            explanation = "No supported vulnerability."
            fix_principle = "No change justified."
            confidence = 0.6
        elif response_style == "decision_only":
            explanation = "No supported vulnerability."
            fix_principle = "No change."
            confidence = 0.55
        elif response_style == "binary_judge":
            explanation = "Not supported."
            fix_principle = "No change."
            confidence = 0.6
        elif response_style == "label_only":
            explanation = "Not supported."
            fix_principle = "No change."
            confidence = 0.55
        payload = {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "severity": "none",
            "evidence": [],
            "explanation": explanation,
            "fix_principle": fix_principle,
            "confidence": confidence,
            "fix_choice": sample.get("gold_fix_choice") or "",
        }
        return json.dumps(payload, ensure_ascii=False)

    evidence = sample.get("gold_evidence")
    if not isinstance(evidence, list) or not evidence:
        evidence = heuristic_evidence(sample.get("code") or "", vulnerability_type)
    if response_style == "label_only":
        evidence = []
    elif response_style in {"compact", "decision_only", "binary_judge"} and evidence:
        evidence = evidence[:1]
    explanation = (
        f"The first-pass safe judgment missed evidence consistent with {vulnerability_type}. "
        "A second-pass review should treat this snippet as vulnerable."
    )
    fix_principle = FIX_PRINCIPLES.get(vulnerability_type, FIX_PRINCIPLES["default"])
    confidence = 0.9
    if response_style == "compact":
        explanation = f"Missed evidence supports {vulnerability_type}."
        fix_principle = "Escalate and inspect this code."
        confidence = 0.85
    elif response_style == "decision_only":
        explanation = f"Supported {vulnerability_type}."
        fix_principle = "Escalate."
        confidence = 0.75
    elif response_style == "binary_judge":
        explanation = "Supported."
        fix_principle = "Escalate."
        confidence = 0.8
    elif response_style == "label_only":
        explanation = "Supported."
        fix_principle = "Escalate."
        confidence = 0.7
    payload = {
        "has_vulnerability": True,
        "vulnerability_type": vulnerability_type,
        "severity": sample.get("severity") or "unknown",
        "evidence": evidence,
        "explanation": explanation,
        "fix_principle": fix_principle,
        "confidence": confidence,
        "fix_choice": sample.get("gold_fix_choice") or "",
    }
    return json.dumps(payload, ensure_ascii=False)


def truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def build_prompt(sample: dict, generation: dict, raw_text_limit: int, response_style: str = "default") -> str:
    language = sample.get("language") or "unknown"
    code = sample.get("code") or sample.get("prompt") or ""
    confidence = generation.get("confidence")
    predicted_type = generation.get("predicted_vulnerability_type") or "none"
    predicted_has = generation.get("has_vulnerability")
    parse_confidence = generation.get("parse_confidence")
    first_pass_summary = [
        "The first-pass model marked this code as safe or non-actionable.",
        f"first_pass_has_vulnerability: {predicted_has}",
        f"first_pass_vulnerability_type: {predicted_type}",
        f"first_pass_confidence: {confidence}",
        f"first_pass_parse_confidence: {parse_confidence}",
        f"first_pass_raw_text: {truncate(generation.get('raw_text') or '', raw_text_limit)}",
    ]
    instruction = (
        "You are performing a second-pass defensive security review.\n"
        "The first-pass model may have incorrectly marked the code as safe.\n"
        "Only return a vulnerability when the code supports a defensible canonical cwe-* label.\n"
        "If the evidence is insufficient, return has_vulnerability=false and vulnerability_type=none.\n"
    )
    if response_style == "compact":
        instruction += (
            "Return exactly one short JSON object.\n"
            "Keep explanation and fix_principle very short.\n"
            "Use at most one evidence item.\n"
        )
    elif response_style == "decision_only":
        instruction += (
            "Return exactly one tiny JSON object.\n"
            "Use short fixed-style fields.\n"
            "Keep explanation to one short sentence.\n"
            "Keep fix_principle to one short phrase.\n"
            "Use at most one evidence item.\n"
            "Do not elaborate.\n"
        )
    elif response_style == "binary_judge":
        instruction += (
            "Return exactly one tiny JSON object.\n"
            "This is a binary second-pass judgment, not a full audit report.\n"
            "Only overturn the first-pass safe prediction when the snippet defensibly supports a canonical cwe-* label.\n"
            "Use explanation values only 'Supported.' or 'Not supported.'.\n"
            "Use fix_principle values only 'Escalate.' or 'No change.'.\n"
            "Use at most one evidence item.\n"
            "Do not elaborate.\n"
        )
    elif response_style == "label_only":
        instruction += (
            "Return exactly one tiny JSON object.\n"
            "This is a label-only reranking judgment, not a full audit report.\n"
            "Only overturn the first-pass safe prediction when the snippet defensibly supports a canonical cwe-* label.\n"
            "Always emit an empty evidence array.\n"
            "Use explanation values only 'Supported.' or 'Not supported.'.\n"
            "Use fix_principle values only 'Escalate.' or 'No change.'.\n"
            "Do not elaborate.\n"
        )
    return (
        instruction + "\n"
        + "\n".join(first_pass_summary)
        + f"\n\nlanguage: {language}\ncode:\n{code}"
    )


def confidence_value(generation: dict) -> float:
    value = generation.get("confidence")
    if isinstance(value, (int, float)):
        return float(value)
    return 0.0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build failure-driven verifier SFT data from first-pass false negatives.")
    parser.add_argument("--dataset", required=True, help="Gold JSONL dataset used for generations")
    parser.add_argument("--generations", required=True, help="First-pass generation JSONL")
    parser.add_argument("--output", required=True, help="Output verifier SFT JSONL")
    parser.add_argument(
        "--max-safe-per-fn",
        type=int,
        default=1,
        help="Number of matched safe examples to keep for each false negative",
    )
    parser.add_argument(
        "--duplicate-false-negatives",
        type=int,
        default=1,
        help="Additional copies per false-negative row to emphasize missed vulnerabilities",
    )
    parser.add_argument("--seed", type=int, default=17)
    parser.add_argument("--raw-text-limit", type=int, default=300)
    parser.add_argument(
        "--response-style",
        choices=["default", "compact", "decision_only", "binary_judge", "label_only"],
        default="default",
        help="How verbose the verifier target should be.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    dataset_rows = {row["id"]: row for row in load_jsonl(Path(args.dataset))}
    generation_rows = {row["id"]: row for row in load_jsonl(Path(args.generations))}

    false_negatives: list[tuple[dict, dict]] = []
    safe_predictions_by_language: dict[str, list[tuple[dict, dict]]] = defaultdict(list)

    for sample_id, sample in dataset_rows.items():
        generation = generation_rows.get(sample_id)
        if not generation:
            continue
        pred_has = generation.get("has_vulnerability")
        gold_has = bool(sample.get("has_vulnerability"))
        language = sample.get("language") or "unknown"
        if pred_has is False and gold_has is True:
            false_negatives.append((sample, generation))
        elif pred_has is False and gold_has is False:
            safe_predictions_by_language[language].append((sample, generation))

    rng = random.Random(args.seed)
    for rows in safe_predictions_by_language.values():
        rows.sort(key=lambda item: confidence_value(item[1]))
        rng.shuffle(rows)

    verifier_rows: list[dict] = []
    selected_safe_ids: set[str] = set()

    for sample, generation in false_negatives:
        row = dict(sample)
        row["prompt"] = build_prompt(sample, generation, args.raw_text_limit, response_style=args.response_style)
        row["response"] = build_response_with_style(sample, response_style=args.response_style)
        verifier_rows.append(row)
        for duplicate_idx in range(args.duplicate_false_negatives):
            cloned = dict(row)
            cloned["id"] = f"{row['id']}::fnboost{duplicate_idx + 1}"
            verifier_rows.append(cloned)

    language_buckets: dict[str, list[tuple[dict, dict]]] = defaultdict(list)
    for sample, generation in false_negatives:
        language_buckets[sample.get("language") or "unknown"].append((sample, generation))

    for language, fn_rows in language_buckets.items():
        safe_candidates = safe_predictions_by_language.get(language, [])
        if not safe_candidates:
            safe_candidates = [item for rows in safe_predictions_by_language.values() for item in rows]
        if not safe_candidates:
            continue
        safe_candidates = list(safe_candidates)
        safe_candidates.sort(key=lambda item: confidence_value(item[1]))
        cursor = 0
        target_count = len(fn_rows) * max(0, args.max_safe_per_fn)
        while cursor < len(safe_candidates) and target_count > 0:
            sample, generation = safe_candidates[cursor]
            cursor += 1
            if sample["id"] in selected_safe_ids:
                continue
            selected_safe_ids.add(sample["id"])
            row = dict(sample)
            row["prompt"] = build_prompt(sample, generation, args.raw_text_limit, response_style=args.response_style)
            row["response"] = build_response_with_style(sample, response_style=args.response_style)
            verifier_rows.append(row)
            target_count -= 1

    verifier_rows.sort(key=lambda row: row["id"])
    write_jsonl(Path(args.output), verifier_rows)

    safe_rows = sum(1 for row in verifier_rows if not bool(row.get("has_vulnerability")))
    vulnerable_rows = sum(1 for row in verifier_rows if bool(row.get("has_vulnerability")))
    print(
        json.dumps(
            {
                "output_path": args.output,
                "false_negative_source_rows": len(false_negatives),
                "selected_safe_rows": len(selected_safe_ids),
                "total_rows": len(verifier_rows),
                "vulnerable_rows": vulnerable_rows,
                "safe_rows": safe_rows,
                "response_style": args.response_style,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
