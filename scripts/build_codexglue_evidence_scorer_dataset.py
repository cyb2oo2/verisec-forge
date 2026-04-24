from __future__ import annotations

import argparse
import json

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
    "length",
    "copy",
    "array",
    "bounds",
)


def heuristic_evidence_count(code: str, *, limit: int = 3) -> int:
    evidence_rows: list[tuple[int, int]] = []
    for line_no, line in enumerate(code.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        lowered = stripped.lower()
        score = sum(1 for keyword in KEYWORDS if keyword in lowered)
        if score > 0:
            evidence_rows.append((score, line_no))
    evidence_rows.sort(key=lambda item: (-item[0], item[1]))
    return min(limit, len(evidence_rows))


def build_text(*, code: str, language: str, probability: float) -> str:
    return (
        "A first-pass defect detector has flagged this function.\n"
        f"Detector vulnerability probability: {probability:.4f}\n"
        "Decide whether the visible snippet contains concrete code-level evidence strong enough to support the alert.\n\n"
        f"language: {language}\n"
        f"code:\n{code}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Build detector-positive CodeXGLUE support scorer datasets.")
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--probabilities", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--evidence-limit", type=int, default=3)
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
        code = str(row.get("code") or "")
        language = str(row.get("language") or "c")
        has_vulnerability = bool(row.get("has_vulnerability"))
        supported = has_vulnerability and heuristic_evidence_count(code, limit=max(1, args.evidence_limit)) > 0
        text = build_text(code=code, language=language, probability=probability)
        rows_out.append(
            {
                "id": row["id"],
                "task_type": "evidence_scoring",
                "language": language,
                "code": code,
                "text": text,
                "prompt": text,
                "has_vulnerability": bool(supported),
                "source_has_vulnerability": has_vulnerability,
                "supported_label": bool(supported),
                "detector_probability": probability,
                "split": row.get("split", "unknown"),
                "difficulty": row.get("difficulty", "unknown"),
                "source": row.get("source", "codexglue_defect_detection"),
                "vulnerability_type": row.get("vulnerability_type", "unknown"),
                "severity": row.get("severity", "unknown"),
            }
        )
        if args.max_rows and len(rows_out) >= args.max_rows:
            break

    write_jsonl(args.output, rows_out)
    positives = sum(bool(row["has_vulnerability"]) for row in rows_out)
    payload = {
        "rows": len(rows_out),
        "supported_positive_rows": positives,
        "negative_rows": len(rows_out) - positives,
        "output": args.output,
        "threshold": args.threshold,
        "evidence_limit": args.evidence_limit,
    }
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
