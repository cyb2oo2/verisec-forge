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


def full_heuristic_keyword_count(code: str) -> int:
    lowered = code.lower()
    return sum(lowered.count(keyword) for keyword in KEYWORDS)


def heuristic_keyword_summary(code: str) -> str:
    counts = {
        keyword: code.lower().count(keyword)
        for keyword in KEYWORDS
        if code.lower().count(keyword) > 0
    }
    if not counts:
        return "no tracked security keywords found"
    return "\n".join(f"{keyword}: {count}" for keyword, count in sorted(counts.items()))


def build_text(*, code: str, language: str, probability: float, input_mode: str, label_mode: str = "heuristic_support") -> str:
    header = "A first-pass vulnerability detector has flagged this function.\n"
    if label_mode == "alert_validity":
        instruction = "Decide whether the detector alert is a true vulnerability alert from the available information.\n\n"
    else:
        instruction = "Decide whether the alert is supportable from the available information.\n\n"
    if input_mode == "full":
        return (
            header
            + f"Detector vulnerability probability: {probability:.4f}\n"
            + instruction
            + f"language: {language}\n"
            + f"code:\n{code}"
        )
    if input_mode == "no_probability":
        return header + instruction + f"language: {language}\n" + f"code:\n{code}"
    if input_mode == "probability_only":
        return header + f"Detector vulnerability probability: {probability:.4f}\n" + instruction
    if input_mode == "code_only":
        return f"language: {language}\ncode:\n{code}"
    if input_mode == "heuristic_only":
        return (
            header
            + instruction
            + f"language: {language}\n"
            + "tracked keyword counts:\n"
            + heuristic_keyword_summary(code)
        )
    raise ValueError(f"Unsupported input_mode: {input_mode}")


def balance_support_rows(
    rows: list[dict[str, object]],
    *,
    positive_to_negative_ratio: float,
) -> list[dict[str, object]]:
    if positive_to_negative_ratio <= 0:
        return rows

    positives = [row for row in rows if bool(row["has_vulnerability"])]
    negatives = [row for row in rows if not bool(row["has_vulnerability"])]
    if not positives or not negatives:
        return rows

    negatives = sorted(
        negatives,
        key=lambda row: (
            -float(row.get("detector_probability", 0.0)),
            -int(row.get("heuristic_keyword_count", 0)),
            str(row.get("id", "")),
        ),
    )
    max_positives = min(len(positives), int(len(negatives) * positive_to_negative_ratio))
    positives = sorted(
        positives,
        key=lambda row: (
            -int(row.get("heuristic_keyword_count", 0)),
            -float(row.get("detector_probability", 0.0)),
            str(row.get("id", "")),
        ),
    )[:max_positives]
    selected_ids = {str(row["id"]) for row in positives + negatives}
    return [row for row in rows if str(row["id"]) in selected_ids]


def main() -> None:
    parser = argparse.ArgumentParser(description="Build detector-positive PrimeVul support scorer datasets.")
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--probabilities", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--evidence-limit", type=int, default=3)
    parser.add_argument(
        "--input-mode",
        choices=["full", "no_probability", "probability_only", "code_only", "heuristic_only"],
        default="full",
    )
    parser.add_argument(
        "--label-mode",
        choices=["heuristic_support", "alert_validity"],
        default="heuristic_support",
        help="heuristic_support requires a vulnerable sample plus keyword evidence; alert_validity uses the source vulnerability label.",
    )
    parser.add_argument("--max-rows", type=int, default=0)
    parser.add_argument(
        "--positive-to-negative-ratio",
        type=float,
        default=0.0,
        help="If > 0, keep all detector-positive negatives and downsample positives to this ratio.",
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
        code = str(row.get("code") or "")
        language = str(row.get("language") or "c")
        has_vulnerability = bool(row.get("has_vulnerability"))
        evidence_count = heuristic_evidence_count(code, limit=max(1, args.evidence_limit))
        keyword_count = full_heuristic_keyword_count(code)
        supported = has_vulnerability and evidence_count > 0
        label = has_vulnerability if args.label_mode == "alert_validity" else supported
        text = build_text(
            code=code,
            language=language,
            probability=probability,
            input_mode=args.input_mode,
            label_mode=args.label_mode,
        )
        rows_out.append(
            {
                "id": row["id"],
                "task_type": "evidence_scoring",
                "language": language,
                "code": code,
                "text": text,
                "prompt": text,
                "has_vulnerability": bool(label),
                "source_has_vulnerability": has_vulnerability,
                "supported_label": bool(supported),
                "alert_validity_label": has_vulnerability,
                "detector_probability": probability,
                "heuristic_evidence_count": evidence_count,
                "heuristic_keyword_count": keyword_count,
                "support_scorer_input_mode": args.input_mode,
                "support_scorer_label_mode": args.label_mode,
                "split": row.get("split", "unknown"),
                "difficulty": row.get("difficulty", "unknown"),
                "source": row.get("source", "primevul"),
                "vulnerability_type": row.get("vulnerability_type", "unknown"),
                "severity": row.get("severity", "unknown"),
            }
        )
        if args.max_rows and len(rows_out) >= args.max_rows:
            break

    rows_out = balance_support_rows(
        rows_out,
        positive_to_negative_ratio=args.positive_to_negative_ratio,
    )
    write_jsonl(args.output, rows_out)
    positives = sum(bool(row["has_vulnerability"]) for row in rows_out)
    payload = {
        "rows": len(rows_out),
        "supported_positive_rows": positives,
        "negative_rows": len(rows_out) - positives,
        "positive_to_negative_ratio": args.positive_to_negative_ratio,
        "output": args.output,
        "threshold": args.threshold,
        "evidence_limit": args.evidence_limit,
        "input_mode": args.input_mode,
        "label_mode": args.label_mode,
    }
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
