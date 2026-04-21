from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

from vrf.io_utils import read_jsonl, write_json
from vrf.schemas import SecureCodeGenerationRecord, SecureCodeSample
from vrf.text_utils import family_root_label, safe_mean, security_label_correct, security_presence_correct


def _length_bucket(sample: SecureCodeSample) -> str:
    code = sample.code or sample.prompt or ""
    length = len(code)
    if length < 500:
        return "<500"
    if length < 1500:
        return "500-1499"
    if length < 4000:
        return "1500-3999"
    return "4000+"


def _group_name(sample: SecureCodeSample, bucket_by: str) -> str:
    if bucket_by == "label":
        return "vulnerable" if sample.has_vulnerability else "safe"
    if bucket_by == "family":
        if not sample.has_vulnerability:
            return "none"
        return family_root_label(sample.vulnerability_type)
    if bucket_by == "language":
        return sample.language or "unknown"
    if bucket_by == "length":
        return _length_bucket(sample)
    raise ValueError(f"Unsupported bucket: {bucket_by}")


def _compute_rows(
    samples: dict[str, SecureCodeSample],
    generations: list[SecureCodeGenerationRecord],
    bucket_by: str,
) -> list[dict]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for generation in generations:
        sample = samples[generation.id]
        presence_correct = security_presence_correct(
            generation.has_vulnerability,
            sample.has_vulnerability,
        )
        label_correct = security_label_correct(
            generation.has_vulnerability,
            generation.predicted_vulnerability_type,
            sample.has_vulnerability,
            sample.vulnerability_type,
        )
        key = _group_name(sample, bucket_by)
        grouped[key].append(
            {
                "label_correct": 1.0 if label_correct else 0.0,
                "presence_correct": 1.0 if presence_correct else 0.0,
                "format_ok": 1.0 if generation.format_ok else 0.0,
                "invalid_output": 1.0 if generation.has_vulnerability is None else 0.0,
                "high_confidence_error": 1.0
                if generation.confidence is not None and generation.confidence >= 0.8 and not label_correct
                else 0.0,
                "token_count": float(generation.token_count),
                "is_vulnerable": bool(sample.has_vulnerability),
            }
        )

    rows: list[dict] = []
    for key, values in sorted(grouped.items(), key=lambda item: item[0]):
        vulnerable_values = [value for value in values if value["is_vulnerable"]]
        safe_values = [value for value in values if not value["is_vulnerable"]]
        rows.append(
            {
                "bucket": key,
                "count": len(values),
                "label_accuracy": round(safe_mean([value["label_correct"] for value in values]), 4),
                "presence_accuracy": round(safe_mean([value["presence_correct"] for value in values]), 4),
                "vulnerable_recall": round(
                    safe_mean([value["presence_correct"] for value in vulnerable_values]),
                    4,
                ),
                "safe_specificity": round(
                    safe_mean([value["presence_correct"] for value in safe_values]),
                    4,
                ),
                "format_pass_rate": round(safe_mean([value["format_ok"] for value in values]), 4),
                "invalid_output_rate": round(safe_mean([value["invalid_output"] for value in values]), 4),
                "high_confidence_error_rate": round(
                    safe_mean([value["high_confidence_error"] for value in values]),
                    4,
                ),
                "avg_tokens": round(safe_mean([value["token_count"] for value in values]), 4),
            }
        )
    return rows


def _render_markdown(title: str, sections: dict[str, list[dict]]) -> str:
    lines = [f"# {title}", ""]
    for section_name, rows in sections.items():
        lines.extend([f"## {section_name}", ""])
        lines.append(
            "| Bucket | Count | Label Accuracy | Presence Accuracy | Vulnerable Recall | Safe Specificity | Format Pass Rate | High-Confidence Error Rate | Avg Tokens |"
        )
        lines.append(
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"
        )
        for row in rows:
            lines.append(
                f"| {row['bucket']} | {row['count']} | {row['label_accuracy']:.4f} | "
                f"{row['presence_accuracy']:.4f} | {row['vulnerable_recall']:.4f} | "
                f"{row['safe_specificity']:.4f} | {row['format_pass_rate']:.4f} | "
                f"{row['high_confidence_error_rate']:.4f} | {row['avg_tokens']:.2f} |"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Build bucketed secure-code benchmark diagnostics.")
    parser.add_argument("--dataset", required=True, help="Dataset JSONL path")
    parser.add_argument("--generations", required=True, help="Generation JSONL path")
    parser.add_argument("--output-json", required=True, help="Bucket report JSON path")
    parser.add_argument("--output-md", required=True, help="Bucket report markdown path")
    parser.add_argument(
        "--title",
        default="Secure Code Bucket Diagnostics",
        help="Markdown report title",
    )
    args = parser.parse_args()

    samples = {
        row["id"]: SecureCodeSample.from_dict(row)
        for row in read_jsonl(args.dataset)
    }
    generations = [SecureCodeGenerationRecord(**row) for row in read_jsonl(args.generations)]

    sections = {
        "By Label": _compute_rows(samples, generations, "label"),
        "By CWE Family": _compute_rows(samples, generations, "family"),
        "By Language": _compute_rows(samples, generations, "language"),
        "By Code Length": _compute_rows(samples, generations, "length"),
    }

    payload = {
        "dataset": args.dataset,
        "generations": args.generations,
        "sections": sections,
    }
    write_json(args.output_json, payload)
    Path(args.output_md).write_text(_render_markdown(args.title, sections), encoding="utf-8")
    print(
        json.dumps(
            {
                "output_json": args.output_json,
                "output_md": args.output_md,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
