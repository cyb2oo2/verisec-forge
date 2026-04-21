from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _normalize_code(raw: dict[str, Any]) -> str | None:
    for key in ("func", "function", "code", "source"):
        value = raw.get(key)
        if value:
            return str(value)
    return None


def _normalize_label(raw: dict[str, Any]) -> bool | None:
    value = raw.get("target")
    if value is None:
        value = raw.get("label")
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(int(value))
    lowered = str(value).strip().lower()
    if lowered in {"1", "true", "yes", "vulnerable", "defect"}:
        return True
    if lowered in {"0", "false", "no", "safe", "benign"}:
        return False
    return None


def normalize_codexglue_record(raw: dict[str, Any], split: str, index: int) -> dict[str, Any] | None:
    code = _normalize_code(raw)
    has_vulnerability = _normalize_label(raw)
    if not code or has_vulnerability is None:
        return None

    prompt = (
        "Analyze the following c code for defensive security issues and return JSON only.\n\n"
        f"code:\n{code}"
    )
    return {
        "id": str(raw.get("id", raw.get("idx", f"codexglue-defect-{split}-{index:06d}"))),
        "task_type": "weakness_identification",
        "language": "c",
        "prompt": prompt,
        "code": code,
        "diff": None,
        "context": "Function-level binary vulnerability detection from CodeXGLUE defect detection.",
        "split": split,
        "difficulty": "unknown",
        "source": "codexglue_defect_detection",
        "has_vulnerability": has_vulnerability,
        "vulnerability_type": "unknown" if has_vulnerability else "none",
        "severity": "unknown" if has_vulnerability else "none",
        "gold_fix_choice": None,
        "gold_evidence": [],
        "gold_explanation": (
            "The function contains a vulnerability-like defect and should be treated as unsafe."
            if has_vulnerability
            else "No vulnerability-like defect is labeled for this function."
        ),
        "gold_fix_principle": (
            "Remove the unsafe behavior, validate inputs, and replace fragile logic with safer handling."
            if has_vulnerability
            else "Preserve safe coding practices and avoid introducing unsafe behavior."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Normalize local CodeXGLUE defect detection JSONL files into VeriSec Forge schema."
    )
    parser.add_argument("--input-dir", required=True, help="Directory containing raw split JSONL files")
    parser.add_argument("--output", required=True, help="Output normalized JSONL path")
    parser.add_argument("--limit-train", type=int, default=0, help="Optional train-row cap")
    parser.add_argument("--limit-eval", type=int, default=0, help="Optional eval-row cap per split")
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    split_map: list[tuple[str, str, int]] = [
        ("train", "train", args.limit_train),
        ("validation", "eval", args.limit_eval),
        ("test", "eval", args.limit_eval),
    ]

    rows_out: list[dict[str, Any]] = []
    summary = {"train": 0, "eval": 0, "skipped": 0}
    for raw_split_name, normalized_split, limit in split_map:
        input_path = input_dir / f"{raw_split_name}.jsonl"
        if not input_path.exists():
            continue
        count = 0
        with input_path.open("r", encoding="utf-8") as handle:
            for index, line in enumerate(handle):
                line = line.strip()
                if not line:
                    continue
                row = normalize_codexglue_record(json.loads(line), normalized_split, index)
                if row is None:
                    summary["skipped"] += 1
                    continue
                rows_out.append(row)
                count += 1
                if limit and count >= limit:
                    break
        summary[normalized_split] += count

    with output_path.open("w", encoding="utf-8") as handle:
        for row in rows_out:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(json.dumps({"output_path": str(output_path), "summary": summary}, indent=2))


if __name__ == "__main__":
    main()
