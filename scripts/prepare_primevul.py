from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _first_present(raw: dict[str, Any], keys: list[str]) -> Any:
    for key in keys:
        if key not in raw:
            continue
        value = raw[key]
        if value is None:
            continue
        if isinstance(value, str) and value == "":
            continue
        if isinstance(value, list) and not value:
            continue
        return value
    return None


def _normalize_language(raw: dict[str, Any]) -> str:
    value = _first_present(raw, ["language", "lang", "programming_language"])
    return str(value).strip().lower() if value else "unknown"


def _normalize_code(raw: dict[str, Any]) -> str | None:
    value = _first_present(
        raw,
        [
            "func",
            "function",
            "code",
            "source",
            "source_code",
            "normalized_func",
            "processed_func",
        ],
    )
    if value is None:
        return None
    return str(value)


def _normalize_label(raw: dict[str, Any]) -> bool | None:
    value = _first_present(raw, ["target", "label", "vul", "vulnerable", "is_vulnerable"])
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(int(value))
    lowered = str(value).strip().lower()
    if lowered in {"1", "true", "yes", "vulnerable"}:
        return True
    if lowered in {"0", "false", "no", "safe", "benign"}:
        return False
    return None


def _normalize_cwe(raw: dict[str, Any], has_vulnerability: bool | None) -> str:
    value = _first_present(raw, ["cwe_id", "cwe", "cwe_type", "vulnerability_type"])
    if value is None:
        return "unknown" if has_vulnerability else "none"
    if isinstance(value, list):
        value = value[0] if value else None
    if value is None:
        return "unknown" if has_vulnerability else "none"
    cleaned = str(value).strip().lower().replace("_", "-").replace(" ", "-")
    if cleaned.startswith("cwe") and not cleaned.startswith("cwe-"):
        cleaned = cleaned.replace("cwe", "cwe-", 1)
    return cleaned or ("unknown" if has_vulnerability else "none")


def _normalize_context(raw: dict[str, Any]) -> str | None:
    value = _first_present(
        raw,
        [
            "cwe_description",
            "description",
            "bug_type",
            "vulnerability_description",
            "details",
        ],
    )
    return str(value).strip() if value not in {None, ""} else None


def _normalize_id(raw: dict[str, Any], split: str, index: int) -> str:
    value = _first_present(raw, ["id", "idx", "commit_id", "hash"])
    if value is not None:
        return str(value)
    return f"primevul-{split}-{index:06d}"


def normalize_primevul_record(raw: dict[str, Any], split: str, index: int) -> dict[str, Any] | None:
    code = _normalize_code(raw)
    has_vulnerability = _normalize_label(raw)
    if not code or has_vulnerability is None:
        return None

    language = _normalize_language(raw)
    vulnerability_type = _normalize_cwe(raw, has_vulnerability)
    context = _normalize_context(raw)
    prompt = (
        f"Analyze the following {language} code for defensive security issues and return JSON only.\n\n"
        f"code:\n{code}"
    )

    gold_evidence = []
    evidence_line = _first_present(raw, ["line", "line_number", "vul_line", "vulnerable_line"])
    if evidence_line not in {None, ""}:
        try:
            line_no = int(evidence_line)
        except (TypeError, ValueError):
            line_no = None
        if line_no is not None:
            gold_evidence.append(
                {
                    "file_path": "snippet",
                    "line_start": line_no,
                    "line_end": line_no,
                    "snippet": None,
                }
            )

    return {
        "id": _normalize_id(raw, split, index),
        "task_type": "weakness_identification",
        "language": language,
        "prompt": prompt,
        "code": code,
        "diff": None,
        "context": context,
        "split": split,
        "difficulty": "unknown",
        "source": "primevul",
        "has_vulnerability": has_vulnerability,
        "vulnerability_type": vulnerability_type,
        "severity": "unknown" if has_vulnerability else "none",
        "gold_fix_choice": None,
        "gold_evidence": gold_evidence,
        "gold_explanation": context,
        "gold_fix_principle": (
            "Remove the vulnerable behavior, validate untrusted input, and prefer safer APIs."
            if has_vulnerability
            else "Preserve safe coding practices and input validation."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize local PrimeVul JSONL files into VeriSec Forge schema.")
    parser.add_argument("--input-dir", required=True, help="Directory containing raw PrimeVul split JSONL files")
    parser.add_argument("--output", required=True, help="Output normalized JSONL path")
    parser.add_argument("--train-split", default="primevul_train", help="Raw split file stem to map to train")
    parser.add_argument(
        "--eval-splits",
        nargs="*",
        default=["primevul_valid", "primevul_test"],
        help="Raw split file stems to map to eval",
    )
    parser.add_argument("--limit-train", type=int, default=0, help="Optional train-row cap")
    parser.add_argument("--limit-eval", type=int, default=0, help="Optional eval-row cap")
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    rows_out: list[dict[str, Any]] = []
    summary = {"train": 0, "eval": 0, "skipped": 0}

    split_map: list[tuple[str, str, int]] = [(args.train_split, "train", args.limit_train)]
    split_map.extend((split_name, "eval", args.limit_eval) for split_name in args.eval_splits)

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
                row = normalize_primevul_record(json.loads(line), normalized_split, index)
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
