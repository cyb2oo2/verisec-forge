from __future__ import annotations

import argparse
import json
from pathlib import Path


def normalize_record(raw: dict) -> dict:
    task_type = raw.get("task_type", "weakness_identification")
    language = raw.get("language", "unknown")
    prompt = raw.get("prompt") or raw.get("instruction") or ""
    code = raw.get("code")
    diff = raw.get("diff")
    if not prompt:
        parts = []
        if code:
            parts.append(f"Analyze the following {language} code for defensive security issues and return JSON only.\n\ncode:\n{code}")
        elif diff:
            parts.append(f"Analyze the following {language} diff for defensive security issues and return JSON only.\n\ndiff:\n{diff}")
        prompt = "\n".join(parts)

    vulnerability_type = str(raw.get("vulnerability_type", raw.get("cwe", "none"))).strip().lower().replace("_", "-")
    if vulnerability_type.startswith("cwe") and not vulnerability_type.startswith("cwe-"):
        vulnerability_type = vulnerability_type.replace("cwe", "cwe-", 1)

    return {
        "id": str(raw["id"]),
        "task_type": task_type,
        "language": language,
        "prompt": prompt,
        "code": code,
        "diff": diff,
        "context": raw.get("context"),
        "split": raw.get("split", "train"),
        "difficulty": raw.get("difficulty", "unknown"),
        "source": raw.get("source", "custom_secure_code"),
        "has_vulnerability": raw.get("has_vulnerability"),
        "vulnerability_type": vulnerability_type or "none",
        "severity": raw.get("severity", "unknown"),
        "gold_fix_choice": raw.get("gold_fix_choice"),
        "response": raw.get("response"),
        "chosen": raw.get("chosen"),
        "rejected": raw.get("rejected"),
        "score": raw.get("score"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize a secure-code benchmark JSONL into VeriSec Forge schema.")
    parser.add_argument("--input", required=True, help="Input JSONL file path")
    parser.add_argument("--output", required=True, help="Output JSONL file path")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    rows = []
    with input_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            rows.append(normalize_record(json.loads(line)))

    with output_path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(json.dumps({"input_rows": len(rows), "output_path": str(output_path)}, indent=2))


if __name__ == "__main__":
    main()
