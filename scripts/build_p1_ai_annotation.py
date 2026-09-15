"""Prepare AI annotation requests from masked code only; no model calls."""
import hashlib
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from vrf.ai_annotation import input_hash


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-cases", default="data/annotation/binding_semantics_p1_v2/review_r1.json")
    parser.add_argument("--output", default="data/annotation/binding_semantics_p1_ai_v1")
    parser.add_argument("--manifest", default="reports/scientific_review_2026_09_07/p1/ai_annotation_preparation.json")
    args = parser.parse_args()
    out = ROOT / args.output
    manifest_path = ROOT / args.manifest
    if manifest_path.exists():
        raise FileExistsError("Refusing to overwrite request manifest")
    if out.exists():
        raise FileExistsError("Refusing to overwrite AI annotation work")
    source = ROOT / args.source_cases
    original = json.loads(source.read_text(encoding="utf-8"))
    cases = [{k: r[k] for k in ("case_id", "candidate_A", "candidate_B")} for r in original]
    if len({r["case_id"] for r in cases}) != len(cases):
        raise ValueError("duplicate cases")
    template = ROOT / "docs/P1_AI_ANNOTATION_TEMPLATE.md"
    system = template.read_text(encoding="utf-8").split("## 可直接复制的系统提示\n", 1)[1].split("\n## 每例用户输入", 1)[0].strip()
    string = {"type": "string", "minLength": 1}
    properties = {k: string for k in ("case_id", "input_sha256", "summary", "alternative_explanation")}
    for k, choices in {"annotation_source": ["ai"], "vulnerable_side": ["A", "B", "both", "neither", "unclear"],
                       "context_sufficient": ["yes", "no", "unclear"], "confidence": ["low", "medium", "high"]}.items():
        properties[k] = {"type": "string", "enum": choices}
    for k in ("trigger_conditions", "missing_context"):
        properties[k] = {"type": "array", "items": string}
    properties["evidence"] = {"type": "array", "items": {"type": "object", "additionalProperties": False,
        "required": ["side", "start_line", "end_line", "reason"], "properties": {
            "side": {"enum": ["A", "B"]}, "start_line": {"type": "integer", "minimum": 1},
            "end_line": {"type": "integer", "minimum": 1}, "reason": string}}}
    schema = {"type": "object", "additionalProperties": False, "required": list(properties), "properties": properties}
    requests = []
    for c in cases:
        payload = {"case_id": c["case_id"], "input_sha256": input_hash(c["case_id"], c["candidate_A"], c["candidate_B"])}
        for side in ("A", "B"):
            payload[f"candidate_{side}_numbered"] = "\n".join(f"{i}: {line}" for i, line in enumerate(c[f"candidate_{side}"].splitlines(), 1))
        payload["response_schema"] = schema
        requests.append({"custom_id": c["case_id"], "messages": [{"role": "system", "content": system},
                           {"role": "user", "content": json.dumps(payload, ensure_ascii=False)}]})
    out.mkdir(parents=True)
    for name, value in [("cases.json", cases), ("response_schema.json", schema),
                        ("run_metadata_template.json", {"annotation_source": "ai", "provider": None,
                         "model_id": None, "model_version": None, "run_id": None, "parameters": None,
                         "started_at": None, "raw_responses_path": None, "status": "NOT_RUN"})]:
        (out / name).write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (out / "requests.jsonl").write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in requests), encoding="utf-8")
    manifest = {"status": "AI_REQUESTS_PREPARED_NOT_ANNOTATED", "cases": len(cases), "annotation_source": "ai",
                "human_review_required": False, "model_calls": 0,
                "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "template_sha256": hashlib.sha256(template.read_bytes()).hexdigest(),
                "bundle": out.relative_to(ROOT).as_posix(),
                "hashes": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in out.iterdir()}}
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": manifest["status"], "cases": len(cases)}, indent=2))


if __name__ == "__main__":
    main()
