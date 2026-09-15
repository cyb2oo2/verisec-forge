"""Replay deterministic design counterexamples and summarize frozen AI judgments."""
from collections import Counter
import hashlib
import json
import os.path
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def header_only_answer(text, tag):
    match = re.search(r"^Candidate ([AB]) \[tag " + re.escape(tag) + r"\]", text, re.MULTILINE)
    if match is None:
        raise ValueError("missing candidate header")
    return match.group(1)


def main():
    load = lambda p: json.loads(p.read_text(encoding="utf-8"))
    p1 = ROOT / "reports/scientific_review_2026_09_07/p1"
    bundle = ROOT / "data/annotation/binding_semantics_p1_v2"
    prompts = {r["id"]: r["text"] for r in load(bundle / "model_prompts.json")}
    keys = load(bundle / "PRIVATE_keys.json")
    tasks = [k for k in keys if k["task"].startswith("binding_")]
    correct = sum(header_only_answer(prompts[k["id"]], k["task"].split("_", 1)[1]) == k["gold"] for k in tasks)
    accepted_path = ROOT / "data/annotation/p1_assistant_diagnostic_v1/accepted.json"
    accepted = load(accepted_path)
    raw = p1 / "assistant_annotation_decisions_v1.json"
    decisions = load(raw)
    cases = load(ROOT / "data/annotation/binding_semantics_p1_ai_v1/cases.json")
    # A safe pure path-string counterexample; no file reads outside the workspace.
    root_path = "/srv/components/widget"
    sibling = "/srv/components/widget_extra/private"
    result = {"status": "DESIGN_REVISED_AI_DIAGNOSTIC_COMPLETED",
              "header_only_control": {"correct": correct, "total": len(tasks), "accuracy": correct / len(tasks),
                                      "interpretation": "Tag questions are header lookup, not code identity or security evidence."},
              "path_containment_counterexample": {
                  "character_prefix_accepts_sibling": os.path.commonprefix([root_path, sibling]) == root_path,
                  "path_component_check_rejects_sibling": os.path.commonpath([root_path, sibling]) != root_path,
                  "case_id": cases[21]["case_id"], "boundary": "Demonstrates prefix-check defect; no exploit or project runtime executed."},
              "annotation_labels": dict(Counter(r[1] for r in decisions)),
              "by_source": accepted["by_source"],
              "quality_review": {"fragmentary_or_malformed_cases": [cases[i]["case_id"] for i in [2,7,9,11,15,18,24,29,30,31,32,34]],
                                 "non_corresponding_pair_cases": [cases[26]["case_id"]],
                                 "origin": "Current-assistant code inspection, not compiler certification"},
              "execution_mode": accepted["run_metadata"]["execution_mode"], "independent_annotation": False,
              "primary_next_step": "Repair source extraction/pair matching before any security-model comparison; retain all 36 diagnostic outcomes.",
              "model_training_or_checkpoint_inference": False,
              "inputs_sha256": {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                                for p in [raw, accepted_path, bundle / "model_prompts.json", bundle / "PRIVATE_keys.json"]}}
    (p1 / "design_reaudit.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
