"""Read-only feasibility check of the P1 packet against a candidate local runtime."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from vrf.binding_semantics import project_key, validate_design


def main():
    packet = ROOT / "data/annotation/binding_semantics_p1_v1"
    load = lambda p: json.loads(p.read_text(encoding="utf-8"))
    preflight = load(ROOT / "reports/scientific_review_2026_09_07/p1/preflight.json")
    for name, expected in preflight["bundle_hashes"].items():
        # Review sheets may legitimately acquire human labels after preparation.
        if name.startswith("review_"):
            continue
        if hashlib.sha256((packet / name).read_bytes()).hexdigest() != expected:
            raise ValueError(f"Frozen candidate packet changed: {name}")
    prompts = load(packet / "model_prompts.json")
    keys = load(packet / "PRIVATE_keys.json")
    provenance = load(packet / "PRIVATE_provenance.json")
    validation = validate_design(prompts, keys)
    config_path = ROOT / "configs/research_primevul_joint_pairwise_repair_antisymmetric_v1.json"
    config = load(config_path)
    tokenizer_path = ROOT / config["init_checkpoint"]
    from transformers import AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained(tokenizer_path, local_files_only=True)
    lengths = {p["id"]: len(tokenizer(p["text"], add_special_tokens=True, truncation=False)["input_ids"])
               for p in prompts}
    max_length = config["max_seq_length"]
    cases = {}
    for k in keys:
        cases.setdefault(k["case_id"], []).append(lengths[k["id"]])
    exposure = {}
    for field in ("train_dataset", "eval_dataset"):
        path = ROOT / config[field]
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        row_keys = [r.get("source_pair_key") or r.get("pair_key") for r in rows]
        source_keys = set(row_keys)
        # This file encodes projects in source_pair_key, not a project column.
        projects = {project_key(k.split("|", 1)[0]) for k in source_keys if isinstance(k, str) and "|" in k}
        hits = [p["case_id"] for p in provenance if p["project"] in projects]
        exposure[field] = {"path": config[field], "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                           "rows": len(rows), "candidate_project_overlap": hits,
                           "unparsed_rows": sum(not isinstance(k, str) or "|" not in k for k in row_keys),
                           "boundary": "Known configured inputs only; checkpoint ancestry and pretraining unverified."}
    overlaps = {case for item in exposure.values() for case in item["candidate_project_overlap"]}
    remaining = [case for case, sizes in cases.items() if max(sizes) <= max_length and case not in overlaps]
    from collections import Counter
    result = {"status": "NOT_READY_FOR_INFERENCE", "construction": validation,
              "provisionally_unexposed_and_fitting_by_source": dict(Counter(
                  p["dataset"] for p in provenance if p["case_id"] in remaining)),
              "candidate_runtime_config": config_path.relative_to(ROOT).as_posix(),
              "runtime_config_sha256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
              "tokenizer_path": config["init_checkpoint"],
              "tokenizer_hashes": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in tokenizer_path.glob("*token*.json")},
              "length_check": {"max_length": max_length, "max_observed": max(lengths.values()),
                               "overlength_prompts": sum(n > max_length for n in lengths.values()),
                               "all_cells_fit_cases": sum(max(v) <= max_length for v in cases.values()),
                               "total_cases": len(cases),
                               "boundary": "Plain tokenizer input; chat template or another runtime requires revalidation."},
              "known_exposure": exposure, "new_model_inference": False,
              "human_reviews_completed": sum(bool(r["reviewed_at"]) for slot in ("r1", "r2")
                  for r in load(packet / f"review_{slot}.json")),
              "checkpoint_weights_hashed": False,
              "next_action": "Resolve exposure and runtime feasibility before freezing eligible cases; obtain independent human review."}
    target = ROOT / "reports/scientific_review_2026_09_07/p1/feasibility.json"
    target.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
