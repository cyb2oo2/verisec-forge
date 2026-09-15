"""Trace local checkpoint evidence and screen a new P1 cohort, without inference."""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]
from scripts.build_nuisance_transfer_audit import build_base_pairs
from scripts.build_relational_benchmark_v2 import load_pairs
from vrf.binding_semantics import build_case, code_key, digest, project_key, validate_design
from vrf.relational_benchmark import build_canonical_pair


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def rows(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main():
    output = ROOT / "data/annotation/binding_semantics_p1_v2"
    if output.exists():
        raise FileExistsError("Refusing to overwrite human review materials")
    report = ROOT / "reports/scientific_review_2026_09_07/p1"
    configs = [ROOT / f"configs/{name}.json" for name in
               ("research_primevul_joint_pairwise_qwen15b_v1", "research_primevul_joint_pairwise_repair_antisymmetric_v1")]
    cfgs = [read(p) for p in configs]
    stages = []
    for relative in [cfgs[0]["init_checkpoint"], cfgs[0]["output_dir"], cfgs[1]["output_dir"]]:
        path = ROOT / relative
        adapter = read(path / "adapter_config.json")
        stages.append({"path": relative, "task_type": adapter["task_type"],
                       "base_model_reference": adapter["base_model_name_or_path"],
                       "current_file_hashes": {p.name: sha(p) for p in path.iterdir() if p.is_file()},
                       "historical_data_weight_binding": "not_attested"})
    input_paths = {cfg[field] for cfg in cfgs for field in ("train_dataset", "eval_dataset")}
    # Upstream construction inputs, not claimed to be exact original CLI arguments.
    input_paths.update(f"data/processed/{name}.jsonl" for name in (
        "secure_code_primevul_pair_diff_only_train_balanced_3000_metadata",
        "secure_code_primevul_pair_diff_only_eval_balanced_1800_metadata",
        "secure_code_primevul_pair_diff_only_eval_balanced_1800_dedup_metadata"))
    excluded_projects, excluded_codes, input_evidence = set(), set(), {}
    for relative in sorted(input_paths):
        path = ROOT / relative
        data = rows(path)
        unknown = 0
        for r in data:
            key = r.get("source_pair_key") or r.get("pair_key") or ""
            project = r.get("project") or (key.split("|", 1)[0] if "|" in key else "")
            if not project or project == "unknown":
                unknown += 1
            else:
                excluded_projects.add(project_key(project))
            if r.get("code"):
                excluded_codes.add(code_key(r["code"]))
        input_evidence[relative] = {"sha256": sha(path), "rows": len(data), "unknown_project_rows": unknown}
    # Prove present-day builder matches present-day synthetic train/eval bytes semantically.
    from scripts.build_joint_side_choice_dataset import build_synthetic_examples, build_examples
    rebuilt_train, _ = build_synthetic_examples(ROOT / "data/processed/secure_code_primevul_pair_diff_only_train_balanced_3000_metadata.jsonl")
    rebuilt_eval, _ = build_examples(ROOT / "data/processed/secure_code_primevul_pair_diff_only_eval_balanced_1800_dedup_metadata.jsonl", True)
    reconstruction = {"train_rows_equal": rebuilt_train == rows(ROOT / cfgs[0]["train_dataset"]),
                      "eval_rows_equal": rebuilt_eval == rows(ROOT / cfgs[0]["eval_dataset"])}
    prior, _ = build_base_pairs(limit=200, seed=42)
    excluded_projects.update(project_key(p.project) for p in prior)
    excluded_codes.update(code_key(s.code) for p in prior for s in (p.side_a, p.side_b))
    lineage = {"status": "LOCAL_CHAIN_TRACED_WITH_HISTORICAL_GAPS", "stages": stages,
               "configs": {p.relative_to(ROOT).as_posix(): sha(p) for p in configs},
               "known_input_evidence": input_evidence, "dataset_reconstruction": reconstruction,
               "excluded_project_count": len(excluded_projects),
               "gaps": ["original base-stage CLI and immutable training input manifest unavailable",
                        "current hashes do not prove which bytes historical training consumed",
                        "foundation-model pretraining exposure unknown"],
               "new_model_inference": False}
    backbone = Path(stages[0]["base_model_reference"])
    lineage["backbone"] = {"local_path": str(backbone), "snapshot_revision": backbone.name,
                           "current_file_hashes": {p.name: sha(p) for p in backbone.iterdir() if p.is_file()}}
    evidence = ["scripts/train_joint_pairwise_classifier.py", "scripts/train_antisymmetric_repair.py",
                "scripts/build_joint_side_choice_dataset.py",
                "reports/secure_code_primevul_joint_pairwise_qwen15b_lora_v1_report.json",
                "reports/secure_code_primevul_joint_side_choice_dataset_v1.json", "reports/repair_train_status_v1.json"]
    lineage["supporting_evidence_hashes"] = {p: sha(ROOT / p) for p in evidence}
    write(report / "lineage.json", lineage)

    pools, source_evidence = [], {}
    files = {"primevul": "secure_code_primevul_paired_metadata.jsonl",
             "deltasecommits": "secure_code_deltasecommits_pair_diff_cpp_all_metadata_v2.jsonl",
             "patcheval": "secure_code_patcheval_pair_diff_all_metadata.jsonl"}
    for source, filename in files.items():
        path = ROOT / "data/processed" / filename
        if source == "primevul":
            grouped = defaultdict(list)
            for r in rows(path):
                grouped[(r.get("project"), r.get("commit_id"), r.get("cve"))].append(r)
            pairs, skipped = [], 0
            for key, group in grouped.items():
                # Do not invent pairings in multi-function commits.
                if len(group) != 2 or any(not x or x == "unknown" for x in key):
                    skipped += 1
                    continue
                try:
                    pairs.append(build_canonical_pair("|".join(key), group, dataset=source))
                except ValueError:
                    skipped += 1
        else:
            pairs, skipped = load_pairs(source, path)
        pools.extend(pairs)
        source_evidence[source] = {"path": path.relative_to(ROOT).as_posix(), "sha256": sha(path),
                                   "eligible_pairs": len(pairs), "skipped_groups": skipped}
    from transformers import AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained(ROOT / cfgs[0]["output_dir"], local_files_only=True)
    selected, counts, rejected, all_prompts, all_keys, provenance, packets = [], Counter(), Counter(), [], [], [], []
    used_projects, used_codes = set(), set()
    for p in sorted(pools, key=lambda p: digest(f"p1-v2::{p.dataset}::{p.pair_key}")):
        project = project_key(p.project)
        codes = {code_key(p.side_a.code), code_key(p.side_b.code)}
        reason = None
        if project in {"", "unknown", "none", "null"}:
            reason = "unknown_project"
        elif project in excluded_projects:
            reason = "known_training_eval_or_prior_audit_project"
        elif codes & excluded_codes:
            reason = "known_content_overlap"
        elif len(codes) != 2 or not p.side_a.code.strip() or not p.side_b.code.strip():
            reason = "invalid_code"
        if reason:
            rejected[f"{p.dataset}:{reason}"] += 1
            continue
        pp, kk, meta = build_case(p)
        lengths = [len(tokenizer(r["text"], truncation=False, add_special_tokens=True)["input_ids"]) for r in pp]
        if max(lengths) > 1024:
            rejected[f"{p.dataset}:overlength"] += 1
            continue
        if project in used_projects or codes & used_codes:
            rejected[f"{p.dataset}:selected_project_or_code"] += 1
            continue
        if counts[p.dataset] >= 12:
            rejected[f"{p.dataset}:quota"] += 1
            continue
        counts[p.dataset] += 1
        used_projects.add(project)
        used_codes.update(codes)
        selected.append(p)
        all_prompts.extend(pp)
        all_keys.extend(kk)
        meta["max_prompt_tokens"] = max(lengths)
        provenance.append(meta)
        for slot in ("r1", "r2"):
            reverse = int(digest(slot + meta["case_id"])[0], 16) % 2
            sides = [p.side_a.code, p.side_b.code][::(-1 if reverse else 1)]
            meta[slot + "_reverse"] = bool(reverse)
            packets.append({"reviewer_slot": slot, "case_id": meta["case_id"],
                            "candidate_A": sides[0], "candidate_B": sides[1],
                            "vulnerable_side": "", "context_sufficient": "", "root_cause": "",
                            "minimal_evidence_lines": "", "reviewer_identity": "", "reviewed_at": ""})
    validation = validate_design(all_prompts, all_keys)
    for name, data in [("model_prompts.json", all_prompts), ("PRIVATE_keys.json", all_keys), ("PRIVATE_provenance.json", provenance)]:
        write(output / name, data)
    for slot in ("r1", "r2"):
        write(output / f"review_{slot}.json", sorted([r for r in packets if r["reviewer_slot"] == slot],
                                                    key=lambda r: digest(slot + r["case_id"] + "order")))
    summary = {"status": "READY_FOR_HUMAN_REVIEW_NOT_INFERENCE", "source_counts": dict(counts),
               "design_validation": validation, "rejections": dict(rejected), "source_pools": source_evidence,
               "independence_scope": "No project alias or whitespace-normalized code overlap with enumerated local inputs and prior audit; historical gaps remain.",
               "near_clone_screen": "not_performed", "foundation_pretraining_disjoint": "unknown",
               "runtime": "existing joint tokenizer, plain input, add_special_tokens=True, max_length=1024",
               "bundle": output.relative_to(ROOT).as_posix(), "bundle_hashes": {p.name: sha(p) for p in output.glob("*.json")},
               "model_inference_allowed": False, "human_annotations_completed": 0,
               "selection_amendment": "Expanded pools and pre-outcome exposure/length filters; v1 retained, no predictions used."}
    write(report / "selection_v2.json", summary)
    print(json.dumps({"reconstruction": reconstruction, "counts": dict(counts), "validation": validation, "rejections": dict(rejected)}, indent=2))


if __name__ == "__main__":
    main()
