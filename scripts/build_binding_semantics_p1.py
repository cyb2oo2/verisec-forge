"""Build a review-only P1 candidate bundle. Never runs a model or fills labels."""
from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]
from scripts.build_nuisance_transfer_audit import build_base_pairs
from scripts.build_relational_benchmark_v2 import DEFAULT_SOURCES, load_pairs, parse_source
from vrf.binding_semantics import build_case, digest, select_candidates, validate_design


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main():
    out = ROOT / "data/annotation/binding_semantics_p1_v1"
    # Human work must never be overwritten by regeneration.
    if out.exists():
        raise FileExistsError(f"Refusing to overwrite review bundle: {out}")
    pool, inputs = [], {}
    for spec in DEFAULT_SOURCES:
        name, path = parse_source(spec)
        pairs, skipped = load_pairs(name, path)
        pool.extend(pairs)
        import hashlib
        inputs[path.relative_to(ROOT).as_posix()] = {
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "eligible": len(pairs), "skipped": skipped}
    prior, _ = build_base_pairs(limit=200, seed=42)
    chosen, selection = select_candidates(pool, prior, per_source=12)
    prompts, keys, private, reviews = [], [], [], []
    for pair in chosen:
        pp, kk, metadata = build_case(pair)
        prompts.extend(pp)
        keys.extend(kk)
        private.append(metadata)
        # Independent packet orientation/order; benchmark gold and metadata excluded.
        for reviewer in ("r1", "r2"):
            reverse = int(digest(reviewer + metadata["case_id"])[0], 16) % 2
            sides = [pair.side_a.code, pair.side_b.code][::(-1 if reverse else 1)]
            reviews.append({"reviewer_slot": reviewer, "case_id": metadata["case_id"],
                            "candidate_A": sides[0], "candidate_B": sides[1],
                            "vulnerable_side": "", "context_sufficient": "",
                            "root_cause": "", "minimal_evidence_lines": "",
                            "reviewer_identity": "", "reviewed_at": ""})
            metadata[f"{reviewer}_reverse"] = bool(reverse)
    validation = validate_design(prompts, keys)
    out.mkdir(parents=True)
    write(out / "model_prompts.json", prompts)
    write(out / "PRIVATE_keys.json", keys)
    write(out / "PRIVATE_provenance.json", private)
    for reviewer in ("r1", "r2"):
        packet = sorted([r for r in reviews if r["reviewer_slot"] == reviewer],
                        key=lambda r: digest(reviewer + r["case_id"] + "order"))
        write(out / f"review_{reviewer}.json", packet)
    import hashlib
    summary = {"status": "CANDIDATES_READY_NOT_FROZEN", "model_inference_allowed": False,
               "new_model_inference": False, "validation": validation, "selection": selection,
               "requested_per_source": 12, "input_hashes": inputs,
               "gates_pending": ["independent_human_annotation_and_adjudication",
                                 "checkpoint_identity_and_complete_training_exposure_audit",
                                 "exact_tokenizer_full_prompt_visibility",
                                 "signed_final_sample_and_analysis_freeze"],
               "bundle": out.relative_to(ROOT).as_posix(),
               "bundle_hashes": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in out.glob("*.json")},
               "implementation_hashes": {str(p.relative_to(ROOT)).replace('\\', '/'): hashlib.sha256(p.read_bytes()).hexdigest()
                   for p in [Path(__file__), ROOT / "src/vrf/binding_semantics.py", ROOT / "docs/BINDING_SEMANTICS_P1_PROTOCOL.md"]}}
    target = ROOT / "reports/scientific_review_2026_09_07/p1"
    target.mkdir(exist_ok=True)
    write(target / "preflight.json", summary)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
