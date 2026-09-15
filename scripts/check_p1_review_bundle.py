"""Verify the v2 handoff, including conservative lexical near-clone screening."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]
from scripts.build_nuisance_transfer_audit import build_base_pairs
from vrf.binding_semantics import digest, validate_design


def shingles(code):
    tokens = re.findall(r"\w+|[^\w\s]", code)
    return {tuple(tokens[i:i+5]) for i in range(max(0, len(tokens)-4))}


def near_clone(a, b):
    if not a or not b:
        return False
    overlap = len(a & b)
    return overlap / len(a | b) >= .8 or (min(len(a), len(b)) >= 20 and overlap / min(len(a), len(b)) >= .9)


def main():
    load = lambda p: json.loads(p.read_text(encoding="utf-8"))
    report = ROOT / "reports/scientific_review_2026_09_07/p1"
    selection = load(report / "selection_v2.json")
    lineage = load(report / "lineage.json")
    bundle = ROOT / selection["bundle"]
    for filename, expected in selection["bundle_hashes"].items():
        if not filename.startswith("review_"):
            assert hashlib.sha256((bundle / filename).read_bytes()).hexdigest() == expected, filename
    prompts, keys = load(bundle / "model_prompts.json"), load(bundle / "PRIVATE_keys.json")
    validation = validate_design(prompts, keys)
    provenance = {p["case_id"]: p for p in load(bundle / "PRIVATE_provenance.json")}
    candidate_codes, completion = {}, {}
    for slot in ("r1", "r2"):
        packet = load(bundle / f"review_{slot}.json")
        assert len(packet) == len(provenance) and {r["case_id"] for r in packet} == set(provenance)
        complete = 0
        for r in packet:
            p = provenance[r["case_id"]]
            expected = p["code_sha256"][::(-1 if p[slot + "_reverse"] else 1)]
            assert [digest(r["candidate_A"]), digest(r["candidate_B"])] == expected
            assert not ({"gold", "project", "dataset", "pair_key", "model_prediction"} & set(r))
            if slot == "r1":
                candidate_codes[r["case_id"]] = [shingles(r["candidate_A"]), shingles(r["candidate_B"])]
            complete += (r["vulnerable_side"] in {"A", "B", "neither", "unclear"}
                         and r["context_sufficient"] in {"yes", "no", "unclear"}
                         and all(r[k].strip() for k in ("root_cause", "minimal_evidence_lines", "reviewer_identity", "reviewed_at")))
        completion[slot] = complete
    corpus = {}
    for relative, info in lineage["known_input_evidence"].items():
        path = ROOT / relative
        assert hashlib.sha256(path.read_bytes()).hexdigest() == info["sha256"]
        for line in path.read_text(encoding="utf-8").splitlines():
            r = json.loads(line)
            if r.get("code"):
                corpus[digest(r["code"])] = r["code"]
    prior, _ = build_base_pairs(limit=200, seed=42)
    for p in prior:
        for s in (p.side_a, p.side_b):
            corpus[digest(s.code)] = s.code
    hits = []
    for code_hash, code in corpus.items():
        known = shingles(code)
        for case, candidates in candidate_codes.items():
            if any(near_clone(candidate, known) for candidate in candidates):
                hits.append({"case_id": case, "known_code_sha256": code_hash})
    internal = []
    cases = list(candidate_codes)
    for index, case in enumerate(cases):
        for other in cases[index+1:]:
            if any(near_clone(a, b) for a in candidate_codes[case] for b in candidate_codes[other]):
                internal.append([case, other])
    result = {"status": "PASS_FOR_HUMAN_REVIEW" if not hits and not internal else "HOLD_FOR_CLONE_REVIEW",
              "construction": validation, "human_completed": completion,
              "known_unique_code_count": len(corpus), "external_near_clone_hits": hits,
              "between_case_near_clone_hits": internal,
              "screen_definition": "5 lexical token shingles; Jaccard >= .8 or smaller-set containment >= .9 with >=20 shingles",
              "boundary": "Lexical heuristic only, not semantic clone exclusion or pretraining evidence.",
              "new_model_inference": False, "model_inference_allowed": False}
    (report / "review_readiness.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
