"""Verify recovered bytes, input identity and exposure after source expansion."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]
from scripts.build_nuisance_transfer_audit import build_base_pairs
from scripts.check_p1_review_bundle import near_clone, shingles
from vrf.binding_semantics import project_key


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    report = ROOT / "reports/scientific_review_2026_09_07/p1"
    manifest = load(report / "source_repair_v3.json")
    bundle = ROOT / manifest["bundle"]
    for name, expected in manifest["bundle_hashes"].items():
        if sha(bundle / name) != expected:
            raise ValueError(f"derived artifact changed: {name}")
    units = load(bundle / "PRIVATE_units.json")
    prompts = load(bundle / "security_prompts.json")
    details = load(bundle / "recovery_details.json")
    references = {}
    for r in details:
        for evidence in r.get("evidence", []):
            path = ROOT / evidence["path"]
            if sha(path) != evidence["sha256"]:
                raise ValueError("downloaded evidence changed")
            references[evidence["sha256"]] = path
    for u in units:
        for side in ("before", "after"):
            code = u[side]
            if hashlib.sha256(code.encode()).hexdigest() != u[side + "_sha256"]:
                raise ValueError("source snippet hash mismatch")
            if u["dataset"] == "deltasecommits":
                text = references[u[side + "_file_sha256"]].read_bytes().decode("utf-8")
                if text.count(code) != 1:
                    raise ValueError("recovered function not uniquely bound to full source")
                start = text.index(code)
                if text[:start].count("\n")+1 != u[side + "_lines"][0]:
                    raise ValueError("source line mapping mismatch")
    expected_ids = {f"v3::{u['unit_id']}::{o}" for u in units for o in (0,1)}
    if len(expected_ids) != 2*len(units) or len(prompts) != len(expected_ids) or {p['id'] for p in prompts} != expected_ids:
        raise ValueError("prompt pair coverage mismatch")
    for p in prompts:
        if hashlib.sha256(p['text'].encode()).hexdigest() != p['text_sha256']:
            raise ValueError("prompt changed")
    lineage = load(report / "lineage.json")
    corpus, known_projects = {}, set()
    for relative, info in lineage["known_input_evidence"].items():
        path = ROOT / relative
        if sha(path) != info["sha256"]:
            raise ValueError("known exposure input drift")
        for line in path.read_text(encoding="utf-8").splitlines():
            r = json.loads(line)
            key = r.get("source_pair_key") or r.get("pair_key") or ""
            name = r.get("project") or (key.split("|")[0] if "|" in key else "")
            if name:
                known_projects.add(project_key(name))
            if r.get("code"):
                corpus[hashlib.sha256(r['code'].encode()).hexdigest()] = r['code']
    prior, _ = build_base_pairs(limit=200, seed=42)
    for p in prior:
        known_projects.add(project_key(p.project))
        for s in (p.side_a, p.side_b):
            corpus[hashlib.sha256(s.code.encode()).hexdigest()] = s.code
    signatures = {u['unit_id']: [shingles(u[s]) for s in ('before','after')] for u in units}
    hits = []
    for key, code in corpus.items():
        known = shingles(code)
        for identity, pair in signatures.items():
            if any(near_clone(x, known) for x in pair):
                hits.append({'unit_id': identity, 'known_code_sha256': key})
    project_hits = [u['unit_id'] for u in units if project_key(u['project']) in known_projects]
    # The two new generators must never emit old IDs even when source rows align.
    generated = []
    for pattern, prefix in [("secure_code_patcheval_pair_diff_*_verified_v2.jsonl", "patcheval-v2-"),
                            ("secure_code_deltasecommits_pair_diff_cpp_*_syntax_v3.jsonl", "deltasecommits-v3-")]:
        for path in sorted((ROOT / 'data/processed').glob(pattern)):
            rows = [json.loads(l) for l in path.read_text(encoding='utf-8').splitlines()]
            if len({r['id'] for r in rows}) != len(rows) or any(not r['id'].startswith(prefix) for r in rows):
                raise ValueError('duplicate or legacy prediction identity in rebuilt dataset')
            generated.append({'path': path.relative_to(ROOT).as_posix(), 'sha256': sha(path), 'rows': len(rows)})
    result = {'status': 'VERIFIED_WITH_EXPOSURE_FLAGS' if hits or project_hits else 'VERIFIED_NO_KNOWN_EXPOSURE_HITS',
              'units': len(units), 'downloaded_evidence_files': len(references), 'prompts': len(prompts),
              'known_code_count': len(corpus), 'project_hits': project_hits, 'lexical_clone_hits': hits,
              'generated_datasets': generated, 'inference_performed': False,
              'boundary': 'Structural/source-byte verification only. Lexical heuristic misses semantic clones; foundation pretraining remains unknown.'}
    (report / 'source_repair_verification.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,indent=2))


if __name__ == '__main__':
    main()
