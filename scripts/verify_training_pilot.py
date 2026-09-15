"""Recompute release counts, pair serialization and transitive split isolation."""
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from vrf.training_dataset import (verify_training_manifest,validate_splits,orientations,components,project_key)


def main():
    load=lambda p:json.loads(p.read_text(encoding='utf-8'))
    cfg=load(ROOT/'configs/research_patcheval_training_pilot_v1.json')
    m=verify_training_manifest(ROOT,cfg)
    splits=load(ROOT/'data/processed/patcheval_training_pilot_v1/PRIVATE_released_pairs.json')
    validate_splits(splits)
    blocked={project_key(p['project']) for p in load(ROOT/'data/annotation/binding_semantics_p1_v2/PRIVATE_provenance.json')}
    locations={}
    for split,ps in splits.items():
        rows=[json.loads(l) for l in (ROOT/m['datasets'][split]).read_text(encoding='utf-8').splitlines()]
        expected=[r for p in ps for r in orientations(p)]
        if rows!=expected:raise ValueError('serialized code/direction mismatch')
        if len(ps)!=m['splits'][split]['pairs'] or len(rows)!=m['splits'][split]['rows']:
            raise ValueError('release count mismatch')
        if any(project_key(p['project']) in blocked for p in ps):raise ValueError('P1 project exposure')
        for p in ps:
            if p['pair_key'] in locations:raise ValueError('duplicate pair identity')
            locations[p['pair_key']]=split
    allpairs=[p for ps in splits.values() for p in ps]
    groups,_=components(allpairs)
    if any(len({locations[p['pair_key']] for p in g})!=1 for g in groups):
        raise ValueError('recomputed clone/CVE/project component crosses split')
    quarantine=set(load(ROOT/'data/processed/patcheval_training_pilot_v1/audit_quarantine.json'))
    if quarantine & set(locations):raise ValueError('quarantined pair reintroduced')
    print(json.dumps(dict(status='RELEASE_INTEGRITY_VERIFIED',pairs=len(allpairs),
        rows=2*len(allpairs),project_cve_clone_overlap=False,protected_p1_project_overlap=False,
        quarantine_overlap=False,semantic_gold_certified=False),indent=2))


if __name__=='__main__':main()
