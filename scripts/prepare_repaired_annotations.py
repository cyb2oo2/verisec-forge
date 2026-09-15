"""Prepare new AI input identities from repaired units; never copy old labels."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    out = ROOT / "data/annotation/p1_reannotation_inputs_v3"
    if out.exists():
        raise FileExistsError("Refusing to overwrite reannotation inputs")
    source = ROOT / "data/annotation/p1_source_repair_v3/PRIVATE_units.json"
    report = ROOT / "reports/scientific_review_2026_09_07/p1"
    manifest = json.loads((report / "source_repair_v3.json").read_text())
    if hashlib.sha256(source.read_bytes()).hexdigest() != manifest['bundle_hashes']['PRIVATE_units.json']:
        raise ValueError("repaired source drift")
    cases, bindings = [], []
    for unit in json.loads(source.read_text(encoding='utf-8')):
        identity = "source-v3::" + unit['unit_id']
        reverse = int(hashlib.sha256(identity.encode()).hexdigest()[0], 16) % 2 == 1
        a, b = (unit['after'], unit['before']) if reverse else (unit['before'], unit['after'])
        cases.append({'case_id': identity, 'candidate_A': a, 'candidate_B': b})
        bindings.append({'case_id': identity, 'unit_id': unit['unit_id'], 'original_case_id': unit['case_id'],
                         'source_unit_order_reversed': reverse, 'old_label_inherited': False})
    out.mkdir(parents=True)
    for name, value in [('cases.json', cases), ('PRIVATE_binding.json', bindings)]:
        (out / name).write_text(json.dumps(value,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    print(json.dumps({'new_annotation_cases':len(cases), 'original_clusters':len({r['original_case_id'] for r in bindings}),
                      'old_labels_inherited':False}))


if __name__ == '__main__':
    main()
