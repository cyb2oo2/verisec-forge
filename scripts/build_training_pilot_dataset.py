"""Expand the structurally audited source pool into a leakage-screened weak-label pilot."""
import json
from collections import Counter, defaultdict
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from vrf.training_dataset import (sha, clean_function, project_key, tokens, shingles, similar,
                                  components, split_components, orientations, validate_splits)


def load(path):
    return json.loads(path.read_text(encoding='utf-8'))


def main():
    cfgpath = ROOT / 'configs/dataset_expansion_v1.json'
    cfg = load(cfgpath)
    out = ROOT / cfg['output']
    report = ROOT / 'reports/scientific_review_2026_09_07/p1/training_pilot_v1.json'
    if out.exists() or report.exists():
        raise FileExistsError('Refusing to overwrite dataset version')
    src = ROOT / cfg['source']
    verified = load(ROOT / 'reports/scientific_review_2026_09_07/p1/source_repair_verification.json')
    expected = next(x['sha256'] for x in verified['generated_datasets'] if x['path'] == cfg['source'])
    if sha(src.read_bytes()) != expected:
        raise ValueError('audited upstream source drift')
    provenance_path = ROOT / 'data/annotation/binding_semantics_p1_v2/PRIVATE_provenance.json'
    blocked = {project_key(p['project']) for p in load(provenance_path)}
    p1path = ROOT / 'data/annotation/p1_source_repair_v3/PRIVATE_units.json'
    protected = []
    for u in load(p1path):
        for side in ['before', 'after']:
            try:
                protected.append(shingles(clean_function(u[side], u['language']), cfg['clone_shingle_size']))
            except ValueError:
                protected.append(shingles(u[side], cfg['clone_shingle_size']))
    grouped = defaultdict(list)
    for line in src.read_text(encoding='utf-8').splitlines():
        row = json.loads(line)
        grouped[row['pair_key']].append(row)
    from transformers import AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained(ROOT / cfg['tokenizer_source'], local_files_only=True)
    pairs, rejected, seen = [], [], set()
    for identity, rows in sorted(grouped.items()):
        try:
            if len(rows) != 2 or {type(r['has_vulnerability']) for r in rows} != {bool} or {r['has_vulnerability'] for r in rows} != {False, True}:
                raise ValueError('invalid_pair_labels')
            b = next(r for r in rows if r['has_vulnerability'])
            a = next(r for r in rows if not r['has_vulnerability'])
            if any(b[k] != a[k] for k in ['project','cve','file_path','programming_language']):
                raise ValueError('pair_metadata_mismatch')
            if project_key(b['project']) in blocked:
                raise ValueError('protected_p1_project')
            if not b['project'] or not b['cve']:
                raise ValueError('missing_cluster_identity')
            before = clean_function(b['code'], b['programming_language'])
            after = clean_function(a['code'], a['programming_language'])
            if tokens(before) == tokens(after):
                raise ValueError('no_code_change_after_comment_removal')
            key = tuple(sorted([tokens(before), tokens(after)]))
            if key in seen:
                raise ValueError('duplicate_pair')
            code_sets = [shingles(x,cfg['clone_shingle_size']) for x in [before,after]]
            if any(similar(s,p,cfg['clone_jaccard_threshold']) for s in code_sets for p in protected):
                raise ValueError('protected_p1_lexical_clone')
            p = dict(pair_key='pilot-v1::'+sha(identity.encode())[:24], upstream_pair_key=identity,
                project=b['project'].lower().rstrip('/'), cve=b['cve'], language=b['programming_language'],
                before=before, after=after, file_path=b['file_path'],
                upstream_before_commit=b['commit_id'], upstream_after_commit=a['commit_id'],
                original_before_sha256=sha(b['code'].encode()), original_after_sha256=sha(a['code'].encode()),
                label_source=cfg['label_source'], independently_ai_annotated=False)
            rendered = orientations(p)
            lengths = [len(tokenizer(r['text'], truncation=False, add_special_tokens=True)['input_ids']) for r in rendered]
            if max(lengths) > cfg['max_seq_length']:
                raise ValueError('full_pair_token_overflow')
            p['max_tokens'] = max(lengths)
            pairs.append(p)
            seen.add(key)
        except ValueError as e:
            rejected.append(dict(upstream_pair_key=identity, reason=str(e)))
    groups, edges = components(pairs, cfg['clone_jaccard_threshold'], cfg['clone_shingle_size'])
    splits = split_components(groups, cfg['split_fractions'], cfg['seed'])
    validate_splits(splits)
    out.mkdir(parents=True)
    paths, datasets, token_hashes = [], {}, {}
    for split, ps in splits.items():
        path = out / (split + '.jsonl')
        rows = [r for p in ps for r in orientations(p)]
        path.write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in rows),encoding='utf-8')
        for r in rows:
            ids = tokenizer(r['text'], truncation=False, add_special_tokens=True)['input_ids']
            token_hashes[r['id']] = sha(json.dumps(ids).encode())
        datasets[split] = path.relative_to(ROOT).as_posix()
        paths.append(path)
    for name,value in [('PRIVATE_pairs.json',splits),('rejections.json',rejected)]:
        path = out/name
        path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        paths.append(path)
    counts = {s:dict(pairs=len(ps),rows=2*len(ps),projects=len({p['project'] for p in ps}),
                    cves=len({p['cve'] for p in ps}), components=len({p['component_id'] for p in ps}),
                    max_tokens=max((p['max_tokens'] for p in ps),default=0)) for s,ps in splits.items()}
    gates = {s:counts[s]['pairs']>=cfg['minimum_pairs'][s] and counts[s]['projects']>=cfg['minimum_projects'][s] for s in splits}
    result = dict(status='READY_FOR_WEAK_SUPERVISION_PILOT' if all(gates.values()) else 'INSUFFICIENT_PILOT_DATA',
        label_source=cfg['label_source'], human_gold=False, ai_labels_generated=0,
        input_pairs=len(grouped), retained_pairs=len(pairs), rejected_pairs=len(rejected),
        rejection_reasons=dict(Counter(r['reason'] for r in rejected)), splits=counts, gates=gates,
        grouping='transitive project/CVE/either-side lexical clone components', clone_edges=edges,
        max_seq_length=cfg['max_seq_length'], full_pair_truncation=False, datasets=datasets,
        artifact_sha256={p.relative_to(ROOT).as_posix():sha(p.read_bytes()) for p in paths+[src,cfgpath,provenance_path,p1path]},
        token_ids_sha256=token_hashes, source_dataset_url='https://huggingface.co/datasets/ByteDance/PatchEval',
        dataset_card_license='apache-2.0; upstream source code rights are separate',
        boundary='Weak patch-direction supervision, not semantic gold. Training on a new base initialization only. P1 projects excluded. Pretraining exposure unknown. Test split is internal silver-label holdout, not a certified independent benchmark.',
        training_run=False)
    report.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k not in ['artifact_sha256','token_ids_sha256']},indent=2))


if __name__ == '__main__':
    main()
