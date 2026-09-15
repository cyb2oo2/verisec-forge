"""Build immutable, revision-bound context packets for every unresolved v3 unit.

This pass reads existing cache only. It does not infer repositories or fetch HEAD.
"""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / 'reports/scientific_review_2026_09_07/p1'
OUT = ROOT / 'data/annotation/p1_context_v1'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load(path):
    return json.loads(path.read_text(encoding='utf-8'))


def digest(value):
    return sha(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode())


def excerpt(path, expected_hash, start, end):
    raw = path.read_bytes()
    if sha(raw) != expected_hash:
        raise ValueError('context file hash mismatch')
    lines = raw.decode('utf-8').splitlines()
    if not 1 <= start <= end <= len(lines):
        raise ValueError('context range outside source')
    return '\n'.join(lines[start-1:end])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    manifest_path = REPORT / 'local_context_v1.json'
    if args.check:
        manifest = load(manifest_path)
        for p, expected in manifest['artifact_sha256'].items():
            if sha((ROOT / p).read_bytes()) != expected:
                raise ValueError('artifact drift: ' + p)
        packets = load(OUT / 'packets.json')
        queue = load(REPORT / 'ai_source_v3_context_queue.json')
        expected_ids = {u['case_id'] for c in queue['cases'] for u in c['units']}
        if {p['case_id'] for p in packets} != expected_ids or len(packets) != len(expected_ids):
            raise ValueError('context coverage mismatch')
        for p in packets:
            if p['context_input_sha256'] != digest(p['input']):
                raise ValueError('packet hash mismatch')
            for e in p['input']['context']:
                if e['text'] != excerpt(ROOT / e['path'], e['sha256'], e['start_line'], e['end_line']):
                    raise ValueError('excerpt mismatch')
        print(json.dumps({'status': 'CONTEXT_BYTES_VERIFIED', 'packets': len(packets)}))
        return
    if OUT.exists() or manifest_path.exists():
        raise FileExistsError('Refusing to overwrite context version')
    accepted_path = REPORT / 'ai_source_v3_acceptance.json'
    accepted = load(accepted_path)
    for p, expected in accepted['artifact_sha256'].items():
        if sha((ROOT / p).read_bytes()) != expected:
            raise ValueError('accepted input drift: ' + p)
    queue_path = REPORT / 'ai_source_v3_context_queue.json'
    queue = load(queue_path)
    if queue['accepted_sha256'] != sha(accepted_path.read_bytes()):
        raise ValueError('queue acceptance mismatch')
    units = {u['unit_id']: u for u in load(ROOT / 'data/annotation/p1_source_repair_v3/PRIVATE_units.json')}
    cases = {c['case_id']: c for c in load(ROOT / 'data/annotation/p1_ai_source_v3/cases.json')}
    bindings = {b['case_id']: b for b in load(ROOT / 'data/annotation/p1_reannotation_inputs_v3/PRIVATE_binding.json')}
    details_path = ROOT / 'data/annotation/p1_source_repair_v3/recovery_details.json'
    source_manifest = load(REPORT / 'source_repair_v3.json')
    if sha(details_path.read_bytes()) != source_manifest['bundle_hashes']['recovery_details.json']:
        raise ValueError('recovery evidence drift')
    refs = {e['sha256']: e for r in load(details_path) for e in r.get('evidence', [])}
    ranges = {
        'moddable': {'before': [(323, 342)], 'after': [(323, 342)]},
        'libming': {'before': [(69, 120)], 'after': [(69, 120)]},
        'libreport': {'before': [(418, 446), (1116, 1150), (1332, 1356)],
                      'after': [(418, 444), (1118, 1152), (1334, 1358)]},
        'oocborrt': {'before': [(20, 58)], 'after': [(20, 58)]},
        'proxygen': {'before': [(11, 18)], 'after': [(11, 18)]},
    }
    packets = []
    for group in queue['cases']:
        for item in group['units']:
            identity = item['case_id']
            unit = units[item['unit_id']]
            binding = bindings[identity]
            contexts = []
            for slot in ['before', 'after']:
                expected = unit.get(slot + '_file_sha256')
                ref = refs.get(expected)
                if ref is None:
                    continue
                commit = unit[slot + '_commit']
                if '/' + commit + '/' not in ref['url']:
                    raise ValueError('context revision mismatch')
                for start, end in ranges[unit['project']][slot]:
                    side = ('B' if binding['source_unit_order_reversed'] else 'A') if slot == 'before' else ('A' if binding['source_unit_order_reversed'] else 'B')
                    contexts.append(dict(**ref, commit=commit, source_slot=slot, displayed_side=side,
                        start_line=start, end_line=end,
                        text=excerpt(ROOT / ref['path'], expected, start, end)))
            inp = dict(**cases[identity], context=contexts)
            packets.append(dict(case_id=identity, original_case_id=group['original_case_id'],
                dataset=group['dataset'], input=inp, context_input_sha256=digest(inp),
                retrieval_status='PARTIAL_PINNED_CONTEXT' if contexts else 'NO_PINNED_FULL_FILE_IN_V3_CACHE',
                missing_context=group['required_context']))
    OUT.mkdir(parents=True)
    packet_path = OUT / 'packets.json'
    packet_path.write_text(json.dumps(packets, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    paths = [packet_path, queue_path, accepted_path, details_path]
    manifest = dict(status='LOCAL_CONTEXT_PASS_COMPLETED', units=len(packets),
        original_case_clusters=len({p['original_case_id'] for p in packets}),
        units_with_partial_context=sum(bool(p['input']['context']) for p in packets),
        clusters_with_partial_context=len({p['original_case_id'] for p in packets if p['input']['context']}),
        external_requests=0, new_labels=False,
        artifact_sha256={p.relative_to(ROOT).as_posix(): sha(p.read_bytes()) for p in paths},
        boundary='Selected excerpts from pinned cached files; no claim of complete call-graph recovery. Missing full-file provenance remains explicit.')
    manifest_path.write_text(json.dumps(manifest, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({k:v for k,v in manifest.items() if k != 'artifact_sha256'}))


if __name__ == '__main__':
    main()
