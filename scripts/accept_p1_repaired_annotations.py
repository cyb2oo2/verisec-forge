"""Accept the disclosed current-assistant v3 diagnostic, with input provenance checks."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from vrf.repaired_annotation import accept_repaired_annotations


def main():
    report = ROOT / 'reports/scientific_review_2026_09_07/p1'
    run = ROOT / 'data/annotation/p1_assistant_source_v3'
    output = report / 'ai_source_v3_acceptance.json'
    if output.exists():
        raise FileExistsError('Refusing to overwrite accepted annotation evidence')
    read = lambda p: json.loads(p.read_text(encoding='utf-8'))
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    preparation_path = report / 'ai_source_v3_preparation.json'
    source_manifest_path = report / 'source_repair_v3.json'
    preparation = read(preparation_path)
    source_manifest = read(source_manifest_path)
    bundle = ROOT / preparation['bundle']
    for name, expected in preparation['hashes'].items():
        if sha(bundle / name) != expected:
            raise ValueError('prepared bundle drift: ' + name)
    source = ROOT / 'data/annotation/p1_source_repair_v3/PRIVATE_units.json'
    if sha(source) != source_manifest['bundle_hashes']['PRIVATE_units.json']:
        raise ValueError('repaired source drift')
    response_path = run / 'responses.jsonl'
    metadata = read(run / 'metadata.json')
    raw = report / 'assistant_annotation_decisions_source_v3.json'
    for field, path in [('responses_sha256', response_path), ('requests_sha256', bundle / 'requests.jsonl'),
                        ('actual_input_sha256', bundle / 'cases.json'), ('raw_responses_sha256', raw)]:
        if metadata[field] != sha(path):
            raise ValueError('run hash mismatch: ' + field)
    if (metadata['annotation_source'] != 'ai' or metadata['mock'] is not False
            or metadata['execution_mode'] != 'current_assistant_context'
            or metadata['independent_contexts'] is not False
            or metadata['prepared_requests_executed_verbatim'] is not False):
        raise ValueError('unexpected execution disclosure')
    bindings_path = ROOT / 'data/annotation/p1_reannotation_inputs_v3/PRIVATE_binding.json'
    responses = [json.loads(line) for line in response_path.read_text(encoding='utf-8').splitlines() if line.strip()]
    result = accept_repaired_annotations(read(bundle / 'cases.json'), read(bindings_path), read(source), responses)
    # Serialization consistency proves these are the recorded decisions, not independent model provenance.
    decisions = read(raw)
    cases = read(bundle / 'cases.json')
    if sorted(x[0] for x in decisions) != list(range(len(cases))):
        raise ValueError('raw decision coverage mismatch')
    by_id = {r['case_id']: r for r in responses}
    for i, side, context, confidence, summary, evidence, triggers, missing, alternative in decisions:
        r = by_id[cases[i]['case_id']]
        serialized = [r['vulnerable_side'], r['context_sufficient'], r['confidence'], r['summary'],
                      [[e['side'], e['start_line'], e['end_line'], e['reason']] for e in r['evidence']],
                      r['trigger_conditions'], r['missing_context'], r['alternative_explanation']]
        if serialized != [side, context, confidence, summary, evidence, triggers, missing, alternative]:
            raise ValueError('raw decision/response mismatch')
    paths = [preparation_path, source_manifest_path, source, bindings_path, bundle / 'cases.json',
             response_path, run / 'metadata.json', raw]
    result['artifact_sha256'] = {p.relative_to(ROOT).as_posix(): sha(p) for p in paths}
    result['execution_disclosure'] = metadata['execution_disclosure']
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: v for k, v in result.items() if k not in {'rows', 'artifact_sha256'}}, indent=2))


if __name__ == '__main__':
    main()
