"""Serialize the current assistant's local-context review; does not call a model.

Only one judgment changes. Absent or incomplete evidence never forces an A/B label.
"""
import json
from pathlib import Path
from recover_p1_local_context import ROOT, REPORT, OUT, load, sha, excerpt


def main():
    output = REPORT / 'ai_context_v1_review.json'
    if output.exists():
        raise FileExistsError('Refusing to overwrite contextual judgments')
    manifest_path = REPORT / 'local_context_v1.json'
    manifest = load(manifest_path)
    for path, expected in manifest['artifact_sha256'].items():
        if sha((ROOT / path).read_bytes()) != expected:
            raise ValueError('context manifest drift')
    packets = load(OUT / 'packets.json')
    for packet in packets:
        for e in packet['input']['context']:
            if e['text'] != excerpt(ROOT / e['path'], e['sha256'], e['start_line'], e['end_line']):
                raise ValueError('context evidence drift')
    notes = {
        'fa3fd2c41f4a9a11727f': ('Helper permits nonnegative integer inputs and numeric values up to 0x7FFFFFFF; this does not rule out overflow of a sum or shift. Exact txInteger definition and compilation semantics remain missing. No single safe side established.'),
        '0a44c19072152f039653': ('For number=0 and bufbits=0, SWFInput_readBits returns at source lines 73-77 without rejecting the count. Candidate A then evaluates 1 << (number-1), a negative shift count. Candidate B short-circuits this zero-count expression. This supports a provisional A label for this specific path, not complete safety for arbitrary counts.'),
        '491edb6c069c144f9e45': ('The nearby element-name decoder checks the same return status, but the actual UTF-8 decoder implementation and nesting limits are not in this cached file. Similar call-site checks do not establish its failure-output contract.'),
        'a9f49eee709bab5504f6': ('The old save helper triggers GUI refresh inside the notepad save loop; refresh removes notebook pages. The newer revision moves refresh to callers after saving. This reveals a possible mid-save widget-state/data-loss problem and invalidates a simple missing-refresh interpretation. Security impact and all GUI lifetimes remain unproven; keep all three functions in the same unresolved case cluster.'),
        '6f24cdefc7f7d2dde195': ('Headers identify Boost iterator dependencies and the replacement Base64 helper, but their implementations and precise dependency revisions are not present in the recovered file. Neither decoder rejection behavior nor encoder boundary behavior is established.')}
    rows = []
    for p in packets:
        identity = p['case_id']
        is_zero = p['original_case_id'] == '0a44c19072152f039653'
        has_context = bool(p['input']['context'])
        rows.append(dict(case_id=identity, original_case_id=p['original_case_id'],
            context_input_sha256=p['context_input_sha256'],
            action='REVISED_PROVISIONAL' if is_zero else 'REVIEWED_UNRESOLVED' if has_context else 'NOT_REANNOTATED_NO_CONTEXT',
            previous_vulnerable_side='unclear', vulnerable_side='A' if is_zero else 'unclear',
            confidence='medium' if is_zero else 'not_applicable',
            assessment=notes[p['original_case_id']] if has_context else
                'No revision-bound full file reference in the v3 recovery cache. Prior unclear judgment is retained, not independently reannotated. Recover the original source repository, exact revision and matching function bytes before adding context.',
            evidence=[dict(path=e['path'], sha256=e['sha256'], commit=e['commit'],
                           displayed_side=e['displayed_side'], start_line=e['start_line'], end_line=e['end_line'])
                      for e in p['input']['context']],
            remaining_context=p['missing_context'] if not is_zero else ['Caller reachability and legal nonzero count bounds remain outside the confirmed zero-count path.']))
    base = load(REPORT / 'ai_source_v3_acceptance.json')
    changed = {r['case_id']: r['vulnerable_side'] for r in rows if r['action']=='REVISED_PROVISIONAL'}
    from collections import Counter
    labels = Counter(changed.get(r['case_id'],r['displayed_vulnerable_side']) for r in base['rows'])
    result = dict(status='LOCAL_CONTEXT_REVIEW_COMPLETED', annotation_source='ai',
        execution_mode='current_assistant_context', independent_contexts=False,
        exact_serving_model='unavailable', provider_api_calls=0,
        source_context_and_prior_judgments_visible=True, human_gold=False,
        parent_acceptance_sha256=sha((REPORT / 'ai_source_v3_acceptance.json').read_bytes()),
        context_manifest_sha256=sha(manifest_path.read_bytes()),
        reviewed_with_context=9, retained_without_new_context=9, changed_labels=len(changed),
        combined_diagnostic_counts=dict(labels), main_units=32, original_case_clusters=27,
        eligible_ab_clusters=len({r['original_case_id'] for r in base['rows'] if r['eligible_for_provisional_ab'] or r['case_id'] in changed}),
        evaluation_contract_frozen=False,
        boundary='Mixed input contexts; counts describe a diagnostic ledger, not a comparable model score. No compiled exploit or upstream integration test was run. Prior labels and artifacts remain unchanged.', rows=rows)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k!='rows'}))


if __name__ == '__main__':
    main()
