"""Group unresolved AI judgments by original case; no new labeling or sampling."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    report = ROOT / 'reports/scientific_review_2026_09_07/p1'
    accepted_path = report / 'ai_source_v3_acceptance.json'
    output = report / 'ai_source_v3_context_queue.json'
    if output.exists():
        raise FileExistsError('Refusing to overwrite context queue')
    read = lambda p: json.loads(p.read_text(encoding='utf-8'))
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    accepted = read(accepted_path)
    for path, expected in accepted['artifact_sha256'].items():
        if sha(ROOT / path) != expected:
            raise ValueError('accepted artifact drift: ' + path)
    responses = {r['case_id']: r for r in (json.loads(line) for line in
        (ROOT / 'data/annotation/p1_assistant_source_v3/responses.jsonl').read_text(encoding='utf-8').splitlines())}
    groups = {}
    for row in accepted['rows']:
        if row['displayed_vulnerable_side'] != 'unclear':
            continue
        group = groups.setdefault(row['original_case_id'], dict(original_case_id=row['original_case_id'],
                    dataset=row['dataset'], units=[], required_context=[]))
        response = responses[row['case_id']]
        group['units'].append(dict(case_id=row['case_id'], unit_id=row['unit_id'], summary=response['summary']))
        group['required_context'].extend(x for x in response['missing_context'] if x not in group['required_context'])
    result = dict(status='CONTEXT_RECOVERY_QUEUE_NOT_NEW_LABELS', accepted_sha256=sha(accepted_path),
                  unresolved_units=sum(len(g['units']) for g in groups.values()),
                  original_case_clusters=len(groups), main_diagnostic_denominator=accepted['units'],
                  human_review_required=False, training_authorized=False,
                  policy='Recover revision-matched helpers/callers from cached source first. Preserve unclear when evidence remains insufficient. Do not infer labels from commit direction or benchmark gold.',
                  cases=list(groups.values()))
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({k: v for k, v in result.items() if k != 'cases'}))


if __name__ == '__main__':
    main()
