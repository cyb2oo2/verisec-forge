"""Validate v3 label joins and retain original-case clusters; not a gold certifier."""
from collections import Counter
import hashlib

from vrf.ai_annotation import validate_annotation


def unique_index(rows, key):
    result = {r[key]: r for r in rows}
    if len(result) != len(rows):
        raise ValueError(f'duplicate {key}')
    return result


def accept_repaired_annotations(cases, bindings, units, responses):
    cases = unique_index(cases, 'case_id')
    bindings = unique_index(bindings, 'case_id')
    units = unique_index(units, 'unit_id')
    responses = unique_index(responses, 'case_id')
    if not cases or set(cases) != set(bindings) or set(cases) != set(responses):
        raise ValueError('incomplete or unknown case coverage')
    if {b['unit_id'] for b in bindings.values()} != set(units) or len(bindings) != len(units):
        raise ValueError('source unit coverage mismatch')
    rows = []
    for identity, case in cases.items():
        binding = bindings[identity]
        unit = units[binding['unit_id']]
        reverse = int(hashlib.sha256(identity.encode()).hexdigest()[0], 16) % 2 == 1
        if (identity != 'source-v3::' + unit['unit_id']
                or binding['original_case_id'] != unit['case_id']
                or binding['old_label_inherited'] is not False
                or type(binding['source_unit_order_reversed']) is not bool
                or binding['source_unit_order_reversed'] != reverse):
            raise ValueError('binding identity/order mismatch')
        a, b = (unit['after'], unit['before']) if reverse else (unit['before'], unit['after'])
        if case['candidate_A'] != a or case['candidate_B'] != b:
            raise ValueError('source code/order mismatch')
        response = responses[identity]
        validated = validate_annotation(response, case)
        side = response['vulnerable_side']
        # These slots represent source ordering, not vulnerable/patched chronology.
        source_slot = (('after' if reverse else 'before') if side == 'A'
                       else ('before' if reverse else 'after') if side == 'B' else side)
        rows.append(dict(**validated, original_case_id=unit['case_id'], unit_id=unit['unit_id'],
                         dataset=unit['dataset'], displayed_vulnerable_side=side,
                         source_order_vulnerable_slot=source_slot))
    def counts(items):
        return dict(units=len(items), original_case_clusters=len({x['original_case_id'] for x in items}),
                    judgments=dict(Counter(x['displayed_vulnerable_side'] for x in items)),
                    eligible_provisional_ab=sum(x['eligible_for_provisional_ab'] for x in items),
                    eligible_ab_clusters=len({x['original_case_id'] for x in items if x['eligible_for_provisional_ab']}))
    return dict(status='AI_DIAGNOSTIC_COMPLETED', **counts(rows),
                by_source={s: counts([x for x in rows if x['dataset'] == s]) for s in sorted({x['dataset'] for x in rows})},
                human_gold=False, factual_correctness_validated=False, independent_contexts=False,
                evaluation_contract_frozen=False, main_denominator='all repaired units; cluster by original_case_id',
                ab_subset_role='post-selection sensitivity only, not overall accuracy', rows=rows)
