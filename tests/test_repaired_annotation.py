import copy
import hashlib

import pytest

from vrf.ai_annotation import input_hash
from vrf.repaired_annotation import accept_repaired_annotations


def fixture_rows():
    cases, bindings, units, responses = [], [], [], []
    for number in range(8):
        uid = str(number)
        identity = 'source-v3::' + uid
        reverse = int(hashlib.sha256(identity.encode()).hexdigest()[0], 16) % 2 == 1
        before, after = 'int f() { return 1; }', 'int f() { return 2; }'
        a, b = (after, before) if reverse else (before, after)
        cases.append(dict(case_id=identity, candidate_A=a, candidate_B=b))
        bindings.append(dict(case_id=identity, unit_id=uid, original_case_id='cluster',
                             old_label_inherited=False, source_unit_order_reversed=reverse))
        units.append(dict(unit_id=uid, case_id='cluster', dataset='fixture', before=before, after=after))
        # Select the same source text despite display swaps.
        side = 'B' if reverse else 'A'
        responses.append(dict(case_id=identity, input_sha256=input_hash(identity, a, b), annotation_source='ai',
                              vulnerable_side=side, context_sufficient='yes', confidence='medium',
                              summary='Synthetic transport test, not a security judgment.',
                              evidence=[dict(side=side, start_line=1, end_line=1, reason='Fixture')],
                              trigger_conditions=[], missing_context=[], alternative_explanation='Fixture only'))
    return cases, bindings, units, responses


def test_swaps_preserve_source_slot_and_cluster_denominator():
    args = fixture_rows()
    assert {x['source_unit_order_reversed'] for x in args[1]} == {False, True}
    result = accept_repaired_annotations(*args)
    assert result['original_case_clusters'] == result['eligible_ab_clusters'] == 1
    assert result['units'] == 8
    assert {r['source_order_vulnerable_slot'] for r in result['rows']} == {'before'}
    assert result['human_gold'] is False


@pytest.mark.parametrize('which', range(4))
def test_duplicate_ids_rejected_in_every_join(which):
    args = fixture_rows()
    args[which].append(copy.deepcopy(args[which][0]))
    with pytest.raises(ValueError, match='duplicate'):
        accept_repaired_annotations(*args)


def test_missing_response_is_not_an_exclusion():
    args = fixture_rows()
    args[3].pop()
    with pytest.raises(ValueError, match='coverage'):
        accept_repaired_annotations(*args)


@pytest.mark.parametrize('change', ['order', 'cluster', 'source', 'inherit', 'response_hash'])
def test_binding_and_source_tampering_rejected(change):
    args = fixture_rows()
    if change == 'order':
        args[1][0]['source_unit_order_reversed'] = not args[1][0]['source_unit_order_reversed']
    elif change == 'cluster':
        args[1][0]['original_case_id'] = 'another'
    elif change == 'source':
        args[2][0]['before'] += ' altered'
    elif change == 'inherit':
        args[1][0]['old_label_inherited'] = True
    else:
        args[3][0]['input_sha256'] = 'wrong'
    with pytest.raises(ValueError):
        accept_repaired_annotations(*args)


def test_unclear_stays_in_main_denominator():
    args = fixture_rows()
    args[3][0].update(vulnerable_side='unclear', context_sufficient='no', missing_context=['Caller'])
    result = accept_repaired_annotations(*args)
    assert result['units'] == 8
    assert result['eligible_provisional_ab'] == 7
    assert result['judgments']['unclear'] == 1
    assert result['rows'][0]['source_order_vulnerable_slot'] == 'unclear'
