import json

import pytest

from vrf.training_dataset import (clean_function, components, split_components, orientations,
                                   validate_splits, verify_training_manifest, sha)


def pair(key, project, cve, before, after):
    return dict(pair_key=key, project=project, cve=cve, before=before, after=after)


def test_comment_removal_preserves_strings_and_rejects_outside_fragment():
    clean = clean_function('def f():\n    # CVE-2020-1234 fixed\n    return "#still data"\n', 'Python')
    assert 'CVE' not in clean
    assert '"#still data"' in clean
    with pytest.raises(ValueError, match='outside_function'):
        clean_function('def f():\n    return 1\nreturn f', 'Python')


def test_transitive_project_cve_clone_grouping():
    ps = [pair('1','p1','c1','return one + two','safe one + two'),
          pair('2','p1','c2','distinct three','changed three'),
          pair('3','p2','c2','return five','safe five'),
          pair('4','p3','c3','return one + two','different result')]
    groups,_ = components(ps)
    assert len(groups) == 1
    splits = split_components(groups, {'train':.7,'validation':.15,'test':.15},1)
    validate_splits(splits)
    assert max(map(len,splits.values())) == 4


def test_swap_label_follows_code_not_position():
    p = pair('p','project','cve','bad_code','repaired_code')
    a,b = orientations(p)
    assert a['label'] == 0 and 'Candidate A:\nbad_code' in a['text']
    assert b['label'] == 1 and 'Candidate B:\nbad_code' in b['text']
    assert a['pair_key'] == b['pair_key']


def test_cross_split_project_leak_rejected():
    a = dict(pair('a','same','c1','a','b'), component_id='one')
    b = dict(pair('b','same','c2','c','d'), component_id='two')
    with pytest.raises(ValueError, match='project'):
        validate_splits({'train':[a],'test':[b]})


def fixture_manifest(root):
    data = root/'train.jsonl'
    data.write_text('{}\n')
    manifest = dict(status='READY_FOR_WEAK_SUPERVISION_PILOT', max_seq_length=4096,
                    artifact_sha256={'train.jsonl':sha(data.read_bytes())},
                    datasets={'train':'train.jsonl','validation':'val.jsonl'})
    (root/'manifest.json').write_text(json.dumps(manifest))
    cfg = dict(dataset_manifest='manifest.json',init_checkpoint=None,max_seq_length=4096,
               allow_truncation=False,train_dataset='train.jsonl',eval_dataset='val.jsonl')
    return cfg


@pytest.mark.parametrize('mutation', ['checkpoint','truncation','path','bytes'])
def test_training_preflight_refuses_drift(tmp_path, mutation):
    cfg = fixture_manifest(tmp_path)
    if mutation == 'checkpoint':cfg['init_checkpoint'] = 'old'
    elif mutation == 'truncation':cfg['allow_truncation'] = True
    elif mutation == 'path':cfg['eval_dataset'] = 'test.jsonl'
    else:(tmp_path/'train.jsonl').write_text('changed')
    with pytest.raises(ValueError):verify_training_manifest(tmp_path,cfg)
