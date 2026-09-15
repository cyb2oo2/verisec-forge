"""Leakage-aware construction of explicitly weakly supervised pair datasets."""
import hashlib
import json
import re
from collections import defaultdict

from vrf.source_integrity import functions, parser


def sha(data):
    return hashlib.sha256(data).hexdigest()


def project_key(value):
    return value.lower().rstrip('/').removesuffix('.git').split('/')[-1]


def clean_function(code, language):
    """Remove parser-recognized comments, preserve strings, reject trailing fragments."""
    language = language.lower()
    data = code.encode('utf-8')
    tree = parser(language).parse(data)
    if tree.root_node.has_error and language == 'javascript':
        data = b'({\n' + data + b'\n})'
        tree = parser(language).parse(data)
        wrapped = True
    else:
        wrapped = False
    if tree.root_node.has_error:
        raise ValueError('parse_error')
    comments = []
    pending = [tree.root_node]
    while pending:
        node = pending.pop()
        if 'comment' in node.type:
            comments.append((node.start_byte, node.end_byte))
        else:
            pending.extend(node.named_children)
    for start, end in sorted(comments, reverse=True):
        data = data[:start] + bytes(10 if x == 10 else 32 for x in data[start:end]) + data[end:]
    text = data.decode('utf-8')
    fs, errors = functions(text, language)
    if errors or len(fs) != 1:
        raise ValueError('not_one_function')
    clean = text[3:-3].strip() if wrapped else text.strip()
    if fs[0]['code'].strip() != clean:
        raise ValueError('code_outside_function')
    if re.search(r'CVE-\d{4}-\d+|GHSA-[\w-]+', clean, re.I):
        raise ValueError('advisory_marker_in_code')
    return clean


def tokens(code):
    return tuple(re.findall(r'\w+|[^\w\s]', code))


def shingles(code, size=5):
    ts = tokens(code)
    return {ts[i:i+size] for i in range(max(1, len(ts)-size+1))}


def similar(a, b, threshold):
    return bool(a and b) and len(a & b) / len(a | b) >= threshold


def components(pairs, threshold=0.8, size=5):
    """Join projects, CVEs and cross-pair lexical clones transitively."""
    parent = list(range(len(pairs)))
    def root(i):
        while i != parent[i]:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i
    def join(i, j):
        parent[root(j)] = root(i)
    owners = {}
    code_sets = []
    for i, pair in enumerate(pairs):
        for key in [('project', pair['project']), ('cve', pair['cve'])]:
            if key in owners:
                join(i, owners[key])
            else:
                owners[key] = i
        code_sets.append([shingles(pair[side], size) for side in ('before', 'after')])
    clone_edges = 0
    for i in range(len(pairs)):
        for j in range(i):
            if root(i) == root(j):
                continue
            if any(min(len(a), len(b)) / max(len(a), len(b)) >= threshold and similar(a, b, threshold)
                   for a in code_sets[i] for b in code_sets[j]):
                join(i, j)
                clone_edges += 1
    groups = defaultdict(list)
    for i, pair in enumerate(pairs):
        groups[root(i)].append(pair)
    return list(groups.values()), clone_edges


def split_components(groups, fractions, seed):
    total = sum(map(len, groups))
    result = {s: [] for s in fractions}
    groups = sorted(groups, key=lambda g: (-len(g), sha((str(seed)+min(p['pair_key'] for p in g)).encode())))
    for group in groups:
        dest = max(fractions, key=lambda s: (fractions[s]*total-len(result[s]), s))
        component_id = sha('|'.join(sorted(p['pair_key'] for p in group)).encode())[:24]
        for p in group:
            result[dest].append(dict(p, component_id=component_id))
    return result


def render(a, b):
    return f'Candidate A:\n{a}\n\nCandidate B:\n{b}\n\nWhich candidate is more vulnerable? Choose A or B.'


def orientations(pair):
    return [dict(id=pair['pair_key']+'::'+str(swap), pair_key=pair['pair_key'],
                 text=render(pair['after'], pair['before']) if swap else render(pair['before'], pair['after']),
                 label=int(swap), orientation=swap,
                 label_source='upstream_patch_direction_weak_supervision') for swap in (False, True)]


def validate_splits(splits):
    seen = {key: {} for key in ['project', 'cve', 'component_id', 'pair_key', 'code']}
    for split, pairs in splits.items():
        for p in pairs:
            keys = [(key, p[key]) for key in ['project', 'cve', 'component_id', 'pair_key']]
            keys += [('code', tokens(p[side])) for side in ['before', 'after']]
            for key, value in keys:
                if value in seen[key] and seen[key][value] != split:
                    raise ValueError('cross-split overlap: ' + key)
                seen[key][value] = split


def verify_training_manifest(root, config, tokenizer=None):
    manifest = json.loads((root / config['dataset_manifest']).read_text(encoding='utf-8'))
    if manifest['status'] != 'READY_FOR_WEAK_SUPERVISION_PILOT':
        raise ValueError('dataset not pilot-ready')
    if config.get('init_checkpoint') is not None:
        raise ValueError('old checkpoint initialization forbidden for this dataset')
    if config['max_seq_length'] != manifest['max_seq_length'] or config.get('allow_truncation') is not False:
        raise ValueError('length/truncation contract mismatch')
    for path, expected in manifest['artifact_sha256'].items():
        if sha((root / path).read_bytes()) != expected:
            raise ValueError('dataset artifact drift: ' + path)
    if config['train_dataset'] != manifest['datasets']['train'] or config['eval_dataset'] != manifest['datasets']['validation']:
        raise ValueError('training split path mismatch')
    if tokenizer is not None:
        for split in ['train', 'validation', 'test']:
            for line in (root / manifest['datasets'][split]).read_text(encoding='utf-8').splitlines():
                row = json.loads(line)
                ids = tokenizer(row['text'], truncation=False, add_special_tokens=True)['input_ids']
                if len(ids) > config['max_seq_length'] or sha(json.dumps(ids).encode()) != manifest['token_ids_sha256'][row['id']]:
                    raise ValueError('runtime tokenization drift or overflow')
    return manifest
