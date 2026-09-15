import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location('local_context', Path(__file__).parents[1] / 'scripts/recover_p1_local_context.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_excerpt_binds_original_bytes_and_line_numbers(tmp_path):
    p = tmp_path / 'source.bin'
    p.write_bytes(b'first\r\nsecond\r\nthird\r\n')
    expected = module.sha(p.read_bytes())
    assert module.excerpt(p, expected, 2, 3) == 'second\nthird'
    p.write_bytes(b'first\nsecond\nthird\n')
    with pytest.raises(ValueError, match='hash mismatch'):
        module.excerpt(p, expected, 2, 3)


@pytest.mark.parametrize('start,end', [(0,1), (2,1), (1,4)])
def test_out_of_range_context_rejected(tmp_path, start, end):
    p = tmp_path / 'source.bin'
    p.write_bytes(b'a\nb\nc')
    with pytest.raises(ValueError, match='range'):
        module.excerpt(p, module.sha(p.read_bytes()), start, end)


def test_context_hash_covers_text_and_side():
    a = {'candidate_A':'a', 'candidate_B':'b', 'context':[{'text':'helper','displayed_side':'A'}]}
    original = module.digest(a)
    a['context'][0]['displayed_side'] = 'B'
    assert module.digest(a) != original
