import pytest
pytest.importorskip("tree_sitter")

from vrf.source_integrity import match_patch_functions, snippet_check, pair_changed_functions
from scripts.build_patcheval_pair_diff import pair_rows_from_example
from scripts.build_deltasecommits_pair_diff import normalize_code_for_diff


def func(path, name, expression="1"):
    return {"file_path": path, "snippet": f"def {name}():\n    return {expression}", "id": name}


def test_reordered_fix_list_matches_file_and_function():
    example = {"programming_language": "Python", "vul_func": [func("a.py", "a"), func("b.py", "b")],
               "fix_func": [func("b.py", "b", "2"), func("a.py", "a", "2")]}
    matches, rejected = match_patch_functions(example)
    assert [(m[1]["id"], m[2]["id"]) for m in matches] == [("a", "a"), ("b", "b")]
    assert not rejected
    assert len(pair_rows_from_example(example, example_index=1)) == 4


def test_different_file_or_function_cannot_pair_by_position():
    example = {"programming_language": "Python", "vul_func": [func("a.py", "a")], "fix_func": [func("b.py", "a")]}
    assert not match_patch_functions(example)[0]
    example["fix_func"] = [func("a.py", "other")]
    assert not match_patch_functions(example)[0]


def test_ambiguous_identity_rejected():
    example = {"programming_language": "Python", "vul_func": [func("a.py", "a")],
               "fix_func": [func("a.py", "a"), func("a.py", "a", "2")]}
    assert not match_patch_functions(example)[0]


def test_fragments_rejected_and_comments_strings_not_rewritten():
    assert not snippet_check("int f( if(x) { return 1; }", "c")["ok"]
    assert not snippet_check("return escape(user)", "python")["ok"]
    code = 'int f(){const char*s="a;b{}"; /* ; */ return 1;}'
    assert normalize_code_for_diff(code) == code


def test_changed_function_extracted_from_full_file_not_hunk():
    before = "int untouched(){return 0;}\nint fixed(int x){\nreturn x;\n}\n"
    after = "int untouched(){return 0;}\nint fixed(int x){\nreturn x+1;\n}\n"
    patch = "@@ -3 +3 @@ int fixed(int x)\n-return x;\n+return x+1;"
    pairs = pair_changed_functions(before, after, patch, "c")
    assert len(pairs) == 1
    assert pairs[0][0]["code"] == "int fixed(int x){\nreturn x;\n}"
    assert pairs[0][1]["start_line"] == 2


def test_multi_function_snippet_not_a_single_candidate():
    assert not snippet_check("int a(){return 1;} int b(){return 2;}", "c")["ok"]
