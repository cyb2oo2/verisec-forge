"""Conservative syntax and function-identity checks; no semantic certification."""
from collections import defaultdict
from functools import lru_cache
import importlib
import re


@lru_cache(maxsize=None)
def grammar_language(language):
    from tree_sitter import Language
    lang = {"c++": "cpp", "js": "javascript", "py": "python", "golang": "go"}.get(language.lower(), language.lower())
    if lang not in {"c", "cpp", "javascript", "python", "go"}:
        raise ValueError(f"unsupported language: {language}")
    grammar = importlib.import_module("tree_sitter_" + lang)
    return Language(grammar.language())


def parser(language):
    # Parser instances are mutable and must not be shared by recovery workers.
    from tree_sitter import Parser
    return Parser(grammar_language(language))


def functions(code, language):
    data = code.encode("utf-8")
    tree = parser(language).parse(data)
    found = []
    types = {"function_definition", "function_declaration", "method_declaration", "method_definition", "arrow_function", "function_expression", "generator_function_declaration"}
    def walk(node):
        if node.type in types:
            name = node.child_by_field_name("name")
            decl = node.child_by_field_name("declarator")
            while name is None and decl is not None:
                if decl.type in {"identifier", "qualified_identifier", "field_identifier", "destructor_name"}:
                    name = decl
                    break
                decl = decl.child_by_field_name("declarator")
            found.append({"name": data[name.start_byte:name.end_byte].decode() if name else "<anonymous>",
                          "kind": node.type, "start_line": node.start_point.row+1, "end_line": node.end_point.row+1,
                          "code": data[node.start_byte:node.end_byte].decode(), "has_error": node.has_error})
            return
        for child in node.named_children:
            walk(child)
    walk(tree.root_node)
    return found, tree.root_node.has_error


def snippet_check(code, language):
    try:
        units, errors = functions(code, language)
        # A JS method excerpt is valid in an object/class context. The wrapper is
        # parser-only; exported source bytes are never changed.
        if errors and language.lower() in {"javascript", "js"}:
            wrapped, wrap_errors = functions("({\n" + code + "\n})", language)
            if not wrap_errors:
                units, errors = wrapped, False
        ok = not errors and len(units) == 1 and not units[0]["has_error"]
        return {"ok": ok, "parse_errors": errors, "function_count": len(units),
                "name": units[0]["name"] if len(units) == 1 else None,
                "kind": units[0]["kind"] if len(units) == 1 else None}
    except ValueError as exc:
        return {"ok": False, "reason": str(exc)}


def match_patch_functions(example):
    """Never zip function lists. Match unique file+name, with a guarded unique-file fallback."""
    language = str(example.get("programming_language", "unknown"))
    groups = []
    for side in ("vul_func", "fix_func"):
        by_path = defaultdict(list)
        for index, item in enumerate(example.get(side) or []):
            path = str(item.get("file_path") or "").replace("\\", "/")
            quality = snippet_check(str(item.get("snippet") or ""), language)
            by_path[path].append((index, item, quality))
        groups.append(by_path)
    matched, rejected = [], []
    for path in sorted(set(groups[0]) | set(groups[1])):
        left, right = groups[0].get(path, []), groups[1].get(path, [])
        used = set()
        for i, before, qb in left:
            candidates = [(j, after, qa) for j, after, qa in right if j not in used and
                          qb.get("ok") and qa.get("ok") and qb["name"] == qa["name"] and qb["kind"] == qa["kind"]]
            # Duplicate/anonymous names in a file cannot be disambiguated by order.
            unique_left = sum(q.get("name") == qb.get("name") and q.get("kind") == qb.get("kind") for _, _, q in left) == 1
            if path and len(candidates) == 1 and unique_left:
                j, after, qa = candidates[0]
                if qb["name"] == "<anonymous>":
                    rejected.append({"side": "before", "index": i, "reason": "ambiguous_anonymous_function"})
                    continue
                used.add(j)
                matched.append((i, before, after, {"method": "unique_file_and_parsed_function_identity",
                                                  "file_path": path, "before_index": i, "after_index": j,
                                                  "before_syntax": qb, "after_syntax": qa}))
            else:
                rejected.append({"side": "before", "index": i, "file_path": path,
                                 "reason": "missing_ambiguous_or_syntax_invalid_match", "syntax": qb})
        for j, _, qa in right:
            if j not in used:
                rejected.append({"side": "after", "index": j, "file_path": path, "reason": "unmatched", "syntax": qa})
    return matched, rejected


def changed_lines(patch):
    old, new, removed, added = 0, 0, set(), set()
    in_hunk = False
    for line in patch.splitlines():
        match = re.match(r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@", line)
        if match:
            old, new = map(int, match.groups()); in_hunk = True
        elif in_hunk and line.startswith("-"):
            removed.add(old); old += 1
        elif in_hunk and line.startswith("+"):
            added.add(new); new += 1
        elif in_hunk and line.startswith(" "):
            old += 1; new += 1
    return removed, added


def pair_changed_functions(before, after, patch, language):
    left, _ = functions(before, language)
    right, _ = functions(after, language)
    removed, added = changed_lines(patch)
    touched = lambda f, lines: any(f["start_line"] <= n <= f["end_line"] for n in lines)
    pairs = []
    for b in left:
        matches = [a for a in right if a["name"] == b["name"] and a["kind"] == b["kind"]]
        if len(matches) != 1 or sum(x["name"] == b["name"] and x["kind"] == b["kind"] for x in left) != 1:
            continue
        a = matches[0]
        if not b["has_error"] and not a["has_error"] and b["code"] != a["code"] and (touched(b, removed) or touched(a, added)):
            pairs.append((b, a))
    return pairs
