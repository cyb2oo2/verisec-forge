"""Held-out nuisance-transform renderers for repair transfer evaluation.

These renderers support exploratory evaluation on a mixed-source audit.
Candidate labels are retained, but preservation of security-relevant information
must be validated separately, especially for split-view regrouping. The current
scientific interpretation is reports/scientific_review_2026_09_07/REVIEW.md.

Five presentation families:

- ``context_window``: unified diff with a different context-line budget
  (``difflib`` ``n`` parameter) than the ``n=3`` default used everywhere else.
- ``split_view``: the same removed/added content, restructured into grouped
  "Removed" / "Added" / "Unchanged context" blocks instead of interleaved
  unified hunks.
- ``diff_algorithm_myers_header``: real ``git diff --no-index`` output
  (Myers algorithm, git's default) -- isolates the header-format change
  (``diff --git``, ``index``, ``a/``/``b/`` prefixes) from algorithm choice,
  since it is compared against both canonical (difflib) and the histogram
  condition below (same header family, different algorithm).
- ``diff_algorithm_histogram``: real ``git diff --no-index
  --diff-algorithm=histogram`` output -- same git header family as the Myers
  condition above, different underlying diff algorithm.
- ``whitespace_comment``: reindents diff-body lines and inserts one benign
  comment marker after the file header -- a whitespace/comment perturbation
  that leaves code semantics and the gold answer unchanged.

Each renderer produces BOTH a canonical and a side-swapped rendering (via
``swap_pair``) of the same underlying pair, so the existing antisymmetric
decision ``s = g(canonical) - g(side_swap)`` (`src/vrf/repair_evaluation.py`)
can be computed exactly as in the PrimeVul/CrossVul runs -- no new metric
definition, only new input text.

Honesty note on the two git-based conditions: git's Myers implementation is
not identical to Python's Ratcliff/Obershelp-based ``difflib``, so
``diff_algorithm_myers_header`` changes *both* header format and algorithm
relative to canonical. It is retained as the cleaner isolation of "algorithm
choice alone" (vs. ``diff_algorithm_histogram``, which shares its header
format) rather than a clean isolation of "header format alone" vs. canonical.
This is stated explicitly here and in the report so the family names are not
overclaimed as perfectly orthogonal factors.
"""

from __future__ import annotations

import difflib
import hashlib
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from vrf.relational_benchmark import CanonicalPair, swap_pair, unified_diff

NUISANCE_FAMILIES = [
    "context_window",
    "split_view",
    "diff_algorithm_myers_header",
    "diff_algorithm_histogram",
    "whitespace_comment",
]

_TASK_HEADER = (
    "Task: compare two related code states and choose the riskier side.\n"
    "Output one label: A_RISKIER, B_RISKIER, or INSUFFICIENT_CONTEXT.\n\n"
)


def _metadata_block(pair: CanonicalPair) -> str:
    return (
        f"Dataset: {pair.dataset}\n"
        f"Project: {pair.project}\n"
        f"CVE: {pair.cve}\n"
        f"CWE: {pair.cwe}\n"
        f"Language: {pair.language}\n\n"
    )


def _wrap(pair: CanonicalPair, diff_label: str, diff_body: str) -> str:
    return (
        f"{_TASK_HEADER}"
        f"{_metadata_block(pair)}"
        f"{diff_label}\n"
        f"{diff_body}\n"
    )


def render_context_window(pair: CanonicalPair, *, context_lines: int) -> str:
    """Unified diff with a non-default context-line budget (``difflib`` ``n``).

    The canonical renderer everywhere else in this codebase uses ``n=3``
    (the ``difflib.unified_diff`` default). A tighter or wider window changes
    how much surrounding code is visible per hunk without touching gold.
    """
    diff = "".join(
        difflib.unified_diff(
            pair.side_a.code.splitlines(keepends=True),
            pair.side_b.code.splitlines(keepends=True),
            fromfile="Side A",
            tofile="Side B",
            lineterm="\n",
            n=context_lines,
        )
    ).rstrip()
    return _wrap(pair, "Unified diff from Side A to Side B:", diff)


def render_split_view(pair: CanonicalPair) -> str:
    """Group the same content into Removed / Added / Unchanged-context blocks.

    Same underlying unified diff computation as canonical, restructured so the
    removed and added lines are no longer interleaved hunk-by-hunk.
    """
    removed: list[str] = []
    added: list[str] = []
    context: list[str] = []
    for line in difflib.unified_diff(
        pair.side_a.code.splitlines(keepends=True),
        pair.side_b.code.splitlines(keepends=True),
        fromfile="Side A",
        tofile="Side B",
        lineterm="\n",
    ):
        if line.startswith(("--- ", "+++ ", "@@")):
            continue
        if line.startswith("-"):
            removed.append(line[1:])
        elif line.startswith("+"):
            added.append(line[1:])
        elif line.startswith(" "):
            context.append(line[1:])
        else:
            context.append(line)
    body = (
        "Removed from Side A (absent in Side B):\n"
        + ("".join(removed) if removed else "(none)\n")
        + "\nAdded in Side B (absent in Side A):\n"
        + ("".join(added) if added else "(none)\n")
        + "\nUnchanged context:\n"
        + ("".join(context) if context else "(none)\n")
    ).rstrip()
    return _wrap(pair, "Split-view diff from Side A to Side B:", body)


def split_view_occurrences(pair: CanonicalPair, text: str) -> list[dict[str, Any]]:
    """Source-bound offsets for the exact legacy split-view rendering.

    Preserve input bytes so retained model predictions can be reanalyzed.
    Repeated code lines are mapped by diff position, never by text search.
    """
    if text != render_split_view(pair):
        raise ValueError("split-view text does not match source pair")
    removed, added = [], []
    a_line = b_line = 0
    for line in difflib.unified_diff(pair.side_a.code.splitlines(keepends=True),
                                    pair.side_b.code.splitlines(keepends=True),
                                    fromfile="Side A", tofile="Side B", lineterm="\n"):
        hunk = re.match(r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@", line)
        if hunk:
            a_line, b_line = map(int, hunk.groups())
        elif line.startswith(("--- ", "+++ ")):
            continue
        elif line.startswith("-"):
            removed.append((line[1:], a_line))
            a_line += 1
        elif line.startswith("+"):
            added.append((line[1:], b_line))
            b_line += 1
        elif line.startswith(" "):
            a_line += 1
            b_line += 1
    result = []
    for side, candidate, records, marker in [
        ("A", pair.side_a, removed, "Removed from Side A (absent in Side B):\n"),
        ("B", pair.side_b, added, "Added in Side B (absent in Side A):\n"),
    ]:
        cursor = text.index(marker, text.index("Split-view diff from")) + len(marker)
        for chunk, source_line in records:
            content = chunk.rstrip("\r\n")
            if content.strip():
                if text[cursor:cursor + len(content)] != content:
                    raise ValueError("split-view occurrence mismatch")
                result.append({"occurrence": len(result), "text": content,
                               "char_start": cursor, "char_end": cursor + len(content),
                               "line_index": text[:cursor].count("\n"),
                               "candidate_side": side, "candidate_id": candidate.id,
                               "source_line": source_line,
                               "source_code_sha256": hashlib.sha256(candidate.code.encode()).hexdigest()})
            cursor += len(chunk)
    return result


def render_whitespace_comment(pair: CanonicalPair) -> str:
    """Reindent diff-body lines and insert one benign comment marker.

    Doubles each line's leading whitespace and inserts a single comment line
    after the file header. Code semantics and the gold answer are unchanged --
    this is a presentation perturbation, not a content edit.
    """
    lines = unified_diff(pair).splitlines()
    reindented: list[str] = []
    for line in lines:
        if line.startswith(("--- ", "+++ ", "@@")):
            reindented.append(line)
            continue
        prefix, body = (line[0], line[1:]) if line and line[0] in "+- " else ("", line)
        stripped = body.lstrip(" \t")
        leading = body[: len(body) - len(stripped)]
        reindented.append(prefix + (leading * 2) + stripped)
    result: list[str] = []
    inserted = False
    for line in reindented:
        result.append(line)
        if not inserted and line.startswith("+++ "):
            result.append(
                "# benign whitespace/comment perturbation marker (nuisance transform)"
            )
            inserted = True
    return _wrap(pair, "Unified diff from Side A to Side B:", "\n".join(result))


def _git_diff(code_a: str, code_b: str, *, algorithm: str) -> str:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        file_a = tmp_path / "side_a"
        file_b = tmp_path / "side_b"
        file_a.write_text(code_a, encoding="utf-8", newline="\n")
        file_b.write_text(code_b, encoding="utf-8", newline="\n")
        # Pass POSIX-style path strings even on Windows: git quotes
        # backslash-separated paths in C-style escapes in its diff headers
        # (`"a/C:\\Users\\..."`), which forward-slash paths avoid entirely.
        posix_a, posix_b = file_a.as_posix(), file_b.as_posix()
        result = subprocess.run(
            [
                "git",
                "-c",
                "core.autocrlf=false",
                "diff",
                "--no-index",
                f"--diff-algorithm={algorithm}",
                "--",
                posix_a,
                posix_b,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        # git diff --no-index exits 1 when the inputs differ; anything else is
        # a genuine failure (e.g. git missing, bad algorithm name).
        if result.returncode not in (0, 1):
            raise RuntimeError(
                f"git diff --no-index failed (exit {result.returncode}): {result.stderr}"
            )
        return result.stdout.replace(posix_a, "Side A").replace(posix_b, "Side B")


def render_diff_algorithm(pair: CanonicalPair, *, algorithm: str) -> str:
    """Real ``git diff --no-index`` output using the given diff algorithm.

    Uses git's native header format (``diff --git``, ``index``, ``a/``/``b/``
    prefixes), which differs structurally from the ``difflib``-rendered
    ``--- Side A`` / ``+++ Side B`` header used everywhere else in this
    codebase -- see the module docstring for the header-vs-algorithm
    isolation caveat.
    """
    diff_body = _git_diff(pair.side_a.code, pair.side_b.code, algorithm=algorithm)
    return _wrap(
        pair,
        f"Git diff (--diff-algorithm={algorithm}) from Side A to Side B:",
        diff_body.rstrip(),
    )


def render_nuisance(pair: CanonicalPair, family: str) -> str:
    """Dispatch to the renderer for ``family`` (one of ``NUISANCE_FAMILIES``)."""
    if family == "context_window":
        return render_context_window(pair, context_lines=1)
    if family == "split_view":
        return render_split_view(pair)
    if family == "diff_algorithm_myers_header":
        return render_diff_algorithm(pair, algorithm="myers")
    if family == "diff_algorithm_histogram":
        return render_diff_algorithm(pair, algorithm="histogram")
    if family == "whitespace_comment":
        return render_whitespace_comment(pair)
    raise ValueError(f"unknown nuisance family: {family}")


def build_nuisance_rows(pair: CanonicalPair, family: str) -> tuple[str, str]:
    """Return (canonical_text, side_swap_text) for ``family`` on ``pair``."""
    canonical_text = render_nuisance(pair, family)
    side_swap_text = render_nuisance(swap_pair(pair), family)
    return canonical_text, side_swap_text
