from __future__ import annotations

import re


CODE_MARKER_PATTERN = re.compile(r"\n\n(code|diff):\n", re.IGNORECASE)
SECURITY_FOCUS_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"\beval\s*\(",
        r"\bexec\s*\(",
        r"\bos\.system\b",
        r"\bsubprocess\b",
        r"\binnerhtml\b",
        r"\bdangerouslysetinnerhtml\b",
        r"\bselect\b.+\bfrom\b",
        r"\binsert\b.+\binto\b",
        r"\bupdate\b.+\bset\b",
        r"\bdelete\b.+\bfrom\b",
        r"\bpassword\b",
        r"\btoken\b",
        r"\bauth\b",
        r"\bcsrf\b",
        r"\bxss\b",
        r"\bsql\b",
        r"\bcommand\b",
        r"\bshell\b",
        r"\bserialize\b",
        r"\bdeserialize\b",
        r"\bpickle\b",
        r"\byaml\.load\b",
        r"\bmd5\b",
        r"\bsha1\b",
        r"\bcrypto\b",
        r"\bhttp\.redirect\b",
        r"\bsetheader\b",
        r"\bunsafe\b",
    ]
]
FOCUS_GROUPS: list[tuple[str, list[re.Pattern[str]]]] = [
    (
        "command_execution",
        [
            re.compile(pattern, re.IGNORECASE)
            for pattern in [r"\beval\s*\(", r"\bexec\s*\(", r"\bos\.system\b", r"\bsubprocess\b", r"\bshell\b", r"\bcommand\b"]
        ],
    ),
    (
        "database_query",
        [
            re.compile(pattern, re.IGNORECASE)
            for pattern in [r"\bselect\b.+\bfrom\b", r"\binsert\b.+\binto\b", r"\bupdate\b.+\bset\b", r"\bdelete\b.+\bfrom\b", r"\bsql\b"]
        ],
    ),
    (
        "web_output",
        [
            re.compile(pattern, re.IGNORECASE)
            for pattern in [r"\binnerhtml\b", r"\bdangerouslysetinnerhtml\b", r"\bsetheader\b", r"\bhttp\.redirect\b", r"\bcsrf\b", r"\bauth\b"]
        ],
    ),
    (
        "deserialization_and_crypto",
        [
            re.compile(pattern, re.IGNORECASE)
            for pattern in [r"\bserialize\b", r"\bdeserialize\b", r"\bpickle\b", r"\byaml\.load\b", r"\bmd5\b", r"\bsha1\b", r"\bcrypto\b", r"\btoken\b", r"\bpassword\b"]
        ],
    ),
]
STRUCTURE_HINT_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"^\s*(def|class)\s+\w+",
        r"^\s*(func|type)\s+\w+",
        r"^\s*(public|private|protected)?\s*(static\s+)?\w[\w<>\[\]]*\s+\w+\s*\(",
        r"^\s*router\.",
        r"^\s*http\.",
        r"^\s*if\s+",
        r"^\s*switch\s+",
        r"^\s*case\s+",
    ]
]


def _nearest_structure_start(lines: list[str], idx: int, lookback: int = 80) -> int:
    lower = max(0, idx - lookback)
    for candidate in range(idx, lower - 1, -1):
        if any(pattern.search(lines[candidate]) for pattern in STRUCTURE_HINT_PATTERNS):
            return candidate
    return max(0, idx - 12)


def _structure_end(lines: list[str], start: int, hint_idx: int, lookahead: int = 120) -> int:
    upper = min(len(lines), max(start + 24, hint_idx + lookahead))
    brace_depth = 0
    seen_open = False

    for idx in range(start, upper):
        line = lines[idx]
        brace_depth += line.count("{")
        if line.count("{") > 0:
            seen_open = True
        brace_depth -= line.count("}")

        if idx > start + 8 and any(pattern.search(line) for pattern in STRUCTURE_HINT_PATTERNS):
            return idx
        if seen_open and brace_depth <= 0 and idx >= hint_idx + 4:
            return idx + 1
    return upper


def _expand_span_to_enclosing_block(
    lines: list[str],
    start: int,
    end: int,
    max_block_lines: int = 40,
) -> tuple[int, int]:
    hint_idx = start
    block_start = _nearest_structure_start(lines, hint_idx)
    block_end = _structure_end(lines, block_start, hint_idx)

    merged_start = min(start, block_start)
    merged_end = max(end, block_end)
    if merged_end - merged_start > max_block_lines:
        center = (start + end) // 2
        half = max_block_lines // 2
        merged_start = max(0, center - half)
        merged_end = min(len(lines), merged_start + max_block_lines)
    return merged_start, merged_end


def _focus_spans(
    lines: list[str],
    window: int = 6,
    max_focus_matches: int = 10,
    max_structure_matches: int = 6,
) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    focus_hits = 0
    structure_hits = 0

    for idx, line in enumerate(lines):
        if focus_hits < max_focus_matches and any(pattern.search(line) for pattern in SECURITY_FOCUS_PATTERNS):
            raw_start = max(0, idx - window)
            raw_end = min(len(lines), idx + window + 1)
            spans.append(_expand_span_to_enclosing_block(lines, raw_start, raw_end))
            focus_hits += 1
            continue
        if structure_hits < max_structure_matches and any(pattern.search(line) for pattern in STRUCTURE_HINT_PATTERNS):
            spans.append((idx, min(len(lines), idx + 8)))
            structure_hits += 1

    if not spans:
        return [(0, min(len(lines), 40))]

    spans.sort()
    merged: list[tuple[int, int]] = []
    for start, end in spans:
        if not merged or start > merged[-1][1] + 2:
            merged.append((start, end))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
    return merged[:8]


def _render_focus_windows(lines: list[str], spans: list[tuple[int, int]]) -> str:
    windows: list[str] = []
    for window_idx, (start, end) in enumerate(spans, start=1):
        rendered_lines = [f"{line_no + 1}: {lines[line_no]}" for line_no in range(start, end)]
        windows.append(f"Window {window_idx} (lines {start + 1}-{end}):\n" + "\n".join(rendered_lines).strip())
    return "\n\n".join(windows)


def _group_focus_spans(lines: list[str], max_per_group: int = 2) -> list[tuple[str, tuple[int, int]]]:
    grouped: list[tuple[str, tuple[int, int]]] = []
    for group_name, patterns in FOCUS_GROUPS:
        hits = 0
        for idx, line in enumerate(lines):
            if any(pattern.search(line) for pattern in patterns):
                raw_start = max(0, idx - 6)
                raw_end = min(len(lines), idx + 7)
                grouped.append((group_name, _expand_span_to_enclosing_block(lines, raw_start, raw_end)))
                hits += 1
                if hits >= max_per_group:
                    break
    return grouped


def _render_grouped_focus_windows(lines: list[str], grouped_spans: list[tuple[str, tuple[int, int]]]) -> str:
    if not grouped_spans:
        return ""
    rendered: list[str] = []
    for idx, (group_name, (start, end)) in enumerate(grouped_spans, start=1):
        rendered_lines = [f"{line_no + 1}: {lines[line_no]}" for line_no in range(start, end)]
        rendered.append(
            f"Hotspot {idx} [{group_name}] (lines {start + 1}-{end}):\n" + "\n".join(rendered_lines).strip()
        )
    return "\n\n".join(rendered)


def truncate_text_block(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    head = max_chars // 2
    tail = max_chars - head - 48
    return text[:head] + "\n\n[... TRUNCATED ...]\n\n" + text[-max(0, tail):]


def compress_secure_code_prompt(prompt: str, max_chars: int | None) -> str:
    if not max_chars or len(prompt) <= max_chars:
        return prompt

    marker_match = CODE_MARKER_PATTERN.search(prompt)
    if not marker_match:
        head = max_chars // 2
        tail = max_chars - head
        return (
            prompt[:head]
            + "\n\n[... TRUNCATED FOR MODEL CONTEXT BUDGET ...]\n\n"
            + prompt[-tail:]
        )

    marker = marker_match.group(1).lower()
    prefix = prompt[:marker_match.end()]
    body = prompt[marker_match.end():]
    body_lines = body.splitlines()
    prologue_block = "\n".join(f"{idx + 1}: {line}" for idx, line in enumerate(body_lines[:8])).strip()
    focus_spans = _focus_spans(body_lines)
    focus_block = _render_focus_windows(body_lines, focus_spans).strip()
    grouped_focus_block = _render_grouped_focus_windows(body_lines, _group_focus_spans(body_lines)).strip()

    sections = [
        prefix.rstrip(),
        "The following content is a bounded analysis snippet. It is not a completion target.",
        f"BEGIN {marker.upper()} SNIPPET",
        "[Windowed snippet selection for long-file analysis]",
    ]
    if prologue_block:
        sections.append("File prologue:\n" + prologue_block)

    suffix_sections = [
        f"END {marker.upper()} SNIPPET",
        "Analyze only the bounded snippet above. You are not a code completion model. "
        "Return exactly one JSON object and do not continue or rewrite the source code.",
    ]

    focus_parts: list[str] = []
    if grouped_focus_block:
        focus_parts.append("Candidate security hotspots:\n" + grouped_focus_block)
    if focus_block:
        focus_parts.append("Relevant windows:\n" + focus_block)
    focus_section = "\n\n".join(focus_parts).strip()
    prefix_text = "\n\n".join(section for section in sections if section)
    suffix_text = "\n\n".join(section for section in suffix_sections if section)

    if focus_section:
        compressed = "\n\n".join([prefix_text, focus_section, suffix_text])
    else:
        compressed = "\n\n".join([prefix_text, suffix_text])
    if len(compressed) <= max_chars:
        return compressed

    marker_text = "\n\n[... TRUNCATED FOR MODEL CONTEXT BUDGET ...]\n\n"
    available_focus_chars = max_chars - len(prefix_text) - len(suffix_text) - len(marker_text) - 4
    if available_focus_chars > 120 and focus_section:
        trimmed_focus = truncate_text_block(focus_section, available_focus_chars)
        return "\n\n".join([prefix_text, trimmed_focus, suffix_text])

    available_prefix_chars = max_chars - len(suffix_text) - len(marker_text) - 2
    if available_prefix_chars > 0:
        trimmed_prefix = truncate_text_block(prefix_text, available_prefix_chars)
        return "\n\n".join([trimmed_prefix, suffix_text])
    return truncate_text_block(compressed, max_chars)
