from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any

from vrf.relational_benchmark import (
    CanonicalPair,
    CanonicalSide,
    render_pair,
    swap_pair,
    unified_diff,
)


NEUTRAL_PADDING = "\n".join(
    f"// non-security context line {index + 1}" for index in range(12)
)


def insert_after_instructions(text: str, content: str) -> str:
    marker = "\n\n"
    position = text.find(marker)
    if position < 0:
        return f"{content}\n\n{text}"
    position += len(marker)
    return f"{text[:position]}{content}\n\n{text[position:]}"


def insert_before_diff(text: str, content: str) -> str:
    marker = "Unified diff from Side A to Side B:\n"
    if marker not in text:
        raise ValueError("canonical diff marker missing")
    return text.replace(marker, f"{content}\n\n{marker}", 1)


def insert_mid_diff(text: str, content: str) -> str:
    lines = text.splitlines()
    hunk_seen = False
    for index, line in enumerate(lines):
        if line.startswith("@@"):
            hunk_seen = True
            continue
        if hunk_seen and line.startswith(" "):
            lines[index + 1 : index + 1] = ["", content, ""]
            return "\n".join(lines) + "\n"
    midpoint = max(1, len(lines) // 2)
    lines[midpoint:midpoint] = ["", content, ""]
    return "\n".join(lines) + "\n"


def training_prompt(pair: CanonicalPair) -> str:
    return (
        "Task: compare two versions of the same code change.\n"
        "The unified diff transforms Side A into Side B.\n"
        "Predict which side contains the security vulnerability.\n\n"
        f"{unified_diff(pair)}\n"
    )


def padding_variants(base_text: str) -> dict[str, str]:
    suffix = f"{base_text.rstrip()}\n\n{NEUTRAL_PADDING}\n"
    return {
        "padding_prompt_prefix": f"{NEUTRAL_PADDING}\n\n{base_text}",
        "padding_after_instructions": insert_after_instructions(
            base_text, NEUTRAL_PADDING
        ),
        "padding_pre_diff": insert_before_diff(base_text, NEUTRAL_PADDING),
        "padding_mid_diff": insert_mid_diff(base_text, NEUTRAL_PADDING),
        "padding_post_diff": suffix,
        "padding_post_diff_restored_ending": (
            f"{suffix}\nUnified diff complete.\n"
        ),
        "padding_post_diff_end_patch": f"{suffix}\n[END_PATCH]\n",
    }


def expand_c_like_separators(code: str) -> str:
    expanded = re.sub(r"([{};])", r"\1\n", code)
    lines = [line.strip() for line in expanded.splitlines() if line.strip()]
    return "\n".join(lines) + ("\n" if lines else "")


def clang_format_code(code: str, *, executable: Path) -> str:
    result = subprocess.run(
        [str(executable), "--style=LLVM", "--assume-filename=input.cc"],
        input=code,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return expand_c_like_separators(code)
    return result.stdout


def transform_pair_code(
    pair: CanonicalPair,
    transform,
) -> CanonicalPair:
    return CanonicalPair(
        dataset=pair.dataset,
        pair_key=pair.pair_key,
        project=pair.project,
        language=pair.language,
        cwe=pair.cwe,
        cve=pair.cve,
        year=pair.year,
        side_a=CanonicalSide(
            id=pair.side_a.id,
            code=transform(pair.side_a.code),
            vulnerable=pair.side_a.vulnerable,
        ),
        side_b=CanonicalSide(
            id=pair.side_b.id,
            code=transform(pair.side_b.code),
            vulnerable=pair.side_b.vulnerable,
        ),
    )


def audit_row(
    base: dict[str, Any],
    *,
    variant: str,
    family: str,
    text: str,
    expected_relation: str = "invariant",
    gold_side: str | None = None,
) -> dict[str, Any]:
    return {
        "id": f"audit::{base['dataset']}::{base['pair_key']}::{variant}",
        "base_id": f"audit::{base['dataset']}::{base['pair_key']}::canonical",
        "cluster_id": base["cluster_id"],
        "pair_key": base["pair_key"],
        "dataset": base["dataset"],
        "sampling_suite": "representative",
        "audit_family": family,
        "audit_variant": variant,
        "transformation_family": family,
        "transformation_template": variant,
        "expected_relation": expected_relation,
        "gold_riskier_side": gold_side or base["gold_riskier_side"],
        "runtime_transform": {},
        "text": text,
    }
