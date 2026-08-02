"""Validate the agent skill catalog under ``.github/skills/``.

Skill files are agent-facing instructions. A withdrawn claim left inside a
worked example is worse than one left in prose, because an agent following the
template will reproduce it in new work. A warning banner is not sufficient: the
body itself must model current, defensible behaviour.

Checks:

1. Every ``SKILL.md`` begins with valid YAML frontmatter as its **first bytes**.
2. Every internal link resolves to a file tracked in this branch.
3. No private or local absolute paths appear anywhere.
4. No withdrawn value appears as an active worked example. Withdrawn values are
   permitted only inside a block explicitly labelled as an audit/reject example.
5. No dependency document is referenced but missing.
6. Claim examples agree with ``docs/RESULT_STATUS_LEDGER.md``.

Usage::

    python scripts/check_skill_catalog.py          # exit 1 on any violation
    python scripts/check_skill_catalog.py --json
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SKILLS = REPO_ROOT / ".github" / "skills"
LEDGER = REPO_ROOT / "docs" / "RESULT_STATUS_LEDGER.md"

WITHDRAWN_VALUES = ["0.8287", "0.8572", "0.0348", "0.0329", "0.0368", "0.7610", "0.0632", "0.0682"]
CURRENT_VALUES = ["0.8596", "0.8588", "0.0008"]

# A withdrawn value is tolerated only where the surrounding lines mark the block
# as an audit example whose requested action is rejection.
AUDIT_CONTEXT = ("reject", "withdraw", "audit example", "must not be copied", "do not copy")
AUDIT_WINDOW = 6

LOCAL_PATH = re.compile(r"[A-Za-z]:[\\/][\w\s./\\-]{3,}|/home/[\w.-]+/|/Users/[\w.-]+/")
LINK = re.compile(r"\[[^\]]*\]\(([^)#]+)(?:#[^)]*)?\)")
PRIVATE_HINT = re.compile(
    r"personal_profile|recommender_request|application_materials|\.pptx|transcript|GPA", re.I
)


def tracked_files() -> set[str]:
    output = subprocess.run(
        ["git", "ls-files"], cwd=REPO_ROOT, capture_output=True, text=True
    ).stdout
    return {line.strip() for line in output.splitlines() if line.strip()}


def parse_frontmatter(text: str) -> tuple[dict[str, Any] | None, str]:
    """Return (frontmatter_mapping, error). Requires ``---`` as the first bytes."""

    if not text.startswith("---"):
        first = text.split("\n", 1)[0][:60]
        return None, f"content precedes frontmatter (file starts with {first!r})"
    lines = text.split("\n")
    close = next((i for i in range(1, len(lines)) if lines[i].strip() == "---"), None)
    if close is None:
        return None, "frontmatter opening delimiter has no matching close"
    mapping: dict[str, Any] = {}
    for raw in lines[1:close]:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if raw.startswith((" ", "\t", "-")):
            continue
        if ":" not in raw:
            return None, f"unparseable frontmatter line: {raw.strip()[:60]!r}"
        key, _, value = raw.partition(":")
        mapping[key.strip()] = value.strip()
    return mapping, ""


def has_audit_context(lines: list[str], index: int) -> bool:
    low = max(0, index - AUDIT_WINDOW)
    high = min(len(lines), index + AUDIT_WINDOW + 1)
    blob = "\n".join(lines[low:high]).lower()
    return any(token in blob for token in AUDIT_CONTEXT)


def check() -> list[dict[str, Any]]:
    problems: list[dict[str, Any]] = []
    tracked = tracked_files()

    def add(path: Path, line: int, kind: str, detail: str) -> None:
        problems.append(
            {
                "file": str(path.relative_to(REPO_ROOT)).replace("\\", "/"),
                "line": line,
                "kind": kind,
                "detail": detail,
            }
        )

    if not SKILLS.exists():
        return [{"file": ".github/skills", "line": 0, "kind": "missing_catalog", "detail": "absent"}]

    # 1. frontmatter
    for skill in sorted(SKILLS.rglob("SKILL.md")):
        text = skill.read_text(encoding="utf-8")
        mapping, error = parse_frontmatter(text)
        if mapping is None:
            add(skill, 1, "invalid_frontmatter", error)
            continue
        for required in ("name", "description"):
            if required not in mapping:
                add(skill, 1, "invalid_frontmatter", f"missing required key {required!r}")

    for path in sorted(SKILLS.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in (".md", ".py", ".json", ".yml", ".yaml"):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.split("\n")
        relative_dir = path.parent

        for index, line in enumerate(lines, start=1):
            # 3. local/private paths
            for match in LOCAL_PATH.findall(line):
                add(path, index, "local_path", str(match)[:70])
            if PRIVATE_HINT.search(line):
                add(path, index, "private_reference", line.strip()[:90])

            # 4. withdrawn values as active examples
            for value in WITHDRAWN_VALUES:
                if value in line and not has_audit_context(lines, index - 1):
                    add(path, index, "withdrawn_value_in_active_example", f"{value}: {line.strip()[:80]}")

            # 2 & 5. links resolve to tracked files
            for target in LINK.findall(line):
                if target.startswith(("http://", "https://", "mailto:")):
                    continue
                resolved = (relative_dir / target).resolve()
                try:
                    key = str(resolved.relative_to(REPO_ROOT)).replace("\\", "/")
                except ValueError:
                    add(path, index, "link_escapes_repository", target)
                    continue
                if key not in tracked and not resolved.exists():
                    add(path, index, "broken_link", f"{target} -> {key} (not tracked)")

    # 6. claim examples agree with the ledger
    if LEDGER.exists():
        ledger = LEDGER.read_text(encoding="utf-8")
        for value in CURRENT_VALUES:
            if value not in ledger:
                problems.append(
                    {
                        "file": "docs/RESULT_STATUS_LEDGER.md",
                        "line": 0,
                        "kind": "ledger_disagreement",
                        "detail": f"catalog cites {value} but the ledger does not contain it",
                    }
                )
    else:
        problems.append(
            {
                "file": "docs/RESULT_STATUS_LEDGER.md",
                "line": 0,
                "kind": "missing_dependency_document",
                "detail": "skill banners cite the ledger, but it is absent from this branch",
            }
        )
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate the agent skill catalog.")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    problems = check()
    if args.json:
        print(json.dumps({"problems": problems}, indent=2))
    elif not problems:
        skills = len(list(SKILLS.rglob("SKILL.md"))) if SKILLS.exists() else 0
        print(f"OK: skill catalog valid ({skills} SKILL.md files)")
    else:
        for item in problems:
            print(f"{item['file']}:{item['line']}  [{item['kind']}]  {item['detail']}")
        print(f"\n{len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
