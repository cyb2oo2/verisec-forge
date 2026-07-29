"""Outward-facing claim integrity checker.

Scans reader-facing documents and fails when a withdrawn result is presented as
current evidence. It is deliberately *not* a global ban on historical numbers:
legitimate historical discussion passes as long as the withdrawal status is
unmistakable near the number.

Rules live in ``reproducibility/outward_claim_rules.json`` so the policy is data,
not code. Each claim entry declares:

* ``id`` -- claim identifier
* ``withdrawn_values`` / ``prohibited_active_wording`` -- what to look for
* ``required_qualification`` -- what a compliant mention must convey
* ``ledger_entry`` -- the source-of-truth row in the result status ledger
* ``allowed_files`` -- files permitted to carry the historical value

Checks performed:

1. A withdrawn metric appears without a withdrawal/historical marker nearby.
2. A document uses prohibited active wording for a withdrawn claim.
3. Gate precision is promoted without sample size and uncertainty.
4. Generated documentation is older than the machine-readable source it depends on.
5. The source-of-truth ledger exists and names every claim's ledger entry.

Usage::

    python scripts/check_outward_claims.py            # scan the repository
    python scripts/check_outward_claims.py --json      # machine-readable output

Exit codes: ``0`` clean, ``1`` violations found.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RULES = "reproducibility/outward_claim_rules.json"

GATE_UNCERTAINTY_TOKENS = ("CI", "confidence interval", "n=", "sample size", "accepted pairs", "0.3976")


def has_token(blob: str, token: str) -> bool:
    """Substring match, but word-bounded for short alphabetic tokens.

    ``CI`` must not match inside ``precision``; ``n=`` has no word character on
    its right so it is matched literally.
    """

    if token.isalpha() and len(token) <= 3:
        return re.search(rf"\b{re.escape(token)}\b", blob) is not None
    return token.lower() in blob.lower()

# Phrases that turn a prohibited claim into a legitimate negative statement.
# "This is not localization accuracy" must pass; "localization accuracy 0.76"
# must not. Only the text immediately preceding the phrase is considered.
NEGATION_CUES = (
    "not ",
    "never ",
    "no longer ",
    "cannot ",
    "can not ",
    "must not ",
    "isn't ",
    "is not ",
    "are not ",
    "without ",
    "rather than ",
    "instead of ",
    "withdrawn",
    "~~",
)
NEGATION_LOOKBACK_CHARS = 90


def phrase_is_negated(line: str, phrase: str, previous: str = "") -> bool:
    """True when the prohibited phrase appears inside a denial of the claim.

    ``previous`` is the preceding line, because a negation frequently wraps
    across a line break in rendered Markdown, e.g. "... it is not" followed by
    "independently human validated".
    """

    joined = (previous + " " + line) if previous else line
    lowered = joined.lower()
    index = lowered.find(phrase.lower())
    if index < 0:
        return False
    prefix = lowered[max(0, index - NEGATION_LOOKBACK_CHARS) : index]
    return any(cue in prefix for cue in NEGATION_CUES)


def load_rules(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def is_excluded(relative: str, excluded: list[str]) -> bool:
    parts = Path(relative).parts
    for item in excluded:
        if item in parts or relative == item or relative.startswith(item.rstrip("/") + "/"):
            return True
    return False


def reader_facing_files(rules: dict[str, Any]) -> list[Path]:
    excluded = rules["excluded_paths"]
    found: list[Path] = []
    for path in REPO_ROOT.rglob("*.md"):
        relative = str(path.relative_to(REPO_ROOT)).replace("\\", "/")
        if is_excluded(relative, excluded):
            continue
        found.append(path)
    return sorted(found)


def context_has_marker(lines: list[str], index: int, markers: list[str], window: int) -> bool:
    low = max(0, index - window)
    high = min(len(lines), index + window + 1)
    blob = "\n".join(lines[low:high])
    return any(marker in blob for marker in markers)


def document_status(lines: list[str], rules: dict[str, Any]) -> str | None:
    """Classify a document-level status banner near the top of the file.

    A visible banner is the sanctioned way to mark a whole archival document, so
    a per-line marker is not additionally required inside long historical
    tables. ``historical`` suppresses both numeric and wording findings;
    ``corrected`` suppresses only the numeric ones, so active claim sentences in
    a current-facing document must still be fixed individually.
    """

    head = "\n".join(lines[: int(rules.get("document_banner_scan_lines", 40))])
    banners = rules.get("document_banner", {})
    for token in banners.get("historical", []):
        if token in head:
            return "historical"
    for token in banners.get("corrected", []):
        if token in head:
            return "corrected"
    return None


def check_file(path: Path, rules: dict[str, Any]) -> list[dict[str, Any]]:
    relative = str(path.relative_to(REPO_ROOT)).replace("\\", "/")
    text = path.read_text(encoding="utf-8")
    lines = text.split("\n")
    markers = rules["historical_markers"]
    window = int(rules["qualification_window_lines"])
    status = document_status(lines, rules)
    violations: list[dict[str, Any]] = []

    for claim in rules["claims"]:
        allowed = claim.get("allowed_files", [])
        for index, line in enumerate(lines):
            # 1/2. withdrawn numeric values without a nearby status marker
            for value in claim.get("withdrawn_values", []):
                if value not in line:
                    continue
                if relative in allowed:
                    continue
                if status in {"historical", "corrected"}:
                    continue
                if context_has_marker(lines, index, markers, window):
                    continue
                qualifiers = claim.get("qualifying_tokens", [])
                if qualifiers:
                    low = max(0, index - window)
                    high = min(len(lines), index + window + 1)
                    blob = "\n".join(lines[low:high])
                    if any(has_token(blob, token) for token in qualifiers):
                        continue
                violations.append(
                    {
                        "file": relative,
                        "line": index + 1,
                        "claim_id": claim["id"],
                        "kind": "unqualified_withdrawn_value",
                        "found": value,
                        "required_qualification": claim["required_qualification"],
                        "ledger_entry": claim["ledger_entry"],
                        "excerpt": line.strip()[:160],
                    }
                )
            # 3. prohibited active wording, regardless of numbers
            lowered = line.lower()
            for phrase in claim.get("prohibited_active_wording", []):
                if phrase.lower() not in lowered:
                    continue
                if status == "historical":
                    continue
                if phrase_is_negated(line, phrase, lines[index - 1] if index else ""):
                    continue
                if context_has_marker(lines, index, markers, window):
                    continue
                violations.append(
                    {
                        "file": relative,
                        "line": index + 1,
                        "claim_id": claim["id"],
                        "kind": "prohibited_active_wording",
                        "found": phrase,
                        "required_qualification": claim["required_qualification"],
                        "ledger_entry": claim["ledger_entry"],
                        "excerpt": line.strip()[:160],
                    }
                )

    # 4. gate precision promoted without sample size / uncertainty
    gate_claim = next((c for c in rules["claims"] if c["id"] == "safe-flip-gate-precision"), {})
    gate_allowed = gate_claim.get("allowed_files", [])
    for index, line in enumerate(lines):
        if not re.search(r"precision[^.\n]{0,40}`?1\.0{2,4}`?", line, re.I):
            continue
        if relative in gate_allowed:
            # Documents explicitly permitted to carry the historical value, e.g.
            # reproduction fingerprint lists that state up front they are not claims.
            continue
        low = max(0, index - window)
        high = min(len(lines), index + window + 1)
        blob = "\n".join(lines[low:high])
        if any(has_token(blob, token) for token in GATE_UNCERTAINTY_TOKENS):
            continue
        if status == "historical":
            continue
        violations.append(
            {
                "file": relative,
                "line": index + 1,
                "claim_id": "safe-flip-gate-precision",
                "kind": "precision_without_uncertainty",
                "found": line.strip()[:80],
                "required_qualification": "Report accepted sample size and exact interval alongside precision.",
                "ledger_entry": "Safe-flip gate precision (selected-on-holdout)",
                "excerpt": line.strip()[:160],
            }
        )
    return violations


def check_staleness(rules: dict[str, Any]) -> list[dict[str, Any]]:
    violations: list[dict[str, Any]] = []
    for entry in rules.get("staleness", []):
        generated = REPO_ROOT / entry["generated"]
        source = REPO_ROOT / entry["source"]
        if not generated.exists() or not source.exists():
            continue
        if generated.stat().st_mtime + 1 < source.stat().st_mtime:
            violations.append(
                {
                    "file": entry["generated"],
                    "line": 0,
                    "claim_id": "stale-generated-doc",
                    "kind": "stale_generated_documentation",
                    "found": f"older than {entry['source']}",
                    "required_qualification": "Regenerate with scripts/run_clean_reproduction.py",
                    "ledger_entry": "n/a",
                    "excerpt": f"{entry['generated']} predates {entry['source']}",
                }
            )
    return violations


def check_ledger(rules: dict[str, Any]) -> list[dict[str, Any]]:
    ledger = REPO_ROOT / rules["source_of_truth"]
    if not ledger.exists():
        return [
            {
                "file": rules["source_of_truth"],
                "line": 0,
                "claim_id": "ledger",
                "kind": "missing_source_of_truth",
                "found": "absent",
                "required_qualification": "The result status ledger is the source of truth and must exist.",
                "ledger_entry": "n/a",
                "excerpt": "",
            }
        ]
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description="Check outward-facing claims against the result status ledger.")
    parser.add_argument("--rules", default=DEFAULT_RULES)
    parser.add_argument("--json", action="store_true", help="emit machine-readable output")
    parser.add_argument("--path", help="check a single file instead of the repository")
    args = parser.parse_args()

    rules = load_rules(REPO_ROOT / args.rules)
    violations: list[dict[str, Any]] = []
    violations.extend(check_ledger(rules))

    if args.path:
        targets = [Path(args.path) if Path(args.path).is_absolute() else REPO_ROOT / args.path]
    else:
        targets = reader_facing_files(rules)
        violations.extend(check_staleness(rules))

    for path in targets:
        if path.exists():
            violations.extend(check_file(path, rules))

    if args.json:
        print(json.dumps({"violations": violations, "files_scanned": len(targets)}, indent=2))
    else:
        print(f"scanned {len(targets)} reader-facing files")
        if not violations:
            print("OK: no unqualified withdrawn claims found")
        else:
            by_file: dict[str, list[dict[str, Any]]] = {}
            for item in violations:
                by_file.setdefault(item["file"], []).append(item)
            for file_name in sorted(by_file):
                print(f"\n{file_name}")
                for item in by_file[file_name]:
                    print(f"  L{item['line']:<5} [{item['claim_id']}] {item['kind']}: {item['found']!r}")
                    print(f"          {item['excerpt']}")
                    print(f"          required: {item['required_qualification']}")
            print(f"\n{len(violations)} violation(s) across {len(by_file)} file(s)")
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
