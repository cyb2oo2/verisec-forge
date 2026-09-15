"""Check current navigation, retirement boundaries and retained evidence bytes."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
REVIEW = "reports/scientific_review_2026_09_07/REVIEW.md"


def check_hygiene(root: Path = ROOT) -> list[str]:
    errors = []
    ledger = json.loads((root / "reports/scientific_review_2026_09_07/cleanup_manifest.json").read_text(encoding="utf-8-sig"))
    for item in ledger["removed_files"]:
        if (root / item["path"]).exists():
            errors.append(f"Retired file resurfaced: {item['path']}")
    index = json.loads((root / "configs/report_index.json").read_text(encoding="utf-8"))
    active = {"README.md", "REPRODUCIBILITY.md", "data/README.md", "paper/README.md", "reproducibility/README.md", REVIEW}
    for section in index["sections"]:
        for entry in section["entries"]:
            if entry.get("required") and not (root / entry["path"]).is_file():
                errors.append(f"Missing index target: {entry['path']}")
            if entry["path"].endswith(".md"):
                active.add(entry["path"])
    for relative in sorted(active):
        path = root / relative
        if not path.is_file():
            errors.append(f"Missing active document: {relative}")
            continue
        for match in re.finditer(r"\]\(([^\s)]+)\)", path.read_text(encoding="utf-8")):
            target = unquote(match.group(1).split("#", 1)[0])
            if not target or re.match(r"[a-zA-Z][a-zA-Z0-9+.-]*:", target):
                continue
            if not (path.parent / target).exists():
                errors.append(f"Broken link in {relative}: {target}")
    inventory = json.loads((root / "reports/evidence_inventory.json").read_text(encoding="utf-8"))
    for item in inventory["artifacts"]:
        path = root / item["path"]
        if not path.is_file():
            errors.append(f"Missing historical evidence: {item['path']}")
        elif hashlib.sha256(path.read_bytes()).hexdigest() not in {
            item["sha256"], item.get("git_blob_sha256", item["sha256"])
        }:
            errors.append(f"Historical evidence bytes changed: {item['path']}")
    return errors


if __name__ == "__main__":
    errors = check_hygiene()
    print(json.dumps({"status": "failed" if errors else "ok", "errors": errors}, indent=2))
    raise SystemExit(bool(errors))
