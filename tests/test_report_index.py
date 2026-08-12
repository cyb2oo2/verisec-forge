from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

from vrf.report_index import (
    build_report_index,
    load_report_index_manifest,
    load_report_index_preamble,
)


ROOT = Path(__file__).resolve().parents[1]


def test_report_index_builds_from_manifest() -> None:
    tmp_path = Path(".tmp_test_runs") / f"report-index-{uuid4().hex}"
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "reports").mkdir()

    report_path = tmp_path / "reports" / "demo.md"
    report_path.write_text("# Demo\n", encoding="utf-8")

    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "sections": [
                    {
                        "title": "Demo Section",
                        "description": "Useful reports.",
                        "entries": [
                            {"label": "Demo Report", "path": "reports/demo.md", "required": True},
                            {"label": "Missing Report", "path": "reports/missing.md", "required": False},
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    sections = load_report_index_manifest(manifest_path, tmp_path)
    rendered = build_report_index(sections, tmp_path)

    assert "## Demo Section" in rendered
    assert "`Demo Report`: `reports/demo.md`" in rendered
    assert "`Missing Report`: `reports/missing.md` (missing)" in rendered


def test_checked_in_report_index_matches_complete_manifest() -> None:
    sections = load_report_index_manifest(ROOT / "configs/report_index.json", ROOT)
    preamble = load_report_index_preamble(ROOT / "configs/report_index.json")
    expected = build_report_index(sections, ROOT, preamble=preamble)
    actual = (ROOT / "reports/RESULTS_INDEX.md").read_text(encoding="utf-8")

    assert actual == expected
