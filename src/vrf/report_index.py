from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class ReportIndexEntry:
    label: str
    path: Path
    required: bool = False


@dataclass(slots=True)
class ReportIndexSection:
    title: str
    description: str
    entries: list[ReportIndexEntry]


def load_report_index_manifest(manifest_path: str | Path, root: str | Path | None = None) -> list[ReportIndexSection]:
    manifest_file = Path(manifest_path)
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    base_root = Path(root) if root is not None else manifest_file.resolve().parents[2]
    sections: list[ReportIndexSection] = []
    for section in manifest.get("sections", []):
        entries = [
            ReportIndexEntry(
                label=entry["label"],
                path=base_root / entry["path"],
                required=bool(entry.get("required", False)),
            )
            for entry in section.get("entries", [])
        ]
        sections.append(
            ReportIndexSection(
                title=section["title"],
                description=section.get("description", ""),
                entries=entries,
            )
        )
    return sections


def build_report_index(sections: list[ReportIndexSection], root: str | Path | None = None) -> str:
    base_root = Path(root).resolve() if root is not None else None
    lines = [
        "# Results Index",
        "",
        "This index collects the most important reports, diagnostics, and benchmark summaries in the repository.",
        "",
    ]

    for section in sections:
        lines.append(f"## {section.title}")
        lines.append("")
        if section.description:
            lines.append(section.description)
            lines.append("")
        for entry in section.entries:
            exists = entry.path.exists()
            status = "" if exists else " (missing)"
            if base_root is not None:
                try:
                    relative_path = entry.path.resolve().relative_to(base_root)
                    rendered_path = relative_path.as_posix()
                except ValueError:
                    rendered_path = entry.path.as_posix()
            else:
                rendered_path = entry.path.as_posix()
            lines.append(f"- `{entry.label}`: `{rendered_path}`{status}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
