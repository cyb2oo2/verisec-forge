"""Fail-loud guards for scientific input artifacts.

Research result builders must never substitute remembered numbers for absent
inputs. A missing artifact is a hard error that names the artifact, says how it
is produced or obtained, and exits non-zero.

Usage::

    from vrf.artifact_guard import require_artifact

    require_artifact(
        "reports/foo_threshold_sweep.json",
        produced_by="scripts/evaluate_foo.py --sweep",
        obtain="scripts/download_reproducibility_bundle.py --bundle-name foo --restore",
    )
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parents[2]


class MissingResearchArtifact(FileNotFoundError):
    """Raised when a scientific input artifact is absent.

    Deliberately a ``FileNotFoundError`` subclass so that any pre-existing
    ``except FileNotFoundError`` handler still sees it -- but the message
    carries the remediation path, and result builders are expected to let it
    propagate rather than swallow it.
    """

    def __init__(self, path: str, *, produced_by: str | None, obtain: str | None, purpose: str | None = None) -> None:
        lines = [f"Missing research artifact: {path}"]
        if purpose:
            lines.append(f"  needed for: {purpose}")
        if produced_by:
            lines.append(f"  produced by: {produced_by}")
        if obtain:
            lines.append(f"  or obtain with: {obtain}")
        lines.append(
            "  This build refuses to emit a result without its input. "
            "Historical values are never substituted."
        )
        super().__init__("\n".join(lines))
        self.path = path


def require_artifact(
    path: str | Path,
    *,
    produced_by: str | None = None,
    obtain: str | None = None,
    purpose: str | None = None,
) -> Path:
    """Return ``path`` as an absolute :class:`Path`, or raise if it is absent."""

    candidate = Path(path)
    resolved = candidate if candidate.is_absolute() else REPO_ROOT / candidate
    if not resolved.exists():
        raise MissingResearchArtifact(
            str(candidate), produced_by=produced_by, obtain=obtain, purpose=purpose
        )
    return resolved


def require_all(
    paths: Iterable[str | Path],
    *,
    produced_by: str | None = None,
    obtain: str | None = None,
    purpose: str | None = None,
) -> list[Path]:
    return [
        require_artifact(path, produced_by=produced_by, obtain=obtain, purpose=purpose)
        for path in paths
    ]
