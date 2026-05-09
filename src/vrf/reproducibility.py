from __future__ import annotations

import hashlib
import json
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

from vrf.io_utils import ensure_parent, read_json


@dataclass(frozen=True)
class ArtifactCheck:
    path: str
    role: str
    status: str
    expected_sha256: str | None = None
    actual_sha256: str | None = None
    expected_bytes: int | None = None
    actual_bytes: int | None = None
    expected_rows: int | None = None
    actual_rows: int | None = None
    source_manifest: str | None = None
    message: str | None = None

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "role": self.role,
            "status": self.status,
            "expected_sha256": self.expected_sha256,
            "actual_sha256": self.actual_sha256,
            "expected_bytes": self.expected_bytes,
            "actual_bytes": self.actual_bytes,
            "expected_rows": self.expected_rows,
            "actual_rows": self.actual_rows,
            "source_manifest": self.source_manifest,
            "message": self.message,
        }


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def count_jsonl_rows(path: str | Path) -> int:
    rows = 0
    with Path(path).open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows += 1
    return rows


def load_manifest(path: str | Path, repo_root: str | Path) -> dict[str, Any]:
    manifest_path = resolve_repo_path(path, repo_root)
    manifest = read_json(manifest_path)
    manifest["_manifest_path"] = str(manifest_path)
    manifest["_manifest_relpath"] = repo_relative_path(manifest_path, repo_root)
    return manifest


def resolve_repo_path(path: str | Path, repo_root: str | Path) -> Path:
    raw_path = Path(path)
    if raw_path.is_absolute() or raw_path.exists():
        return raw_path
    return Path(repo_root) / raw_path


def repo_relative_path(path: str | Path, repo_root: str | Path) -> str:
    try:
        return Path(path).resolve().relative_to(Path(repo_root).resolve()).as_posix()
    except ValueError:
        return Path(path).as_posix()


def iter_manifest_artifacts(
    manifest: dict[str, Any],
    *,
    include_generated: bool = False,
) -> Iterable[dict[str, Any]]:
    for artifact in manifest.get("artifacts", []):
        yield {**artifact, "_manifest_relpath": manifest.get("_manifest_relpath")}
    if include_generated:
        for artifact in manifest.get("generated_artifacts", []):
            yield {**artifact, "_manifest_relpath": manifest.get("_manifest_relpath")}


def validate_artifact(
    artifact: dict[str, Any],
    *,
    repo_root: str | Path,
) -> ArtifactCheck:
    rel_path = artifact["path"]
    path = resolve_repo_path(rel_path, repo_root)
    role = artifact.get("role", "artifact")
    expected_sha = artifact.get("sha256")
    expected_bytes = artifact.get("bytes")
    expected_rows = artifact.get("rows")
    source_manifest = artifact.get("_manifest_relpath")

    if not path.exists():
        return ArtifactCheck(
            path=rel_path,
            role=role,
            status="missing",
            expected_sha256=expected_sha,
            expected_bytes=expected_bytes,
            expected_rows=expected_rows,
            source_manifest=source_manifest,
            message="artifact path does not exist",
        )

    actual_bytes = path.stat().st_size
    actual_sha = sha256_file(path)
    actual_rows = count_jsonl_rows(path) if path.suffix == ".jsonl" else None

    mismatches: list[str] = []
    if expected_sha and actual_sha != expected_sha:
        mismatches.append("sha256")
    if expected_bytes is not None and actual_bytes != expected_bytes:
        mismatches.append("bytes")
    if expected_rows is not None and actual_rows != expected_rows:
        mismatches.append("rows")

    return ArtifactCheck(
        path=rel_path,
        role=role,
        status="mismatch" if mismatches else "ok",
        expected_sha256=expected_sha,
        actual_sha256=actual_sha,
        expected_bytes=expected_bytes,
        actual_bytes=actual_bytes,
        expected_rows=expected_rows,
        actual_rows=actual_rows,
        source_manifest=source_manifest,
        message=", ".join(mismatches) if mismatches else None,
    )


def validate_manifests(
    manifest_paths: Iterable[str | Path],
    *,
    repo_root: str | Path,
    include_generated: bool = False,
) -> dict[str, Any]:
    manifests = [load_manifest(path, repo_root) for path in manifest_paths]
    checks: list[ArtifactCheck] = []
    for manifest in manifests:
        for artifact in iter_manifest_artifacts(
            manifest,
            include_generated=include_generated,
        ):
            checks.append(validate_artifact(artifact, repo_root=repo_root))

    return {
        "status": "ok" if all(check.ok for check in checks) else "failed",
        "include_generated": include_generated,
        "manifest_count": len(manifests),
        "artifact_count": len(checks),
        "checks": [check.to_dict() for check in checks],
    }


def build_artifact_bundle(
    manifest_paths: Iterable[str | Path],
    *,
    output_path: str | Path,
    repo_root: str | Path,
    include_generated: bool = False,
) -> dict[str, Any]:
    manifest_paths = list(manifest_paths)
    validation = validate_manifests(
        manifest_paths,
        repo_root=repo_root,
        include_generated=include_generated,
    )
    if validation["status"] != "ok":
        return {
            "status": "failed",
            "output_path": str(output_path),
            "validation": validation,
            "message": "bundle was not created because at least one artifact failed validation",
        }

    output = ensure_parent(output_path)
    created_utc = datetime.now(UTC).replace(microsecond=0).isoformat()
    bundle_manifest = {
        "name": "verisec_forge_reproducibility_bundle",
        "created_utc": created_utc,
        "include_generated": include_generated,
        "source_manifests": [str(path).replace("\\", "/") for path in manifest_paths],
        "artifact_count": validation["artifact_count"],
        "artifacts": validation["checks"],
    }

    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "BUNDLE_MANIFEST.json",
            json.dumps(bundle_manifest, indent=2, ensure_ascii=False),
        )
        for check in validation["checks"]:
            artifact_path = resolve_repo_path(check["path"], repo_root)
            archive.write(artifact_path, arcname=check["path"].replace("\\", "/"))

    return {
        "status": "ok",
        "output_path": str(output),
        "output_bytes": output.stat().st_size,
        "output_sha256": sha256_file(output),
        "artifact_count": validation["artifact_count"],
        "include_generated": include_generated,
        "bundle_manifest": bundle_manifest,
    }
