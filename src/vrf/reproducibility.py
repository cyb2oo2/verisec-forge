from __future__ import annotations

import hashlib
import json
import shutil
import urllib.request
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


def safe_repo_output_path(path: str | Path, repo_root: str | Path) -> Path:
    raw_path = Path(path)
    if raw_path.is_absolute():
        raise ValueError(f"bundle artifact path must be relative: {path}")
    output_path = (Path(repo_root) / raw_path).resolve()
    root = Path(repo_root).resolve()
    try:
        output_path.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"bundle artifact path escapes repo root: {path}") from exc
    return output_path


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


def verify_bundle_file(
    bundle_path: str | Path,
    *,
    expected_sha256: str | None = None,
    expected_bytes: int | None = None,
) -> dict[str, Any]:
    bundle = Path(bundle_path)
    if not bundle.exists():
        return {
            "status": "failed",
            "path": str(bundle),
            "message": "bundle file does not exist",
        }

    actual_bytes = bundle.stat().st_size
    actual_sha = sha256_file(bundle)
    mismatches: list[str] = []
    if expected_sha256 and actual_sha != expected_sha256:
        mismatches.append("sha256")
    if expected_bytes is not None and actual_bytes != expected_bytes:
        mismatches.append("bytes")

    return {
        "status": "mismatch" if mismatches else "ok",
        "path": str(bundle),
        "expected_sha256": expected_sha256,
        "actual_sha256": actual_sha,
        "expected_bytes": expected_bytes,
        "actual_bytes": actual_bytes,
        "message": ", ".join(mismatches) if mismatches else None,
    }


def download_bundle_file(
    source: str,
    *,
    output_path: str | Path,
    expected_sha256: str | None = None,
    expected_bytes: int | None = None,
) -> dict[str, Any]:
    output = ensure_parent(output_path)
    if source.startswith(("http://", "https://", "file://")):
        with urllib.request.urlopen(source) as response, output.open("wb") as handle:
            shutil.copyfileobj(response, handle)
    else:
        source_path = Path(source)
        if not source_path.exists():
            return {
                "status": "failed",
                "source": source,
                "output_path": str(output),
                "message": "source path does not exist",
            }
        shutil.copyfile(source_path, output)

    verification = verify_bundle_file(
        output,
        expected_sha256=expected_sha256,
        expected_bytes=expected_bytes,
    )
    return {
        "status": "ok" if verification["status"] == "ok" else "failed",
        "source": source,
        "output_path": str(output),
        "verification": verification,
    }


def load_bundle_release_metadata(path: str | Path, repo_root: str | Path) -> dict[str, Any]:
    metadata = read_json(resolve_repo_path(path, repo_root))
    bundles = metadata.get("bundles", [])
    if not bundles:
        raise ValueError("release metadata must contain at least one bundle entry")
    bundle = bundles[0]
    return {
        "name": bundle.get("name", metadata.get("name", "reproducibility_bundle")),
        "url": bundle.get("url"),
        "filename": bundle.get("filename"),
        "sha256": bundle.get("sha256"),
        "bytes": bundle.get("bytes"),
        "status": metadata.get("status", "unknown"),
        "metadata": metadata,
    }


def _bundle_check_to_artifact(check: dict[str, Any]) -> dict[str, Any]:
    return {
        "path": check["path"],
        "role": check.get("role", "artifact"),
        "sha256": check.get("expected_sha256"),
        "bytes": check.get("expected_bytes"),
        "rows": check.get("expected_rows"),
        "_manifest_relpath": check.get("source_manifest"),
    }


def restore_artifact_bundle(
    bundle_path: str | Path,
    *,
    repo_root: str | Path,
    overwrite: bool = False,
    check_only: bool = False,
) -> dict[str, Any]:
    bundle = Path(bundle_path)
    if not bundle.exists():
        return {
            "status": "failed",
            "bundle_path": str(bundle),
            "message": "bundle path does not exist",
        }

    actions: list[dict[str, Any]] = []
    with zipfile.ZipFile(bundle) as archive:
        names = set(archive.namelist())
        if "BUNDLE_MANIFEST.json" not in names:
            return {
                "status": "failed",
                "bundle_path": str(bundle),
                "message": "BUNDLE_MANIFEST.json is missing from bundle",
            }

        bundle_manifest = json.loads(archive.read("BUNDLE_MANIFEST.json"))
        artifacts = [
            _bundle_check_to_artifact(check)
            for check in bundle_manifest.get("artifacts", [])
        ]
        for artifact in artifacts:
            rel_path = artifact["path"].replace("\\", "/")
            if rel_path not in names:
                actions.append(
                    {
                        "path": rel_path,
                        "action": "missing_in_bundle",
                        "status": "failed",
                    }
                )
                continue

            target = safe_repo_output_path(rel_path, repo_root)
            existing_check = validate_artifact(artifact, repo_root=repo_root)
            if target.exists() and not overwrite:
                actions.append(
                    {
                        "path": rel_path,
                        "action": "keep_existing" if existing_check.ok else "blocked_existing_mismatch",
                        "status": "ok" if existing_check.ok else "failed",
                    }
                )
                continue

            if check_only:
                actions.append(
                    {
                        "path": rel_path,
                        "action": "would_extract",
                        "status": "ok",
                    }
                )
                continue

            ensure_parent(target)
            with archive.open(rel_path, "r") as source, target.open("wb") as output:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    output.write(chunk)
            actions.append({"path": rel_path, "action": "extracted", "status": "ok"})

    validation_checks = [
        validate_artifact(artifact, repo_root=repo_root).to_dict()
        for artifact in artifacts
    ]
    action_ok = all(action["status"] == "ok" for action in actions)
    validation_ok = all(check["status"] == "ok" for check in validation_checks)
    return {
        "status": "ok" if action_ok and validation_ok else "failed",
        "bundle_path": str(bundle),
        "overwrite": overwrite,
        "check_only": check_only,
        "artifact_count": len(artifacts),
        "actions": actions,
        "validation": validation_checks,
    }
