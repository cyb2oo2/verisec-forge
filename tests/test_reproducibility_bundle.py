from __future__ import annotations

import json
import shutil
import zipfile
from pathlib import Path

from vrf.io_utils import write_json, write_jsonl
from vrf.reproducibility import (
    build_artifact_bundle,
    download_bundle_file,
    load_bundle_release_metadata,
    restore_artifact_bundle,
    sha256_file,
    validate_manifests,
)


TMP_ROOT = Path(".tmp_test_runs/reproducibility_bundle")


def setup_function() -> None:
    if TMP_ROOT.exists():
        shutil.rmtree(TMP_ROOT)
    TMP_ROOT.mkdir(parents=True)


def teardown_function() -> None:
    if TMP_ROOT.exists():
        shutil.rmtree(TMP_ROOT)


def _write_demo_manifest(repo_root: Path) -> Path:
    artifact_path = repo_root / "data" / "demo.jsonl"
    rows = [{"id": "a", "label": 1}, {"id": "b", "label": 0}]
    write_jsonl(artifact_path, rows)
    manifest_path = repo_root / "reproducibility" / "demo_manifest.json"
    write_json(
        manifest_path,
        {
            "name": "demo",
            "artifacts": [
                {
                    "role": "dataset",
                    "path": "data/demo.jsonl",
                    "sha256": sha256_file(artifact_path),
                    "bytes": artifact_path.stat().st_size,
                    "rows": len(rows),
                }
            ],
        },
    )
    return manifest_path


def test_validate_manifest_artifacts_ok() -> None:
    manifest_path = _write_demo_manifest(TMP_ROOT)

    payload = validate_manifests([manifest_path], repo_root=TMP_ROOT)

    assert payload["status"] == "ok"
    assert payload["artifact_count"] == 1
    assert payload["checks"][0]["actual_rows"] == 2
    assert payload["checks"][0]["status"] == "ok"


def test_validate_manifest_artifacts_reports_missing_file() -> None:
    manifest_path = TMP_ROOT / "reproducibility" / "demo_manifest.json"
    write_json(
        manifest_path,
        {
            "name": "demo",
            "artifacts": [
                {
                    "role": "dataset",
                    "path": "data/missing.jsonl",
                    "sha256": "abc",
                    "bytes": 10,
                    "rows": 1,
                }
            ],
        },
    )

    payload = validate_manifests([manifest_path], repo_root=TMP_ROOT)

    assert payload["status"] == "failed"
    assert payload["checks"][0]["status"] == "missing"


def test_build_artifact_bundle_writes_zip_manifest_and_files() -> None:
    manifest_path = _write_demo_manifest(TMP_ROOT)
    output_path = TMP_ROOT / "artifacts" / "demo_bundle.zip"

    payload = build_artifact_bundle(
        [manifest_path],
        output_path=output_path,
        repo_root=TMP_ROOT,
    )

    assert payload["status"] == "ok"
    assert output_path.exists()
    with zipfile.ZipFile(output_path) as archive:
        names = set(archive.namelist())
        assert "BUNDLE_MANIFEST.json" in names
        assert "data/demo.jsonl" in names
        bundle_manifest = json.loads(archive.read("BUNDLE_MANIFEST.json"))
    assert bundle_manifest["artifact_count"] == 1
    assert bundle_manifest["artifacts"][0]["path"] == "data/demo.jsonl"


def test_restore_artifact_bundle_extracts_and_validates_files() -> None:
    source_root = TMP_ROOT / "source"
    restore_root = TMP_ROOT / "restore"
    source_root.mkdir()
    restore_root.mkdir()
    manifest_path = _write_demo_manifest(source_root)
    output_path = TMP_ROOT / "artifacts" / "demo_bundle.zip"
    build_payload = build_artifact_bundle(
        [manifest_path],
        output_path=output_path,
        repo_root=source_root,
    )
    assert build_payload["status"] == "ok"

    payload = restore_artifact_bundle(output_path, repo_root=restore_root)

    assert payload["status"] == "ok"
    assert payload["actions"][0]["action"] == "extracted"
    assert (restore_root / "data" / "demo.jsonl").exists()
    assert payload["validation"][0]["status"] == "ok"


def test_restore_artifact_bundle_blocks_mismatching_existing_file() -> None:
    source_root = TMP_ROOT / "source"
    restore_root = TMP_ROOT / "restore"
    source_root.mkdir()
    restore_root.mkdir()
    manifest_path = _write_demo_manifest(source_root)
    output_path = TMP_ROOT / "artifacts" / "demo_bundle.zip"
    build_artifact_bundle([manifest_path], output_path=output_path, repo_root=source_root)
    write_jsonl(restore_root / "data" / "demo.jsonl", [{"id": "wrong"}])

    payload = restore_artifact_bundle(output_path, repo_root=restore_root)

    assert payload["status"] == "failed"
    assert payload["actions"][0]["action"] == "blocked_existing_mismatch"


def test_download_bundle_file_copies_and_verifies_local_source() -> None:
    source_root = TMP_ROOT / "source"
    source_root.mkdir()
    manifest_path = _write_demo_manifest(source_root)
    source_bundle = TMP_ROOT / "artifacts" / "demo_bundle.zip"
    build_artifact_bundle([manifest_path], output_path=source_bundle, repo_root=source_root)
    output_bundle = TMP_ROOT / "downloads" / "demo_bundle.zip"

    payload = download_bundle_file(
        str(source_bundle),
        output_path=output_bundle,
        expected_sha256=sha256_file(source_bundle),
        expected_bytes=source_bundle.stat().st_size,
    )

    assert payload["status"] == "ok"
    assert output_bundle.exists()
    assert payload["verification"]["actual_sha256"] == sha256_file(source_bundle)


def test_download_bundle_file_reports_hash_mismatch() -> None:
    source_root = TMP_ROOT / "source"
    source_root.mkdir()
    manifest_path = _write_demo_manifest(source_root)
    source_bundle = TMP_ROOT / "artifacts" / "demo_bundle.zip"
    build_artifact_bundle([manifest_path], output_path=source_bundle, repo_root=source_root)

    payload = download_bundle_file(
        str(source_bundle),
        output_path=TMP_ROOT / "downloads" / "demo_bundle.zip",
        expected_sha256="not-the-real-sha",
    )

    assert payload["status"] == "failed"
    assert payload["verification"]["status"] == "mismatch"


def test_load_bundle_release_metadata_reads_first_bundle() -> None:
    metadata_path = TMP_ROOT / "reproducibility" / "release_artifacts.json"
    write_json(
        metadata_path,
        {
            "name": "demo_release",
            "status": "published",
            "bundles": [
                {
                    "name": "demo_bundle",
                    "filename": "demo.zip",
                    "url": "https://example.invalid/demo.zip",
                    "sha256": "abc",
                    "bytes": 123,
                }
            ],
        },
    )

    payload = load_bundle_release_metadata(metadata_path, TMP_ROOT)

    assert payload["name"] == "demo_bundle"
    assert payload["status"] == "published"
    assert payload["filename"] == "demo.zip"
    assert payload["sha256"] == "abc"
