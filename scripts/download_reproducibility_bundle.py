from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.reproducibility import (
    download_bundle_file,
    load_bundle_release_metadata,
    restore_artifact_bundle,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Download, verify, and optionally restore a VeriSec Forge reproducibility bundle.",
    )
    parser.add_argument("--url", help="Bundle URL or local source path.")
    parser.add_argument(
        "--metadata",
        default="reproducibility/release_artifacts.json",
        help="Release metadata JSON used when --url is not provided.",
    )
    parser.add_argument(
        "--bundle-name",
        help="Bundle name to select from release metadata. Defaults to the first bundle.",
    )
    parser.add_argument(
        "--output",
        help="Downloaded bundle path. Defaults to artifacts/<metadata filename>.",
    )
    parser.add_argument("--sha256", help="Expected bundle SHA256. Overrides metadata.")
    parser.add_argument("--bytes", type=int, help="Expected bundle byte size. Overrides metadata.")
    parser.add_argument(
        "--restore",
        action="store_true",
        help="Restore the downloaded bundle into the repository after verification.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow restore to overwrite existing artifact files.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    metadata = None
    source = args.url
    filename = "verisec_forge_repro_bundle.zip"
    expected_sha = args.sha256
    expected_bytes = args.bytes

    if source is None:
        metadata = load_bundle_release_metadata(args.metadata, ROOT)
        if args.bundle_name:
            release_metadata = metadata["metadata"]
            matches = [
                bundle
                for bundle in release_metadata.get("bundles", [])
                if bundle.get("name") == args.bundle_name
            ]
            if not matches:
                payload = {
                    "status": "failed",
                    "metadata": args.metadata,
                    "bundle_name": args.bundle_name,
                    "message": "release metadata does not contain the requested bundle",
                }
                print(json.dumps(payload, indent=2, ensure_ascii=False))
                return 1
            bundle = matches[0]
            metadata = {
                "name": bundle.get("name", args.bundle_name),
                "url": bundle.get("url"),
                "filename": bundle.get("filename"),
                "sha256": bundle.get("sha256"),
                "bytes": bundle.get("bytes"),
                "status": release_metadata.get("status", "unknown"),
                "metadata": release_metadata,
            }
        source = metadata.get("url")
        filename = metadata.get("filename") or filename
        expected_sha = expected_sha or metadata.get("sha256")
        expected_bytes = expected_bytes if expected_bytes is not None else metadata.get("bytes")
        if not source:
            payload = {
                "status": "failed",
                "metadata": args.metadata,
                "message": "release metadata does not yet define a bundle URL",
            }
            print(json.dumps(payload, indent=2, ensure_ascii=False))
            return 1

    output_path = Path(args.output) if args.output else ROOT / "artifacts" / filename
    payload = download_bundle_file(
        source,
        output_path=output_path,
        expected_sha256=expected_sha,
        expected_bytes=expected_bytes,
    )
    if metadata is not None:
        payload["release_metadata"] = {
            "name": metadata["name"],
            "status": metadata["status"],
            "filename": filename,
        }

    if payload["status"] == "ok" and args.restore:
        payload["restore"] = restore_artifact_bundle(
            output_path,
            repo_root=ROOT,
            overwrite=args.overwrite,
        )
        if payload["restore"]["status"] != "ok":
            payload["status"] = "failed"

    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0 if payload["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
